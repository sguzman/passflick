//! Experimental explicit Vaultwarden updater. NEVER part of the default build.
//! Remote and local passphrases are read from the terminal without echo, and
//! all identities, login names, and secrets are excluded from diagnostics.
//! No credential, bearer token or refresh token is written to disk.
//! The original vault.passvault and its picker are never opened by this path.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{BufRead, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::passphrase;
use crate::projection::ProjectionSnapshot;

use super::auth::{AuthError, MfaChallenge, MfaProvider};
use super::cache_store;
use super::keywrap;
use super::projection_identity::{self, IdentityError};
use super::refresh_status::{self, Outcome, Report};
use super::transport::{ReadOnlySyncTransport, ServerEndpoint};
use super::update;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PreviewError {
    #[error("masked terminal input unavailable")]
    Input,
    #[error("unsupported or invalid HTTPS endpoint")]
    Endpoint,
    #[error("server differs from the existing offline projection; no authentication attempted")]
    ServerMismatch,
    #[error("trusted HTTPS transport could not be initialized")]
    Transport,
    #[error("Vaultwarden authentication or MFA failed")]
    Authentication,
    #[error(
        "Vaultwarden HTTPS connection or certificate validation failed; local snapshot unchanged"
    )]
    Network,
    #[error("Vaultwarden authentication rate limited; retry later; local snapshot unchanged")]
    RateLimited,
    #[error(
        "Vaultwarden authentication service unavailable; local snapshot unchanged"
    )]
    RemoteService,
    #[error("complete authenticated Vaultwarden sync failed; local snapshot unchanged")]
    RemoteSync,
    #[error("local projection directory or certificate is inaccessible or unsafe")]
    Storage,
    #[error("local encrypted projection authentication or update failed")]
    Local,
}

impl PreviewError {
    fn refresh_outcome(&self) -> Outcome {
        match self {
            Self::Input => Outcome::Input,
            Self::Endpoint | Self::ServerMismatch => Outcome::Configuration,
            Self::Authentication => Outcome::Authentication,
            Self::Transport
            | Self::Network
            | Self::RateLimited
            | Self::RemoteService
            | Self::RemoteSync => Outcome::Sync,
            Self::Storage | Self::Local => Outcome::Local,
        }
    }
}

/// Keep TLS/connectivity failures distinct from a rejected password or MFA.
/// Never preserve or display the upstream reqwest error: it may contain
/// private endpoint details.
fn auth_failure(error: AuthError) -> PreviewError {
    match error {
        AuthError::Transport => PreviewError::Network,
        AuthError::RateLimited => PreviewError::RateLimited,
        AuthError::RemoteService => PreviewError::RemoteService,
        _ => PreviewError::Authentication,
    }
}

/// A rejected read-only sync bearer is an authorization failure, not a
/// network outage. Keep malformed payloads and remote HTTP/server failures
/// classified as Sync; neither case may publish an incomplete projection.
/// Return only fixed categories, never the upstream response or URL.
fn sync_failure(error: update::UpdateError) -> PreviewError {
    match error {
        update::UpdateError::Auth(error) => auth_failure(error),
        update::UpdateError::Transport(super::transport::TransportError::Unauthorized) => {
            PreviewError::Authentication
        }
        _ => PreviewError::RemoteSync,
    }
}

/// Prevent an input-echo race: rpassword prints before it disables echo.
struct PromptTerminal {
    tty: fs::File,
    saved: libc::termios,
}

impl Drop for PromptTerminal {
    fn drop(&mut self) {
        // SAFETY: saved was initialized by tcgetattr on this live TTY.
        unsafe {
            libc::tcsetattr(self.tty.as_raw_fd(), libc::TCSAFLUSH, &self.saved);
        }
    }
}

pub(super) fn masked(prompt: &str) -> Result<Zeroizing<String>, PreviewError> {
    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| PreviewError::Input)?;
    let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: the descriptor is an open terminal; original is writable storage.
    if unsafe { libc::tcgetattr(tty.as_raw_fd(), original.as_mut_ptr()) } != 0 {
        return Err(PreviewError::Input);
    }
    // SAFETY: tcgetattr successfully initialized the entire structure.
    let original = unsafe { original.assume_init() };
    let mut hidden = original;
    hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
    // SAFETY: hide input on this controlling TTY before printing any prompt.
    if unsafe { libc::tcsetattr(tty.as_raw_fd(), libc::TCSAFLUSH, &hidden) } != 0 {
        return Err(PreviewError::Input);
    }
    let mut protected = PromptTerminal {
        tty,
        saved: original,
    };
    protected
        .tty
        .write_all(prompt.as_bytes())
        .and_then(|_| protected.tty.flush())
        .map_err(|_| PreviewError::Input)?;
    // rpassword's nested guard restores to the already-hidden mode.
    // The outer guard restores the original terminal flags on every exit.
    let password = rpassword::read_password().map_err(|_| PreviewError::Input)?;
    Ok(Zeroizing::new(password))
}

/// Visible, editable input for non-secret configuration only. The TTY
/// mode is restored on every exit. Never use for credentials or MFA codes.
pub(super) fn visible(prompt: &str) -> Result<Zeroizing<String>, PreviewError> {
    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| PreviewError::Input)?;
    let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: tty is live; the destination points to writable termios storage.
    if unsafe { libc::tcgetattr(tty.as_raw_fd(), original.as_mut_ptr()) } != 0 {
        return Err(PreviewError::Input);
    }
    // SAFETY: successful tcgetattr initialized the termios.
    let original = unsafe { original.assume_init() };
    let mut echoed = original;
    echoed.c_lflag |= libc::ECHO;
    // SAFETY: tty remains open; enable echo before showing the prompt.
    if unsafe { libc::tcsetattr(tty.as_raw_fd(), libc::TCSAFLUSH, &echoed) } != 0 {
        return Err(PreviewError::Input);
    }
    let mut terminal = PromptTerminal {
        tty,
        saved: original,
    };
    terminal
        .tty
        .write_all(prompt.as_bytes())
        .and_then(|_| terminal.tty.flush())
        .map_err(|_| PreviewError::Input)?;
    let mut value = Zeroizing::new(String::new());
    let count = std::io::BufReader::new(&mut terminal.tty)
        .read_line(&mut value)
        .map_err(|_| PreviewError::Input)?;
    if count == 0 {
        return Err(PreviewError::Input);
    }
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    Ok(value)
}

/// The non-secret device identifier must survive explicit reauthentication.
/// It is a distinct, owner-only file, never part of legacy vault state.
fn read_device_id(path: &Path) -> Result<String, PreviewError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| PreviewError::Storage)?;
    let meta = file.metadata().map_err(|_| PreviewError::Storage)?;
    if !meta.is_file()
        || !crate::vault::owned_by_current_user(&meta)
        || meta.permissions().mode() & 0o777 != 0o600
        || meta.nlink() != 1
        || meta.len() != 32
    {
        return Err(PreviewError::Storage);
    }
    let mut bytes = [0_u8; 32];
    file.read_exact(&mut bytes)
        .map_err(|_| PreviewError::Storage)?;
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(PreviewError::Storage);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| PreviewError::Storage)
}

/// Create one random, stable device ID per local installation. The keywrap and
/// encrypted snapshot are separate files. Never rotate a malformed ID silently,
/// and never overwrite a concurrently created ID.
fn device_id(snapshot_path: &Path) -> Result<String, PreviewError> {
    private_parent(snapshot_path)?;
    let path = snapshot_path.with_file_name("projection.pfdevice");
    match read_device_id(&path) {
        Ok(value) => return Ok(value),
        Err(PreviewError::Storage) if path.symlink_metadata().is_ok() => {
            return Err(PreviewError::Storage);
        }
        Err(_) => {}
    }

    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| PreviewError::Storage)?;
    let identifier: String = bytes.iter().map(|value| format!("{value:02x}")).collect();
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(identifier.as_bytes())
                .map_err(|_| PreviewError::Storage)?;
            file.sync_all().map_err(|_| PreviewError::Storage)?;
            fs::File::open(snapshot_path.parent().ok_or(PreviewError::Storage)?)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| PreviewError::Storage)?;
            Ok(identifier)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => read_device_id(&path),
        Err(_) => Err(PreviewError::Storage),
    }
}

fn additional_ca(path: &Path) -> Result<Zeroizing<Vec<u8>>, PreviewError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| PreviewError::Storage)?;
    let meta = file.metadata().map_err(|_| PreviewError::Storage)?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
        return Err(PreviewError::Storage);
    }
    let mut pem = Zeroizing::new(Vec::new());
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut pem)
        .map_err(|_| PreviewError::Storage)?;
    if pem.is_empty() || pem.len() > 1024 * 1024 {
        return Err(PreviewError::Storage);
    }
    Ok(pem)
}

fn private_parent(snapshot_path: &Path) -> Result<(), PreviewError> {
    let directory = snapshot_path.parent().ok_or(PreviewError::Storage)?;
    if fs::symlink_metadata(directory).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        let ancestor = directory.parent().ok_or(PreviewError::Storage)?;
        fs::create_dir_all(ancestor).map_err(|_| PreviewError::Storage)?;
        if let Err(e) = DirBuilder::new().mode(0o700).create(directory)
            && e.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(PreviewError::Storage);
        }
    }
    let meta = fs::symlink_metadata(directory).map_err(|_| PreviewError::Storage)?;
    if !meta.is_dir()
        || meta.permissions().mode() & 0o077 != 0
        || !crate::vault::owned_by_current_user(&meta)
    {
        return Err(PreviewError::Storage);
    }
    Ok(())
}

fn snapshot_exists(path: &Path) -> Result<bool, PreviewError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => Ok(true),
        Ok(_) => Err(PreviewError::Storage),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(PreviewError::Storage),
    }
}

/// Fail early on a known different configured server, before reading any
/// account identifier or master password and before attempting HTTPS login.
/// This 0600 metadata is only a preflight hint: publication must still verify
/// the authenticated encrypted snapshot and source account. Older snapshots
/// without the sidecar retain their existing authenticated migration path.
fn preflight_server_scope(
    snapshot_path: &Path,
    endpoint: &ServerEndpoint,
) -> Result<(), PreviewError> {
    match projection_identity::read(&snapshot_path.with_file_name("projection.pfidentity")) {
        Ok(identity) if identity.server() == endpoint.server_identity() => Ok(()),
        Ok(_) => Err(PreviewError::ServerMismatch),
        Err(IdentityError::Missing) => Ok(()),
        Err(_) => Err(PreviewError::Local),
    }
}

/// Local-only publication step. Initial install creates a distinct keywrap
/// and ciphertext; later updates verify old AEAD and identity before replace.
/// In either case the same server-issued account is bound to the snapshot.
pub(crate) fn publish_candidate(
    candidate: &ProjectionSnapshot,
    snapshot_path: &Path,
    local_passphrase: &[u8],
    first_install: bool,
) -> Result<usize, PreviewError> {
    private_parent(snapshot_path)?;
    let wrapped = snapshot_path.with_file_name("projection.pfkey");
    let identity_path = snapshot_path.with_file_name("projection.pfidentity");
    // An existing sidecar cannot redirect a healthy encrypted snapshot to
    // another account. Older preview snapshots may acquire the sidecar only
    // after their old ciphertext has authenticated successfully.
    match projection_identity::read(&identity_path) {
        Ok(found)
            if found.server() == candidate.server_identity()
                && found.account() == candidate.account_id() => {}
        Ok(_) => return Err(PreviewError::Local),
        Err(IdentityError::Missing) => {}
        Err(_) => return Err(PreviewError::Local),
    }
    if first_install {
        let count = update::install_initial_projection(
            candidate,
            snapshot_path,
            &wrapped,
            local_passphrase,
        )
        .map_err(|_| PreviewError::Local)?;
        projection_identity::ensure(&identity_path, candidate).map_err(|_| PreviewError::Local)?;
        return Ok(count);
    }
    let key = keywrap::unlock(
        &wrapped,
        local_passphrase,
        candidate.server_identity(),
        candidate.account_id(),
    )
    .map_err(|_| PreviewError::Local)?;
    // A wrong or corrupt key, another server/account, or invalid permissions
    // must fail before any attempt to replace the existing ciphertext.
    cache_store::load(
        snapshot_path,
        &key,
        candidate.server_identity(),
        candidate.account_id(),
    )
    .map_err(|_| PreviewError::Local)?;
    cache_store::publish(snapshot_path, &key, candidate).map_err(|_| PreviewError::Local)?;
    projection_identity::ensure(&identity_path, candidate).map_err(|_| PreviewError::Local)?;
    Ok(candidate.items().len())
}

/// Retry local first-install input without repeating a successful remote
/// authentication or sync. The old all-or-nothing candidate stays in memory
/// until validation succeeds; no projection ciphertext is written on error.
/// Prompt injection lets tests exercise invalid entries without a real TTY.
fn prompt_new_projection_passphrase(
    mut prompt: impl FnMut(&str) -> Result<Zeroizing<String>, PreviewError>,
) -> Result<Zeroizing<String>, PreviewError> {
    loop {
        let local = prompt("New independent local projection passphrase (12–1024 characters): ")?;
        // Reject invalid length *before* asking for an exact confirmation.
        if let Err(error) = passphrase::validate_new(local.as_str(), local.as_str()) {
            eprintln!(
                "Local projection passphrase rejected: {error}. Try again (Ctrl+C to cancel)."
            );
            continue;
        }
        let confirmation = prompt("Confirm local projection passphrase: ")?;
        match passphrase::validate_new(local.as_str(), confirmation.as_str()) {
            Ok(()) => return Ok(local),
            Err(error) => {
                eprintln!(
                    "Local projection passphrase rejected: {error}. Re-enter both fields (Ctrl+C to cancel)."
                );
            }
        }
    }
}

/// Explicit, opt-in preview command. All network activity occurs here, never
/// during normal picker/search/copy. Login is performed for each update;
/// remote tokens are never cached or serialized.
pub fn run() -> Result<(), PreviewError> {
    let result = run_explicit();
    // This non-secret record is advisory only. Never create it for a missing
    // projection, and never let a reporting error change the update result.
    // The encrypted snapshot remains the sole authority for offline data.
    if let Ok(path) = crate::paths::projection_path()
        && snapshot_exists(&path) == Ok(true)
        && let Ok(at) = SystemTime::now().duration_since(UNIX_EPOCH)
    {
        let outcome = match &result {
            Ok(()) => Outcome::Success,
            Err(error) => error.refresh_outcome(),
        };
        if refresh_status::record(
            &path,
            Report {
                at: at.as_secs(),
                outcome,
            },
        )
        .is_err()
        {
            eprintln!(
                "Passflick: refresh status could not be recorded; local snapshot status is unchanged."
            );
        }
    }
    result
}

fn run_explicit() -> Result<(), PreviewError> {
    let server = visible("Vaultwarden HTTPS server URL: ")?;
    let endpoint = ServerEndpoint::parse(&server).map_err(|_| PreviewError::Endpoint)?;
    // Reject a different server before accepting remote account credentials.
    // This preflight never authorizes publication: the encrypted identity,
    // keywrap and snapshot are checked again after a full remote sync.
    let path = crate::paths::projection_path().map_err(|_| PreviewError::Storage)?;
    private_parent(&path)?;
    preflight_server_scope(&path, &endpoint)?;
    let email = visible("Vaultwarden login email: ")?;
    let master = masked("Vaultwarden master password: ")?;
    let ca_path = visible("Custom trusted CA PEM path (empty for system trust): ")?;
    let transport = if ca_path.is_empty() {
        ReadOnlySyncTransport::new()
    } else {
        let pem = additional_ca(Path::new(ca_path.as_str()))?;
        ReadOnlySyncTransport::with_additional_root_pem(&pem)
    }
    .map_err(|_| PreviewError::Transport)?;

    // Keep the device identifier outside the historical encrypted vault.
    // Validate the local destination before any login request is transmitted.
    let identifier = device_id(&path)?;
    let (mut session, decoder) =
        match transport.authenticate(&endpoint, &email, &master, &identifier, None) {
            Ok(result) => result,
            Err(AuthError::MfaRequired) => {
                let method = visible("MFA method (totp/email): ")?;
                let provider = match method.as_str() {
                    "totp" => MfaProvider::Totp,
                    "email" => MfaProvider::EmailCode,
                    _ => return Err(PreviewError::Authentication),
                };
                let code = masked("MFA code: ")?;
                transport
                    .authenticate(
                        &endpoint,
                        &email,
                        &master,
                        &identifier,
                        Some(MfaChallenge {
                            provider,
                            code: &code,
                        }),
                    )
                    .map_err(auth_failure)?
            }
            Err(error) => return Err(auth_failure(error)),
        };

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PreviewError::RemoteSync)?
        .as_secs();
    let candidate =
        update::prepare_initial_sync(&transport, &mut session, &endpoint, timestamp, &decoder)
            .map_err(sync_failure)?;
    // Do not touch the historical PASSFLICK_VAULT override or original file.
    let first_install = !snapshot_exists(&path)?;
    let local = if first_install {
        prompt_new_projection_passphrase(masked)?
    } else {
        masked("Local projection passphrase: ")?
    };
    let count = publish_candidate(&candidate, &path, local.as_bytes(), first_install)?;
    println!("Encrypted offline projection updated ({count} login items).");
    println!("Normal picker remains on the historical vault in this preview.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection::{LoginItem, ProjectionSnapshot};
    use std::path::PathBuf;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let mut random = [0_u8; 8];
            getrandom::fill(&mut random).unwrap();
            let root = std::env::temp_dir().join(format!(
                "passflick-preview-test-{:016x}",
                u64::from_le_bytes(random)
            ));
            DirBuilder::new().mode(0o700).create(&root).unwrap();
            Self(root)
        }

        fn snapshot(&self) -> PathBuf {
            self.0.join("projection.pfsnapshot")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn candidate(timestamp: u64, password: &str) -> ProjectionSnapshot {
        ProjectionSnapshot::new(
            "https://vault.example.test/".to_owned(),
            "synthetic-account".to_owned(),
            timestamp,
            vec![LoginItem::new(
                "server-id".to_owned(),
                "Synthetic".to_owned(),
                vec!["https://example.test/login".to_owned()],
                "fictional-user".to_owned(),
                password.to_owned(),
                None,
            )],
        )
        .unwrap()
    }

    #[test]
    fn update_failures_have_only_fixed_privacy_safe_status_categories() {
        assert_eq!(PreviewError::Input.refresh_outcome(), Outcome::Input);
        assert_eq!(
            PreviewError::Endpoint.refresh_outcome(),
            Outcome::Configuration
        );
        assert_eq!(
            PreviewError::ServerMismatch.refresh_outcome(),
            Outcome::Configuration
        );
        assert_eq!(
            PreviewError::Authentication.refresh_outcome(),
            Outcome::Authentication
        );
        assert_eq!(PreviewError::Network.refresh_outcome(), Outcome::Sync);
        assert_eq!(PreviewError::RateLimited.refresh_outcome(), Outcome::Sync);
        assert_eq!(PreviewError::RemoteService.refresh_outcome(), Outcome::Sync);
        assert_eq!(PreviewError::Transport.refresh_outcome(), Outcome::Sync);
        assert_eq!(auth_failure(AuthError::Transport), PreviewError::Network);
        assert_eq!(
            auth_failure(AuthError::RateLimited),
            PreviewError::RateLimited
        );
        assert_eq!(
            auth_failure(AuthError::RemoteService),
            PreviewError::RemoteService
        );
        assert_eq!(
            auth_failure(AuthError::Rejected),
            PreviewError::Authentication
        );
        assert_eq!(
            auth_failure(AuthError::MfaRequired),
            PreviewError::Authentication
        );
        assert_eq!(PreviewError::RemoteSync.refresh_outcome(), Outcome::Sync);
        // Rejected access to /api/sync must not masquerade as a TLS outage
        // or cause any snapshot publication; only a fixed category persists.
        assert_eq!(
            sync_failure(update::UpdateError::Transport(
                super::super::transport::TransportError::Unauthorized
            )),
            PreviewError::Authentication
        );
        for status in [429, 500, 503] {
            assert_eq!(
                sync_failure(update::UpdateError::Transport(
                    super::super::transport::TransportError::UnexpectedStatus(status)
                )),
                PreviewError::RemoteSync
            );
        }
        assert_eq!(
            sync_failure(update::UpdateError::Transport(
                super::super::transport::TransportError::Network
            )),
            PreviewError::RemoteSync
        );
        assert_eq!(
            sync_failure(update::UpdateError::Auth(AuthError::Transport)),
            PreviewError::Network
        );
        assert_eq!(
            sync_failure(update::UpdateError::Auth(AuthError::Rejected)),
            PreviewError::Authentication
        );
        assert_eq!(PreviewError::Storage.refresh_outcome(), Outcome::Local);
        assert_eq!(PreviewError::Local.refresh_outcome(), Outcome::Local);
    }

    #[test]
    fn local_passphrase_retry_recovers_without_restarting_remote_sync() {
        use std::collections::VecDeque;

        // First input is too short (no confirmation prompt), then the
        // confirmation differs, then both entries match exactly.
        let mut answers = VecDeque::from([
            "short",
            "correct horse battery staple",
            "correct horse battery staplE",
            "correct horse battery staple",
            "correct horse battery staple",
        ]);
        let mut prompts = Vec::new();
        let accepted = prompt_new_projection_passphrase(|label| {
            prompts.push(label.to_owned());
            answers
                .pop_front()
                .map(|value| Zeroizing::new(value.to_owned()))
                .ok_or(PreviewError::Input)
        })
        .unwrap();
        assert_eq!(accepted.as_str(), "correct horse battery staple");
        assert!(answers.is_empty());
        assert_eq!(prompts.len(), 5);
        assert_eq!(
            prompts
                .iter()
                .filter(|label| label.contains("Confirm"))
                .count(),
            2
        );
    }

    #[test]
    fn local_passphrase_prompt_failure_cancels_without_publishing() {
        // A closed terminal, Ctrl+C, or unavailable input must return an
        // error instead of silently proceeding with an invalid passphrase.
        let mut calls = 0;
        assert_eq!(
            prompt_new_projection_passphrase(|_| {
                calls += 1;
                Err(PreviewError::Input)
            }),
            Err(PreviewError::Input)
        );
        assert_eq!(calls, 1);
    }

    #[test]
    fn preview_first_install_refresh_and_wrong_passphrase_preserve_ciphertext() {
        let fixture = Fixture::new();
        let path = fixture.snapshot();
        let passphrase = b"fictional independent local passphrase";
        let legacy = fixture.0.join("vault.passvault");
        fs::write(&legacy, b"original fictional legacy encrypted data").unwrap();
        assert_eq!(
            publish_candidate(&candidate(100, "first"), &path, passphrase, true).unwrap(),
            1
        );
        let initial = fs::read(&path).unwrap();
        assert_eq!(
            publish_candidate(
                &candidate(101, "different"),
                &path,
                b"incorrect passphrase",
                false
            ),
            Err(PreviewError::Local)
        );
        assert_eq!(fs::read(&path).unwrap(), initial);
        assert_eq!(
            publish_candidate(&candidate(102, "replacement"), &path, passphrase, true),
            Err(PreviewError::Local)
        );
        assert_eq!(fs::read(&path).unwrap(), initial);
        assert_eq!(
            publish_candidate(&candidate(101, "second"), &path, passphrase, false).unwrap(),
            1
        );
        assert_ne!(fs::read(&path).unwrap(), initial);
        let key = keywrap::unlock(
            &fixture.0.join("projection.pfkey"),
            passphrase,
            "https://vault.example.test/",
            "synthetic-account",
        )
        .unwrap();
        let read = cache_store::load(
            &path,
            &key,
            "https://vault.example.test/",
            "synthetic-account",
        )
        .unwrap();
        assert_eq!(read.items()[0].password(), "second");
        assert_eq!(
            fs::read(legacy).unwrap(),
            b"original fictional legacy encrypted data"
        );
    }

    #[test]
    fn configured_server_scope_is_checked_before_credential_prompts() {
        let fixture = Fixture::new();
        let path = fixture.snapshot();
        let configured = ServerEndpoint::parse("https://vault.example.test/").unwrap();
        let different = ServerEndpoint::parse("https://other.example.test/").unwrap();

        // Fresh and older sidecar-less snapshots retain their safe migration
        // path. This hint cannot authorize publication by itself.
        assert_eq!(preflight_server_scope(&path, &different), Ok(()));
        publish_candidate(
            &candidate(100, "fictional-secret"),
            &path,
            b"fictional independent local passphrase",
            true,
        )
        .unwrap();
        let original_ciphertext = fs::read(&path).unwrap();
        let identity_path = fixture.0.join("projection.pfidentity");
        let original_identity = fs::read(&identity_path).unwrap();

        assert_eq!(preflight_server_scope(&path, &configured), Ok(()));
        assert_eq!(
            preflight_server_scope(&path, &different),
            Err(PreviewError::ServerMismatch)
        );
        assert_eq!(fs::read(&path).unwrap(), original_ciphertext);
        assert_eq!(fs::read(&identity_path).unwrap(), original_identity);

        // An invalid sidecar cannot be used to choose another authority.
        fs::write(&identity_path, b"invalid metadata").unwrap();
        assert_eq!(
            preflight_server_scope(&path, &configured),
            Err(PreviewError::Local)
        );
        assert_eq!(fs::read(&path).unwrap(), original_ciphertext);

        // For old installations without a sidecar, the final authenticated
        // cache checks remain mandatory before a replacement can succeed.
        fs::remove_file(&identity_path).unwrap();
        assert_eq!(preflight_server_scope(&path, &different), Ok(()));
    }

    #[test]
    fn stable_device_id_survives_restarts_without_legacy_vault_changes() {
        let fixture = Fixture::new();
        let legacy = fixture.0.join("vault.passvault");
        fs::write(&legacy, b"original fictional legacy encrypted data").unwrap();
        let first = device_id(&fixture.snapshot()).unwrap();
        assert_eq!(first.len(), 32);
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_eq!(device_id(&fixture.snapshot()).unwrap(), first);
        let path = fixture.0.join("projection.pfdevice");
        assert_eq!(fs::read(&path).unwrap(), first.as_bytes());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::read(legacy).unwrap(),
            b"original fictional legacy encrypted data"
        );
    }

    #[test]
    fn malformed_or_unsafe_device_identity_never_rotates_silently() {
        let fixture = Fixture::new();
        let path = fixture.0.join("projection.pfdevice");
        fs::write(&path, b"tampered-id").unwrap();
        let tampered = fs::read(&path).unwrap();
        assert_eq!(device_id(&fixture.snapshot()), Err(PreviewError::Storage));
        assert_eq!(fs::read(&path).unwrap(), tampered);
        fs::remove_file(&path).unwrap();

        let external = fixture.0.join("external-id");
        fs::write(&external, b"00000000000000000000000000000000").unwrap();
        std::os::unix::fs::symlink(&external, &path).unwrap();
        assert_eq!(device_id(&fixture.snapshot()), Err(PreviewError::Storage));
        fs::remove_file(&path).unwrap();

        let original = device_id(&fixture.snapshot()).unwrap();
        let other_link = fixture.0.join("hardlink-id");
        fs::hard_link(&path, &other_link).unwrap();
        assert_eq!(device_id(&fixture.snapshot()), Err(PreviewError::Storage));
        assert_eq!(fs::read(&path).unwrap(), original.as_bytes());
        fs::remove_file(&other_link).unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(device_id(&fixture.snapshot()), Err(PreviewError::Storage));
    }

    #[test]
    fn preview_rejects_unsafe_directory_and_untrusted_ca_file() {
        let fixture = Fixture::new();
        let cert = fixture.0.join("not-a-certificate");
        fs::write(&cert, b"not a PEM certificate").unwrap();
        let pem = additional_ca(&cert).unwrap();
        assert!(ReadOnlySyncTransport::with_additional_root_pem(&pem).is_err());
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            private_parent(&fixture.snapshot()),
            Err(PreviewError::Storage)
        );
    }
}
