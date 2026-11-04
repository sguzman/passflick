//! Experimental explicit Vaultwarden updater. NEVER part of the default build.
//! Remote and local passphrases are read from the terminal without echo, and
//! all identities, login names, and secrets are excluded from diagnostics.
//! No credential, bearer token or refresh token is written to disk.
//! The original vault.passvault and its picker are never opened by this path.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::passphrase;
use crate::projection::ProjectionSnapshot;

use super::auth::{AuthError, MfaChallenge, MfaProvider};
use super::cache_store;
use super::keywrap;
use super::transport::{ReadOnlySyncTransport, ServerEndpoint};
use super::update;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PreviewError {
    #[error("masked terminal input unavailable")]
    Input,
    #[error("unsupported or invalid HTTPS endpoint")]
    Endpoint,
    #[error("trusted HTTPS transport could not be initialized")]
    Transport,
    #[error("Vaultwarden authentication or MFA failed")]
    Authentication,
    #[error("complete authenticated Vaultwarden sync failed; local snapshot unchanged")]
    RemoteSync,
    #[error("local projection directory or certificate is inaccessible or unsafe")]
    Storage,
    #[error("local passphrase confirmation or strength check failed")]
    Passphrase,
    #[error("local encrypted projection authentication or update failed")]
    Local,
}

fn masked(prompt: &str) -> Result<Zeroizing<String>, PreviewError> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(|_| PreviewError::Input)
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
    if first_install {
        return update::install_initial_projection(
            candidate,
            snapshot_path,
            &wrapped,
            local_passphrase,
        )
        .map_err(|_| PreviewError::Local);
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
    Ok(candidate.items().len())
}

/// Explicit, opt-in preview command. All network activity occurs here, never
/// during normal picker/search/copy. Login is performed for each update;
/// remote tokens are never cached or serialized.
pub fn run() -> Result<(), PreviewError> {
    let server = masked("Vaultwarden HTTPS server URL: ")?;
    let endpoint = ServerEndpoint::parse(&server).map_err(|_| PreviewError::Endpoint)?;
    let email = masked("Vaultwarden login email: ")?;
    let master = masked("Vaultwarden master password: ")?;
    let ca_path = masked("Custom trusted CA PEM path (empty for system trust): ")?;
    let transport = if ca_path.is_empty() {
        ReadOnlySyncTransport::new()
    } else {
        let pem = additional_ca(Path::new(ca_path.as_str()))?;
        ReadOnlySyncTransport::with_additional_root_pem(&pem)
    }
    .map_err(|_| PreviewError::Transport)?;

    let path = crate::paths::projection_path().map_err(|_| PreviewError::Storage)?;
    // Keep the device identifier outside the historical encrypted vault.
    // Validate the local destination before any login request is transmitted.
    private_parent(&path)?;
    let identifier = device_id(&path)?;
    let (mut session, decoder) =
        match transport.authenticate(&endpoint, &email, &master, &identifier, None) {
            Ok(result) => result,
            Err(AuthError::MfaRequired) => {
                let method = masked("MFA method (totp/email): ")?;
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
                    .map_err(|_| PreviewError::Authentication)?
            }
            Err(_) => return Err(PreviewError::Authentication),
        };

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PreviewError::RemoteSync)?
        .as_secs();
    let candidate =
        update::prepare_initial_sync(&transport, &mut session, &endpoint, timestamp, &decoder)
            .map_err(|_| PreviewError::RemoteSync)?;
    // Do not touch the historical PASSFLICK_VAULT override or original file.
    let first_install = !snapshot_exists(&path)?;
    let local = masked(if first_install {
        "New independent local projection passphrase: "
    } else {
        "Local projection passphrase: "
    })?;
    if first_install {
        let confirmation = masked("Confirm local projection passphrase: ")?;
        passphrase::validate_new(local.as_str(), confirmation.as_str())
            .map_err(|_| PreviewError::Passphrase)?;
    }
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
