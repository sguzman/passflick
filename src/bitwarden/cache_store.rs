//! Encrypted, independently keyed offline Vaultwarden projection snapshot.
//!
//! This module is test-only until the production local unlock / keyring and
//! real-server integration gates pass. It NEVER opens or writes vault.passvault.
//! The caller provides an independent local 32-byte key: it is NOT a Bitwarden
//! master key, login token, or a key recovered from the legacy vault.
//!
//! Only fully validated projection records may be encrypted. Under a private
//! owner-owned directory, an advisory lock covers existing-snapshot validation
//! through atomic publication. Existing snapshots are authenticated before
//! replacement and cross-account/server or timestamp rollback is rejected.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{AeadInOut, KeyInit},
};
use zeroize::Zeroizing;

use crate::projection::{ProjectionError, ProjectionSnapshot};
use crate::vault::owned_by_current_user;
use crate::write_lock;

const MAGIC: &[u8; 8] = b"PFPROJ01";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 8 + 2 + 2 + 24;
const AEAD_TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const MAX_CACHE_BYTES: u64 = 64 * 1024 * 1024 + HEADER_LEN as u64 + AEAD_TAG_LEN as u64;
const CACHE_FILENAME: &str = "projection.pfsnapshot";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CacheError {
    #[error("invalid local snapshot key")]
    InvalidKey,
    #[error("snapshot must use the dedicated projection.pfsnapshot filename")]
    InvalidPath,
    #[error("snapshot directory must be private and owned by current user")]
    UnsafeDirectory,
    #[error("snapshot must be a private owner-owned regular file")]
    UnsafeFile,
    #[error("snapshot is missing")]
    Missing,
    #[error("snapshot is too large")]
    Oversized,
    #[error("snapshot format or encryption header is invalid")]
    InvalidFormat,
    #[error("snapshot authentication failed")]
    AuthenticationFailed,
    #[error("snapshot identity does not match the expected server/account")]
    IdentityMismatch,
    #[error("snapshot timestamp would be rolled back")]
    Rollback,
    #[error("snapshot data failed validation: {0}")]
    Projection(#[from] ProjectionError),
    #[error("snapshot filesystem operation failed")]
    Io,
}

impl From<std::io::Error> for CacheError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

pub struct CacheKey(Zeroizing<[u8; KEY_LEN]>);

impl CacheKey {
    /// Accept an already-unlocked local projection key. The production unlock
    /// flow must persist/recover this *separate* key securely, never plaintext.
    pub fn from_slice(key: &[u8]) -> Result<Self, CacheError> {
        if key.len() != KEY_LEN {
            return Err(CacheError::InvalidKey);
        }
        let mut wrapped = Zeroizing::new([0_u8; KEY_LEN]);
        wrapped.copy_from_slice(key);
        Ok(Self(wrapped))
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, CacheError> {
        XChaCha20Poly1305::new_from_slice(&*self.0).map_err(|_| CacheError::InvalidKey)
    }
}

fn validate_filename(path: &Path) -> Result<(), CacheError> {
    if path.file_name() != Some(OsStr::new(CACHE_FILENAME)) {
        return Err(CacheError::InvalidPath);
    }
    Ok(())
}

fn private_parent(path: &Path) -> Result<(), CacheError> {
    validate_filename(path)?;
    let parent = path.parent().ok_or(CacheError::InvalidPath)?;
    let meta = fs::symlink_metadata(parent).map_err(CacheError::from)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 || !owned_by_current_user(&meta) {
        return Err(CacheError::UnsafeDirectory);
    }
    Ok(())
}

fn header() -> Result<[u8; HEADER_LEN], CacheError> {
    let mut header = [0_u8; HEADER_LEN];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&VERSION.to_le_bytes());
    getrandom::fill(&mut header[12..HEADER_LEN]).map_err(|_| CacheError::Io)?;
    Ok(header)
}

fn encrypt_snapshot(
    snapshot: &ProjectionSnapshot,
    key: &CacheKey,
) -> Result<Zeroizing<Vec<u8>>, CacheError> {
    let header = header()?;
    let mut ciphertext = snapshot.encode_json()?;
    let cipher = key.cipher()?;
    let mut nonce_bytes = [0_u8; 24];
    nonce_bytes.copy_from_slice(&header[12..HEADER_LEN]);
    let nonce = XNonce::from(nonce_bytes);
    cipher
        .encrypt_in_place(&nonce, &header, &mut *ciphertext)
        .map_err(|_| CacheError::AuthenticationFailed)?;
    let mut file = Zeroizing::new(Vec::with_capacity(HEADER_LEN + ciphertext.len()));
    file.extend_from_slice(&header);
    file.extend_from_slice(&ciphertext);
    if file.len() as u64 > MAX_CACHE_BYTES {
        return Err(CacheError::Oversized);
    }
    Ok(file)
}

fn decrypt_snapshot(raw: &[u8], key: &CacheKey) -> Result<ProjectionSnapshot, CacheError> {
    if raw.len() as u64 > MAX_CACHE_BYTES {
        return Err(CacheError::Oversized);
    }
    if raw.len() < HEADER_LEN + AEAD_TAG_LEN
        || &raw[..8] != MAGIC
        || raw[8..10] != VERSION.to_le_bytes()
        || raw[10..12] != [0, 0]
    {
        return Err(CacheError::InvalidFormat);
    }
    let cipher = key.cipher()?;
    let mut nonce_bytes = [0_u8; 24];
    nonce_bytes.copy_from_slice(&raw[12..HEADER_LEN]);
    let nonce = XNonce::from(nonce_bytes);
    let mut plaintext = Zeroizing::new(raw[HEADER_LEN..].to_vec());
    cipher
        .decrypt_in_place(&nonce, &raw[..HEADER_LEN], &mut *plaintext)
        .map_err(|_| CacheError::AuthenticationFailed)?;
    ProjectionSnapshot::decode_json(&plaintext).map_err(CacheError::from)
}

fn read_private(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, CacheError> {
    let handle = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(handle) => handle,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let meta = handle.metadata()?;
    if !meta.is_file()
        || meta.permissions().mode() & 0o077 != 0
        || !owned_by_current_user(&meta)
        || meta.nlink() != 1
    {
        return Err(CacheError::UnsafeFile);
    }
    if meta.len() > MAX_CACHE_BYTES {
        return Err(CacheError::Oversized);
    }
    let mut data = Zeroizing::new(Vec::new());
    handle.take(MAX_CACHE_BYTES + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_CACHE_BYTES {
        return Err(CacheError::Oversized);
    }
    Ok(Some(data))
}

fn check_identity(
    snapshot: &ProjectionSnapshot,
    server: &str,
    account: &str,
) -> Result<(), CacheError> {
    if snapshot.server_identity() != server || snapshot.account_id() != account {
        return Err(CacheError::IdentityMismatch);
    }
    Ok(())
}

/// Offline read: no HTTP requests, login tokens or upstream credentials.
/// Authentication is always checked before JSON/schema decoding.
pub fn load(
    path: &Path,
    key: &CacheKey,
    expected_server: &str,
    expected_account: &str,
) -> Result<ProjectionSnapshot, CacheError> {
    private_parent(path)?;
    let raw = read_private(path)?.ok_or(CacheError::Missing)?;
    let snapshot = decrypt_snapshot(&raw, key)?;
    check_identity(&snapshot, expected_server, expected_account)?;
    Ok(snapshot)
}

/// Atomic full replacement. Both upstream and local snapshot identities
/// must match; a corrupt or unreadable existing snapshot is NOT overwritten.
/// A stale timestamp is also rejected. No legacy vault path is accepted.
pub fn publish(
    path: &Path,
    key: &CacheKey,
    snapshot: &ProjectionSnapshot,
) -> Result<(), CacheError> {
    private_parent(path)?;
    let _guard = write_lock::acquire(path).map_err(|_| CacheError::Io)?;
    // Never write even a temporary file if the existing snapshot is damaged,
    // bound to another source, or newer than the incoming complete projection.
    let existing = read_private(path)?;
    if let Some(existing) = existing {
        let old = decrypt_snapshot(&existing, key)?;
        check_identity(&old, snapshot.server_identity(), snapshot.account_id())?;
        if snapshot.last_success_at() < old.last_success_at() {
            return Err(CacheError::Rollback);
        }
    }

    let encoded = encrypt_snapshot(snapshot, key)?;
    write_atomic(path, &encoded)
}

fn write_atomic(path: &Path, encrypted: &[u8]) -> Result<(), CacheError> {
    let parent = path.parent().ok_or(CacheError::InvalidPath)?;
    let mut nonce = [0_u8; 8];
    getrandom::fill(&mut nonce).map_err(|_| CacheError::Io)?;
    let temp_path = parent.join(format!(
        ".passflick-projection.tmp.{}.{:016x}",
        std::process::id(),
        u64::from_le_bytes(nonce)
    ));

    let outcome = (|| -> Result<(), CacheError> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temp_path)?;
        file.write_all(encrypted)?;
        file.sync_all()?;
        drop(file);

        // Creating a new cache must not replace a surprise preexisting file.
        // An existing authenticated cache can be replaced by an atomic rename.
        match fs::symlink_metadata(path) {
            Ok(meta)
                if !meta.is_file()
                    || meta.permissions().mode() & 0o077 != 0
                    || !owned_by_current_user(&meta)
                    || meta.nlink() != 1 =>
            {
                return Err(CacheError::UnsafeFile);
            }
            Ok(_) => fs::rename(&temp_path, path)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::hard_link(&temp_path, path)?;
                fs::remove_file(&temp_path)?;
            }
            Err(e) => return Err(e.into()),
        }
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if outcome.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection::LoginItem;
    use std::os::unix::fs::{DirBuilderExt, symlink};

    struct TestDir(std::path::PathBuf);

    impl TestDir {
        fn new() -> Self {
            let mut unique = [0_u8; 8];
            getrandom::fill(&mut unique).unwrap();
            let path = std::env::temp_dir().join(format!(
                "passflick-projection-test-{:016x}",
                u64::from_le_bytes(unique)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn cache(&self) -> std::path::PathBuf {
            self.0.join(CACHE_FILENAME)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn key() -> CacheKey {
        CacheKey::from_slice(&[17; 32]).unwrap()
    }

    fn snapshot(server: &str, account: &str, time: u64, password: &str) -> ProjectionSnapshot {
        ProjectionSnapshot::new(
            server.to_owned(),
            account.to_owned(),
            time,
            vec![LoginItem::new(
                "upstream-id-one".to_owned(),
                "Example Login".to_owned(),
                vec!["https://example.test".to_owned()],
                "mañana用户".to_owned(),
                password.to_owned(),
                None,
            )],
        )
        .unwrap()
    }

    #[test]
    fn ciphertext_round_trip_and_offline_load_preserve_exact_secret() {
        let dir = TestDir::new();
        let path = dir.cache();
        let secret = "  🗝️ contraseña\n  ";
        publish(
            &path,
            &key(),
            &snapshot("https://vault.example.test", "account", 123, secret),
        )
        .unwrap();
        let raw = fs::read(&path).unwrap();
        assert!(raw.starts_with(MAGIC));
        assert!(
            !raw.windows(secret.len())
                .any(|part| part == secret.as_bytes())
        );
        let got = load(&path, &key(), "https://vault.example.test", "account").unwrap();
        assert_eq!(got.items()[0].password(), secret);
        assert_eq!(got.items()[0].username(), "mañana用户");
        assert_eq!(got.last_success_at(), 123);
        let meta = fs::metadata(path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn wrong_key_cross_account_and_tampering_fail_closed() {
        let dir = TestDir::new();
        let path = dir.cache();
        publish(
            &path,
            &key(),
            &snapshot("https://vault.example.test", "one", 100, "secret"),
        )
        .unwrap();
        let wrong = CacheKey::from_slice(&[18; 32]).unwrap();
        assert!(matches!(
            load(&path, &wrong, "https://vault.example.test", "one"),
            Err(CacheError::AuthenticationFailed)
        ));
        assert!(matches!(
            load(&path, &key(), "https://vault.example.test", "two"),
            Err(CacheError::IdentityMismatch)
        ));
        let mut raw = fs::read(&path).unwrap();
        raw[HEADER_LEN + 1] ^= 1;
        fs::write(&path, raw).unwrap();
        assert!(matches!(
            load(&path, &key(), "https://vault.example.test", "one"),
            Err(CacheError::AuthenticationFailed)
        ));
        assert!(matches!(
            publish(
                &path,
                &key(),
                &snapshot("https://vault.example.test", "one", 101, "new")
            ),
            Err(CacheError::AuthenticationFailed)
        ));
    }

    #[test]
    fn rejected_identity_and_timestamp_never_replace_last_good_ciphertext() {
        let dir = TestDir::new();
        let path = dir.cache();
        publish(
            &path,
            &key(),
            &snapshot("https://vault.example.test", "one", 200, "original"),
        )
        .unwrap();
        let original = fs::read(&path).unwrap();
        assert!(matches!(
            publish(
                &path,
                &key(),
                &snapshot("https://vault.example.test", "two", 300, "other")
            ),
            Err(CacheError::IdentityMismatch)
        ));
        assert!(matches!(
            publish(
                &path,
                &key(),
                &snapshot("https://vault.example.test", "one", 199, "stale")
            ),
            Err(CacheError::Rollback)
        ));
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    #[test]
    fn successful_replacement_drops_removed_ids_and_rotates_nonce() {
        let dir = TestDir::new();
        let path = dir.cache();
        publish(
            &path,
            &key(),
            &snapshot("https://vault.example.test", "one", 200, "old"),
        )
        .unwrap();
        let first = fs::read(&path).unwrap();
        let next = ProjectionSnapshot::new(
            "https://vault.example.test".to_owned(),
            "one".to_owned(),
            201,
            vec![],
        )
        .unwrap();
        publish(&path, &key(), &next).unwrap();
        let later = fs::read(&path).unwrap();
        assert_ne!(&first[12..HEADER_LEN], &later[12..HEADER_LEN]);
        let current = load(&path, &key(), "https://vault.example.test", "one").unwrap();
        assert_eq!(current.items().len(), 0);
        assert_eq!(current.last_success_at(), 201);
    }

    #[test]
    fn legacy_vault_filename_is_rejected_and_preserved() {
        let dir = TestDir::new();
        let legacy = dir.0.join("vault.passvault");
        fs::write(&legacy, b"fictional legacy ciphertext - untouched").unwrap();
        let before = fs::read(&legacy).unwrap();
        let incoming = snapshot("https://vault.example.test", "one", 1, "synthetic");
        assert!(matches!(
            publish(&legacy, &key(), &incoming),
            Err(CacheError::InvalidPath)
        ));
        publish(&dir.cache(), &key(), &incoming).unwrap();
        assert_eq!(fs::read(legacy).unwrap(), before);
    }

    #[test]
    fn symlink_hardlink_and_shared_directory_are_rejected() {
        let dir = TestDir::new();
        let path = dir.cache();
        let other = dir.0.join("target");
        fs::write(&other, b"fictional ciphertext").unwrap();
        symlink(&other, &path).unwrap();
        assert!(load(&path, &key(), "https://vault.example.test", "one").is_err());
        assert!(
            publish(
                &path,
                &key(),
                &snapshot("https://vault.example.test", "one", 1, "x")
            )
            .is_err()
        );
        fs::remove_file(&path).unwrap();

        fs::hard_link(&other, &path).unwrap();
        assert!(matches!(
            load(&path, &key(), "https://vault.example.test", "one"),
            Err(CacheError::UnsafeFile)
        ));
        fs::remove_file(&path).unwrap();

        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            publish(
                &path,
                &key(),
                &snapshot("https://vault.example.test", "one", 1, "x")
            ),
            Err(CacheError::UnsafeDirectory)
        ));
    }

    #[test]
    fn incomplete_temporary_file_is_not_an_offline_projection() {
        let dir = TestDir::new();
        let path = dir.cache();
        publish(
            &path,
            &key(),
            &snapshot("https://vault.example.test", "one", 10, "valid"),
        )
        .unwrap();
        let truncated = fs::read(&path).unwrap();
        fs::write(
            dir.0.join(".passflick-projection.tmp.incomplete"),
            &truncated[..16],
        )
        .unwrap();
        let reopened = load(&path, &key(), "https://vault.example.test", "one").unwrap();
        assert_eq!(reopened.last_success_at(), 10);
    }
}
