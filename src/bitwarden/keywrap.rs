//! Independent passphrase-wrapped content-key envelope for the *new* offline
//! Vaultwarden projection. Never open, migrate or re-key vault.passvault.
//!
//! A fresh random 256-bit content key is wrapped with Argon2id-derived
//! XChaCha20-Poly1305 encryption, under a distinct, fixed-size, create-only
//! projection.pfkey file. The header and exact canonical source/account
//! identity are AEAD-associated data. No raw key is ever stored on disk.
//!
//! This remains isolated behind #[cfg(test)] until keyring/lock, explicit
//! command, target-host and power-loss acceptance are complete.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{AeadInOut, KeyInit},
};
use zeroize::Zeroizing;

use super::cache_store::CacheKey;
use crate::vault::owned_by_current_user;

const NAME: &str = "projection.pfkey";
const MAGIC: &[u8; 8] = b"PFKEY001";
const FORMAT_VERSION: u16 = 1;
const KDF_ARGON2ID: u8 = 1;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const HEADER_BYTES: usize = 64;
const KEY_BYTES: usize = 32;
const TAG_BYTES: usize = 16;
const FILE_BYTES: usize = HEADER_BYTES + KEY_BYTES + TAG_BYTES;
const DEFAULT_MIB: u32 = 64;
const DEFAULT_ITERATIONS: u32 = 3;
const DEFAULT_PARALLELISM: u32 = 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeywrapError {
    #[error("invalid local unlock passphrase")]
    InvalidPassphrase,
    #[error("invalid Vaultwarden projection identity")]
    InvalidIdentity,
    #[error("local keywrap must use projection.pfkey")]
    InvalidPath,
    #[error("keywrap directory must be private and owner-owned")]
    UnsafeDirectory,
    #[error("keywrap file must be an owner-owned private regular file")]
    UnsafeFile,
    #[error("a local projection keywrap already exists")]
    AlreadyExists,
    #[error("no local projection keywrap exists")]
    Missing,
    #[error("unsupported or invalid keywrap header")]
    InvalidFormat,
    #[error("passphrase or projection identity could not authenticate the key")]
    AuthenticationFailed,
    #[error("Argon2id key derivation failed")]
    Kdf,
    #[error("local keywrap filesystem operation failed")]
    Io,
}

impl From<std::io::Error> for KeywrapError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

fn validate_input(
    path: &Path,
    passphrase: &[u8],
    server: &str,
    account: &str,
) -> Result<(), KeywrapError> {
    if path.file_name() != Some(OsStr::new(NAME)) {
        return Err(KeywrapError::InvalidPath);
    }
    if !(12..=1024).contains(&passphrase.len()) {
        return Err(KeywrapError::InvalidPassphrase);
    }
    if !server.starts_with("https://")
        || server.len() > 16 * 1024
        || server.trim() != server
        || server.chars().any(char::is_control)
        || account.is_empty()
        || account.len() > 256
        || account.trim() != account
        || account.chars().any(char::is_control)
    {
        return Err(KeywrapError::InvalidIdentity);
    }
    let parent = path.parent().ok_or(KeywrapError::InvalidPath)?;
    let meta = fs::symlink_metadata(parent)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 || !owned_by_current_user(&meta) {
        return Err(KeywrapError::UnsafeDirectory);
    }
    Ok(())
}

fn associated_data(header: &[u8], server: &str, account: &str) -> Zeroizing<Vec<u8>> {
    let mut aad = Zeroizing::new(Vec::with_capacity(
        header.len() + 2 * std::mem::size_of::<u32>() + server.len() + account.len(),
    ));
    aad.extend_from_slice(header);
    aad.extend_from_slice(&(server.len() as u32).to_le_bytes());
    aad.extend_from_slice(server.as_bytes());
    aad.extend_from_slice(&(account.len() as u32).to_le_bytes());
    aad.extend_from_slice(account.as_bytes());
    aad
}

fn derive_wrap_key(
    passphrase: &[u8],
    salt: &[u8; SALT_BYTES],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; KEY_BYTES]>, KeywrapError> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(KEY_BYTES))
        .map_err(|_| KeywrapError::Kdf)?;
    let algorithm = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0_u8; KEY_BYTES]);
    algorithm
        .hash_password_into(passphrase, salt, &mut *output)
        .map_err(|_| KeywrapError::Kdf)?;
    Ok(output)
}

fn nonce(header: &[u8; HEADER_BYTES]) -> XNonce {
    let mut bytes = [0_u8; NONCE_BYTES];
    bytes.copy_from_slice(&header[40..64]);
    XNonce::from(bytes)
}

fn build_header() -> Result<[u8; HEADER_BYTES], KeywrapError> {
    let mut header = [0_u8; HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    header[10] = KDF_ARGON2ID;
    header[12..16].copy_from_slice(&(DEFAULT_MIB * 1024).to_le_bytes());
    header[16..20].copy_from_slice(&DEFAULT_ITERATIONS.to_le_bytes());
    header[20..24].copy_from_slice(&DEFAULT_PARALLELISM.to_le_bytes());
    getrandom::fill(&mut header[24..40]).map_err(|_| KeywrapError::Io)?;
    getrandom::fill(&mut header[40..64]).map_err(|_| KeywrapError::Io)?;
    Ok(header)
}

fn parse_header(raw: &[u8]) -> Result<[u8; HEADER_BYTES], KeywrapError> {
    if raw.len() != FILE_BYTES
        || &raw[..8] != MAGIC
        || raw[8..10] != FORMAT_VERSION.to_le_bytes()
        || raw[10] != KDF_ARGON2ID
        || raw[11] != 0
    {
        return Err(KeywrapError::InvalidFormat);
    }
    let mut header = [0_u8; HEADER_BYTES];
    header.copy_from_slice(&raw[..HEADER_BYTES]);
    let mem = u32::from_le_bytes(header[12..16].try_into().unwrap());
    let iters = u32::from_le_bytes(header[16..20].try_into().unwrap());
    let lanes = u32::from_le_bytes(header[20..24].try_into().unwrap());
    if !(8 * 1024..=256 * 1024).contains(&mem)
        || !(1..=10).contains(&iters)
        || !(1..=8).contains(&lanes)
        || mem < 8 * lanes
    {
        return Err(KeywrapError::InvalidFormat);
    }
    Ok(header)
}

fn seal(
    key: &CacheKey,
    passphrase: &[u8],
    server: &str,
    account: &str,
) -> Result<Zeroizing<Vec<u8>>, KeywrapError> {
    let header = build_header()?;
    let mut salt = [0_u8; SALT_BYTES];
    salt.copy_from_slice(&header[24..40]);
    let wrapping_key = derive_wrap_key(
        passphrase,
        &salt,
        DEFAULT_MIB * 1024,
        DEFAULT_ITERATIONS,
        DEFAULT_PARALLELISM,
    )?;
    let cipher = XChaCha20Poly1305::new_from_slice(&*wrapping_key)
        .map_err(|_| KeywrapError::InvalidFormat)?;
    let mut ciphertext = Zeroizing::new(key.as_bytes().to_vec());
    let aad = associated_data(&header, server, account);
    cipher
        .encrypt_in_place(&nonce(&header), &aad, &mut *ciphertext)
        .map_err(|_| KeywrapError::AuthenticationFailed)?;
    let mut output = Zeroizing::new(Vec::with_capacity(FILE_BYTES));
    output.extend_from_slice(&header);
    output.extend_from_slice(&ciphertext);
    if output.len() != FILE_BYTES {
        return Err(KeywrapError::InvalidFormat);
    }
    Ok(output)
}

fn open(
    raw: &[u8],
    passphrase: &[u8],
    server: &str,
    account: &str,
) -> Result<CacheKey, KeywrapError> {
    let header = parse_header(raw)?;
    let mem = u32::from_le_bytes(header[12..16].try_into().unwrap());
    let iters = u32::from_le_bytes(header[16..20].try_into().unwrap());
    let lanes = u32::from_le_bytes(header[20..24].try_into().unwrap());
    let mut salt = [0_u8; SALT_BYTES];
    salt.copy_from_slice(&header[24..40]);
    let wrapping_key = derive_wrap_key(passphrase, &salt, mem, iters, lanes)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&*wrapping_key)
        .map_err(|_| KeywrapError::InvalidFormat)?;
    let mut plaintext = Zeroizing::new(raw[HEADER_BYTES..].to_vec());
    let aad = associated_data(&header, server, account);
    cipher
        .decrypt_in_place(&nonce(&header), &aad, &mut *plaintext)
        .map_err(|_| KeywrapError::AuthenticationFailed)?;
    CacheKey::from_slice(&plaintext).map_err(|_| KeywrapError::InvalidFormat)
}

fn read_private(path: &Path) -> Result<Zeroizing<Vec<u8>>, KeywrapError> {
    let handle = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(handle) => handle,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(KeywrapError::Missing),
        Err(e) => return Err(e.into()),
    };
    let meta = handle.metadata()?;
    if !meta.is_file()
        || meta.permissions().mode() & 0o077 != 0
        || !owned_by_current_user(&meta)
        || meta.nlink() != 1
    {
        return Err(KeywrapError::UnsafeFile);
    }
    if meta.len() != FILE_BYTES as u64 {
        return Err(KeywrapError::InvalidFormat);
    }
    let mut raw = Zeroizing::new(Vec::with_capacity(FILE_BYTES));
    handle.take((FILE_BYTES + 1) as u64).read_to_end(&mut raw)?;
    if raw.len() != FILE_BYTES {
        return Err(KeywrapError::InvalidFormat);
    }
    Ok(raw)
}

/// Generate and store a new independent content key for a chosen remote
/// account. Fails if the keywrap already exists; never rewraps old vault data.
pub fn initialize(
    path: &Path,
    passphrase: &[u8],
    server: &str,
    account: &str,
) -> Result<CacheKey, KeywrapError> {
    validate_input(path, passphrase, server, account)?;
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(KeywrapError::AlreadyExists),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let key = CacheKey::generate().map_err(|_| KeywrapError::Io)?;
    let output = seal(&key, passphrase, server, account)?;
    write_create_only(path, &output)?;
    Ok(key)
}

/// Offline local passphrase unlock. There are no server/token requests.
pub fn unlock(
    path: &Path,
    passphrase: &[u8],
    server: &str,
    account: &str,
) -> Result<CacheKey, KeywrapError> {
    validate_input(path, passphrase, server, account)?;
    let raw = read_private(path)?;
    open(&raw, passphrase, server, account)
}

fn write_create_only(path: &Path, encrypted: &[u8]) -> Result<(), KeywrapError> {
    let parent = path.parent().ok_or(KeywrapError::InvalidPath)?;
    let mut entropy = [0_u8; 8];
    getrandom::fill(&mut entropy).map_err(|_| KeywrapError::Io)?;
    let temp = parent.join(format!(
        ".passflick-projection-key.tmp.{}.{:016x}",
        std::process::id(),
        u64::from_le_bytes(entropy)
    ));
    let outcome = (|| -> Result<(), KeywrapError> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(encrypted)?;
        file.sync_all()?;
        drop(file);
        match fs::hard_link(&temp, path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(KeywrapError::AlreadyExists);
            }
            Err(e) => return Err(e.into()),
        }
        fs::remove_file(&temp)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if outcome.is_err() {
        let _ = fs::remove_file(&temp);
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitwarden::cache_store;
    use crate::projection::{LoginItem, ProjectionSnapshot};
    use std::os::unix::fs::{DirBuilderExt, symlink};

    struct TestDir(std::path::PathBuf);

    impl TestDir {
        fn new() -> Self {
            let mut random = [0_u8; 8];
            getrandom::fill(&mut random).unwrap();
            let directory = std::env::temp_dir().join(format!(
                "passflick-keywrap-test-{:016x}",
                u64::from_le_bytes(random)
            ));
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
            Self(directory)
        }

        fn keywrap(&self) -> std::path::PathBuf {
            self.0.join(NAME)
        }

        fn snapshot(&self) -> std::path::PathBuf {
            self.0.join("projection.pfsnapshot")
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const SERVER: &str = "https://vault.example.test/";
    const ACCOUNT: &str = "fictional-account";
    const PASSPHRASE: &[u8] = b"fictional local offline secret";

    #[test]
    fn independent_passphrase_keywrap_opens_offline_projection() {
        let dir = TestDir::new();
        let path = dir.keywrap();
        let key = initialize(&path, PASSPHRASE, SERVER, ACCOUNT).unwrap();
        let stored = fs::read(&path).unwrap();
        assert_eq!(stored.len(), FILE_BYTES);
        assert_eq!(&stored[..8], MAGIC);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!stored.windows(9).any(|w| w == b"fictional"));

        let snapshot = ProjectionSnapshot::new(
            SERVER.to_owned(),
            ACCOUNT.to_owned(),
            1,
            vec![LoginItem::new(
                "id-1".to_owned(),
                "Synthetic Login".to_owned(),
                vec!["https://example.test/login".to_owned()],
                "user-name".to_owned(),
                "🗝️ local cache password".to_owned(),
                None,
            )],
        )
        .unwrap();
        cache_store::publish(&dir.snapshot(), &key, &snapshot).unwrap();

        let recovered = unlock(&path, PASSPHRASE, SERVER, ACCOUNT).unwrap();
        let read = cache_store::load(&dir.snapshot(), &recovered, SERVER, ACCOUNT).unwrap();
        assert_eq!(read.items().len(), 1);
        assert_eq!(read.items()[0].password(), "🗝️ local cache password");
    }

    #[test]
    fn wrong_passphrase_and_identity_reject_without_overwrite() {
        let dir = TestDir::new();
        let path = dir.keywrap();
        let _key = initialize(&path, PASSPHRASE, SERVER, ACCOUNT).unwrap();
        let original = fs::read(&path).unwrap();
        for (passphrase, server, account) in [
            (
                b"fictional wrong local password".as_slice(),
                SERVER,
                ACCOUNT,
            ),
            (PASSPHRASE, "https://other.example.test/", ACCOUNT),
            (PASSPHRASE, SERVER, "other-account"),
        ] {
            assert!(matches!(
                unlock(&path, passphrase, server, account),
                Err(KeywrapError::AuthenticationFailed)
            ));
        }
        assert_eq!(fs::read(path).unwrap(), original);
    }

    #[test]
    fn tamper_and_oversized_kdf_parameters_fail_without_mutating_file() {
        let dir = TestDir::new();
        let path = dir.keywrap();
        initialize(&path, PASSPHRASE, SERVER, ACCOUNT).unwrap();
        let mut corrupted = fs::read(&path).unwrap();
        corrupted[20..24].copy_from_slice(&999_u32.to_le_bytes());
        fs::write(&path, &corrupted).unwrap();
        assert!(matches!(
            unlock(&path, PASSPHRASE, SERVER, ACCOUNT),
            Err(KeywrapError::InvalidFormat)
        ));
        assert_eq!(fs::read(&path).unwrap(), corrupted);
    }

    #[test]
    fn create_only_isolation_and_unsafe_paths_are_rejected() {
        let dir = TestDir::new();
        let legacy = dir.0.join("vault.passvault");
        fs::write(&legacy, b"fictional untouched legacy bytes").unwrap();
        let key = initialize(&dir.keywrap(), PASSPHRASE, SERVER, ACCOUNT).unwrap();
        let ciphertext = fs::read(dir.keywrap()).unwrap();
        assert!(matches!(
            initialize(&dir.keywrap(), PASSPHRASE, SERVER, ACCOUNT),
            Err(KeywrapError::AlreadyExists)
        ));
        assert_eq!(
            fs::read(legacy).unwrap(),
            b"fictional untouched legacy bytes"
        );
        assert!(key.as_bytes().len() == KEY_BYTES);
        assert_eq!(fs::read(dir.keywrap()).unwrap(), ciphertext);
        assert!(matches!(
            initialize(&dir.0.join("vault.passvault"), PASSPHRASE, SERVER, ACCOUNT),
            Err(KeywrapError::InvalidPath)
        ));
        let linked = TestDir::new();
        let victim = linked.0.join("victim");
        fs::write(&victim, b"synthetic").unwrap();
        symlink(&victim, linked.keywrap()).unwrap();
        assert!(unlock(&linked.keywrap(), PASSPHRASE, SERVER, ACCOUNT).is_err());
        assert!(matches!(
            initialize(&linked.keywrap(), PASSPHRASE, SERVER, ACCOUNT),
            Err(KeywrapError::AlreadyExists)
        ));
    }
}
