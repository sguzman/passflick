use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::model::Credential;

const MAGIC: &[u8; 8] = b"PASSFL01";
const FORMAT_VERSION: u16 = 1;
const PLAINTEXT_SCHEMA_VERSION: u16 = 1;
const KDF_ARGON2ID: u8 = 1;
const HEADER_LEN: usize = 64;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;

const DEFAULT_KDF: KdfParams = KdfParams {
    memory_kib: 64 * 1024,
    iterations: 3,
    parallelism: 1,
};

#[derive(Clone, Copy)]
struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

#[derive(Clone, Copy)]
struct Header {
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

pub struct VaultKey(Zeroizing<[u8; KEY_LEN]>);

impl VaultKey {
    pub(crate) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub struct Vault {
    header: Header,
    key: VaultKey,
    records: Vec<Credential>,
}

impl Vault {
    pub fn create(path: &Path, passphrase: &[u8]) -> Result<Self, VaultError> {
        // symlink_metadata also recognizes dangling symlinks. Never overwrite a
        // previous vault or user-selected path while initializing.
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(VaultError::AlreadyExists(path.to_path_buf())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        let header = Header::random(DEFAULT_KDF)?;
        let key = derive_key(passphrase, &header)?;
        let mut vault = Self {
            header,
            key,
            records: Vec::new(),
        };
        vault.save_new(path)?;
        Ok(vault)
    }

    pub fn unlock(path: &Path, passphrase: &[u8]) -> Result<Self, VaultError> {
        ensure_private_vault_parent(path)?;
        let bytes = read_private_vault(path)?;
        let header = Header::parse(&bytes)?;
        let key = derive_key(passphrase, &header)?;
        Self::decode(bytes, header, key)
    }

    pub fn open_with_key(path: &Path, key: VaultKey) -> Result<Self, VaultError> {
        ensure_private_vault_parent(path)?;
        Self::open_snapshot_with_key(path, key)
    }

    /// A backup source can live outside the active vault directory. It still
    /// must be a private regular file and authenticate under the supplied key.
    pub(crate) fn open_snapshot_with_key(path: &Path, key: VaultKey) -> Result<Self, VaultError> {
        let bytes = read_private_vault(path)?;
        let header = Header::parse(&bytes)?;
        Self::decode(bytes, header, key)
    }

    /// Authenticate the exact encrypted bytes before any disaster recovery
    /// write. No primary vault is required, and no plaintext file is created.
    pub(crate) fn authenticate_bytes(bytes: &[u8], passphrase: &[u8]) -> Result<usize, VaultError> {
        if bytes.len() as u64 > MAX_VAULT_BYTES {
            return Err(VaultError::TooLarge);
        }
        let header = Header::parse(bytes)?;
        let key = derive_key(passphrase, &header)?;
        Ok(Self::decode(bytes.to_vec(), header, key)?.records.len())
    }

    /// The caller must hold the vault write lock, authenticate `bytes`, and
    /// preserve the old ciphertext first when overwriting a previous vault.
    pub(crate) fn install_verified_bytes(
        path: &Path,
        bytes: &[u8],
        create_only: bool,
    ) -> Result<(), VaultError> {
        if bytes.len() as u64 > MAX_VAULT_BYTES {
            return Err(VaultError::TooLarge);
        }
        write_atomic(path, bytes, create_only)
    }

    pub fn key(&self) -> &VaultKey {
        &self.key
    }

    pub fn records(&self) -> &[Credential] {
        &self.records
    }

    pub fn into_records(self) -> Vec<Credential> {
        self.records
    }

    pub fn records_mut(&mut self) -> &mut Vec<Credential> {
        &mut self.records
    }

    pub fn save(&mut self, path: &Path) -> Result<(), VaultError> {
        self.header.rotate_nonce()?;
        let encoded = self.encode()?;
        if encoded.len() as u64 > MAX_VAULT_BYTES {
            return Err(VaultError::TooLarge);
        }
        write_atomic(path, &encoded, false)?;
        Ok(())
    }

    fn save_new(&mut self, path: &Path) -> Result<(), VaultError> {
        self.header.rotate_nonce()?;
        let encoded = self.encode()?;
        if encoded.len() as u64 > MAX_VAULT_BYTES {
            return Err(VaultError::TooLarge);
        }
        write_atomic(path, &encoded, true)
    }

    fn decode(bytes: Vec<u8>, header: Header, key: VaultKey) -> Result<Self, VaultError> {
        if bytes.len() <= HEADER_LEN {
            return Err(VaultError::Truncated);
        }

        let header_bytes = header.encode();
        let cipher =
            XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| VaultError::CipherKey)?;
        let nonce = XNonce::from(header.nonce);
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &bytes[HEADER_LEN..],
                    aad: &header_bytes,
                },
            )
            .map_err(|_| VaultError::Decrypt)?;

        let plaintext = Zeroizing::new(plaintext);
        let document: PlainVault = serde_json::from_slice(&plaintext)?;
        if document.schema_version != PLAINTEXT_SCHEMA_VERSION {
            return Err(VaultError::UnsupportedSchema(document.schema_version));
        }

        Ok(Self {
            header,
            key,
            records: document.records,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, VaultError> {
        let document = PlainVaultRef {
            schema_version: PLAINTEXT_SCHEMA_VERSION,
            records: &self.records,
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&document)?);

        let header_bytes = self.header.encode();
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_bytes())
            .map_err(|_| VaultError::CipherKey)?;
        let nonce = XNonce::from(self.header.nonce);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plaintext,
                    aad: &header_bytes,
                },
            )
            .map_err(|_| VaultError::Encrypt)?;

        let mut output = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        output.extend_from_slice(&header_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }
}

#[derive(Deserialize)]
struct PlainVault {
    schema_version: u16,
    records: Vec<Credential>,
}

#[derive(Serialize)]
struct PlainVaultRef<'a> {
    schema_version: u16,
    records: &'a [Credential],
}

impl Header {
    fn random(kdf: KdfParams) -> Result<Self, VaultError> {
        let mut salt = [0_u8; SALT_LEN];
        let mut nonce = [0_u8; NONCE_LEN];
        fill_random(&mut salt)?;
        fill_random(&mut nonce)?;

        Ok(Self { kdf, salt, nonce })
    }

    fn rotate_nonce(&mut self) -> Result<(), VaultError> {
        fill_random(&mut self.nonce)
    }

    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut bytes = [0_u8; HEADER_LEN];
        bytes[0..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[10] = KDF_ARGON2ID;
        bytes[11] = 0;
        bytes[12..16].copy_from_slice(&self.kdf.memory_kib.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.kdf.iterations.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.kdf.parallelism.to_le_bytes());
        bytes[24..40].copy_from_slice(&self.salt);
        bytes[40..64].copy_from_slice(&self.nonce);
        bytes
    }

    fn parse(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() < HEADER_LEN {
            return Err(VaultError::Truncated);
        }
        if &bytes[0..8] != MAGIC {
            return Err(VaultError::BadMagic);
        }

        let version = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed header slice"));
        if version != FORMAT_VERSION {
            return Err(VaultError::UnsupportedFormat(version));
        }
        if bytes[10] != KDF_ARGON2ID {
            return Err(VaultError::UnsupportedKdf(bytes[10]));
        }
        if bytes[11] != 0 {
            return Err(VaultError::InvalidHeader);
        }

        let memory_kib = u32::from_le_bytes(bytes[12..16].try_into().expect("fixed header slice"));
        let iterations = u32::from_le_bytes(bytes[16..20].try_into().expect("fixed header slice"));
        let parallelism = u32::from_le_bytes(bytes[20..24].try_into().expect("fixed header slice"));

        // Reject forged resource parameters before invoking Argon2. The header is
        // authenticated only after key derivation, so its cost must be bounded here.
        // The test KDF uses 8 KiB. Production defaults use 64 MiB.
        if !(8..=256 * 1024).contains(&memory_kib)
            || !(1..=10).contains(&iterations)
            || !(1..=8).contains(&parallelism)
            || memory_kib < 8 * parallelism
        {
            return Err(VaultError::InvalidHeader);
        }

        let mut salt = [0_u8; SALT_LEN];
        salt.copy_from_slice(&bytes[24..40]);
        let mut nonce = [0_u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[40..64]);

        Ok(Self {
            kdf: KdfParams {
                memory_kib,
                iterations,
                parallelism,
            },
            salt,
            nonce,
        })
    }
}

fn derive_key(passphrase: &[u8], header: &Header) -> Result<VaultKey, VaultError> {
    let params = Params::new(
        header.kdf.memory_kib,
        header.kdf.iterations,
        header.kdf.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|error| VaultError::Kdf(error.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase, &header.salt, &mut key)
        .map_err(|error| VaultError::Kdf(error.to_string()))?;

    Ok(VaultKey::from_bytes(key))
}

fn fill_random(bytes: &mut [u8]) -> Result<(), VaultError> {
    getrandom::fill(bytes).map_err(|error| VaultError::Random(error.to_string()))
}

/// The active vault must live in a private directory even during read-only
/// unlock. A private file inside a shared directory can be replaced or rolled
/// back by another user with directory write permission.
/// Vault and managed-backup paths must belong to the effective user, not
/// merely have private mode bits. This also rejects unexpected ownership when
/// launched with elevated credentials.
/// SAFETY: geteuid reads the process's effective UID without dereferencing
/// pointers or changing process state.
pub(crate) fn owned_by_current_user(metadata: &fs::Metadata) -> bool {
    metadata.uid() == unsafe { libc::geteuid() }
}

fn ensure_private_vault_parent(path: &Path) -> Result<(), VaultError> {
    let parent = path
        .parent()
        .ok_or_else(|| VaultError::InvalidPath(path.to_path_buf()))?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 || !owned_by_current_user(&metadata) {
        return Err(VaultError::UnsafeDirectory);
    }
    Ok(())
}

pub(crate) fn read_private_vault(path: &Path) -> Result<Vec<u8>, VaultError> {
    // O_NOFOLLOW prevents a vault-path symlink from redirecting reads to another file.
    let file = OpenOptions::new()
        .read(true)
        // Never block opening an attacker-controlled FIFO or device: validate the
        // opened descriptor's file type before attempting any read.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 || !owned_by_current_user(&metadata) {
        return Err(VaultError::UnsafeFile);
    }

    // Reject a huge or corrupt vault without allocating an unbounded buffer.
    let mut bytes = Vec::new();
    file.take(MAX_VAULT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_VAULT_BYTES {
        return Err(VaultError::TooLarge);
    }
    Ok(bytes)
}

fn write_atomic(path: &Path, bytes: &[u8], create_only: bool) -> Result<(), VaultError> {
    let parent = path
        .parent()
        .ok_or_else(|| VaultError::InvalidPath(path.to_path_buf()))?;

    if !parent.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(parent)?;
    }

    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir()
        || parent_metadata.permissions().mode() & 0o077 != 0
        || !owned_by_current_user(&parent_metadata)
    {
        return Err(VaultError::UnsafeDirectory);
    }

    let mut suffix = [0_u8; 8];
    fill_random(&mut suffix)?;
    let suffix = u64::from_le_bytes(suffix);
    let temp_path = parent.join(format!(
        ".passflick-vault.tmp.{}.{suffix:016x}",
        std::process::id()
    ));

    let result = (|| -> Result<(), VaultError> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);

        if create_only {
            // hard_link is atomic and fails if the target already exists, unlike
            // rename. Both paths are in the same private vault directory.
            match fs::hard_link(&temp_path, path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(VaultError::AlreadyExists(path.to_path_buf()));
                }
                Err(error) => return Err(error.into()),
            }
            fs::remove_file(&temp_path)?;
        } else {
            // Existing target paths must already be private regular files.
            match fs::symlink_metadata(path) {
                Ok(meta)
                    if !meta.is_file()
                        || meta.permissions().mode() & 0o077 != 0
                        || !owned_by_current_user(&meta) =>
                {
                    return Err(VaultError::UnsafeFile);
                }
                Ok(_) => {}
                Err(error) => return Err(error.into()),
            }
            fs::rename(&temp_path, path)?;
        }
        File::open(parent)?.sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }

    result
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("invalid vault path: {0}")]
    InvalidPath(PathBuf),
    #[error("vault is truncated")]
    Truncated,
    #[error("not a Passflick vault")]
    BadMagic,
    #[error("unsupported vault format version {0}")]
    UnsupportedFormat(u16),
    #[error("unsupported vault plaintext schema {0}")]
    UnsupportedSchema(u16),
    #[error("unsupported vault KDF id {0}")]
    UnsupportedKdf(u8),
    #[error("invalid vault header")]
    InvalidHeader,
    #[error("vault file must be a private regular file, not a symlink or shared file")]
    UnsafeFile,
    #[error("vault directory must be private and must not be a symlink")]
    UnsafeDirectory,
    #[error("vault exceeds 64 MiB safety limit")]
    TooLarge,
    #[error("Argon2 key derivation failed: {0}")]
    Kdf(String),
    #[error("system randomness failed: {0}")]
    Random(String),
    #[error("invalid encryption key")]
    CipherKey,
    #[error("vault encryption failed")]
    Encrypt,
    #[error("vault decryption failed; the passphrase or session key is wrong")]
    Decrypt,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Source;

    const TEST_KDF: KdfParams = KdfParams {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    };

    fn test_vault(passphrase: &[u8]) -> Vault {
        let header = Header::random(TEST_KDF).unwrap();
        let key = derive_key(passphrase, &header).unwrap();
        Vault {
            header,
            key,
            records: vec![Credential::new(
                Source::Edge,
                "Example",
                "https://example.test",
                "alice@example.test",
                "strong sample value",
                1234,
            )],
        }
    }

    #[test]
    fn encrypted_round_trip_preserves_records_and_hides_plaintext() {
        let mut original = test_vault(b"correct horse battery staple");
        original.header.rotate_nonce().unwrap();
        let bytes = original.encode().unwrap();
        for sensitive in ["alice@example.test", "strong sample value"] {
            assert!(
                !bytes
                    .windows(sensitive.len())
                    .any(|w| w == sensitive.as_bytes())
            );
        }
        let header = Header::parse(&bytes).unwrap();
        let key = derive_key(b"correct horse battery staple", &header).unwrap();
        let reopened = Vault::decode(bytes, header, key).unwrap();
        assert_eq!(reopened.records().len(), 1);
        assert_eq!(reopened.records()[0].password(), "strong sample value");
    }

    #[test]
    fn malicious_kdf_costs_are_rejected_before_allocation() {
        let mut original = test_vault(b"passphrase");
        original.header.rotate_nonce().unwrap();
        let mut bytes = original.encode().unwrap();
        bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            Header::parse(&bytes),
            Err(VaultError::InvalidHeader)
        ));

        bytes[12..16].copy_from_slice(&DEFAULT_KDF.memory_kib.to_le_bytes());
        bytes[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            Header::parse(&bytes),
            Err(VaultError::InvalidHeader)
        ));

        bytes[16..20].copy_from_slice(&DEFAULT_KDF.iterations.to_le_bytes());
        bytes[20..24].copy_from_slice(&0_u32.to_le_bytes());
        assert!(matches!(
            Header::parse(&bytes),
            Err(VaultError::InvalidHeader)
        ));
    }

    #[test]
    fn init_refuses_existing_vault_and_dangling_symlink() {
        use std::os::unix::fs::symlink;
        let mut entropy = [0_u8; 8];
        fill_random(&mut entropy).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "passflick-no-clobber-test-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("vault.passvault");
        Vault::create(&path, b"test-one").unwrap();
        let original = fs::read(&path).unwrap();
        assert!(matches!(
            Vault::create(&path, b"test-two"),
            Err(VaultError::AlreadyExists(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), original);

        let dangling = dir.join("unresolved-link");
        symlink(dir.join("missing"), &dangling).unwrap();
        assert!(matches!(
            Vault::create(&dangling, b"test-three"),
            Err(VaultError::AlreadyExists(_))
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn vault_persists_with_private_permissions_and_atomic_replacement() {
        let mut entropy = [0_u8; 8];
        fill_random(&mut entropy).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "passflick-vault-roundtrip-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        let path = dir.join("vault.passvault");
        let mut vault = test_vault(b"test-only-passphrase");
        vault.save_new(&path).unwrap();

        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o077, 0);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o077, 0);
        let key = derive_key(b"test-only-passphrase", &vault.header).unwrap();
        let opened = Vault::open_with_key(&path, key).unwrap();
        assert_eq!(opened.records().len(), 1);

        vault.records_mut().push(Credential::new(
            Source::Firefox,
            "Second",
            "https://second.example.test",
            "user",
            "private-second-test-value",
            42,
        ));
        vault.save(&path).unwrap();
        let key = derive_key(b"test-only-passphrase", &vault.header).unwrap();
        let reopened = Vault::open_with_key(&path, key).unwrap();
        assert_eq!(reopened.records().len(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn vault_refuses_to_save_into_shared_directory() {
        let mut entropy = [0_u8; 8];
        fill_random(&mut entropy).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "passflick-unsafe-dir-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let mut vault = test_vault(b"test-only-passphrase");
        let outcome = vault.save(&dir.join("vault.passvault"));
        assert!(matches!(outcome, Err(VaultError::UnsafeDirectory)));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unlocking_requires_private_parent_even_when_vault_file_is_private() {
        let mut entropy = [0_u8; 8];
        fill_random(&mut entropy).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "passflick-shared-unlock-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        let path = dir.join("vault.passvault");
        let vault = Vault::create(&path, b"fictional-directory-test-key").unwrap();
        let mut key_bytes = [0_u8; KEY_LEN];
        key_bytes.copy_from_slice(vault.key().as_bytes());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            Vault::unlock(&path, b"fictional-directory-test-key"),
            Err(VaultError::UnsafeDirectory)
        ));
        assert!(matches!(
            Vault::open_with_key(&path, VaultKey::from_bytes(key_bytes)),
            Err(VaultError::UnsafeDirectory)
        ));
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(Vault::unlock(&path, b"fictional-directory-test-key").is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn private_vault_reader_rejects_symlinks_and_shared_files() {
        use std::os::unix::fs::symlink;
        let mut entropy = [0_u8; 8];
        fill_random(&mut entropy).unwrap();
        let temp = std::env::temp_dir().join(format!(
            "passflick-security-test-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        fs::create_dir(&temp).unwrap();
        let file = temp.join("real-vault");
        fs::write(&file, b"example").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            read_private_vault(&file),
            Err(VaultError::UnsafeFile)
        ));
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_private_vault(&file).unwrap(), b"example");
        let link = temp.join("vault-link");
        symlink(&file, &link).unwrap();
        assert!(read_private_vault(&link).is_err());
        fs::remove_dir_all(&temp).unwrap();
    }

    #[test]
    fn vault_metadata_requires_the_effective_owner() {
        let mut entropy = [0_u8; 8];
        fill_random(&mut entropy).unwrap();
        let root = std::env::temp_dir().join(format!(
            "passflick-vault-owner-check-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("synthetic-vault");
        fs::write(&path, b"fictional ciphertext").unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(owned_by_current_user(&metadata));
        assert_ne!(metadata.uid(), metadata.uid().wrapping_add(1));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn private_vault_reader_rejects_fifo_without_waiting_for_writer() {
        use std::os::unix::ffi::OsStrExt;

        let mut entropy = [0_u8; 8];
        fill_random(&mut entropy).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "passflick-fifo-vault-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let fifo = dir.join("vault.passvault");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: name is a valid NUL-terminated pathname and mkfifo does
        // not retain this pointer after returning.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            read_private_vault(&fifo),
            Err(VaultError::UnsafeFile)
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let mut original = test_vault(b"right");
        original.header.rotate_nonce().unwrap();
        let bytes = original.encode().unwrap();
        let header = Header::parse(&bytes).unwrap();
        let wrong_key = derive_key(b"wrong", &header).unwrap();
        assert!(matches!(
            Vault::decode(bytes, header, wrong_key),
            Err(VaultError::Decrypt)
        ));
    }

    #[test]
    fn authenticated_header_rejects_tampering() {
        let mut original = test_vault(b"passphrase");
        original.header.rotate_nonce().unwrap();
        let mut bytes = original.encode().unwrap();
        bytes[12] ^= 1;
        let header = Header::parse(&bytes).unwrap();
        let key = derive_key(b"passphrase", &header).unwrap();
        assert!(matches!(
            Vault::decode(bytes, header, key),
            Err(VaultError::Decrypt)
        ));
    }
}
