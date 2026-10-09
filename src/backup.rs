use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::vault::{Vault, VaultError, VaultKey, read_private_vault};

/// Create an encrypted backup without ever serializing or exposing plaintext.
/// Fail rather than overwrite any existing backup, including symlinks.
pub fn create(vault_path: &Path) -> Result<PathBuf, VaultError> {
    let bytes = read_private_vault(vault_path)?;
    let parent = vault_path
        .parent()
        .ok_or_else(|| VaultError::InvalidPath(vault_path.to_path_buf()))?;
    // Reject a shared or symlinked vault directory before creating backups.
    // A caller invoking backup directly should receive the same filesystem
    // protections as an operation that already holds the write lock.
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir() || parent_metadata.permissions().mode() & 0o077 != 0 {
        return Err(VaultError::UnsafeDirectory);
    }
    let directory = parent.join("backups");

    match fs::symlink_metadata(&directory) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
                return Err(VaultError::UnsafeDirectory);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder.create(&directory)?;
        }
        Err(error) => return Err(error.into()),
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| std::io::Error::other("system clock precedes Unix epoch"))?;
    let mut entropy = [0_u8; 8];
    getrandom::fill(&mut entropy).map_err(|error| VaultError::Random(error.to_string()))?;
    let basename = format!(
        "passflick-{}-{:09}-{:016x}.passvault",
        timestamp.as_secs(),
        timestamp.subsec_nanos(),
        u64::from_le_bytes(entropy),
    );
    let destination = directory.join(&basename);
    let temporary = directory.join(format!(".{basename}.tmp"));
    let result = (|| -> Result<(), VaultError> {
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        drop(output);
        // Publish only a complete, synced encrypted file. A hard link fails
        // instead of overwriting another backup with the same name.
        fs::hard_link(&temporary, &destination)?;
        fs::remove_file(&temporary)?;
        File::open(&directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    Ok(destination)
}

/// Authenticate an encrypted snapshot under this vault's key, without
/// changing any files or exposing credential contents. This does not prove
/// future readability of the storage medium; it verifies this file now.
pub fn verify_snapshot(snapshot: &Path, live: &Vault) -> Result<usize, VaultError> {
    Ok(open_verified_snapshot(snapshot, live)?.records().len())
}

fn open_verified_snapshot(snapshot: &Path, live: &Vault) -> Result<Vault, VaultError> {
    let mut key_bytes = [0_u8; 32];
    key_bytes.copy_from_slice(live.key().as_bytes());
    Vault::open_snapshot_with_key(snapshot, VaultKey::from_bytes(key_bytes))
}

/// Explicit recovery from a verified encrypted snapshot when the active
/// vault is damaged or absent. Caller holds the exclusive write lock.
pub struct RecoveryResult {
    pub records: usize,
    /// An exact ciphertext copy, possibly corrupted, of the previous target.
    pub previous_raw_snapshot: Option<PathBuf>,
}

pub fn recover_into(
    vault_path: &Path,
    snapshot: &Path,
    passphrase: &[u8],
) -> Result<RecoveryResult, VaultError> {
    // Read only once: authenticate exactly the bytes that will be installed.
    // A source changing between verification and installation cannot swap an
    // unverified ciphertext into the active vault.
    let bytes = read_private_vault(snapshot)?;
    let records = Vault::authenticate_bytes(&bytes, passphrase)?;

    let existing = match fs::symlink_metadata(vault_path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if existing && fs::canonicalize(vault_path)? == fs::canonicalize(snapshot)? {
        return Err(VaultError::InvalidPath(snapshot.to_path_buf()));
    }
    // The previous primary need not decrypt. Preserve its exact raw bytes
    // before replacing anything, even when its authentication tag is broken.
    let previous_raw_snapshot = if existing {
        Some(create(vault_path)?)
    } else {
        None
    };
    Vault::install_verified_bytes(vault_path, &bytes, !existing)?;
    Ok(RecoveryResult {
        records,
        previous_raw_snapshot,
    })
}

/// Restore a verified backup from this vault's encryption lineage.
/// The caller must hold the exclusive vault write lock. Before any replacement,
/// preserve the current encrypted vault as a fresh backup. The source snapshot
/// must decrypt under the current vault's key; no passphrase/key migration occurs.
pub fn restore_into(
    vault_path: &Path,
    snapshot: &Path,
    live: &mut Vault,
) -> Result<PathBuf, VaultError> {
    if fs::canonicalize(vault_path)? == fs::canonicalize(snapshot)? {
        return Err(VaultError::InvalidPath(snapshot.to_path_buf()));
    }

    let validated = open_verified_snapshot(snapshot, live)?;

    // A restore can only become destructive after this encrypted safety backup
    // completes; if backup creation fails, the live vault is left unchanged.
    let safety_snapshot = create(vault_path)?;
    let previous = std::mem::replace(live.records_mut(), validated.into_records());
    if let Err(error) = live.save(vault_path) {
        *live.records_mut() = previous;
        return Err(error);
    }
    Ok(safety_snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Credential, Source};
    use crate::vault::Vault;

    #[test]
    fn restore_round_trip_and_failure_leave_protected_snapshots() {
        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let root = std::env::temp_dir().join(format!(
            "passflick-restore-test-{:016x}",
            u64::from_le_bytes(entropy),
        ));
        let path = root.join("vault.passvault");
        let mut vault = Vault::create(&path, b"synthetic-key-for-restore").unwrap();
        vault.records_mut().push(Credential::new(
            Source::Edge,
            "Before",
            "https://before.example.test",
            "alice",
            "before-secret",
            1,
        ));
        vault.save(&path).unwrap();
        let saved = create(&path).unwrap();
        assert_eq!(verify_snapshot(&saved, &vault).unwrap(), 1);

        vault.records_mut().push(Credential::new(
            Source::Firefox,
            "After",
            "https://after.example.test",
            "bob",
            "after-secret",
            2,
        ));
        vault.save(&path).unwrap();
        let safety = restore_into(&path, &saved, &mut vault).unwrap();
        assert!(safety.exists());
        let reopened = Vault::unlock(&path, b"synthetic-key-for-restore").unwrap();
        assert_eq!(reopened.records().len(), 1);
        assert_eq!(reopened.records()[0].password(), "before-secret");

        let mut saved_bytes = fs::read(&saved).unwrap();
        let final_byte = saved_bytes.last_mut().unwrap();
        *final_byte ^= 1;
        let broken = root.join("corrupt.passvault");
        fs::write(&broken, saved_bytes).unwrap();
        fs::set_permissions(&broken, fs::Permissions::from_mode(0o600)).unwrap();
        let live_before = fs::read(&path).unwrap();
        assert!(verify_snapshot(&broken, &vault).is_err());
        assert!(restore_into(&path, &broken, &mut vault).is_err());
        assert_eq!(fs::read(&path).unwrap(), live_before);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn verifies_private_snapshot_in_shared_external_directory() {
        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let root = std::env::temp_dir().join(format!(
            "passflick-external-snapshot-test-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        let private = root.join("vault");
        let external = root.join("external");
        fs::create_dir_all(&private).unwrap();
        fs::create_dir_all(&external).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&external, fs::Permissions::from_mode(0o755)).unwrap();
        let active = private.join("vault.passvault");
        let vault = Vault::create(&active, b"fictional-snapshot-passphrase").unwrap();
        let external_copy = external.join("snapshot.passvault");
        fs::copy(&active, &external_copy).unwrap();
        assert_eq!(verify_snapshot(&external_copy, &vault).unwrap(), 0);
        // An external snapshot does not relax the active vault requirement.
        assert!(matches!(
            Vault::unlock(&external_copy, b"fictional-snapshot-passphrase"),
            Err(VaultError::UnsafeDirectory)
        ));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn backups_refuse_shared_vault_directories_without_creating_files() {
        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let root = std::env::temp_dir().join(format!(
            "passflick-backup-private-test-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        let path = root.join("vault.passvault");
        Vault::create(&path, b"fictional-backup-test").unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(create(&path), Err(VaultError::UnsafeDirectory)));
        assert!(!root.join("backups").exists());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn recovery_handles_corrupt_and_missing_primary_without_plaintext() {
        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let root = std::env::temp_dir().join(format!(
            "passflick-recover-test-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        let path = root.join("vault.passvault");
        let passphrase = b"fictional-recovery-passphrase";
        let mut live = Vault::create(&path, passphrase).unwrap();
        live.records_mut().push(Credential::new(
            Source::Edge,
            "Recovered",
            "https://recovered.example.test",
            "alice",
            "fictional-recovered-secret",
            1,
        ));
        live.save(&path).unwrap();
        let snapshot = create(&path).unwrap();
        let original_backup = fs::read(&snapshot).unwrap();

        let mut broken = fs::read(&path).unwrap();
        *broken.last_mut().unwrap() ^= 1;
        fs::write(&path, &broken).unwrap();
        assert!(Vault::unlock(&path, passphrase).is_err());
        let previous = recover_into(&path, &snapshot, passphrase).unwrap();
        assert_eq!(previous.records, 1);
        let raw = previous.previous_raw_snapshot.expect("raw safety copy");
        assert_eq!(fs::read(&raw).unwrap(), broken);
        assert_eq!(fs::read(&path).unwrap(), original_backup);
        assert_eq!(
            Vault::unlock(&path, passphrase).unwrap().records()[0].password(),
            "fictional-recovered-secret"
        );

        // Wrong credentials never overwrite a valid primary.
        let before = fs::read(&path).unwrap();
        assert!(recover_into(&path, &snapshot, b"incorrect-passphrase").is_err());
        assert_eq!(fs::read(&path).unwrap(), before);

        fs::remove_file(&path).unwrap();
        let recreated = recover_into(&path, &snapshot, passphrase).unwrap();
        assert_eq!(recreated.records, 1);
        assert!(recreated.previous_raw_snapshot.is_none());
        assert_eq!(fs::read(&path).unwrap(), original_backup);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn recovery_can_replace_a_different_vault_key_without_reusing_old_secrets() {
        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let root = std::env::temp_dir().join(format!(
            "passflick-cross-key-recovery-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        let old_path = root.join("old/vault.passvault");
        let new_path = root.join("new/vault.passvault");
        let old_passphrase = b"fictional-old-vault-passphrase";
        let new_passphrase = b"fictional-recovery-vault-passphrase";

        let mut old = Vault::create(&old_path, old_passphrase).unwrap();
        old.records_mut().push(Credential::new(
            Source::Edge,
            "Former vault",
            "https://old.example.test",
            "old-user",
            "fictional-old-secret",
            1,
        ));
        old.save(&old_path).unwrap();
        let before = fs::read(&old_path).unwrap();

        let mut incoming = Vault::create(&new_path, new_passphrase).unwrap();
        incoming.records_mut().push(Credential::new(
            Source::Firefox,
            "Incoming vault",
            "https://new.example.test",
            "new-user",
            "fictional-new-secret",
            2,
        ));
        incoming.save(&new_path).unwrap();
        let snapshot = create(&new_path).unwrap();
        let imported_bytes = fs::read(&snapshot).unwrap();

        // Recovery must authenticate with the backup's own passphrase, not
        // the damaged primary's old key. A bad password is non-destructive.
        assert!(recover_into(&old_path, &snapshot, old_passphrase).is_err());
        assert_eq!(fs::read(&old_path).unwrap(), before);

        let result = recover_into(&old_path, &snapshot, new_passphrase).unwrap();
        assert_eq!(result.records, 1);
        assert_eq!(fs::read(&old_path).unwrap(), imported_bytes);
        let safety = result.previous_raw_snapshot.expect("old ciphertext copy");
        assert_eq!(fs::read(safety).unwrap(), before);

        let reopened = Vault::unlock(&old_path, new_passphrase).unwrap();
        assert_eq!(reopened.records().len(), 1);
        assert_eq!(reopened.records()[0].source, Source::Firefox);
        assert_eq!(reopened.records()[0].password(), "fictional-new-secret");
        assert!(Vault::unlock(&old_path, old_passphrase).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn backup_is_byte_exact_and_privately_permissioned() {
        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let root = std::env::temp_dir().join(format!(
            "passflick-backup-test-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        let vault_path = root.join("vault.passvault");
        let mut vault = Vault::create(&vault_path, b"synthetic-backup-key").unwrap();
        vault.records_mut().push(Credential::new(
            Source::Edge,
            "Example",
            "https://example.test",
            "alice",
            "fixture-password-not-for-public-use",
            17,
        ));
        vault.save(&vault_path).unwrap();
        let destination = create(&vault_path).unwrap();
        assert_eq!(
            fs::read(&vault_path).unwrap(),
            fs::read(&destination).unwrap()
        );
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o077,
            0
        );
        assert_eq!(
            fs::metadata(destination.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
        assert_ne!(create(&vault_path).unwrap(), destination);
        assert!(
            fs::read_dir(destination.parent().unwrap())
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp"))
        );
        fs::remove_dir_all(&root).unwrap();
    }
}
