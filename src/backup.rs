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

    let mut key_bytes = [0_u8; 32];
    key_bytes.copy_from_slice(live.key().as_bytes());
    let validated = Vault::open_with_key(snapshot, VaultKey::from_bytes(key_bytes))?;

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
        assert!(restore_into(&path, &broken, &mut vault).is_err());
        assert_eq!(fs::read(&path).unwrap(), live_before);
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
