use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::vault::{VaultError, read_private_vault};

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
    let destination = directory.join(basename);
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&destination)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    drop(output);
    File::open(&directory)?.sync_all()?;
    Ok(destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Credential, Source};
    use crate::vault::Vault;

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
        fs::remove_dir_all(&root).unwrap();
    }
}
