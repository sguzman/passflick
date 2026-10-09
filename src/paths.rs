use std::env;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("HOME is not set and XDG_DATA_HOME is unavailable")]
    MissingHome,
    #[error("PASSFLICK_VAULT must name a file, not an empty path or directory")]
    InvalidVaultPath,
    #[error("could not resolve the working directory for a relative vault path: {0}")]
    CurrentDirectory(#[from] std::io::Error),
}

fn absolute_file_path(path: PathBuf) -> Result<PathBuf, PathError> {
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        return Err(PathError::InvalidVaultPath);
    }
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(env::current_dir()?.join(path))
    }
}

/// Stable identity for a vault, including while the vault file is missing
/// during disaster recovery. Canonicalizing the full file fails when it has
/// been deleted, but its parent generally still exists and can be resolved.
/// Never open or follow the vault file itself to construct its cache identity.
pub fn vault_identity_path(path: &std::path::Path) -> PathBuf {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(filename)) => std::fs::canonicalize(parent)
            .map(|canonical_parent| canonical_parent.join(filename))
            .unwrap_or_else(|_| path.to_path_buf()),
        _ => path.to_path_buf(),
    }
}

pub fn vault_path() -> Result<PathBuf, PathError> {
    if let Some(path) = env::var_os("PASSFLICK_VAULT") {
        return absolute_file_path(PathBuf::from(path));
    }

    let data_home = if let Some(path) = env::var_os("XDG_DATA_HOME").filter(|p| !p.is_empty()) {
        PathBuf::from(path)
    } else {
        let home = env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .ok_or(PathError::MissingHome)?;
        PathBuf::from(home).join(".local/share")
    };

    absolute_file_path(data_home.join("passflick/vault.passvault"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_relative_path_resolves_without_changing_working_directory() {
        let result = absolute_file_path(PathBuf::from("vault.passvault")).unwrap();
        assert!(result.is_absolute());
        assert_eq!(result, env::current_dir().unwrap().join("vault.passvault"));
    }

    #[test]
    fn empty_and_directory_only_explicit_paths_are_rejected() {
        for path in ["", ".", "..", "/"] {
            assert!(matches!(
                absolute_file_path(PathBuf::from(path)),
                Err(PathError::InvalidVaultPath)
            ));
        }
    }

    #[test]
    fn cache_identity_is_stable_across_missing_vault_and_symlinked_parent() {
        use std::fs;
        use std::os::unix::fs::{symlink, PermissionsExt};

        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let root = env::temp_dir().join(format!(
            "passflick-path-identity-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        let real = root.join("real");
        fs::create_dir_all(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let alias = root.join("alias");
        symlink(&real, &alias).unwrap();

        let through_alias = alias.join("vault.passvault");
        let expected = real.join("vault.passvault");
        assert_eq!(vault_identity_path(&through_alias), expected);
        fs::write(&expected, b"synthetic ciphertext").unwrap();
        assert_eq!(vault_identity_path(&through_alias), expected);
        assert_eq!(vault_identity_path(&expected), expected);
        fs::remove_file(&expected).unwrap();
        assert_eq!(vault_identity_path(&through_alias), expected);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn absolute_file_path_is_preserved() {
        let absolute = PathBuf::from("/tmp/passflick-example.test/vault.passvault");
        assert_eq!(absolute_file_path(absolute.clone()).unwrap(), absolute);
    }
}
