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
    fn absolute_file_path_is_preserved() {
        let absolute = PathBuf::from("/tmp/passflick-example.test/vault.passvault");
        assert_eq!(absolute_file_path(absolute.clone()).unwrap(), absolute);
    }
}
