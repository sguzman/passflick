use std::env;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("HOME is not set and XDG_DATA_HOME is unavailable")]
    MissingHome,
}

pub fn vault_path() -> Result<PathBuf, PathError> {
    if let Some(path) = env::var_os("PASSFLICK_VAULT") {
        return Ok(PathBuf::from(path));
    }

    let data_home = if let Some(path) = env::var_os("XDG_DATA_HOME") {
        PathBuf::from(path)
    } else {
        let home = env::var_os("HOME").ok_or(PathError::MissingHome)?;
        PathBuf::from(home).join(".local/share")
    };

    Ok(data_home.join("passflick/vault.passvault"))
}

