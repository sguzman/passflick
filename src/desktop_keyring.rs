use std::collections::HashMap;
use std::path::Path;

use secret_service::EncryptionType;
use secret_service::blocking::SecretService;
use zeroize::Zeroize;

use crate::vault::VaultKey;

const APP: &str = "passflick";
const KIND: &str = "vault-key-v1";
const LABEL: &str = "Passflick vault key";
const KEY_LEN: usize = 32;

pub fn load(vault_path: &Path) -> Result<Option<VaultKey>, DesktopKeyringError> {
    let service = SecretService::connect(EncryptionType::Dh)?;
    let vault = vault_id(vault_path);
    let attrs = attributes(&vault);
    let mut found = service.search_items(attrs)?;

    let item = if let Some(item) = found.unlocked.pop() {
        item
    } else if let Some(item) = found.locked.pop() {
        item.unlock()?;
        item
    } else {
        return Ok(None);
    };

    let mut secret = item.get_secret()?;
    let result = decode_key(&secret);
    secret.zeroize();
    result.map(Some)
}

pub fn store(vault_path: &Path, key: &VaultKey) -> Result<(), DesktopKeyringError> {
    let service = SecretService::connect(EncryptionType::Dh)?;
    let collection = service.get_default_collection()?;
    if collection.is_locked()? {
        collection.unlock()?;
    }

    let vault = vault_id(vault_path);
    collection.create_item(
        LABEL,
        attributes(&vault),
        key.as_bytes(),
        true,
        "application/octet-stream",
    )?;

    Ok(())
}

pub fn remove(vault_path: &Path) -> Result<bool, DesktopKeyringError> {
    let service = SecretService::connect(EncryptionType::Dh)?;
    let vault = vault_id(vault_path);
    let found = service.search_items(attributes(&vault))?;
    let mut removed = false;

    for item in found.unlocked.into_iter().chain(found.locked) {
        if item.is_locked()? {
            item.unlock()?;
        }
        item.delete()?;
        removed = true;
    }

    Ok(removed)
}

pub fn exists(vault_path: &Path) -> Result<bool, DesktopKeyringError> {
    let service = SecretService::connect(EncryptionType::Dh)?;
    let vault = vault_id(vault_path);
    let found = service.search_items(attributes(&vault))?;
    Ok(!found.unlocked.is_empty() || !found.locked.is_empty())
}

fn attributes(vault: &str) -> HashMap<&str, &str> {
    HashMap::from([("application", APP), ("kind", KIND), ("vault", vault)])
}

fn vault_id(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn decode_key(secret: &[u8]) -> Result<VaultKey, DesktopKeyringError> {
    if secret.len() != KEY_LEN {
        return Err(DesktopKeyringError::InvalidKeyLength(secret.len()));
    }

    let mut bytes = [0_u8; KEY_LEN];
    bytes.copy_from_slice(secret);
    Ok(VaultKey::from_bytes(bytes))
}

#[derive(Debug, thiserror::Error)]
pub enum DesktopKeyringError {
    #[error("desktop Secret Service error: {0}")]
    SecretService(#[from] secret_service::Error),
    #[error("desktop keyring returned an invalid Passflick key length: {0} bytes")]
    InvalidKeyLength(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_key_length_without_touching_dbus() {
        assert!(decode_key(&[7_u8; KEY_LEN]).is_ok());
        assert!(matches!(
            decode_key(&[7_u8; 10]),
            Err(DesktopKeyringError::InvalidKeyLength(10))
        ));
    }
}
