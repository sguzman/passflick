use std::collections::HashMap;
use std::fmt::Write as _;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use secret_service::EncryptionType;
use secret_service::blocking::SecretService;
use zeroize::Zeroize;

use crate::{paths, vault::VaultKey};

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
    let identity = paths::vault_identity_path(path);
    // Preserve existing Secret Service labels for ordinary UTF-8 paths.
    if let Some(utf8) = identity.to_str() {
        return utf8.to_owned();
    }
    // Lossy conversion can map different invalid UTF-8 path bytes to the
    // same replacement character. Encode raw bytes for unambiguous lookup.
    // The prefix cannot collide with an ordinary absolute vault path.
    let mut encoded = String::from("nonutf8:");
    for byte in identity.as_os_str().as_bytes() {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
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
    fn non_utf8_vault_paths_have_distinct_desktop_keyring_ids() {
        use std::ffi::OsStr;

        let first = Path::new(OsStr::from_bytes(b"/fictional/credentials-\\xff/vault.passvault"));
        let second = Path::new(OsStr::from_bytes(b"/fictional/credentials-\\xfe/vault.passvault"));
        assert_ne!(vault_id(first), vault_id(second));
        assert!(vault_id(first).starts_with("nonutf8:"));
        assert_eq!(
            vault_id(Path::new("/fictional/utf8/vault.passvault")),
            "/fictional/utf8/vault.passvault"
        );
    }

    #[test]
    fn validates_key_length_without_touching_dbus() {
        assert!(decode_key(&[7_u8; KEY_LEN]).is_ok());
        assert!(matches!(
            decode_key(&[7_u8; 10]),
            Err(DesktopKeyringError::InvalidKeyLength(10))
        ));
    }
}
