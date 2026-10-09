use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;

use linux_keyutils::{KeyError, KeyPermissionsBuilder, KeyRing, KeyRingIdentifier, Permission};
use zeroize::Zeroize;

use crate::{paths, vault::VaultKey};

const KEY_NAMESPACE: &str = "passflick:vault-key:v2";
const LOCK_NAMESPACE: &str = "passflick:manual-lock:v2";
const KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("Linux session keyring error: {0}")]
    Keyring(#[from] KeyError),
    #[error("Passflick session key has an invalid length")]
    InvalidKeyLength,
}

/// Multiple independently encrypted vaults must not reuse one cached session
/// key or manual-lock marker. This label is a lookup aid, not authentication:
/// the vault's AEAD tag still authenticates all decrypted credentials.
///
/// The hash is intentionally not persisted in the vault format. A Rust upgrade
/// changing DefaultHasher would at worst require one extra session unlock.
fn description(namespace: &str, vault_path: &Path) -> String {
    let identity = paths::vault_identity_path(vault_path);
    let mut hash = DefaultHasher::new();
    identity.hash(&mut hash);
    format!("{namespace}:{:016x}", hash.finish())
}

pub fn load(vault_path: &Path) -> Result<Option<VaultKey>, SessionError> {
    let ring = session_ring()?;
    let label = description(KEY_NAMESPACE, vault_path);
    let key = match ring.search(&label) {
        Ok(key) => key,
        Err(KeyError::KeyDoesNotExist | KeyError::MissingFileOrDirectory) => return Ok(None),
        Err(error) => return Err(error.into()),
    };

    let mut payload = key.read_to_vec()?;
    if payload.len() != KEY_LEN {
        payload.zeroize();
        return Err(SessionError::InvalidKeyLength);
    }

    let mut bytes = [0_u8; KEY_LEN];
    bytes.copy_from_slice(&payload);
    payload.zeroize();

    Ok(Some(VaultKey::from_bytes(bytes)))
}

pub fn store(vault_path: &Path, key: &VaultKey) -> Result<(), SessionError> {
    let ring = session_ring()?;
    let label = description(KEY_NAMESPACE, vault_path);
    let stored = ring.add_key(&label, key.as_bytes())?;

    let permissions = KeyPermissionsBuilder::builder()
        .posessor(Permission::ALL)
        .build();
    stored.set_perms(permissions)?;
    clear_manual_lock(vault_path)?;

    Ok(())
}

pub fn mark_locked(vault_path: &Path) -> Result<(), SessionError> {
    let ring = session_ring()?;
    let label = description(LOCK_NAMESPACE, vault_path);
    let stored = ring.add_key(&label, b"1")?;
    let permissions = KeyPermissionsBuilder::builder()
        .posessor(Permission::ALL)
        .build();
    stored.set_perms(permissions)?;
    Ok(())
}

pub fn is_manually_locked(vault_path: &Path) -> Result<bool, SessionError> {
    let ring = session_ring()?;
    let label = description(LOCK_NAMESPACE, vault_path);
    match ring.search(&label) {
        Ok(_) => Ok(true),
        Err(KeyError::KeyDoesNotExist | KeyError::MissingFileOrDirectory) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub fn clear_manual_lock(vault_path: &Path) -> Result<bool, SessionError> {
    invalidate(&description(LOCK_NAMESPACE, vault_path))
}

pub fn clear(vault_path: &Path) -> Result<bool, SessionError> {
    invalidate(&description(KEY_NAMESPACE, vault_path))
}

fn invalidate(description: &str) -> Result<bool, SessionError> {
    let ring = session_ring()?;
    let key = match ring.search(description) {
        Ok(key) => key,
        Err(KeyError::KeyDoesNotExist | KeyError::MissingFileOrDirectory) => return Ok(false),
        Err(error) => return Err(error.into()),
    };

    key.invalidate()?;
    Ok(true)
}

fn session_ring() -> Result<KeyRing, KeyError> {
    KeyRing::from_special_id(KeyRingIdentifier::Session, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_keys_and_explicit_locks_are_scoped_per_vault() {
        let left = Path::new("/example.test/first.passvault");
        let right = Path::new("/example.test/second.passvault");
        assert_ne!(
            description(KEY_NAMESPACE, left),
            description(KEY_NAMESPACE, right)
        );
        assert_ne!(
            description(KEY_NAMESPACE, left),
            description(LOCK_NAMESPACE, left)
        );
        assert_eq!(
            description(KEY_NAMESPACE, left),
            description(KEY_NAMESPACE, left)
        );
    }
}
