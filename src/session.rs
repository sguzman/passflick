use linux_keyutils::{KeyError, KeyPermissionsBuilder, KeyRing, KeyRingIdentifier, Permission};
use zeroize::Zeroize;

use crate::vault::VaultKey;

const KEY_DESCRIPTION: &str = "passflick:vault-key:v1";
const LOCK_DESCRIPTION: &str = "passflick:manual-lock:v1";
const KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("Linux session keyring error: {0}")]
    Keyring(#[from] KeyError),
    #[error("Passflick session key has an invalid length")]
    InvalidKeyLength,
}

pub fn load() -> Result<Option<VaultKey>, SessionError> {
    let ring = session_ring()?;
    let key = match ring.search(KEY_DESCRIPTION) {
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

pub fn store(key: &VaultKey) -> Result<(), SessionError> {
    let ring = session_ring()?;
    let stored = ring.add_key(KEY_DESCRIPTION, key.as_bytes())?;

    let permissions = KeyPermissionsBuilder::builder()
        .posessor(Permission::ALL)
        .build();
    stored.set_perms(permissions)?;
    clear_manual_lock()?;

    Ok(())
}

pub fn mark_locked() -> Result<(), SessionError> {
    let ring = session_ring()?;
    let stored = ring.add_key(LOCK_DESCRIPTION, b"1")?;
    let permissions = KeyPermissionsBuilder::builder()
        .posessor(Permission::ALL)
        .build();
    stored.set_perms(permissions)?;
    Ok(())
}

pub fn is_manually_locked() -> Result<bool, SessionError> {
    let ring = session_ring()?;
    match ring.search(LOCK_DESCRIPTION) {
        Ok(_) => Ok(true),
        Err(KeyError::KeyDoesNotExist | KeyError::MissingFileOrDirectory) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub fn clear_manual_lock() -> Result<bool, SessionError> {
    invalidate(LOCK_DESCRIPTION)
}

pub fn clear() -> Result<bool, SessionError> {
    invalidate(KEY_DESCRIPTION)
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
