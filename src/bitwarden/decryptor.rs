//! Native Bitwarden-compatible *personal login* decryptor built on rbw 1.15.
//!
//! The MIT-licensed rbw crypto routines perform KDF, AES-CBC and HMAC
//! verification; Passflick owns only the lossless raw-sync field mapping and
//! admission policy. This is test-only until authenticated server, key
//! lifecycle and rollback gates pass. Organization items are not supported
//! and MUST abort a refresh rather than expose the wrong key or drop items.
//!
//! IMPORTANT: rbw accepts type-2 cipherstrings without HMAC for legacy
//! interoperability; this adapter deliberately requires the MAC on every
//! encrypted credential field and wrapped symmetric key.

use rbw::api::KdfType;
use rbw::cipherstring::CipherString;
use rbw::identity::Identity;
use rbw::locked::{Keys, Password};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::pipeline::{DecodeError, LoginDecryptor};
use crate::projection::LoginItem;

const MAX_ENCRYPTED_FIELD_BYTES: usize = 1_048_576;
const MAX_KDF_ITERATIONS_PBKDF2: u32 = 2_000_000;
const MAX_KDF_ITERATIONS_ARGON2: u32 = 10;
const MAX_KDF_MEMORY_MIB: u32 = 256;
const MAX_URI_COUNT: usize = 64;

/// An in-memory, zeroizing personal vault key owned by a single update
/// attempt. This is not a keyring or unlock session.
pub struct PersonalLoginDecryptor {
    account_keys: Keys,
}

impl PersonalLoginDecryptor {
    /// Derive the protected user key from a master password and server KDF
    /// profile. KDF parameters are checked *before* invoking rbw, whose
    /// Argon2 initializer assumes well-formed inputs.
    pub fn unlock(
        email: &str,
        master_password: &str,
        kdf: KdfType,
        iterations: u32,
        memory_mib: Option<u32>,
        parallelism: Option<u32>,
        encrypted_user_key: &str,
    ) -> Result<Self, DecodeError> {
        if email.trim().is_empty() || email.len() > 320 || master_password.is_empty() {
            return Err(DecodeError::InvalidCipher);
        }
        match kdf {
            KdfType::Pbkdf2 if !(1..=MAX_KDF_ITERATIONS_PBKDF2).contains(&iterations) => {
                return Err(DecodeError::InvalidCipher);
            }
            KdfType::Argon2id
                if !(1..=MAX_KDF_ITERATIONS_ARGON2).contains(&iterations)
                    || !memory_mib
                        .is_some_and(|memory| (16..=MAX_KDF_MEMORY_MIB).contains(&memory))
                    || !parallelism.is_some_and(|threads| (1..=8).contains(&threads)) =>
            {
                return Err(DecodeError::InvalidCipher);
            }
            _ => {}
        }

        let mut locked_password = rbw::locked::Vec::new();
        locked_password.extend(master_password.as_bytes().iter().copied());
        let password = Password::new(locked_password);
        let identity = Identity::new(email, &password, kdf, iterations, memory_mib, parallelism)
            .map_err(|_| DecodeError::InvalidCipher)?;
        let decrypted = decrypt_authenticated(encrypted_user_key, &identity.keys)?;
        let user_key = locked_keys(&decrypted)?;
        Ok(Self {
            account_keys: user_key,
        })
    }

    #[cfg(test)]
    fn from_synthetic_keys(key_bytes: &[u8]) -> Self {
        Self {
            account_keys: locked_keys(key_bytes).expect("synthetic 64-byte key"),
        }
    }
}

fn locked_keys(bytes: &[u8]) -> Result<Keys, DecodeError> {
    if bytes.len() != 64 {
        return Err(DecodeError::InvalidCipher);
    }
    let mut protected = rbw::locked::Vec::new();
    protected.extend(bytes.iter().copied());
    Ok(Keys::new(protected))
}

fn decrypt_authenticated(encrypted: &str, keys: &Keys) -> Result<Zeroizing<Vec<u8>>, DecodeError> {
    if encrypted.len() > MAX_ENCRYPTED_FIELD_BYTES
        || !encrypted.starts_with("2.")
        || encrypted.split('|').count() != 3
        || encrypted.split('|').any(str::is_empty)
    {
        return Err(DecodeError::InvalidCipher);
    }
    // rbw's HMAC verifier expects a 32-byte digest and may panic when
    // presented with a differently sized decoded MAC. Validate structural
    // lengths before passing untrusted ciphertext to that primitive.
    let parts = encrypted[2..].split('|').collect::<Vec<_>>();
    let iv = rbw::base64::decode(parts[0]).map_err(|_| DecodeError::InvalidCipher)?;
    let ciphertext = rbw::base64::decode(parts[1]).map_err(|_| DecodeError::InvalidCipher)?;
    let mac = rbw::base64::decode(parts[2]).map_err(|_| DecodeError::InvalidCipher)?;
    if iv.len() != 16 || ciphertext.is_empty() || ciphertext.len() % 16 != 0 || mac.len() != 32 {
        return Err(DecodeError::InvalidCipher);
    }
    let cipher = CipherString::new(encrypted).map_err(|_| DecodeError::InvalidCipher)?;
    cipher
        .decrypt_symmetric(keys, None)
        .map(Zeroizing::new)
        .map_err(|_| DecodeError::InvalidCipher)
}

/// Moves the authenticated plaintext allocation into a String on successful
/// UTF-8 validation. The receiving LoginItem zeroizes it on drop. Invalid
/// UTF-8 is erased when the zeroizing byte buffer drops.
fn decrypt_utf8(encrypted: &str, keys: &Keys) -> Result<String, DecodeError> {
    let mut bytes = decrypt_authenticated(encrypted, keys)?;
    std::str::from_utf8(&bytes).map_err(|_| DecodeError::InvalidCipher)?;
    Ok(String::from_utf8(std::mem::take(&mut *bytes)).expect("validated UTF-8"))
}

fn encrypted_string<'a>(
    object: &'a Map<String, Value>,
    lower: &str,
    upper: &str,
) -> Result<&'a str, DecodeError> {
    if object.contains_key(lower) && object.contains_key(upper) {
        return Err(DecodeError::InvalidCipher);
    }
    object
        .get(lower)
        .or_else(|| object.get(upper))
        .and_then(Value::as_str)
        .ok_or(DecodeError::InvalidCipher)
}

fn field<'a>(
    object: &'a Map<String, Value>,
    lower: &str,
    upper: &str,
) -> Result<Option<&'a Value>, DecodeError> {
    if object.contains_key(lower) && object.contains_key(upper) {
        return Err(DecodeError::InvalidCipher);
    }
    Ok(object.get(lower).or_else(|| object.get(upper)))
}

impl LoginDecryptor for PersonalLoginDecryptor {
    fn decrypt_login(
        &self,
        upstream_id: &str,
        raw_cipher: &Map<String, Value>,
    ) -> Result<LoginItem, DecodeError> {
        // Prevent bypassing upstream master-password re-prompt protection and
        // unsupported organization policy. This is intentionally fail-closed:
        // no partially decrypted projection may be published.
        if field(raw_cipher, "organizationId", "OrganizationId")?.is_some_and(|v| !v.is_null())
            || field(raw_cipher, "reprompt", "Reprompt")?.is_some_and(|v| v.as_u64() != Some(0))
        {
            return Err(DecodeError::InvalidCipher);
        }
        let item_keys = match field(raw_cipher, "key", "Key")? {
            None | Some(Value::Null) => None,
            Some(Value::String(encrypted)) => {
                let decrypted = decrypt_authenticated(encrypted, &self.account_keys)?;
                Some(locked_keys(&decrypted)?)
            }
            Some(_) => return Err(DecodeError::InvalidCipher),
        };
        let keys = item_keys.as_ref().unwrap_or(&self.account_keys);

        let name = decrypt_utf8(encrypted_string(raw_cipher, "name", "Name")?, keys)?;
        let login = field(raw_cipher, "login", "Login")?
            .and_then(Value::as_object)
            .ok_or(DecodeError::InvalidCipher)?;

        let username = match field(login, "username", "Username")? {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(value)) => decrypt_utf8(value, keys)?,
            Some(_) => return Err(DecodeError::InvalidCipher),
        };
        let password = match field(login, "password", "Password")? {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(value)) => decrypt_utf8(value, keys)?,
            Some(_) => return Err(DecodeError::InvalidCipher),
        };
        let uris = match field(login, "uris", "Uris")? {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(uris)) if uris.len() <= MAX_URI_COUNT => {
                let mut result = Vec::with_capacity(uris.len());
                for uri in uris {
                    let uri = uri.as_object().ok_or(DecodeError::InvalidCipher)?;
                    match field(uri, "uri", "Uri")? {
                        None | Some(Value::Null) => {}
                        Some(Value::String(value)) => result.push(decrypt_utf8(value, keys)?),
                        Some(_) => return Err(DecodeError::InvalidCipher),
                    }
                }
                result
            }
            Some(_) => return Err(DecodeError::InvalidCipher),
        };

        let folder_id = match field(raw_cipher, "folderId", "FolderId")? {
            None | Some(Value::Null) => None,
            Some(Value::String(id)) => Some(id.to_owned()),
            Some(_) => return Err(DecodeError::InvalidCipher),
        };
        Ok(LoginItem::new(
            upstream_id.to_owned(),
            name,
            uris,
            username,
            password,
            folder_id,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitwarden::{envelope, pipeline};
    use serde_json::json;

    fn keys() -> Keys {
        locked_keys(&[b'K'; 64]).unwrap()
    }

    fn cipher(plaintext: &str, keys: &Keys) -> String {
        CipherString::encrypt_symmetric(keys, plaintext.as_bytes())
            .unwrap()
            .to_string()
    }

    fn login_cipher(id: &str, account_keys: &Keys) -> Value {
        json!({
            "id": id,
            "type": 1,
            "name": cipher("Fictional Service", account_keys),
            "folderId": "folder-a",
            "login": {
                "username": cipher("niño用户", account_keys),
                "password": cipher("  🗝️ contraseña  ", account_keys),
                "uris": [
                    {"uri":cipher("https://example.test/a?token=synthetic", account_keys)},
                    {"uri":cipher("https://another.example.test/b", account_keys)}
                ]
            },
            "archivedDate": null,
            "deletedDate": null,
            "viewPassword": true
        })
    }

    #[test]
    fn decrypts_authenticated_type_two_login_and_all_uris_without_normalizing() {
        let keys = keys();
        let record = login_cipher("item-a", &keys);
        let decoder = PersonalLoginDecryptor::from_synthetic_keys(&[b'K'; 64]);
        let item = decoder
            .decrypt_login("item-a", record.as_object().unwrap())
            .unwrap();
        assert_eq!(item.id(), "item-a");
        assert_eq!(item.title(), "Fictional Service");
        assert_eq!(item.username(), "niño用户");
        assert_eq!(item.password(), "  🗝️ contraseña  ");
        assert_eq!(item.uris().len(), 2);
        assert_eq!(item.uris()[0], "https://example.test/a?token=synthetic");
    }

    #[test]
    fn accepts_per_item_keys_encrypted_with_user_key() {
        let user_keys = keys();
        let entry = locked_keys(&[b'J'; 64]).unwrap();
        let mut record = login_cipher("item-a", &entry);
        record["key"] = json!(
            CipherString::encrypt_symmetric(&user_keys, &[b'J'; 64])
                .unwrap()
                .to_string()
        );
        let decoder = PersonalLoginDecryptor::from_synthetic_keys(&[b'K'; 64]);
        assert_eq!(
            decoder
                .decrypt_login("item-a", record.as_object().unwrap())
                .unwrap()
                .username(),
            "niño用户"
        );
    }

    #[test]
    fn rejects_macless_and_bad_mac_cipherstrings() {
        let keys = keys();
        let mut record = login_cipher("item-a", &keys);
        let mut macless = record["name"].as_str().unwrap().to_owned();
        macless.truncate(macless.rfind('|').unwrap());
        record["name"] = json!(macless);
        let decoder = PersonalLoginDecryptor::from_synthetic_keys(&[b'K'; 64]);
        assert!(
            decoder
                .decrypt_login("item-a", record.as_object().unwrap())
                .is_err()
        );

        record["name"] = json!(cipher("Fictional Service", &keys));
        let mut broken = record["name"].as_str().unwrap().to_owned();
        let last = broken.pop().unwrap();
        broken.push(if last == 'A' { 'B' } else { 'A' });
        record["name"] = json!(broken);
        assert!(
            decoder
                .decrypt_login("item-a", record.as_object().unwrap())
                .is_err()
        );
    }

    #[test]
    fn rejects_unsupported_organizations_and_reprompt_items() {
        let keys = keys();
        let decoder = PersonalLoginDecryptor::from_synthetic_keys(&[b'K'; 64]);
        let mut record = login_cipher("item-a", &keys);
        record["organizationId"] = json!("org-restricted");
        assert!(
            decoder
                .decrypt_login("item-a", record.as_object().unwrap())
                .is_err()
        );
        record["organizationId"] = Value::Null;
        record["reprompt"] = json!(1);
        assert!(
            decoder
                .decrypt_login("item-a", record.as_object().unwrap())
                .is_err()
        );
    }

    #[test]
    fn authentic_full_sync_to_projection_preserves_distinct_ids_and_excludes_trash() {
        let key = keys();
        let mut deleted = login_cipher("deleted", &key);
        deleted["deletedDate"] = json!("2026-11-03T10:00:00Z");
        let first = login_cipher("first", &key);
        let second = login_cipher("second", &key);
        let payload = json!({
            "object": "sync",
            "profile": {"id":"synthetic-account"},
            "folders": [{"id":"folder-a"}],
            "ciphers": [first, second, deleted]
        });
        let admitted = envelope::admit(&payload, Some("synthetic-account")).unwrap();
        let decoder = PersonalLoginDecryptor::from_synthetic_keys(&[b'K'; 64]);
        let projected =
            pipeline::project_full_sync(admitted, "https://vault.example.test", 1, &decoder)
                .unwrap();
        assert_eq!(projected.items().len(), 2);
        assert_eq!(projected.items()[0].id(), "first");
        assert_eq!(projected.items()[1].id(), "second");
    }

    #[test]
    fn rejects_incorrect_user_master_key_and_unsupported_kdf_parameters() {
        let email = "fixture@example.test";
        let mut locked = rbw::locked::Vec::new();
        locked.extend("fictional master password".as_bytes().iter().copied());
        let identity = Identity::new(
            email,
            &Password::new(locked),
            KdfType::Pbkdf2,
            1500,
            None,
            None,
        )
        .unwrap();
        let protected_user_key = CipherString::encrypt_symmetric(&identity.keys, &[b'K'; 64])
            .unwrap()
            .to_string();
        assert!(
            PersonalLoginDecryptor::unlock(
                email,
                "wrong password",
                KdfType::Pbkdf2,
                1500,
                None,
                None,
                &protected_user_key
            )
            .is_err()
        );
        let unlocked = PersonalLoginDecryptor::unlock(
            email,
            "fictional master password",
            KdfType::Pbkdf2,
            1500,
            None,
            None,
            &protected_user_key,
        )
        .unwrap();
        assert_eq!(unlocked.account_keys.enc_key(), &[b'K'; 32]);
        assert!(
            PersonalLoginDecryptor::unlock(
                email,
                "fictional master password",
                KdfType::Pbkdf2,
                0,
                None,
                None,
                &protected_user_key
            )
            .is_err()
        );
        assert!(
            PersonalLoginDecryptor::unlock(
                email,
                "fictional master password",
                KdfType::Argon2id,
                3,
                None,
                None,
                &protected_user_key
            )
            .is_err()
        );
    }
}
