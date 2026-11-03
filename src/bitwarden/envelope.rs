//! Validate a complete user-level Vaultwarden sync envelope before decryption.
//! No authentication, transport or secret decryption occurs in this module.
//! The caller must supply the entire authenticated /sync response, not a
//! partial page, an organization-only response, or a ciphers-only JSON object.

use std::collections::HashSet;

use serde_json::Value;

use super::sync_filter::{self, ActiveLogin, SyncFilterError};

const MAX_SYNC_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_FOLDERS: usize = 100_000;
const MAX_ACCOUNT_ID_BYTES: usize = 256;

pub struct AdmittedSync<'a> {
    pub account_id: &'a str,
    pub active_logins: Vec<ActiveLogin<'a>>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SyncEnvelopeError {
    #[error("sync response is too large")]
    OversizedResponse,
    #[error("sync response is not valid JSON")]
    InvalidJson,
    #[error("sync response has an invalid or missing object marker")]
    InvalidMarker,
    #[error("sync response has an invalid or missing account profile")]
    InvalidProfile,
    #[error("sync response has ambiguous lower/Pascal-case fields")]
    AmbiguousFields,
    #[error("sync response belongs to a different account")]
    AccountMismatch,
    #[error("sync response has an invalid or missing folders array")]
    InvalidFolders,
    #[error("sync response has duplicate folder IDs")]
    DuplicateFolderId,
    #[error("sync cipher admission failed: {0}")]
    Ciphers(#[from] SyncFilterError),
}

/// Only parse a bounded, already authenticated response. Do not print the raw
/// payload or serde errors: they may include private account/server details.
pub fn parse_sync_json(raw: &[u8]) -> Result<Value, SyncEnvelopeError> {
    if raw.len() > MAX_SYNC_BODY_BYTES {
        return Err(SyncEnvelopeError::OversizedResponse);
    }
    super::strict_json::parse(raw).map_err(|_| SyncEnvelopeError::InvalidJson)
}

/// Bind the full response to a known upstream account before projecting
/// any credentials. The transport must separately verify HTTPS and the
/// authenticated user's identity; this check prevents cross-account cache
/// replacement by a well-formed response with a different profile ID.
pub fn admit<'a>(
    sync: &'a Value,
    expected_account_id: Option<&str>,
) -> Result<AdmittedSync<'a>, SyncEnvelopeError> {
    let obj = sync.as_object().ok_or(SyncEnvelopeError::InvalidMarker)?;
    for (lower, upper) in [
        ("object", "Object"),
        ("profile", "Profile"),
        ("folders", "Folders"),
        ("ciphers", "Ciphers"),
    ] {
        if obj.contains_key(lower) && obj.contains_key(upper) {
            return Err(SyncEnvelopeError::AmbiguousFields);
        }
    }
    if field(obj, "object", "Object").and_then(Value::as_str) != Some("sync") {
        return Err(SyncEnvelopeError::InvalidMarker);
    }

    let profile = field(obj, "profile", "Profile")
        .and_then(Value::as_object)
        .ok_or(SyncEnvelopeError::InvalidProfile)?;
    if profile.contains_key("id") && profile.contains_key("Id") {
        return Err(SyncEnvelopeError::AmbiguousFields);
    }
    let account_id = field(profile, "id", "Id")
        .and_then(Value::as_str)
        .filter(|id| {
            !id.is_empty()
                && id.len() <= MAX_ACCOUNT_ID_BYTES
                && id.trim() == *id
                && !id.chars().any(char::is_control)
        })
        .ok_or(SyncEnvelopeError::InvalidProfile)?;
    if expected_account_id.is_some_and(|expected| expected != account_id) {
        return Err(SyncEnvelopeError::AccountMismatch);
    }

    let folders = field(obj, "folders", "Folders")
        .and_then(Value::as_array)
        .filter(|items| items.len() <= MAX_FOLDERS)
        .ok_or(SyncEnvelopeError::InvalidFolders)?;
    let mut folder_ids = HashSet::with_capacity(folders.len());
    for folder in folders {
        let folder = folder
            .as_object()
            .ok_or(SyncEnvelopeError::InvalidFolders)?;
        if folder.contains_key("id") && folder.contains_key("Id") {
            return Err(SyncEnvelopeError::AmbiguousFields);
        }
        let id = field(folder, "id", "Id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= MAX_ACCOUNT_ID_BYTES)
            .ok_or(SyncEnvelopeError::InvalidFolders)?;
        if !folder_ids.insert(id) {
            return Err(SyncEnvelopeError::DuplicateFolderId);
        }
    }

    let active_logins = sync_filter::active_logins(sync)?;
    Ok(AdmittedSync {
        account_id,
        active_logins,
    })
}

fn field<'a>(
    obj: &'a serde_json::Map<String, Value>,
    lower: &str,
    upper: &str,
) -> Option<&'a Value> {
    obj.get(lower).or_else(|| obj.get(upper))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn full_sync() -> Value {
        json!({
            "object":"sync",
            "profile":{"id":"fixture-account"},
            "folders":[{"id":"folder-one","name":"2.encrypted-folder"}],
            "ciphers":[{
                "id":"login-one", "type":1,
                "name":"2.encrypted-name",
                "login":{"username":"2.encrypted-user","password":"2.encrypted-password"},
                "archivedDate":null, "deletedDate":null, "viewPassword":true
            }]
        })
    }

    #[test]
    fn admits_a_full_user_sync_bound_to_expected_account() {
        let value = full_sync();
        let checked = admit(&value, Some("fixture-account")).unwrap();
        assert_eq!(checked.account_id, "fixture-account");
        assert_eq!(checked.active_logins.len(), 1);
        assert_eq!(checked.active_logins[0].id, "login-one");
    }

    #[test]
    fn fails_closed_on_partial_or_cross_account_results() {
        assert!(matches!(
            admit(&json!({"ciphers":[]}), None),
            Err(SyncEnvelopeError::InvalidMarker)
        ));
        let mut value = full_sync();
        assert!(matches!(
            admit(&value, Some("another-account")),
            Err(SyncEnvelopeError::AccountMismatch)
        ));
        value.as_object_mut().unwrap().remove("profile");
        assert!(matches!(
            admit(&value, None),
            Err(SyncEnvelopeError::InvalidProfile)
        ));
    }

    #[test]
    fn valid_empty_vault_is_distinct_from_an_incomplete_response() {
        let mut valid = full_sync();
        valid["ciphers"] = json!([]);
        let admitted = admit(&valid, Some("fixture-account")).unwrap();
        assert!(admitted.active_logins.is_empty());

        valid.as_object_mut().unwrap().remove("ciphers");
        assert!(matches!(
            admit(&valid, None),
            Err(SyncEnvelopeError::Ciphers(SyncFilterError::MissingCiphers))
        ));
    }

    #[test]
    fn missing_or_duplicate_folders_abort_snapshot() {
        let mut value = full_sync();
        value.as_object_mut().unwrap().remove("folders");
        assert!(matches!(
            admit(&value, None),
            Err(SyncEnvelopeError::InvalidFolders)
        ));

        value["folders"] = json!([{"id":"same"},{"id":"same"}]);
        assert!(matches!(
            admit(&value, None),
            Err(SyncEnvelopeError::DuplicateFolderId)
        ));
        value["folders"] = json!([null]);
        assert!(matches!(
            admit(&value, None),
            Err(SyncEnvelopeError::InvalidFolders)
        ));
    }

    #[test]
    fn ambiguous_and_malformed_envelopes_are_rejected() {
        let mut value = full_sync();
        value["Profile"] = value["profile"].clone();
        assert!(matches!(
            admit(&value, None),
            Err(SyncEnvelopeError::AmbiguousFields)
        ));
        let mut value = full_sync();
        value["profile"]["id"] = json!(" ");
        assert!(matches!(
            admit(&value, None),
            Err(SyncEnvelopeError::InvalidProfile)
        ));
        let mut value = full_sync();
        value["object"] = json!("cipherDetails");
        assert!(matches!(
            admit(&value, None),
            Err(SyncEnvelopeError::InvalidMarker)
        ));
    }

    #[test]
    fn json_size_and_parse_failures_are_private_and_bounded() {
        let oversized = vec![b' '; MAX_SYNC_BODY_BYTES + 1];
        assert!(matches!(
            parse_sync_json(&oversized),
            Err(SyncEnvelopeError::OversizedResponse)
        ));
        assert!(matches!(
            parse_sync_json(b"{private-data"),
            Err(SyncEnvelopeError::InvalidJson)
        ));
        let response = serde_json::to_vec(&full_sync()).unwrap();
        let parsed = parse_sync_json(&response).unwrap();
        assert_eq!(admit(&parsed, None).unwrap().active_logins.len(), 1);
    }
}
