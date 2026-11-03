//! Admission check for ciphertext received from a Bitwarden-compatible sync response.
//!
//! This deliberately does not decrypt credentials or authenticate to a server.
//! It is a test-only foundation until a reviewed native transport/crypto adapter
//! can supply the raw sync envelope before any lossy conversion to entries.
//!
//! Vaultwarden serializes archival as `archivedDate`: the field is null for
//! active items. A backend that drops this field must be rejected rather than
//! accidentally reactivating historical credentials in the Passflick projection.

use std::collections::HashSet;

use serde_json::{Map, Value};

const MAX_SYNC_CIPHERS: usize = 100_000;

#[derive(Debug, PartialEq, Eq)]
pub struct ActiveLogin<'a> {
    pub id: &'a str,
    pub cipher: &'a Map<String, Value>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SyncFilterError {
    #[error("sync response is missing a ciphers array")]
    MissingCiphers,
    #[error("sync response exceeds the supported cipher count")]
    TooManyCiphers,
    #[error("sync contains a malformed cipher")]
    InvalidCipher,
    #[error("sync contains ambiguous lower/Pascal-case fields")]
    AmbiguousFields,
    #[error("sync contains a missing or invalid item ID")]
    InvalidId,
    #[error("sync contains duplicate item IDs")]
    DuplicateId,
    #[error("sync is missing required archival metadata")]
    MissingArchiveStatus,
    #[error("sync is missing required deletion metadata")]
    MissingDeletedStatus,
    #[error("sync contains invalid or ambiguous lifecycle metadata")]
    InvalidLifecycleStatus,
    #[error("active login is missing its login data")]
    InvalidLogin,
    #[error("active login is missing its password visibility permission")]
    MissingPasswordPermission,
    #[error("active login has invalid password visibility permission")]
    InvalidPasswordPermission,
}

/// Select only active login envelopes, retaining their exact upstream IDs.
/// The returned map references remain encrypted at this boundary.
///
/// Missing `archivedDate` is intentionally a hard failure: legacy libraries
/// can deserialize a sync response while silently dropping archive status.
pub fn active_logins(snapshot: &Value) -> Result<Vec<ActiveLogin<'_>>, SyncFilterError> {
    if snapshot.get("ciphers").is_some() && snapshot.get("Ciphers").is_some() {
        return Err(SyncFilterError::AmbiguousFields);
    }
    let ciphers = snapshot
        .get("ciphers")
        .or_else(|| snapshot.get("Ciphers"))
        .and_then(Value::as_array)
        .ok_or(SyncFilterError::MissingCiphers)?;
    if ciphers.len() > MAX_SYNC_CIPHERS {
        return Err(SyncFilterError::TooManyCiphers);
    }

    let mut ids = HashSet::with_capacity(ciphers.len());
    let mut active = Vec::new();

    for cipher in ciphers {
        let object = cipher.as_object().ok_or(SyncFilterError::InvalidCipher)?;
        for (lower, upper) in [
            ("id", "Id"),
            ("type", "Type"),
            ("login", "Login"),
            ("viewPassword", "ViewPassword"),
        ] {
            if object.contains_key(lower) && object.contains_key(upper) {
                return Err(SyncFilterError::AmbiguousFields);
            }
        }
        let id = value(object, "id", "Id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or(SyncFilterError::InvalidId)?;
        if !ids.insert(id) {
            return Err(SyncFilterError::DuplicateId);
        }

        let archived = lifecycle_status(
            object,
            "archivedDate",
            "ArchivedDate",
            SyncFilterError::MissingArchiveStatus,
        )?;
        let deleted = lifecycle_status(
            object,
            "deletedDate",
            "DeletedDate",
            SyncFilterError::MissingDeletedStatus,
        )?;
        if archived || deleted {
            continue;
        }

        let kind = value(object, "type", "Type")
            .and_then(Value::as_u64)
            .ok_or(SyncFilterError::InvalidCipher)?;
        if kind != 1 {
            continue;
        }
        if !value(object, "login", "Login").is_some_and(Value::is_object) {
            return Err(SyncFilterError::InvalidLogin);
        }
        // A user sync explicitly states whether upstream permits viewing the
        // secret. Restricted collection items must not enter the projection.
        match value(object, "viewPassword", "ViewPassword") {
            Some(Value::Bool(true)) => {}
            Some(Value::Bool(false)) => continue,
            Some(_) => return Err(SyncFilterError::InvalidPasswordPermission),
            None => return Err(SyncFilterError::MissingPasswordPermission),
        }
        active.push(ActiveLogin { id, cipher: object });
    }
    Ok(active)
}

fn value<'a>(obj: &'a Map<String, Value>, lower: &str, upper: &str) -> Option<&'a Value> {
    obj.get(lower).or_else(|| obj.get(upper))
}

fn lifecycle_status(
    obj: &Map<String, Value>,
    lower: &str,
    upper: &str,
    missing: SyncFilterError,
) -> Result<bool, SyncFilterError> {
    if obj.contains_key(lower) && obj.contains_key(upper) {
        return Err(SyncFilterError::InvalidLifecycleStatus);
    }
    match value(obj, lower, upper) {
        Some(Value::Null) => Ok(false),
        Some(Value::String(date)) if !date.trim().is_empty() => Ok(true),
        None => Err(missing),
        _ => Err(SyncFilterError::InvalidLifecycleStatus),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn active(id: &str) -> Value {
        json!({
            "id": id,
            "type": 1,
            "name": "2.encrypted-name",
            "login": {"username": "2.encrypted-user", "password": "2.encrypted-secret"},
            "archivedDate": null,
            "deletedDate": null,
            "viewPassword": true
        })
    }

    #[test]
    fn only_active_logins_survive_archive_trash_and_type_filter() {
        let a = active("a");
        let b = active("b");
        let mut archive = active("legacy");
        archive["archivedDate"] = json!("2026-11-03T21:00:00Z");
        let mut trashed = active("trash");
        trashed["deletedDate"] = json!("2026-11-03T21:00:00Z");
        let note = json!({
            "id":"note", "type":2, "secureNote": {},
            "archivedDate":null, "deletedDate":null
        });
        let snapshot = json!({"ciphers":[a,b,archive,trashed,note]});
        let entries = active_logins(&snapshot).unwrap();
        assert_eq!(
            entries.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert_eq!(entries[0].cipher["name"], "2.encrypted-name");
    }

    #[test]
    fn missing_archive_metadata_cannot_silently_reactivate_passwords() {
        let mut record = active("legacy");
        record.as_object_mut().unwrap().remove("archivedDate");
        assert_eq!(
            active_logins(&json!({"ciphers":[record]})).unwrap_err(),
            SyncFilterError::MissingArchiveStatus
        );
    }

    #[test]
    fn invalid_and_ambiguous_lifecycle_states_fail_closed() {
        for bad in [json!(false), json!(0), json!(""), json!({})] {
            let mut record = active("a");
            record["archivedDate"] = bad;
            assert_eq!(
                active_logins(&json!({"ciphers":[record]})).unwrap_err(),
                SyncFilterError::InvalidLifecycleStatus
            );
        }
        let mut record = active("a");
        record["ArchivedDate"] = Value::Null;
        assert_eq!(
            active_logins(&json!({"ciphers":[record]})).unwrap_err(),
            SyncFilterError::InvalidLifecycleStatus
        );
    }

    #[test]
    fn duplicate_ids_abort_entire_snapshot_even_if_one_is_archived() {
        let mut archived = active("same-id");
        archived["archivedDate"] = json!("2026-11-03T21:00:00Z");
        assert_eq!(
            active_logins(&json!({"ciphers":[active("same-id"), archived]})).unwrap_err(),
            SyncFilterError::DuplicateId
        );
    }

    #[test]
    fn pascal_case_sync_responses_are_supported() {
        let snapshot = json!({
            "Ciphers": [{
                "Id":"a", "Type":1, "Login":{},
                "ArchivedDate":null, "DeletedDate":null,
                "ViewPassword":true
            }]
        });
        let entries = active_logins(&snapshot).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "a");
    }

    #[test]
    fn malformed_envelopes_and_missing_login_fail_closed() {
        assert_eq!(
            active_logins(&json!({})).unwrap_err(),
            SyncFilterError::MissingCiphers
        );
        assert_eq!(
            active_logins(&json!({"ciphers":[null]})).unwrap_err(),
            SyncFilterError::InvalidCipher
        );
        let mut invalid = active("a");
        invalid["id"] = json!("");
        assert_eq!(
            active_logins(&json!({"ciphers":[invalid]})).unwrap_err(),
            SyncFilterError::InvalidId
        );
        let mut invalid_login = active("a");
        invalid_login["login"] = Value::Null;
        assert_eq!(
            active_logins(&json!({"ciphers":[invalid_login]})).unwrap_err(),
            SyncFilterError::InvalidLogin
        );
    }

    #[test]
    fn zero_active_logins_can_be_a_valid_snapshot() {
        assert!(active_logins(&json!({"ciphers":[]})).unwrap().is_empty());
    }

    #[test]
    fn permission_restricted_logins_are_not_exposed() {
        let mut restricted = active("restricted-org");
        restricted["viewPassword"] = json!(false);
        let entries = active_logins(&json!({"ciphers":[active("personal"), restricted]})).unwrap();
        assert_eq!(
            entries.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec!["personal"]
        );
    }

    #[test]
    fn missing_or_invalid_permission_fails_the_entire_sync() {
        let mut missing = active("unknown-permission");
        missing.as_object_mut().unwrap().remove("viewPassword");
        assert_eq!(
            active_logins(&json!({"ciphers":[active("good"), missing]})).unwrap_err(),
            SyncFilterError::MissingPasswordPermission
        );
        for bad in [json!(null), json!("true"), json!(1), json!({})] {
            let mut item = active("invalid-permission");
            item["viewPassword"] = bad;
            assert_eq!(
                active_logins(&json!({"ciphers":[item]})).unwrap_err(),
                SyncFilterError::InvalidPasswordPermission
            );
        }
    }

    #[test]
    fn absent_deleted_status_is_not_assumed_active() {
        let mut item = active("unknown-deletion-status");
        item.as_object_mut().unwrap().remove("deletedDate");
        assert_eq!(
            active_logins(&json!({"ciphers":[item]})).unwrap_err(),
            SyncFilterError::MissingDeletedStatus
        );
    }

    #[test]
    fn ambiguous_case_variants_fail_without_silent_precedence() {
        assert_eq!(
            active_logins(&json!({"ciphers":[], "Ciphers":[active("other")]})).unwrap_err(),
            SyncFilterError::AmbiguousFields
        );
        for (lower, upper) in [
            ("id", "Id"),
            ("type", "Type"),
            ("login", "Login"),
            ("viewPassword", "ViewPassword"),
        ] {
            let mut item = active("ambiguous");
            let duplicate = item[lower].clone();
            item[upper] = duplicate;
            assert_eq!(
                active_logins(&json!({"ciphers":[item]})).unwrap_err(),
                SyncFilterError::AmbiguousFields
            );
        }
    }
}
