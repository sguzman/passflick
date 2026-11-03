//! Versioned, validated *plaintext in-memory* projection schema.
//!
//! A Bitwarden adapter will construct this only after authenticating, admitting
//! and decrypting a complete user sync. These structures are NOT a disk format
//! on their own: serialize only inside a zeroizing buffer that is immediately
//! authenticated/encrypted by the future projection store.
//!
//! No legacy browser provider precedence or site+username de-duplication.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const SCHEMA_VERSION: u16 = 1;
const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
const MAX_ITEMS: usize = 100_000;
const MAX_URIS: usize = 64;
const MAX_ID_BYTES: usize = 256;
const MAX_SITE_BYTES: usize = 16 * 1024;
const MAX_SECRET_BYTES: usize = 256 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionSnapshot {
    schema_version: u16,
    server_identity: String,
    account_id: String,
    last_success_at: u64,
    items: Vec<LoginItem>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginItem {
    id: String,
    title: String,
    uris: Vec<String>,
    username: String,
    password: Zeroizing<String>,
    folder_id: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProjectionError {
    #[error("unsupported projection schema version")]
    UnsupportedSchema,
    #[error("projection exceeds size or item limits")]
    TooLarge,
    #[error("projection has an invalid source identity or timestamp")]
    InvalidSource,
    #[error("projection contains an invalid login item")]
    InvalidItem,
    #[error("projection contains duplicate upstream item IDs")]
    DuplicateId,
    #[error("projection JSON serialization failed")]
    InvalidJson,
}

impl LoginItem {
    pub fn new(
        id: String,
        title: String,
        uris: Vec<String>,
        username: String,
        password: String,
        folder_id: Option<String>,
    ) -> Self {
        Self {
            id,
            title,
            uris,
            username,
            password: Zeroizing::new(password),
            folder_id,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn uris(&self) -> &[String] {
        &self.uris
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        self.password.as_str()
    }

    fn validate(&self) -> Result<(), ProjectionError> {
        if !valid_id(&self.id)
            || self.title.len() > MAX_SITE_BYTES
            || self.username.len() > MAX_SITE_BYTES
            || self.password.len() > MAX_SECRET_BYTES
            || self.uris.len() > MAX_URIS
            || self.uris.iter().any(|uri| uri.len() > MAX_SITE_BYTES)
            || self.folder_id.as_ref().is_some_and(|id| !valid_id(id))
            || (self.title.trim().is_empty() && self.uris.iter().all(|uri| uri.trim().is_empty()))
        {
            return Err(ProjectionError::InvalidItem);
        }
        Ok(())
    }
}

impl Drop for LoginItem {
    fn drop(&mut self) {
        self.id.zeroize();
        self.title.zeroize();
        self.username.zeroize();
        for uri in &mut self.uris {
            uri.zeroize();
        }
        if let Some(folder) = &mut self.folder_id {
            folder.zeroize();
        }
        // password is Zeroizing<String> and clears itself on drop.
    }
}

impl ProjectionSnapshot {
    /// Construct from the *entire* successfully decrypted upstream login set.
    /// Repeated refreshes produce replacement snapshots; old entries must not
    /// be merged back from any browser import or previous local projection.
    pub fn new(
        server_identity: String,
        account_id: String,
        last_success_at: u64,
        items: Vec<LoginItem>,
    ) -> Result<Self, ProjectionError> {
        let snapshot = Self {
            schema_version: SCHEMA_VERSION,
            server_identity,
            account_id,
            last_success_at,
            items,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn server_identity(&self) -> &str {
        &self.server_identity
    }

    pub fn last_success_at(&self) -> u64 {
        self.last_success_at
    }

    pub fn items(&self) -> &[LoginItem] {
        &self.items
    }

    /// The return value is plaintext and MUST NOT be written directly to disk.
    /// A storage adapter will encrypt it before performing an atomic publish.
    pub fn encode_json(&self) -> Result<Zeroizing<Vec<u8>>, ProjectionError> {
        self.validate()?;
        let bytes = Zeroizing::new(
            serde_json::to_vec(self).map_err(|_| ProjectionError::InvalidJson)?,
        );
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(ProjectionError::TooLarge);
        }
        Ok(bytes)
    }

    /// Pass an authenticated, decrypted, zeroizing input buffer here; never
    /// decode untrusted plaintext from a normal unencrypted cache file.
    pub fn decode_json(raw: &[u8]) -> Result<Self, ProjectionError> {
        if raw.len() > MAX_SNAPSHOT_BYTES {
            return Err(ProjectionError::TooLarge);
        }
        let candidate: Self =
            serde_json::from_slice(raw).map_err(|_| ProjectionError::InvalidJson)?;
        candidate.validate()?;
        Ok(candidate)
    }

    fn validate(&self) -> Result<(), ProjectionError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ProjectionError::UnsupportedSchema);
        }
        if !valid_source(&self.server_identity)
            || !valid_id(&self.account_id)
            || self.last_success_at == 0
        {
            return Err(ProjectionError::InvalidSource);
        }
        if self.items.len() > MAX_ITEMS {
            return Err(ProjectionError::TooLarge);
        }
        let mut ids = HashSet::with_capacity(self.items.len());
        for item in &self.items {
            item.validate()?;
            if !ids.insert(item.id.as_str()) {
                return Err(ProjectionError::DuplicateId);
            }
        }
        Ok(())
    }
}

impl Drop for ProjectionSnapshot {
    fn drop(&mut self) {
        self.server_identity.zeroize();
        self.account_id.zeroize();
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_source(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SITE_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(id: &str, username: &str, password: &str) -> LoginItem {
        LoginItem::new(
            id.to_owned(),
            "Example Account".to_owned(),
            vec!["https://example.test/path?token=fictional".to_owned()],
            username.to_owned(),
            password.to_owned(),
            Some("folder-one".to_owned()),
        )
    }

    fn snapshot(items: Vec<LoginItem>) -> Result<ProjectionSnapshot, ProjectionError> {
        ProjectionSnapshot::new(
            "https://vault.example.test".to_owned(),
            "account-one".to_owned(),
            1_783_180_800,
            items,
        )
    }

    #[test]
    fn round_trip_preserves_exact_unicode_and_whitespace_secrets() {
        let expected = "  clé🗝️\npass كلمة  ";
        let original = snapshot(vec![login("uuid-one", "mañana用户", expected)]).unwrap();
        let encoded = original.encode_json().unwrap();
        let decoded = ProjectionSnapshot::decode_json(encoded.as_slice()).unwrap();
        assert_eq!(decoded.server_identity(), "https://vault.example.test");
        assert_eq!(decoded.account_id(), "account-one");
        assert_eq!(decoded.last_success_at(), 1_783_180_800);
        assert_eq!(decoded.items().len(), 1);
        assert_eq!(decoded.items()[0].username(), "mañana用户");
        assert_eq!(decoded.items()[0].password(), expected);
        assert_eq!(decoded.items()[0].uris()[0], "https://example.test/path?token=fictional");
    }

    #[test]
    fn upstream_id_not_site_or_username_is_unique() {
        let items = vec![
            login("uuid-one", "same-user", "old"),
            login("uuid-two", "same-user", "different"),
        ];
        let result = snapshot(items).unwrap();
        assert_eq!(result.items().len(), 2);
        assert_ne!(result.items()[0].id(), result.items()[1].id());
    }

    #[test]
    fn new_full_snapshot_replaces_changed_and_archived_entries() {
        let first = snapshot(vec![
            login("retained", "same-user", "old"),
            login("archived", "other", "old-secret"),
        ]).unwrap();
        let second = snapshot(vec![login("retained", "same-user", "new")]).unwrap();
        assert_eq!(first.items().len(), 2);
        assert_eq!(second.items().len(), 1);
        assert_eq!(second.items()[0].id(), "retained");
        assert_eq!(second.items()[0].password(), "new");
    }

    #[test]
    fn duplicate_ids_reject_even_when_site_and_username_match() {
        assert!(matches!(
            snapshot(vec![login("same", "a", "x"), login("same", "b", "y")]),
            Err(ProjectionError::DuplicateId)
        ));
    }

    #[test]
    fn corrupted_or_unsupported_payloads_fail_closed() {
        let payload = snapshot(vec![login("first", "user", "pw")]).unwrap();
        let bytes = payload.encode_json().unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(bytes.as_slice()).unwrap();
        value["schema_version"] = serde_json::json!(2);
        let tampered = serde_json::to_vec(&value).unwrap();
        assert!(matches!(
            ProjectionSnapshot::decode_json(&tampered),
            Err(ProjectionError::UnsupportedSchema)
        ));
        value["schema_version"] = serde_json::json!(1);
        value["extra_field"] = serde_json::json!(true);
        let unknown = serde_json::to_vec(&value).unwrap();
        assert!(matches!(
            ProjectionSnapshot::decode_json(&unknown),
            Err(ProjectionError::InvalidJson)
        ));
    }

    #[test]
    fn item_and_identity_limits_are_enforced_without_truncation() {
        let mut bad = login("one", "user", "pw");
        bad.uris = vec![];
        bad.title = "  ".to_owned();
        assert!(matches!(snapshot(vec![bad]), Err(ProjectionError::InvalidItem)));

        let long_secret = "x".repeat(MAX_SECRET_BYTES + 1);
        assert!(matches!(
            snapshot(vec![login("one", "user", &long_secret)]),
            Err(ProjectionError::InvalidItem)
        ));
        assert!(matches!(
            ProjectionSnapshot::new(" ".to_owned(), "account".to_owned(), 1, vec![]),
            Err(ProjectionError::InvalidSource)
        ));
        assert!(matches!(
            ProjectionSnapshot::new("https://vault.example.test".to_owned(), "account".to_owned(), 0, vec![]),
            Err(ProjectionError::InvalidSource)
        ));
    }

    #[test]
    fn valid_empty_snapshot_is_allowed_after_complete_upstream_sync() {
        let empty = snapshot(vec![]).unwrap();
        assert!(empty.items().is_empty());
        assert_eq!(ProjectionSnapshot::decode_json(empty.encode_json().unwrap().as_slice()).unwrap().items().len(), 0);
    }
}
