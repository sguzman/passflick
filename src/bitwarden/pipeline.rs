//! Read-only boundary from admitted encrypted sync to a validated projection.
//! The decryptor must be a reviewed Bitwarden-compatible implementation.
//! This interface is deliberately test-only until a native backend exists.

use serde_json::{Map, Value};

use crate::projection::{LoginItem, ProjectionError, ProjectionSnapshot};

use super::envelope::AdmittedSync;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("cipher decryption or mapping failed")]
    InvalidCipher,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProjectionPipelineError {
    #[error("cipher decryption or mapping failed")]
    Decode,
    #[error("decrypted item ID does not match admitted upstream ID")]
    IdentityMismatch,
    #[error("projection validation failed: {0}")]
    InvalidProjection(#[from] ProjectionError),
}

/// The production implementation will decrypt a single admitted ciphertext
/// with proven crypto primitives. It has no remote mutation methods.
pub trait LoginDecryptor {
    fn decrypt_login(
        &self,
        upstream_id: &str,
        raw_cipher: &Map<String, Value>,
    ) -> Result<LoginItem, DecodeError>;
}

/// All-or-nothing conversion: every permitted login must decrypt and validate
/// before the caller may publish a new encrypted projection. A failure drops
/// any already-decrypted items; the previous on-disk snapshot is not touched.
pub fn project_full_sync<D: LoginDecryptor>(
    upstream: AdmittedSync<'_>,
    server_identity: &str,
    timestamp: u64,
    decryptor: &D,
) -> Result<ProjectionSnapshot, ProjectionPipelineError> {
    let mut items = Vec::with_capacity(upstream.active_logins.len());
    for raw in upstream.active_logins {
        let decrypted = decryptor
            .decrypt_login(raw.id, raw.cipher)
            .map_err(|_| ProjectionPipelineError::Decode)?;
        if decrypted.id() != raw.id {
            return Err(ProjectionPipelineError::IdentityMismatch);
        }
        items.push(decrypted);
    }
    ProjectionSnapshot::new(
        server_identity.to_owned(),
        upstream.account_id.to_owned(),
        timestamp,
        items,
    )
    .map_err(ProjectionPipelineError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitwarden::envelope;
    use serde_json::json;

    // Synthetic decoder, NOT a Bitwarden cipher implementation. Its only
    // purpose is to test orchestration and full-snapshot identity semantics.
    struct FixtureDecoder;

    impl LoginDecryptor for FixtureDecoder {
        fn decrypt_login(
            &self,
            id: &str,
            raw: &Map<String, Value>,
        ) -> Result<LoginItem, DecodeError> {
            let title = raw
                .get("name")
                .and_then(Value::as_str)
                .and_then(|value| value.strip_prefix("2."))
                .ok_or(DecodeError::InvalidCipher)?;
            let login = raw
                .get("login")
                .and_then(Value::as_object)
                .ok_or(DecodeError::InvalidCipher)?;
            let username = login
                .get("username")
                .and_then(Value::as_str)
                .and_then(|value| value.strip_prefix("2."))
                .ok_or(DecodeError::InvalidCipher)?;
            let password = login
                .get("password")
                .and_then(Value::as_str)
                .and_then(|value| value.strip_prefix("2."))
                .ok_or(DecodeError::InvalidCipher)?;
            Ok(LoginItem::new(
                id.to_owned(),
                title.to_owned(),
                vec!["https://example.test/login".to_owned()],
                username.to_owned(),
                password.to_owned(),
                None,
            ))
        }
    }

    struct MismatchedDecoder;
    impl LoginDecryptor for MismatchedDecoder {
        fn decrypt_login(
            &self,
            _id: &str,
            _raw: &Map<String, Value>,
        ) -> Result<LoginItem, DecodeError> {
            Ok(LoginItem::new(
                "wrong-id".to_owned(),
                "Synthetic".to_owned(),
                vec![],
                "fixture".to_owned(),
                "fictional".to_owned(),
                None,
            ))
        }
    }

    fn cipher(id: &str, secret: &str) -> Value {
        json!({
            "id":id, "type":1, "name":"2.Example",
            "login":{"username":"2.usuario","password":format!("2.{secret}")},
            "archivedDate":null, "deletedDate":null, "viewPassword":true
        })
    }

    fn complete(ciphers: Vec<Value>) -> Value {
        json!({
            "object":"sync", "profile":{"id":"synthetic-account"},
            "folders":[], "ciphers":ciphers
        })
    }

    #[test]
    fn full_sync_maps_only_active_visible_ids_and_exact_secrets() {
        let mut archived = cipher("old", "legacy");
        archived["archivedDate"] = json!("2026-11-03T20:00:00Z");
        let mut hidden = cipher("restricted", "hidden");
        hidden["viewPassword"] = json!(false);
        let body = complete(vec![
            cipher("active-a", "  🗝️ uno  "),
            cipher("active-b", "different"),
            archived,
            hidden,
        ]);
        let sync = envelope::admit(&body, Some("synthetic-account")).unwrap();
        let result =
            project_full_sync(sync, "https://vault.example.test", 1, &FixtureDecoder).unwrap();
        assert_eq!(result.items().len(), 2);
        assert_eq!(result.items()[0].id(), "active-a");
        assert_eq!(result.items()[0].password(), "  🗝️ uno  ");
        assert_eq!(result.items()[1].id(), "active-b");
    }

    #[test]
    fn edits_and_archival_replace_old_items_by_id_not_site_username() {
        let first_body = complete(vec![cipher("id-a", "old"), cipher("id-b", "old")]);
        let first = project_full_sync(
            envelope::admit(&first_body, None).unwrap(),
            "https://vault.example.test",
            1,
            &FixtureDecoder,
        )
        .unwrap();
        let next_body = complete(vec![cipher("id-a", "new")]);
        let next = project_full_sync(
            envelope::admit(&next_body, None).unwrap(),
            "https://vault.example.test",
            2,
            &FixtureDecoder,
        )
        .unwrap();
        assert_eq!(first.items().len(), 2);
        assert_eq!(next.items().len(), 1);
        assert_eq!(next.items()[0].password(), "new");
        assert_eq!(next.last_success_at(), 2);
    }

    #[test]
    fn decode_failure_aborts_instead_of_publishing_partial_items() {
        let mut invalid = cipher("invalid", "secret");
        invalid["login"]["password"] = json!(null);
        let body = complete(vec![cipher("valid", "secret"), invalid]);
        let sync = envelope::admit(&body, None).unwrap();
        assert!(matches!(
            project_full_sync(sync, "https://vault.example.test", 1, &FixtureDecoder),
            Err(ProjectionPipelineError::Decode)
        ));
    }

    #[test]
    fn malicious_decoder_cannot_remap_cipher_identity() {
        let body = complete(vec![cipher("authorized-id", "secret")]);
        let sync = envelope::admit(&body, None).unwrap();
        assert!(matches!(
            project_full_sync(sync, "https://vault.example.test", 1, &MismatchedDecoder),
            Err(ProjectionPipelineError::IdentityMismatch)
        ));
    }
}
