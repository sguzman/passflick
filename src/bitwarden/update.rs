//! Explicit, read-only full-sync -> decrypted -> encrypted-cache transaction.
//!
//! This orchestrator is test-only until a disposable Vaultwarden has passed
//! full protocol and local cache acceptance. No upstream mutation methods,
//! automatic polling, CSV merge or plaintext disk writes are exposed.
//! The commit boundary runs only after *all* admitted logins decrypt and the
//! complete projection validates. A failed refresh never changes the cache.

use std::path::Path;

use serde_json::Value;

use super::{
    auth::{AuthError, RemoteSession},
    cache_store::{self, CacheError, CacheKey},
    envelope::{self, SyncEnvelopeError},
    pipeline::{self, LoginDecryptor, ProjectionPipelineError},
    transport::{ReadOnlySyncTransport, ServerEndpoint, TransportError},
};

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("authentication failed: {0}")]
    Auth(#[from] AuthError),
    #[error("remote session has expired")]
    SessionExpired,
    #[error("read-only server sync failed: {0}")]
    Transport(#[from] TransportError),
    #[error("complete vault admission failed: {0}")]
    Admission(#[from] SyncEnvelopeError),
    #[error("credential decryption failed: {0}")]
    Projection(#[from] ProjectionPipelineError),
    #[error("encrypted local projection was not published: {0}")]
    Cache(#[from] CacheError),
}

/// Commit a *complete*, previously authenticated sync response. This
/// boundary is usable in synthetic tests without making any network calls.
/// A caller must not pass a partial cipher list or pre-filtered response.
pub fn commit_full_sync<D: LoginDecryptor>(
    payload: &Value,
    endpoint: &ServerEndpoint,
    expected_account: &str,
    timestamp: u64,
    decoder: &D,
    key: &CacheKey,
    path: &Path,
) -> Result<usize, UpdateError> {
    let admitted = envelope::admit(payload, Some(expected_account))?;
    let candidate =
        pipeline::project_full_sync(admitted, endpoint.server_identity(), timestamp, decoder)?;
    let count = candidate.items().len();
    cache_store::publish(path, key, &candidate)?;
    Ok(count)
}

/// The single networked update entrypoint. Ordinary launch/search/copy must
/// never call it. Refresh tokens are touched only if the in-memory bearer
/// has expired; the resulting encrypted snapshot is entirely local.
pub fn refresh_explicit<D: LoginDecryptor>(
    transport: &ReadOnlySyncTransport,
    endpoint: &ServerEndpoint,
    session: &mut RemoteSession,
    expected_account: &str,
    timestamp: u64,
    decoder: &D,
    key: &CacheKey,
    path: &Path,
) -> Result<usize, UpdateError> {
    if session.bearer_token().is_none() {
        transport.refresh_session(endpoint, session)?;
    }
    let bearer = session.bearer_token().ok_or(UpdateError::SessionExpired)?;
    let payload = transport.fetch_sync(endpoint, bearer, expected_account)?;
    commit_full_sync(
        &payload,
        endpoint,
        expected_account,
        timestamp,
        decoder,
        key,
        path,
    )
}

#[cfg(test)]
mod tests {
    use super::super::decryptor::PersonalLoginDecryptor;
    use super::*;
    use crate::projection::ProjectionSnapshot;
    use rbw::api::KdfType;
    use rbw::cipherstring::CipherString;
    use rbw::identity::Identity;
    use rbw::locked::{Keys, Password};
    use serde_json::json;
    use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};

    struct PrivateTestDir(PathBuf);

    impl PrivateTestDir {
        fn new() -> Self {
            let mut random = [0_u8; 8];
            getrandom::fill(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!(
                "passflick-transaction-test-{:016x}",
                u64::from_le_bytes(random)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn cache(&self) -> PathBuf {
            self.0.join("projection.pfsnapshot")
        }
    }

    impl Drop for PrivateTestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn key() -> CacheKey {
        CacheKey::from_slice(&[30_u8; 32]).unwrap()
    }

    fn user_keys() -> Keys {
        let mut storage = rbw::locked::Vec::new();
        storage.extend([71_u8; 64].into_iter());
        Keys::new(storage)
    }

    fn decoder() -> PersonalLoginDecryptor {
        let mut master = rbw::locked::Vec::new();
        master.extend(b"fictional-master-passphrase".iter().copied());
        let identity = Identity::new(
            "synthetic@example.test",
            &Password::new(master),
            KdfType::Pbkdf2,
            1500,
            None,
            None,
        )
        .unwrap();
        let wrapped = CipherString::encrypt_symmetric(&identity.keys, &[71_u8; 64])
            .unwrap()
            .to_string();
        PersonalLoginDecryptor::unlock(
            "synthetic@example.test",
            "fictional-master-passphrase",
            KdfType::Pbkdf2,
            1500,
            None,
            None,
            &wrapped,
        )
        .unwrap()
    }

    fn encrypted(clear: &str) -> String {
        CipherString::encrypt_symmetric(&user_keys(), clear.as_bytes())
            .unwrap()
            .to_string()
    }

    fn login(id: &str, password: &str) -> Value {
        json!({
            "id": id,
            "type": 1,
            "name": encrypted("Fictional Service"),
            "folderId": "folder-one",
            "login": {
                "username": encrypted("same-user"),
                "password": encrypted(password),
                "uris": [
                    {"uri": encrypted("https://example.test/login")},
                    {"uri": encrypted("https://alternative.example.test")}
                ]
            },
            "archivedDate": null,
            "deletedDate": null,
            "viewPassword": true
        })
    }

    fn full(ciphers: Vec<Value>) -> Value {
        json!({
            "object": "sync",
            "profile": {"id": "test-account"},
            "folders": [{"id": "folder-one"}],
            "ciphers": ciphers
        })
    }

    fn endpoint() -> ServerEndpoint {
        ServerEndpoint::parse("https://vault.example.test/").unwrap()
    }

    fn offline(dir: &PrivateTestDir) -> ProjectionSnapshot {
        cache_store::load(
            &dir.cache(),
            &key(),
            endpoint().server_identity(),
            "test-account",
        )
        .unwrap()
    }

    #[test]
    fn real_cipherstrings_round_trip_into_authenticated_offline_projection() {
        let dir = PrivateTestDir::new();
        let first = full(vec![
            login("unique-id-a", "  🗝️ contraseña  "),
            login("unique-id-b", "other"),
        ]);
        assert_eq!(
            commit_full_sync(
                &first,
                &endpoint(),
                "test-account",
                100,
                &decoder(),
                &key(),
                &dir.cache()
            )
            .unwrap(),
            2
        );
        let actual = offline(&dir);
        assert_eq!(actual.items().len(), 2);
        assert_eq!(actual.items()[0].password(), "  🗝️ contraseña  ");
        assert_eq!(actual.items()[0].uris().len(), 2);
        assert_eq!(actual.items()[1].id(), "unique-id-b");
        assert_eq!(actual.items()[1].username(), "same-user");
        let encrypted_disk = fs::read(dir.cache()).unwrap();
        assert!(!encrypted_disk.windows(6).any(|w| w == b"other"));
    }

    #[test]
    fn next_full_refresh_replaces_edits_and_removes_archived_hidden_deleted() {
        let dir = PrivateTestDir::new();
        let original = full(vec![login("a", "old"), login("b", "old")]);
        commit_full_sync(
            &original,
            &endpoint(),
            "test-account",
            100,
            &decoder(),
            &key(),
            &dir.cache(),
        )
        .unwrap();

        let mut archived = login("b", "archived");
        archived["archivedDate"] = json!("2026-11-03T21:00:00Z");
        let mut hidden = login("c", "hidden");
        hidden["viewPassword"] = json!(false);
        let mut deleted = login("d", "deleted");
        deleted["deletedDate"] = json!("2026-11-03T21:00:00Z");
        let changed = full(vec![login("a", "new"), archived, hidden, deleted]);
        assert_eq!(
            commit_full_sync(
                &changed,
                &endpoint(),
                "test-account",
                101,
                &decoder(),
                &key(),
                &dir.cache()
            )
            .unwrap(),
            1
        );
        let current = offline(&dir);
        assert_eq!(current.items().len(), 1);
        assert_eq!(current.items()[0].id(), "a");
        assert_eq!(current.items()[0].password(), "new");
        assert_eq!(current.last_success_at(), 101);
    }

    #[test]
    fn failed_decode_or_incomplete_sync_never_replaces_good_cache() {
        let dir = PrivateTestDir::new();
        commit_full_sync(
            &full(vec![login("original", "preserved")]),
            &endpoint(),
            "test-account",
            100,
            &decoder(),
            &key(),
            &dir.cache(),
        )
        .unwrap();
        let original_bytes = fs::read(dir.cache()).unwrap();

        let mut corrupted = login("wrong", "wrong");
        corrupted["login"]["password"] = json!("2.bad|ciphertext|mac");
        assert!(matches!(
            commit_full_sync(
                &full(vec![login("valid", "valid"), corrupted]),
                &endpoint(),
                "test-account",
                101,
                &decoder(),
                &key(),
                &dir.cache()
            ),
            Err(UpdateError::Projection(_))
        ));

        let incomplete = json!({"object":"sync","profile":{"id":"test-account"},"folders":[]});
        assert!(matches!(
            commit_full_sync(
                &incomplete,
                &endpoint(),
                "test-account",
                101,
                &decoder(),
                &key(),
                &dir.cache()
            ),
            Err(UpdateError::Admission(_))
        ));

        let wrong_account = json!({
            "object":"sync","profile":{"id":"another-account"},"folders":[],"ciphers":[]
        });
        assert!(matches!(
            commit_full_sync(
                &wrong_account,
                &endpoint(),
                "test-account",
                101,
                &decoder(),
                &key(),
                &dir.cache()
            ),
            Err(UpdateError::Admission(_))
        ));
        assert_eq!(fs::read(dir.cache()).unwrap(), original_bytes);
        assert_eq!(offline(&dir).items()[0].password(), "preserved");
    }

    #[test]
    fn repeat_refresh_with_lower_timestamp_is_rejected_without_overwrite() {
        let dir = PrivateTestDir::new();
        commit_full_sync(
            &full(vec![login("one", "newer")]),
            &endpoint(),
            "test-account",
            150,
            &decoder(),
            &key(),
            &dir.cache(),
        )
        .unwrap();
        let bytes = fs::read(dir.cache()).unwrap();
        assert!(matches!(
            commit_full_sync(
                &full(vec![login("one", "older")]),
                &endpoint(),
                "test-account",
                149,
                &decoder(),
                &key(),
                &dir.cache()
            ),
            Err(UpdateError::Cache(CacheError::Rollback))
        ));
        assert_eq!(fs::read(dir.cache()).unwrap(), bytes);
    }
}
