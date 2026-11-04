//! Explicit, read-only full-sync -> decrypted -> encrypted-cache transaction.
//!
//! This orchestrator is test-only until a disposable Vaultwarden has passed
//! full protocol and local cache acceptance. No upstream mutation methods,
//! automatic polling, CSV merge or plaintext disk writes are exposed.
//! The commit boundary runs only after *all* admitted logins decrypt and the
//! complete projection validates. A failed refresh never changes the cache.

use std::ffi::OsStr;
use std::path::Path;

#[cfg(test)]
use serde_json::Value;

#[cfg(test)]
use super::cache_store::CacheKey;
use super::{
    auth::{AuthError, RemoteSession},
    cache_store::{self, CacheError},
    envelope::{self, SyncEnvelopeError},
    keywrap::{self, KeywrapError},
    pipeline::{self, LoginDecryptor, ProjectionPipelineError},
    transport::{ReadOnlySyncTransport, ServerEndpoint, TransportError},
};
use crate::projection::ProjectionSnapshot;

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("authentication failed: {0}")]
    Auth(#[from] AuthError),
    #[error("read-only server sync failed: {0}")]
    Transport(#[from] TransportError),
    #[error("complete vault admission failed: {0}")]
    Admission(#[from] SyncEnvelopeError),
    #[error("credential decryption failed: {0}")]
    Projection(#[from] ProjectionPipelineError),
    #[error("encrypted local projection was not published: {0}")]
    Cache(#[from] CacheError),
    #[error("local projection keywrap setup failed: {0}")]
    Keywrap(#[from] KeywrapError),
    #[error("initial projection paths must be the designated sibling files")]
    InvalidSetupPaths,
}

/// Commit a *complete*, previously authenticated sync response. This
/// boundary is usable in synthetic tests without making any network calls.
/// A caller must not pass a partial cipher list or pre-filtered response.
#[cfg(test)]
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

/// Build the first complete projection from the authenticated server's own
/// account ID. This step never touches disk or allocates a local keywrap;
/// caller must separately confirm local setup before any initial publication.
/// Existing installations MUST use the account-bound refresh_explicit path.
pub fn prepare_initial_sync<D: LoginDecryptor>(
    transport: &ReadOnlySyncTransport,
    session: &mut RemoteSession,
    endpoint: &ServerEndpoint,
    timestamp: u64,
    decoder: &D,
) -> Result<ProjectionSnapshot, UpdateError> {
    session.ensure_endpoint(endpoint)?;
    if session.bearer_token().is_none() {
        transport.refresh_session(endpoint, session)?;
    }
    let bearer = session.bearer_token().ok_or(AuthError::InvalidResponse)?;
    let payload = transport.fetch_initial_sync(endpoint, bearer)?;
    let admitted = envelope::admit(&payload, None)?;
    pipeline::project_full_sync(admitted, endpoint.server_identity(), timestamp, decoder)
        .map_err(UpdateError::from)
}

/// Install a previously authenticated, fully decrypted initial snapshot.
/// A preexisting projection is never overwritten. If an interruption leaves
/// only an encrypted keywrap, an explicit retry with the SAME local passphrase
/// can authenticate that envelope and complete the initial install.
/// This does not contact the server, modify a legacy vault, or enable the
/// production picker. Caller owns masked/confirmed passphrase entry.
pub fn install_initial_projection(
    snapshot: &ProjectionSnapshot,
    snapshot_path: &Path,
    keywrap_path: &Path,
    local_passphrase: &[u8],
) -> Result<usize, UpdateError> {
    if snapshot_path.file_name() != Some(OsStr::new("projection.pfsnapshot"))
        || keywrap_path != snapshot_path.with_file_name("projection.pfkey")
    {
        return Err(UpdateError::InvalidSetupPaths);
    }
    cache_store::ensure_initial_absent(snapshot_path)?;
    let key = match keywrap::initialize(
        keywrap_path,
        local_passphrase,
        snapshot.server_identity(),
        snapshot.account_id(),
    ) {
        Ok(key) => key,
        Err(KeywrapError::AlreadyExists) => keywrap::unlock(
            keywrap_path,
            local_passphrase,
            snapshot.server_identity(),
            snapshot.account_id(),
        )?,
        Err(error) => return Err(error.into()),
    };
    cache_store::publish_initial(snapshot_path, &key, snapshot)?;
    Ok(snapshot.items().len())
}

/// The explicitly supplied account and local cache identity for one update.
/// Group the details so authentication and publication use the same source.
#[cfg(test)]
pub struct UpdateRequest<'a, D: LoginDecryptor> {
    pub endpoint: &'a ServerEndpoint,
    pub expected_account: &'a str,
    pub timestamp: u64,
    pub decoder: &'a D,
    pub key: &'a CacheKey,
    pub path: &'a Path,
}

/// The single networked update entrypoint. Ordinary launch/search/copy must
/// never call it. Refresh tokens are touched only if the in-memory bearer
/// has expired; the resulting encrypted snapshot is entirely local.
///
/// This entrypoint is not called until real-server integration is proven.
#[cfg(test)]
pub fn refresh_explicit<D: LoginDecryptor>(
    transport: &ReadOnlySyncTransport,
    session: &mut RemoteSession,
    request: UpdateRequest<'_, D>,
) -> Result<usize, UpdateError> {
    // Guard even an unexpired bearer token against cross-server replay.
    session.ensure_endpoint(request.endpoint)?;
    if session.bearer_token().is_none() {
        transport.refresh_session(request.endpoint, session)?;
    }
    let bearer = session.bearer_token().ok_or(AuthError::InvalidResponse)?;
    let payload = transport.fetch_sync(request.endpoint, bearer, request.expected_account)?;
    commit_full_sync(
        &payload,
        request.endpoint,
        request.expected_account,
        request.timestamp,
        request.decoder,
        request.key,
        request.path,
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
    fn initial_install_is_create_only_and_keeps_legacy_ciphertext_untouched() {
        let dir = PrivateTestDir::new();
        let legacy = dir.0.join("vault.passvault");
        fs::write(&legacy, b"fictional legacy ciphertext unchanged").unwrap();
        let initial = ProjectionSnapshot::new(
            endpoint().server_identity().to_owned(),
            "test-account".to_owned(),
            100,
            vec![],
        )
        .unwrap();
        let keywrap_path = dir.0.join("projection.pfkey");
        assert!(matches!(
            install_initial_projection(
                &initial,
                &dir.cache(),
                &dir.0.join("foreign.pfkey"),
                b"fictional independent local passphrase",
            ),
            Err(UpdateError::InvalidSetupPaths)
        ));
        assert!(!keywrap_path.exists());
        assert_eq!(
            install_initial_projection(
                &initial,
                &dir.cache(),
                &keywrap_path,
                b"fictional independent local passphrase",
            )
            .unwrap(),
            0
        );
        let first_snapshot = fs::read(dir.cache()).unwrap();
        let first_keywrap = fs::read(&keywrap_path).unwrap();
        assert!(matches!(
            install_initial_projection(
                &initial,
                &dir.cache(),
                &keywrap_path,
                b"fictional independent local passphrase",
            ),
            Err(UpdateError::Cache(CacheError::AlreadyExists))
        ));
        assert_eq!(fs::read(dir.cache()).unwrap(), first_snapshot);
        assert_eq!(fs::read(&keywrap_path).unwrap(), first_keywrap);
        assert_eq!(
            fs::read(legacy).unwrap(),
            b"fictional legacy ciphertext unchanged"
        );
    }

    #[test]
    fn interrupted_initial_setup_recovers_with_original_local_passphrase_only() {
        let dir = PrivateTestDir::new();
        let snapshot = ProjectionSnapshot::new(
            endpoint().server_identity().to_owned(),
            "test-account".to_owned(),
            200,
            vec![],
        )
        .unwrap();
        let wrapped = dir.0.join("projection.pfkey");
        let passphrase = b"fictional independent local passphrase";
        let initial_key = keywrap::initialize(
            &wrapped,
            passphrase,
            snapshot.server_identity(),
            snapshot.account_id(),
        )
        .unwrap();
        drop(initial_key);
        assert!(!dir.cache().exists());
        let old_keywrap = fs::read(&wrapped).unwrap();
        assert!(matches!(
            install_initial_projection(&snapshot, &dir.cache(), &wrapped, b"incorrect passphrase"),
            Err(UpdateError::Keywrap(KeywrapError::AuthenticationFailed))
        ));
        assert_eq!(fs::read(&wrapped).unwrap(), old_keywrap);
        assert!(!dir.cache().exists());
        assert_eq!(
            install_initial_projection(&snapshot, &dir.cache(), &wrapped, passphrase).unwrap(),
            0
        );
        let recovered = keywrap::unlock(
            &wrapped,
            passphrase,
            snapshot.server_identity(),
            snapshot.account_id(),
        )
        .unwrap();
        let reopened = cache_store::load(
            &dir.cache(),
            &recovered,
            snapshot.server_identity(),
            snapshot.account_id(),
        )
        .unwrap();
        assert_eq!(reopened.last_success_at(), 200);
        assert_eq!(fs::read(&wrapped).unwrap(), old_keywrap);
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
