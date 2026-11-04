//! Isolated kernel session-key cache for the new encrypted projection.
//! Key labels cannot collide with the historical vault session/desktop keys.
//! A manual lock marker always outranks a cached key, and every cached key
//! must authenticate the complete local ciphertext before returning records.
//! No HTTP request or remote session credential is involved.
//! This module remains test-only until target-host and CLI/GUI acceptance.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;

use linux_keyutils::{KeyError, KeyPermissionsBuilder, KeyRing, KeyRingIdentifier, Permission};
use zeroize::Zeroizing;

use super::cache_store::{self, CacheError, CacheKey};
use super::keywrap::{self, KeywrapError};
use crate::projection::ProjectionSnapshot;

const KEY_NAMESPACE: &str = "passflick:projection-session-key:v1";
const LOCK_NAMESPACE: &str = "passflick:projection-manual-lock:v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AccessError {
    #[error("invalid projection identity")]
    InvalidScope,
    #[error("local projection explicitly locked")]
    Locked,
    #[error("cached local projection key is invalid")]
    InvalidCachedKey,
    #[error("session keyring operation failed")]
    Keyring,
    #[error("offline projection authentication failed")]
    Cache(#[from] CacheError),
    #[error("independent local passphrase unlock failed")]
    Keywrap(#[from] KeywrapError),
}

/// Fake store in unit tests; real kernel keyctl implementation on Linux.
/// Host-specific keyctl permission semantics still require target-host QA.
pub trait SessionStore {
    fn read(&self, label: &str) -> Result<Option<Zeroizing<Vec<u8>>>, AccessError>;
    fn exists(&self, label: &str) -> Result<bool, AccessError>;
    fn put(&self, label: &str, contents: &[u8]) -> Result<(), AccessError>;
    fn remove(&self, label: &str) -> Result<(), AccessError>;
}

pub struct KernelSessionStore;

fn kernel_ring() -> Result<KeyRing, AccessError> {
    KeyRing::from_special_id(KeyRingIdentifier::Session, true).map_err(|_| AccessError::Keyring)
}

impl SessionStore for KernelSessionStore {
    fn read(&self, label: &str) -> Result<Option<Zeroizing<Vec<u8>>>, AccessError> {
        let ring = kernel_ring()?;
        let key = match ring.search(label) {
            Ok(key) => key,
            Err(KeyError::KeyDoesNotExist | KeyError::MissingFileOrDirectory) => return Ok(None),
            Err(_) => return Err(AccessError::Keyring),
        };
        Ok(Some(Zeroizing::new(
            key.read_to_vec().map_err(|_| AccessError::Keyring)?,
        )))
    }

    fn exists(&self, label: &str) -> Result<bool, AccessError> {
        let ring = kernel_ring()?;
        match ring.search(label) {
            Ok(_) => Ok(true),
            Err(KeyError::KeyDoesNotExist | KeyError::MissingFileOrDirectory) => Ok(false),
            Err(_) => Err(AccessError::Keyring),
        }
    }

    fn put(&self, label: &str, contents: &[u8]) -> Result<(), AccessError> {
        let ring = kernel_ring()?;
        let key = ring
            .add_key(label, contents)
            .map_err(|_| AccessError::Keyring)?;
        let permissions = KeyPermissionsBuilder::builder()
            .posessor(Permission::ALL)
            .build();
        key.set_perms(permissions).map_err(|_| AccessError::Keyring)
    }

    fn remove(&self, label: &str) -> Result<(), AccessError> {
        let ring = kernel_ring()?;
        let key = match ring.search(label) {
            Ok(key) => key,
            Err(KeyError::KeyDoesNotExist | KeyError::MissingFileOrDirectory) => return Ok(()),
            Err(_) => return Err(AccessError::Keyring),
        };
        key.invalidate().map_err(|_| AccessError::Keyring)
    }
}

/// Keyring labels are lookup aids only; AEAD is the authentication boundary.
/// Stable canonical parent paths disambiguate independent local projections.
pub struct ProjectionScope {
    key: String,
    lock: String,
}

impl ProjectionScope {
    pub fn new(path: &Path, server: &str, account: &str) -> Result<Self, AccessError> {
        if path.file_name() != Some(std::ffi::OsStr::new("projection.pfsnapshot"))
            || !server.starts_with("https://")
            || server.len() > 16 * 1024
            || server.trim() != server
            || server.chars().any(char::is_control)
            || account.is_empty()
            || account.len() > 256
            || account.trim() != account
            || account.chars().any(char::is_control)
        {
            return Err(AccessError::InvalidScope);
        }
        let mut hasher = DefaultHasher::new();
        crate::paths::vault_identity_path(path).hash(&mut hasher);
        server.hash(&mut hasher);
        account.hash(&mut hasher);
        let identity = hasher.finish();
        Ok(Self {
            key: format!("{KEY_NAMESPACE}:{identity:016x}"),
            lock: format!("{LOCK_NAMESPACE}:{identity:016x}"),
        })
    }

    fn validate_binding(&self, path: &Path, server: &str, account: &str) -> Result<(), AccessError> {
        let expected = Self::new(path, server, account)?;
        if self.key != expected.key || self.lock != expected.lock {
            return Err(AccessError::InvalidScope);
        }
        Ok(())
    }
}

/// Install a deny marker *first*, then invalidate the cached key. A failure
/// does not claim successful lock; existing marker still denies future reads.
pub fn lock<S: SessionStore>(backend: &S, scope: &ProjectionScope) -> Result<(), AccessError> {
    backend.put(&scope.lock, b"1")?;
    backend.remove(&scope.key)
}

/// Read an already unlocked local projection without contacting Vaultwarden.
pub fn cached_read<S: SessionStore>(
    backend: &S,
    scope: &ProjectionScope,
    snapshot_path: &Path,
    server: &str,
    account: &str,
) -> Result<Option<ProjectionSnapshot>, AccessError> {
    scope.validate_binding(snapshot_path, server, account)?;
    if backend.exists(&scope.lock)? {
        return Err(AccessError::Locked);
    }
    let Some(raw) = backend.read(&scope.key)? else {
        return Ok(None);
    };
    let key = CacheKey::from_slice(&raw).map_err(|_| AccessError::InvalidCachedKey)?;
    let snapshot = cache_store::load(snapshot_path, &key, server, account)?;
    // Guard against a concurrent manual-lock operation during decryption.
    if backend.exists(&scope.lock)? {
        return Err(AccessError::Locked);
    }
    Ok(Some(snapshot))
}

/// Explicit passphrase unlock; authenticate keywrap and the local snapshot
/// before caching any key. A failed lock-marker cleanup leaves a deny marker,
/// not a claimed unlocked session.
pub fn unlock<S: SessionStore>(
    backend: &S,
    scope: &ProjectionScope,
    keywrap_path: &Path,
    snapshot_path: &Path,
    passphrase: &[u8],
    server: &str,
    account: &str,
) -> Result<ProjectionSnapshot, AccessError> {
    scope.validate_binding(snapshot_path, server, account)?;
    let key = keywrap::unlock(keywrap_path, passphrase, server, account)?;
    let snapshot = cache_store::load(snapshot_path, &key, server, account)?;
    backend.put(&scope.key, key.as_bytes())?;
    backend.remove(&scope.lock)?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection::{LoginItem, ProjectionSnapshot};
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::fs::{self, DirBuilder};
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;

    #[derive(Default)]
    struct Fake {
        entries: RefCell<HashMap<String, Zeroizing<Vec<u8>>>>,
        fail_key_remove: Cell<bool>,
        fail_lock_remove: Cell<bool>,
    }

    impl SessionStore for Fake {
        fn read(&self, label: &str) -> Result<Option<Zeroizing<Vec<u8>>>, AccessError> {
            Ok(self
                .entries
                .borrow()
                .get(label)
                .map(|v| Zeroizing::new(v.to_vec())))
        }
        fn exists(&self, label: &str) -> Result<bool, AccessError> {
            Ok(self.entries.borrow().contains_key(label))
        }
        fn put(&self, label: &str, contents: &[u8]) -> Result<(), AccessError> {
            self.entries
                .borrow_mut()
                .insert(label.to_owned(), Zeroizing::new(contents.to_vec()));
            Ok(())
        }
        fn remove(&self, label: &str) -> Result<(), AccessError> {
            if (label.starts_with(KEY_NAMESPACE) && self.fail_key_remove.get())
                || (label.starts_with(LOCK_NAMESPACE) && self.fail_lock_remove.get())
            {
                return Err(AccessError::Keyring);
            }
            self.entries.borrow_mut().remove(label);
            Ok(())
        }
    }

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            let mut bytes = [0_u8; 8];
            getrandom::fill(&mut bytes).unwrap();
            let path = std::env::temp_dir().join(format!(
                "passflick-projection-session-fixture-{:016x}",
                u64::from_le_bytes(bytes)
            ));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn snapshot(&self) -> PathBuf {
            self.0.join("projection.pfsnapshot")
        }
        fn wrapped(&self) -> PathBuf {
            self.0.join("projection.pfkey")
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const SERVER: &str = "https://vault.example.test/";
    const ACCOUNT: &str = "synthetic-account";
    const PASSPHRASE: &[u8] = b"fictional local projection passphrase";

    fn fixture() -> (Directory, ProjectionScope) {
        let dir = Directory::new();
        let scope = ProjectionScope::new(&dir.snapshot(), SERVER, ACCOUNT).unwrap();
        let key = keywrap::initialize(&dir.wrapped(), PASSPHRASE, SERVER, ACCOUNT).unwrap();
        let candidate = ProjectionSnapshot::new(
            SERVER.to_owned(),
            ACCOUNT.to_owned(),
            20,
            vec![LoginItem::new(
                "separate-server-id".to_owned(),
                "Synthetic Login".to_owned(),
                vec!["https://example.test/".to_owned()],
                "synthetic-user".to_owned(),
                "synthetic-secret".to_owned(),
                None,
            )],
        )
        .unwrap();
        cache_store::publish(&dir.snapshot(), &key, &candidate).unwrap();
        (dir, scope)
    }

    #[test]
    fn kernel_backend_compiles_without_touching_ci_host_keyrings() {
        let _store: &dyn SessionStore = &KernelSessionStore;
        let _kernel_ring_constructor: fn() -> Result<KeyRing, AccessError> = kernel_ring;
        // Runtime keyctl semantics remain a separate target-host QA gate.
    }

    #[test]
    fn session_labels_cannot_overlap_with_legacy_or_other_projection_identities() {
        let path = Path::new("/example.test/private/projection.pfsnapshot");
        let first = ProjectionScope::new(path, SERVER, ACCOUNT).unwrap();
        let other_account = ProjectionScope::new(path, SERVER, "other-account").unwrap();
        let other_server =
            ProjectionScope::new(path, "https://other.example.test/", ACCOUNT).unwrap();
        assert_ne!(first.key, other_account.key);
        assert_ne!(first.key, other_server.key);
        assert_ne!(first.key, first.lock);
        assert!(first.key.starts_with(KEY_NAMESPACE));
        assert!(first.lock.starts_with(LOCK_NAMESPACE));
        assert!(!first.key.contains("vault-key:v2"));
        assert!(ProjectionScope::new(Path::new("/tmp/vault.passvault"), SERVER, ACCOUNT).is_err());
    }

    #[test]
    fn offline_unlock_cache_manual_lock_and_explicit_reunlock() {
        let (dir, scope) = fixture();
        let backend = Fake::default();
        assert!(
            cached_read(&backend, &scope, &dir.snapshot(), SERVER, ACCOUNT)
                .unwrap()
                .is_none()
        );
        let value = unlock(
            &backend,
            &scope,
            &dir.wrapped(),
            &dir.snapshot(),
            PASSPHRASE,
            SERVER,
            ACCOUNT,
        )
        .unwrap();
        assert_eq!(value.items()[0].password(), "synthetic-secret");
        let cached = cached_read(&backend, &scope, &dir.snapshot(), SERVER, ACCOUNT)
            .unwrap()
            .unwrap();
        assert_eq!(cached.items()[0].id(), "separate-server-id");
        lock(&backend, &scope).unwrap();
        assert!(matches!(
            cached_read(&backend, &scope, &dir.snapshot(), SERVER, ACCOUNT),
            Err(AccessError::Locked)
        ));
        assert!(!backend.entries.borrow().contains_key(&scope.key));
        let value = unlock(
            &backend,
            &scope,
            &dir.wrapped(),
            &dir.snapshot(),
            PASSPHRASE,
            SERVER,
            ACCOUNT,
        )
        .unwrap();
        assert_eq!(value.items()[0].username(), "synthetic-user");
        assert!(
            cached_read(&backend, &scope, &dir.snapshot(), SERVER, ACCOUNT)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn cached_and_explicit_access_reject_mismatched_scope_before_keyring_or_keywrap() {
        let (dir, scope) = fixture();
        let backend = Fake::default();
        assert!(matches!(
            cached_read(
                &backend,
                &scope,
                &dir.snapshot(),
                SERVER,
                "different-account",
            ),
            Err(AccessError::InvalidScope)
        ));
        assert!(matches!(
            unlock(
                &backend,
                &scope,
                &dir.wrapped(),
                &dir.snapshot(),
                PASSPHRASE,
                "https://unrelated.example.test/",
                ACCOUNT,
            ),
            Err(AccessError::InvalidScope)
        ));
        assert!(matches!(
            cached_read(
                &backend,
                &scope,
                &dir.0.join("different/projection.pfsnapshot"),
                SERVER,
                ACCOUNT,
            ),
            Err(AccessError::InvalidScope)
        ));
        assert!(backend.entries.borrow().is_empty());
    }

    #[test]
    fn failed_passphrase_cannot_clear_manual_lock_and_bad_cached_key_fails_closed() {
        let (dir, scope) = fixture();
        let backend = Fake::default();
        lock(&backend, &scope).unwrap();
        assert!(
            unlock(
                &backend,
                &scope,
                &dir.wrapped(),
                &dir.snapshot(),
                b"incorrect fictional local passphrase",
                SERVER,
                ACCOUNT,
            )
            .is_err()
        );
        assert!(matches!(
            cached_read(&backend, &scope, &dir.snapshot(), SERVER, ACCOUNT),
            Err(AccessError::Locked)
        ));
        backend.remove(&scope.lock).unwrap();
        backend.put(&scope.key, &[7; 32]).unwrap();
        assert!(matches!(
            cached_read(&backend, &scope, &dir.snapshot(), SERVER, ACCOUNT),
            Err(AccessError::Cache(CacheError::AuthenticationFailed))
        ));
    }

    #[test]
    fn failed_key_invalidation_leaves_manual_deny_marker_active() {
        let (dir, scope) = fixture();
        let backend = Fake::default();
        unlock(
            &backend,
            &scope,
            &dir.wrapped(),
            &dir.snapshot(),
            PASSPHRASE,
            SERVER,
            ACCOUNT,
        )
        .unwrap();
        backend.fail_key_remove.set(true);
        assert_eq!(lock(&backend, &scope), Err(AccessError::Keyring));
        assert!(backend.entries.borrow().contains_key(&scope.lock));
        assert!(backend.entries.borrow().contains_key(&scope.key));
        assert!(matches!(
            cached_read(&backend, &scope, &dir.snapshot(), SERVER, ACCOUNT),
            Err(AccessError::Locked)
        ));
    }

    #[test]
    fn failed_manual_lock_clear_does_not_claim_unlocked_session() {
        let (dir, scope) = fixture();
        let backend = Fake::default();
        lock(&backend, &scope).unwrap();
        backend.fail_lock_remove.set(true);
        assert_eq!(
            unlock(
                &backend,
                &scope,
                &dir.wrapped(),
                &dir.snapshot(),
                PASSPHRASE,
                SERVER,
                ACCOUNT,
            )
            .err(),
            Some(AccessError::Keyring)
        );
        assert!(matches!(
            cached_read(&backend, &scope, &dir.snapshot(), SERVER, ACCOUNT),
            Err(AccessError::Locked)
        ));
    }
}
