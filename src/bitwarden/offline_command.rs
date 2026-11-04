//! Opt-in local-only projection session lifecycle. No HTTP or Vaultwarden
//! authentication is needed. The separate historical vault remains untouched.
//! Untrusted non-secret source hints never authorize a read: the keywrap and
//! complete encrypted snapshot must authenticate the server and account.

use std::path::Path;

use super::command::{self, PreviewError};
use super::projection_identity::{self, IdentityError};
use super::session_cache::{self, AccessError, KernelSessionStore, ProjectionScope, SessionStore};
use crate::projection::ProjectionSnapshot;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OfflineError {
    #[error("projection command requires unlock, lock or status")]
    InvalidCommand,
    #[error("offline projection identity unavailable or invalid; perform a verified update first")]
    Identity,
    #[error("offline projection scope cannot be trusted")]
    Scope,
    #[error("offline projection passphrase input failed")]
    Input,
    #[error("offline projection keyring or cache authentication failed")]
    Access,
}

#[derive(Debug, PartialEq, Eq)]
enum LocalState {
    Locked,
    SessionMissing,
    Open { items: usize, timestamp: u64 },
}

impl LocalState {
    fn from_snapshot(snapshot: &ProjectionSnapshot) -> Self {
        Self::Open {
            items: snapshot.items().len(),
            timestamp: snapshot.last_success_at(),
        }
    }
}

fn scope(path: &Path) -> Result<(projection_identity::Identity, ProjectionScope), OfflineError> {
    let identity = projection_identity::read(&path.with_file_name("projection.pfidentity"))
        .map_err(|_: IdentityError| OfflineError::Identity)?;
    let scope = ProjectionScope::new(path, identity.server(), identity.account())
        .map_err(|_| OfflineError::Scope)?;
    Ok((identity, scope))
}

fn unlock_snapshot_with<S: SessionStore>(
    backend: &S,
    path: &Path,
    local_passphrase: &[u8],
) -> Result<ProjectionSnapshot, OfflineError> {
    let (identity, scope) = scope(path)?;
    session_cache::unlock(
        backend,
        &scope,
        &path.with_file_name("projection.pfkey"),
        path,
        local_passphrase,
        identity.server(),
        identity.account(),
    )
    .map_err(|_| OfflineError::Access)
}

fn unlock_with<S: SessionStore>(
    backend: &S,
    path: &Path,
    local_passphrase: &[u8],
) -> Result<LocalState, OfflineError> {
    let snapshot = unlock_snapshot_with(backend, path, local_passphrase)?;
    Ok(LocalState::from_snapshot(&snapshot))
}

/// The GUI can unlock an existing authenticated projection with the same
/// local-only kernel-keyring policy as the terminal command. No network,
/// Vaultwarden master password or legacy vault is involved.
pub(super) fn unlock_for_picker(
    local_passphrase: &[u8],
) -> Result<ProjectionSnapshot, OfflineError> {
    let path = crate::paths::projection_path().map_err(|_| OfflineError::Identity)?;
    unlock_snapshot_with(&KernelSessionStore, &path, local_passphrase)
}

fn status_with<S: SessionStore>(backend: &S, path: &Path) -> Result<LocalState, OfflineError> {
    let (identity, scope) = scope(path)?;
    match session_cache::cached_read(backend, &scope, path, identity.server(), identity.account()) {
        Ok(Some(snapshot)) => Ok(LocalState::from_snapshot(&snapshot)),
        Ok(None) => Ok(LocalState::SessionMissing),
        Err(AccessError::Locked) => Ok(LocalState::Locked),
        Err(_) => Err(OfflineError::Access),
    }
}

fn lock_with<S: SessionStore>(backend: &S, path: &Path) -> Result<(), OfflineError> {
    let (identity, scope) = scope(path)?;
    session_cache::lock(backend, &scope, path, identity.server(), identity.account())
        .map_err(|_| OfflineError::Access)
}

/// Authenticated local snapshot read for the separate opt-in graphical picker.
/// Never contacts Vaultwarden or reads the historical encrypted vault.
pub(super) fn read_for_picker() -> Result<Option<ProjectionSnapshot>, OfflineError> {
    let path = crate::paths::projection_path().map_err(|_| OfflineError::Identity)?;
    let (identity, scope) = scope(&path)?;
    session_cache::cached_read(
        &KernelSessionStore,
        &scope,
        &path,
        identity.server(),
        identity.account(),
    )
    .map_err(|_| OfflineError::Access)
}

/// A fast, non-authoritative availability check for clearing memory in a
/// running picker. Successful results never replace authenticated reads.
pub(super) fn session_present_for_picker() -> Result<bool, OfflineError> {
    let path = crate::paths::projection_path().map_err(|_| OfflineError::Identity)?;
    let (_, scope) = scope(&path)?;
    session_cache::session_present(&KernelSessionStore, &scope).map_err(|_| OfflineError::Access)
}

/// Returns only non-secret aggregate metadata. Status never decrypts a local
/// snapshot unless the session keyring already contains a valid unlocked key.
pub fn run(action: &str) -> Result<(), OfflineError> {
    if !matches!(action, "unlock" | "lock" | "status") {
        return Err(OfflineError::InvalidCommand);
    }
    let path = crate::paths::projection_path().map_err(|_| OfflineError::Identity)?;
    let store = KernelSessionStore;
    match action {
        "unlock" => {
            let passphrase = command::masked("Independent local projection passphrase: ")
                .map_err(|_: PreviewError| OfflineError::Input)?;
            let state = unlock_with(&store, &path, passphrase.as_bytes())?;
            print_state(state);
        }
        "lock" => {
            lock_with(&store, &path)?;
            println!("Offline projection manually locked.");
        }
        "status" => print_state(status_with(&store, &path)?),
        _ => unreachable!(),
    }
    Ok(())
}

fn print_state(state: LocalState) {
    match state {
        LocalState::Locked => println!("Offline projection manually locked."),
        LocalState::SessionMissing => {
            println!("Offline projection not unlocked in this Linux keyring session.");
        }
        LocalState::Open { items, timestamp } => {
            println!("Offline projection unlocked: {items} login items.");
            println!("Last successful remote sync (Unix seconds): {timestamp}");
            println!("Offline data may be stale; server revocation is not instantaneous.");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitwarden::{cache_store, keywrap, projection_identity};
    use crate::projection::{LoginItem, ProjectionSnapshot};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::fs::{self, DirBuilder};
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use zeroize::Zeroizing;

    #[derive(Default)]
    struct FakeStore(RefCell<HashMap<String, Vec<u8>>>);
    impl SessionStore for FakeStore {
        fn read(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, AccessError> {
            Ok(self.0.borrow().get(name).cloned().map(Zeroizing::new))
        }
        fn exists(&self, name: &str) -> Result<bool, AccessError> {
            Ok(self.0.borrow().contains_key(name))
        }
        fn put(&self, name: &str, bytes: &[u8]) -> Result<(), AccessError> {
            self.0.borrow_mut().insert(name.to_owned(), bytes.to_vec());
            Ok(())
        }
        fn remove(&self, name: &str) -> Result<(), AccessError> {
            self.0.borrow_mut().remove(name);
            Ok(())
        }
    }

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let mut salt = [0_u8; 8];
            getrandom::fill(&mut salt).unwrap();
            let dir = std::env::temp_dir().join(format!(
                "passflick-offline-command-{:016x}",
                u64::from_le_bytes(salt)
            ));
            DirBuilder::new().mode(0o700).create(&dir).unwrap();
            Self(dir)
        }
        fn path(&self) -> PathBuf {
            self.0.join("projection.pfsnapshot")
        }
        fn install(&self) {
            let data = snapshot();
            let key = keywrap::initialize(
                &self.0.join("projection.pfkey"),
                b"fictional separate local passphrase",
                data.server_identity(),
                data.account_id(),
            )
            .unwrap();
            cache_store::publish_initial(&self.path(), &key, &data).unwrap();
            projection_identity::ensure(&self.0.join("projection.pfidentity"), &data).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn snapshot() -> ProjectionSnapshot {
        ProjectionSnapshot::new(
            "https://vault.example.test/".to_owned(),
            "synthetic-account".to_owned(),
            1_800_000_000,
            vec![LoginItem::new(
                "vault-item-id".to_owned(),
                "Synthetic".to_owned(),
                vec!["https://example.test".to_owned()],
                "username".to_owned(),
                "fictional secret".to_owned(),
                None,
            )],
        )
        .unwrap()
    }

    #[test]
    fn lock_priority_and_explicit_unlock_are_completely_offline() {
        let fixture = Fixture::new();
        fixture.install();
        let store = FakeStore::default();
        assert_eq!(
            status_with(&store, &fixture.path()).unwrap(),
            LocalState::SessionMissing
        );
        assert_eq!(
            unlock_with(&store, &fixture.path(), b"incorrect local passphrase"),
            Err(OfflineError::Access)
        );
        assert_eq!(
            status_with(&store, &fixture.path()).unwrap(),
            LocalState::SessionMissing
        );
        assert_eq!(
            unlock_with(
                &store,
                &fixture.path(),
                b"fictional separate local passphrase"
            )
            .unwrap(),
            LocalState::Open {
                items: 1,
                timestamp: 1_800_000_000
            }
        );
        assert_eq!(
            status_with(&store, &fixture.path()).unwrap(),
            LocalState::Open {
                items: 1,
                timestamp: 1_800_000_000
            }
        );
        lock_with(&store, &fixture.path()).unwrap();
        assert_eq!(
            status_with(&store, &fixture.path()).unwrap(),
            LocalState::Locked
        );
        assert_eq!(
            unlock_with(&store, &fixture.path(), b"incorrect local passphrase"),
            Err(OfflineError::Access)
        );
        assert_eq!(
            status_with(&store, &fixture.path()).unwrap(),
            LocalState::Locked
        );
        unlock_with(
            &store,
            &fixture.path(),
            b"fictional separate local passphrase",
        )
        .unwrap();
        assert_eq!(
            status_with(&store, &fixture.path()).unwrap(),
            LocalState::Open {
                items: 1,
                timestamp: 1_800_000_000
            }
        );
    }

    #[test]
    fn missing_or_tampered_identity_does_not_unlock() {
        let fixture = Fixture::new();
        fixture.install();
        let store = FakeStore::default();
        let identity_path = fixture.0.join("projection.pfidentity");
        fs::remove_file(&identity_path).unwrap();
        assert_eq!(
            status_with(&store, &fixture.path()),
            Err(OfflineError::Identity)
        );
        assert_eq!(
            unlock_with(
                &store,
                &fixture.path(),
                b"fictional separate local passphrase"
            ),
            Err(OfflineError::Identity)
        );
        let current = snapshot();
        // Replacing the missing locator with a second authenticated account
        // must be impossible without a full successful remote update.
        let mismatched = ProjectionSnapshot::new(
            current.server_identity().to_owned(),
            "different-account".to_owned(),
            current.last_success_at(),
            vec![],
        )
        .unwrap();
        projection_identity::ensure(&identity_path, &mismatched).unwrap();
        assert_eq!(
            unlock_with(
                &store,
                &fixture.path(),
                b"fictional separate local passphrase"
            ),
            Err(OfflineError::Access)
        );
    }
}
