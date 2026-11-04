//! Strict, non-secret scope locator for opt-in offline projection commands.
//! The actual authority is the independently passphrase-wrapped key and
//! authenticated snapshot, never this 0600 hint. No credential is stored here.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::projection::ProjectionSnapshot;
use crate::vault::owned_by_current_user;

const FILE_NAME: &str = "projection.pfidentity";
const MAGIC: &[u8; 8] = b"PFID0001";
const HEADER: usize = 12;
const MAX_SERVER: usize = 16 * 1024;
const MAX_ACCOUNT: usize = 256;
const MAX_BYTES: usize = HEADER + MAX_SERVER + MAX_ACCOUNT;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("encrypted projection identity metadata is missing")]
    Missing,
    #[error("projection identity metadata is inaccessible or unsafe")]
    Unsafe,
    #[error("invalid projection identity metadata")]
    Invalid,
    #[error("projection identity differs from authenticated server account")]
    Mismatch,
    #[error("could not write projection identity metadata")]
    Io,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    server: String,
    account: String,
}

impl Identity {
    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    fn from_snapshot(snapshot: &ProjectionSnapshot) -> Self {
        Self {
            server: snapshot.server_identity().to_owned(),
            account: snapshot.account_id().to_owned(),
        }
    }

    fn valid(&self) -> bool {
        self.server.len() <= MAX_SERVER
            && super::transport::ServerEndpoint::parse(&self.server)
                .is_ok_and(|endpoint| endpoint.server_identity() == self.server)
            && !self.account.is_empty()
            && self.account.len() <= MAX_ACCOUNT
            && self.account.trim() == self.account
            && !self.account.chars().any(char::is_control)
    }
}

fn check_path(path: &Path) -> Result<(), IdentityError> {
    if path.file_name() != Some(OsStr::new(FILE_NAME)) {
        return Err(IdentityError::Unsafe);
    }
    let parent = path.parent().ok_or(IdentityError::Unsafe)?;
    let meta = fs::symlink_metadata(parent).map_err(|_| IdentityError::Unsafe)?;
    if !meta.is_dir()
        || !owned_by_current_user(&meta)
        || meta.permissions().mode() & 0o077 != 0
    {
        return Err(IdentityError::Unsafe);
    }
    Ok(())
}

fn encode(identity: &Identity) -> Result<Vec<u8>, IdentityError> {
    if !identity.valid() {
        return Err(IdentityError::Invalid);
    }
    let mut result = Vec::with_capacity(HEADER + identity.server.len() + identity.account.len());
    result.extend_from_slice(MAGIC);
    result.extend_from_slice(&(identity.server.len() as u16).to_le_bytes());
    result.extend_from_slice(&(identity.account.len() as u16).to_le_bytes());
    result.extend_from_slice(identity.server.as_bytes());
    result.extend_from_slice(identity.account.as_bytes());
    Ok(result)
}

fn decode(raw: &[u8]) -> Result<Identity, IdentityError> {
    if raw.len() < HEADER || raw.len() > MAX_BYTES || &raw[..8] != MAGIC {
        return Err(IdentityError::Invalid);
    }
    let server_len = u16::from_le_bytes([raw[8], raw[9]]) as usize;
    let account_len = u16::from_le_bytes([raw[10], raw[11]]) as usize;
    if server_len == 0
        || server_len > MAX_SERVER
        || account_len == 0
        || account_len > MAX_ACCOUNT
        || raw.len() != HEADER + server_len + account_len
    {
        return Err(IdentityError::Invalid);
    }
    let server = std::str::from_utf8(&raw[HEADER..HEADER + server_len])
        .map_err(|_| IdentityError::Invalid)?
        .to_owned();
    let account = std::str::from_utf8(&raw[HEADER + server_len..])
        .map_err(|_| IdentityError::Invalid)?
        .to_owned();
    let identity = Identity { server, account };
    if !identity.valid() {
        return Err(IdentityError::Invalid);
    }
    Ok(identity)
}

/// Read exactly one private regular file. A symlink, hard link, oversized,
/// malformed, or user-inaccessible identity always fails closed.
pub fn read(path: &Path) -> Result<Identity, IdentityError> {
    check_path(path)?;
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                IdentityError::Missing
            } else {
                IdentityError::Unsafe
            }
        })?;
    let meta = handle.metadata().map_err(|_| IdentityError::Unsafe)?;
    if !meta.is_file()
        || !owned_by_current_user(&meta)
        || meta.permissions().mode() & 0o777 != 0o600
        || meta.nlink() != 1
        || meta.len() < HEADER as u64
        || meta.len() > MAX_BYTES as u64
    {
        return Err(IdentityError::Unsafe);
    }
    let mut raw = Vec::with_capacity(meta.len() as usize);
    handle
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| IdentityError::Unsafe)?;
    decode(&raw)
}

/// Never replace a mismatched or corrupt scope. In first-install and older
/// preview installations this creates the hint *after* an authenticated
/// encrypted snapshot was published. On collision it must match exactly.
pub fn ensure(path: &Path, snapshot: &ProjectionSnapshot) -> Result<(), IdentityError> {
    check_path(path)?;
    let expected = Identity::from_snapshot(snapshot);
    let encoded = encode(&expected)?;
    match read(path) {
        Ok(actual) if actual == expected => return Ok(()),
        Ok(_) => return Err(IdentityError::Mismatch),
        Err(IdentityError::Missing) => {}
        Err(error) => return Err(error),
    }
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return if read(path)? == expected {
                Ok(())
            } else {
                Err(IdentityError::Mismatch)
            };
        }
        Err(_) => return Err(IdentityError::Io),
    };
    file.write_all(&encoded).map_err(|_| IdentityError::Io)?;
    file.sync_all().map_err(|_| IdentityError::Io)?;
    fs::File::open(path.parent().ok_or(IdentityError::Unsafe)?)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| IdentityError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection::{LoginItem, ProjectionSnapshot};
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let mut bytes = [0_u8; 8];
            getrandom::fill(&mut bytes).unwrap();
            let path = std::env::temp_dir().join(format!(
                "passflick-identity-{:016x}",
                u64::from_le_bytes(bytes)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> PathBuf {
            self.0.join(FILE_NAME)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn snapshot(account: &str) -> ProjectionSnapshot {
        ProjectionSnapshot::new(
            "https://vault.example.test/".to_owned(),
            account.to_owned(),
            100,
            vec![LoginItem::new(
                "remote-id".to_owned(),
                "Example".to_owned(),
                vec![],
                "example-user".to_owned(),
                "fictional secret".to_owned(),
                None,
            )],
        )
        .unwrap()
    }

    #[test]
    fn identity_is_private_create_only_and_bound_to_server_account() {
        let dir = Fixture::new();
        let path = dir.path();
        assert_eq!(read(&path), Err(IdentityError::Missing));
        ensure(&path, &snapshot("account-one")).unwrap();
        assert_eq!(
            read(&path).unwrap(),
            Identity {
                server: "https://vault.example.test/".to_owned(),
                account: "account-one".to_owned()
            }
        );
        let before = fs::read(&path).unwrap();
        ensure(&path, &snapshot("account-one")).unwrap();
        assert_eq!(
            ensure(&path, &snapshot("account-two")),
            Err(IdentityError::Mismatch)
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn unsafe_and_malformed_scope_metadata_never_changes() {
        let dir = Fixture::new();
        let path = dir.path();
        fs::write(&path, b"broken").unwrap();
        let original = fs::read(&path).unwrap();
        assert_eq!(ensure(&path, &snapshot("same")), Err(IdentityError::Unsafe));
        assert_eq!(fs::read(&path).unwrap(), original);
        fs::remove_file(&path).unwrap();
        ensure(&path, &snapshot("same")).unwrap();
        let duplicate = dir.0.join("other-link");
        fs::hard_link(&path, &duplicate).unwrap();
        assert_eq!(read(&path), Err(IdentityError::Unsafe));
        fs::remove_file(&duplicate).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read(&path), Err(IdentityError::Unsafe));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let contents = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        let target = dir.0.join("target");
        fs::write(&target, &contents).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(read(&path).is_err());
        assert!(ensure(&path, &snapshot("same")).is_err());
    }

    #[test]
    fn rejected_identity_formats_are_not_accepted() {
        let dir = Fixture::new();
        let path = dir.path();
        let base = encode(&Identity::from_snapshot(&snapshot("account"))).unwrap();
        for malformed in [
            Vec::new(),
            b"garbage".to_vec(),
            base[..base.len() - 1].to_vec(),
            [&base[..], b"x"].concat(),
        ] {
            fs::write(&path, &malformed).unwrap();
            assert!(read(&path).is_err());
        }
    }
}
