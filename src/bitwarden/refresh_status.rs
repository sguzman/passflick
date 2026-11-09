//! Privacy-safe status of the most recent explicit update attempt.
//! This 0600 sidecar is only a UI hint, never an authentication or cache
//! authority. No URL, account, credential, token, error text or path is stored.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::vault::owned_by_current_user;

const MAGIC: &[u8; 8] = b"PFREF001";
const SIZE: usize = 17;
const FILENAME: &str = "projection.pfrefresh";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Outcome {
    Success = 0,
    Input = 1,
    Configuration = 2,
    Authentication = 3,
    Sync = 4,
    Local = 5,
}

impl Outcome {
    pub fn failure_label(self) -> Option<&'static str> {
        match self {
            Self::Success => None,
            Self::Input => Some("input cancelled or unavailable"),
            Self::Configuration => Some("server configuration rejected"),
            Self::Authentication => Some("remote authentication or MFA failed"),
            Self::Sync => Some("transport, sync or decryption failed"),
            Self::Local => Some("local authentication or publication failed"),
        }
    }

    fn from_byte(value: u8) -> Result<Self, ReportError> {
        match value {
            0 => Ok(Self::Success),
            1 => Ok(Self::Input),
            2 => Ok(Self::Configuration),
            3 => Ok(Self::Authentication),
            4 => Ok(Self::Sync),
            5 => Ok(Self::Local),
            _ => Err(ReportError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub at: u64,
    pub outcome: Outcome,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReportError {
    #[error("unsafe or inaccessible refresh-status path")]
    Unsafe,
    #[error("invalid refresh-status record")]
    Invalid,
    #[error("refresh-status filesystem operation failed")]
    Io,
}

fn private_parent(snapshot: &Path) -> Result<&Path, ReportError> {
    if snapshot.file_name() != Some(std::ffi::OsStr::new("projection.pfsnapshot")) {
        return Err(ReportError::Unsafe);
    }
    let parent = snapshot.parent().ok_or(ReportError::Unsafe)?;
    let meta = fs::symlink_metadata(parent).map_err(|_| ReportError::Unsafe)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 || !owned_by_current_user(&meta) {
        return Err(ReportError::Unsafe);
    }
    Ok(parent)
}

fn valid_file(meta: &fs::Metadata) -> bool {
    meta.is_file()
        && owned_by_current_user(meta)
        && meta.permissions().mode() & 0o777 == 0o600
        && meta.nlink() == 1
        && meta.len() == SIZE as u64
}

pub fn read(snapshot: &Path) -> Result<Option<Report>, ReportError> {
    private_parent(snapshot)?;
    let path = snapshot.with_file_name(FILENAME);
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ReportError::Unsafe),
    };
    if !valid_file(&file.metadata().map_err(|_| ReportError::Unsafe)?) {
        return Err(ReportError::Unsafe);
    }
    let mut bytes = [0_u8; SIZE];
    file.read_exact(&mut bytes).map_err(|_| ReportError::Invalid)?;
    if &bytes[..8] != MAGIC {
        return Err(ReportError::Invalid);
    }
    let at = u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| ReportError::Invalid)?);
    if at == 0 {
        return Err(ReportError::Invalid);
    }
    Ok(Some(Report {
        at,
        outcome: Outcome::from_byte(bytes[16])?,
    }))
}

/// A single atomic, bounded metadata replacement under the same cross-process
/// lock used for encrypted projection publication. Do not modify a suspicious
/// pre-existing sidecar or ever open the historical vault.
pub fn record(snapshot: &Path, report: Report) -> Result<(), ReportError> {
    if report.at == 0 {
        return Err(ReportError::Invalid);
    }
    let parent = private_parent(snapshot)?;
    let _guard = crate::write_lock::acquire(snapshot).map_err(|_| ReportError::Unsafe)?;
    // Includes filename, owner, mode, link count and format validation.
    read(snapshot)?;
    let mut entropy = [0_u8; 8];
    getrandom::fill(&mut entropy).map_err(|_| ReportError::Io)?;
    let temporary = parent.join(format!(
        ".projection.pfrefresh-{:016x}.tmp",
        u64::from_le_bytes(entropy)
    ));
    let target = snapshot.with_file_name(FILENAME);
    let mut bytes = [0_u8; SIZE];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..16].copy_from_slice(&report.at.to_le_bytes());
    bytes[16] = report.outcome as u8;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|_| ReportError::Io)?;
    let outcome = (|| {
        file.write_all(&bytes).map_err(|_| ReportError::Io)?;
        file.sync_all().map_err(|_| ReportError::Io)?;
        fs::rename(&temporary, &target).map_err(|_| ReportError::Io)?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ReportError::Io)
    })();
    if outcome.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, symlink};
    use std::path::PathBuf;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let mut entropy = [0_u8; 8];
            getrandom::fill(&mut entropy).unwrap();
            let root = std::env::temp_dir().join(format!(
                "passflick-refresh-report-{:016x}",
                u64::from_le_bytes(entropy)
            ));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            Self(root)
        }
        fn snapshot(&self) -> PathBuf {
            self.0.join("projection.pfsnapshot")
        }
        fn report(&self) -> PathBuf {
            self.0.join(FILENAME)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn fixed_private_report_survives_restart_without_touching_encrypted_cache() {
        let fixture = Fixture::new();
        let snapshot = fixture.snapshot();
        fs::write(&snapshot, b"fictional encrypted projection bytes").unwrap();
        assert_eq!(read(&snapshot).unwrap(), None);
        for (at, outcome) in [
            (100, Outcome::Authentication),
            (101, Outcome::Sync),
            (102, Outcome::Local),
            (103, Outcome::Success),
        ] {
            let report = Report { at, outcome };
            record(&snapshot, report).unwrap();
            assert_eq!(read(&snapshot).unwrap(), Some(report));
            assert_eq!(fs::metadata(fixture.report()).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(fixture.report()).unwrap().len(), SIZE as u64);
            assert_eq!(fs::read(&snapshot).unwrap(), b"fictional encrypted projection bytes");
        }
        assert_eq!(Outcome::Success.failure_label(), None);
        assert_eq!(Outcome::Authentication.failure_label(), Some("remote authentication or MFA failed"));
    }

    #[test]
    fn unsafe_status_file_never_redirects_or_overwrites_other_files() {
        let fixture = Fixture::new();
        let snapshot = fixture.snapshot();
        let destination = fixture.0.join("fictional-foreign");
        fs::write(&destination, b"untouched").unwrap();
        symlink(&destination, fixture.report()).unwrap();
        let report = Report { at: 100, outcome: Outcome::Sync };
        assert_eq!(read(&snapshot), Err(ReportError::Unsafe));
        assert_eq!(record(&snapshot, report), Err(ReportError::Unsafe));
        assert_eq!(fs::read(&destination).unwrap(), b"untouched");
        fs::remove_file(fixture.report()).unwrap();

        fs::write(fixture.report(), b"malformed").unwrap();
        assert_eq!(read(&snapshot), Err(ReportError::Unsafe));
        assert_eq!(record(&snapshot, report), Err(ReportError::Unsafe));
        assert_eq!(fs::read(fixture.report()).unwrap(), b"malformed");
        fs::remove_file(fixture.report()).unwrap();

        record(&snapshot, report).unwrap();
        let second = fixture.0.join("hardlink");
        fs::hard_link(fixture.report(), &second).unwrap();
        assert_eq!(record(&snapshot, report), Err(ReportError::Unsafe));
        fs::remove_file(second).unwrap();
    }

    #[test]
    fn invalid_version_timestamp_and_status_are_rejected() {
        let fixture = Fixture::new();
        let snapshot = fixture.snapshot();
        assert_eq!(record(&snapshot, Report { at: 0, outcome: Outcome::Success }), Err(ReportError::Invalid));
        record(&snapshot, Report { at: 100, outcome: Outcome::Success }).unwrap();
        let mut bytes = fs::read(fixture.report()).unwrap();
        bytes[16] = 255;
        fs::write(fixture.report(), &bytes).unwrap();
        assert_eq!(read(&snapshot), Err(ReportError::Invalid));
        bytes[16] = 0;
        bytes[0] = b'X';
        fs::write(fixture.report(), &bytes).unwrap();
        assert_eq!(read(&snapshot), Err(ReportError::Invalid));
    }
}
