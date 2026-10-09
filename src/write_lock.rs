use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::vault::owned_by_current_user;

/// Hold this guard through the entire load, replace, and encrypted save.
pub struct VaultWriteGuard {
    _lock_file: File,
}

pub fn acquire(vault_path: &Path) -> io::Result<VaultWriteGuard> {
    let parent = vault_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid vault path"))?;
    let directory = fs::symlink_metadata(parent)?;
    if !directory.is_dir()
        || directory.permissions().mode() & 0o077 != 0
        || !owned_by_current_user(&directory)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "vault directory must be private and owned by the current user",
        ));
    }

    // Keep this file across runs. Unlinking a flock lock file can cause two
    // processes to lock different inodes and silently lose source snapshots.
    let lock_path = parent.join(".passflick.write-lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        // Open nonblocking so a substituted FIFO cannot hang before the
        // regular-file check. This does not make flock nonblocking.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&lock_path)?;
    let info = file.metadata()?;
    if !info.is_file() || info.permissions().mode() & 0o077 != 0 || !owned_by_current_user(&info) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "vault lock file must be private and owned by the current user",
        ));
    }

    // SAFETY: file.as_raw_fd() is valid for the duration of this call and
    // the returned guard owns File until dropped. The OS releases flock on close.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(VaultWriteGuard { _lock_file: file })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn lock_file_symlink_cannot_redirect_writes() {
        use std::os::unix::fs::symlink;

        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "passflick-symlink-lock-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let target = dir.join("other-file");
        fs::write(&target, b"do-not-touch").unwrap();
        symlink(&target, dir.join(".passflick.write-lock")).unwrap();
        let vault = dir.join("vault.passvault");
        assert!(acquire(&vault).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"do-not-touch");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn lock_file_fifo_is_rejected_without_waiting_for_a_reader() {
        use std::os::unix::ffi::OsStrExt;

        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "passflick-fifo-lock-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let fifo = dir.join(".passflick.write-lock");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: this is a valid NUL-terminated pathname, and mkfifo does
        // not keep the pointer after returning.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(acquire(&dir.join("vault.passvault")).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn independent_file_handles_serialize_writes() {
        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "passflick-write-lock-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let vault = dir.join("vault.passvault");
        let first = acquire(&vault).unwrap();

        let (started_tx, started_rx) = mpsc::channel();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let another = vault.clone();
        let handle = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let _second = acquire(&another).unwrap();
            acquired_tx.send(()).unwrap();
        });
        started_rx.recv().unwrap();
        // While the first guard exists a second nonblocking flock must fail.
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join(".passflick.write-lock"))
            .unwrap();
        // SAFETY: fd is owned and open during this call.
        let rc = unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, -1);
        assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
        drop(first);
        acquired_rx.recv().unwrap();
        handle.join().unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }
}
