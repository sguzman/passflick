use std::io;

/// Reduce accidental memory disclosure from a crash or postmortem inspection.
/// This needs to run before reading any vault data or prompting for a key.
pub fn protect_process() -> io::Result<()> {
    // SAFETY: the rlimit pointer points to a valid initialized libc struct.
    // Reducing our own core-file resource limits is permitted without privilege.
    let limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limits) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: PR_SET_DUMPABLE accepts an integer flag, with 0 disabling
    // memory core dumps and PTRACE_ATTACH to the current process.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
