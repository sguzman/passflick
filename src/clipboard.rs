use std::ffi::OsStr;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum ClipboardError {
    #[error("could not start wl-copy; install wl-clipboard")]
    Spawn(#[source] io::Error),
    #[error("wl-copy stdin was unavailable")]
    MissingStdin,
    #[error("could not write the value to wl-copy")]
    Write(#[source] io::Error),
    #[error("could not wait for wl-copy")]
    Wait(#[source] io::Error),
    #[error("wl-copy exited unsuccessfully")]
    Failed,
    #[error("wl-copy did not respond within the clipboard operation deadline")]
    TimedOut,
    #[error("value contains a NUL byte; refusing unsafe clipboard copy")]
    NulByte,
    #[error(
        "wl-clipboard 2.3 or newer is needed for sensitive password copying; upgrade wl-clipboard"
    )]
    SensitiveUnsupported,
}

/// Preserve every byte of a password, including intentional trailing newlines.
/// OTPick can safely trim a generated TOTP code; Passflick cannot.
fn wl_copy_command(executable: &OsStr) -> Command {
    let mut command = Command::new(executable);
    command.args(["--type", "text/plain;charset=utf-8", "--sensitive"]);
    command
}

fn has_sensitive_flag(output: &[u8]) -> bool {
    // Actual wl-copy help lists this long, no-argument option at the start
    // of its indented help line. A prose mention or similarly named option
    // is not enough to authorize transmitting credential bytes.
    output
        .split(|byte| matches!(byte, b'\n' | b'\r'))
        .any(|line| {
            line.trim_ascii_start()
                .strip_prefix(b"--sensitive")
                .is_some_and(|tail| tail.is_empty() || tail[0].is_ascii_whitespace())
        })
}

/// Reap helpers that do not exit. In particular, a frozen Wayland session
/// must not trap the one-shot picker forever in child.wait(). A timeout
/// terminates only our direct helper process, then reaps it.
fn wait_bounded(child: &mut Child, deadline: Duration) -> Result<ExitStatus, ClipboardError> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if started.elapsed() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(None) => {
                let _ = child.kill();
                child.wait().map_err(ClipboardError::Wait)?;
                return Err(ClipboardError::TimedOut);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ClipboardError::Wait(error));
            }
        }
    }
}

/// Do not allow a helper that stops reading stdin to freeze the picker.
/// Making our *write end* nonblocking means an oversized password value
/// cannot trap write_all() before we reach the process-exit timeout.
fn write_with_deadline(
    stdin: &mut ChildStdin,
    bytes: &[u8],
    started: Instant,
    deadline: Duration,
) -> Result<(), ClipboardError> {
    let fd = stdin.as_raw_fd();
    // SAFETY: fcntl receives the valid, borrowed ChildStdin file descriptor.
    // F_GETFL and F_SETFL change only its file-status flags, not ownership.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(ClipboardError::Write(io::Error::last_os_error()));
    }
    // SAFETY: The file descriptor is still owned by stdin in this scope.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(ClipboardError::Write(io::Error::last_os_error()));
    }

    let mut remaining = bytes;
    while !remaining.is_empty() {
        if started.elapsed() >= deadline {
            return Err(ClipboardError::TimedOut);
        }
        match stdin.write(remaining) {
            Ok(0) => {
                return Err(ClipboardError::Write(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "clipboard helper stopped accepting input",
                )));
            }
            Ok(length) => remaining = &remaining[length..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(ClipboardError::Write(error)),
        }
    }
    Ok(())
}

/// Probe the installed helper *before* passing it any credential bytes.
/// An old or incompatible wl-copy must never get a chance to place an
/// unmarked secret on the clipboard, even if it tolerates unknown options.
fn require_sensitive_support(executable: &OsStr, deadline: Duration) -> Result<(), ClipboardError> {
    let mut child = Command::new(executable)
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(ClipboardError::Spawn)?;
    let status = wait_bounded(&mut child, deadline)?;
    if !status.success() {
        return Err(ClipboardError::SensitiveUnsupported);
    }
    // Only collect help after the helper exits. A helper that hangs or floods
    // its pipe fails closed, rather than keeping an ordinary .output() open.
    let help = child.wait_with_output().map_err(ClipboardError::Wait)?;
    if !(has_sensitive_flag(&help.stdout) || has_sensitive_flag(&help.stderr)) {
        return Err(ClipboardError::SensitiveUnsupported);
    }
    Ok(())
}

pub fn copy_sensitive(text: &str) -> Result<(), ClipboardError> {
    copy_sensitive_using(text, OsStr::new("wl-copy"))
}

fn copy_sensitive_using(text: &str, executable: &OsStr) -> Result<(), ClipboardError> {
    copy_sensitive_with_limits(
        text,
        executable,
        Duration::from_secs(3),
        Duration::from_secs(7),
    )
}

fn copy_sensitive_with_limits(
    text: &str,
    executable: &OsStr,
    help_deadline: Duration,
    copy_deadline: Duration,
) -> Result<(), ClipboardError> {
    // Import validates new records, but old vaults and future adapters can
    // still reach this public boundary. Embedded NUL can be truncated by
    // clipboard consumers and silently copy a different password.
    if text.contains('\0') {
        return Err(ClipboardError::NulByte);
    }
    // Fail closed if the helper's advertised sensitive support is absent.
    require_sensitive_support(executable, help_deadline)?;
    let started = Instant::now();
    let mut child = wl_copy_command(executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(ClipboardError::Spawn)?;

    let mut stdin = child.stdin.take().ok_or(ClipboardError::MissingStdin)?;
    // A small password generally fits into one pipe write. Even if the
    // helper never reads a large value, nonblocking writes can time out.
    let write_result = write_with_deadline(
        &mut stdin,
        text.as_bytes(),
        started,
        copy_deadline,
    );
    drop(stdin);
    if matches!(write_result, Err(ClipboardError::TimedOut)) {
        let _ = child.kill();
        child.wait().map_err(ClipboardError::Wait)?;
        return Err(ClipboardError::TimedOut);
    }

    // An early child exit can cause EPIPE; reap it before diagnosing the
    // write. The remaining deadline includes time spent writing to stdin.
    let remaining = copy_deadline.saturating_sub(started.elapsed());
    let status = wait_bounded(&mut child, remaining)?;
    if !status.success() {
        if let Err(error) = write_result {
            return Err(error);
        }
        return Err(ClipboardError::Failed);
    }

    write_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_flag_detection_distinguishes_old_and_new_wl_copy() {
        assert!(!has_sensitive_flag(
            b"wl-copy --type --paste-once --trim-newline"
        ));
        assert!(has_sensitive_flag(
            b"\t --sensitive\t\tHint that the content is sensitive"
        ));
        assert!(has_sensitive_flag(b"  --sensitive\tDo not save to history"));
        assert!(!has_sensitive_flag(
            b"Warning: --sensitive is unsupported by this build"
        ));
        assert!(!has_sensitive_flag(
            b"  --sensitive-legacy   A different option"
        ));
        assert!(!has_sensitive_flag(
            b"  --not-sensitive   A different option"
        ));
    }

    #[test]
    fn nul_values_are_rejected_before_invoking_any_clipboard_helper() {
        // The absent helper would report Spawn if the content guard ran too late.
        let missing = OsStr::new("/fictional/passflick/missing-wl-copy");
        assert!(matches!(
            copy_sensitive_using("fictional\0secret", missing),
            Err(ClipboardError::NulByte)
        ));
        assert!(matches!(
            copy_sensitive_using("fictional\0username", missing),
            Err(ClipboardError::NulByte)
        ));
    }

    #[test]
    fn older_wl_copy_reports_explicit_upgrade_instead_of_a_pipe_error() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "passflick-clipboard-cli-test-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        fs::create_dir(&dir).unwrap();
        let executable = dir.join("old-wl-copy");
        // A fake unsupported wl-copy that can exit before stdin is written.
        fs::write(
            &executable,
            br#"#!/bin/sh
if [ "$1" = "--help" ]; then echo '--type --trim-newline'; exit 0; fi
printf 'unsafe invocation' > "$(dirname "$0")/unexpected-copy"
exit 2
"#,
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(matches!(
            copy_sensitive_using("fictional-clipboard-secret", executable.as_os_str()),
            Err(ClipboardError::SensitiveUnsupported)
        ));
        assert!(!dir.join("unexpected-copy").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn misleading_help_cannot_trigger_clipboard_execution() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "passflick-clipboard-help-test-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        fs::create_dir(&dir).unwrap();
        let executable = dir.join("misleading-wl-copy");
        fs::write(
            &executable,
            br#"#!/bin/sh
if [ "$1" = "--help" ]; then
    echo 'Note: --sensitive is not available'
    echo '  --sensitive-legacy    Old incompatible option'
    exit 0
fi
printf 'unsafe invocation' > "$(dirname "$0")/unexpected-copy"
exit 0
"#,
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(matches!(
            copy_sensitive_using("fictional-clipboard-secret", executable.as_os_str()),
            Err(ClipboardError::SensitiveUnsupported)
        ));
        assert!(!dir.join("unexpected-copy").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sensitive_copy_preserves_exact_synthetic_text_with_supported_helper() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "passflick-clipboard-success-test-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        fs::create_dir(&dir).unwrap();
        let executable = dir.join("new-wl-copy");
        let destination = dir.join("copied-synthetic-text");
        let script = format!(
            r#"#!/bin/sh
if [ "${{1:-}}" = "--help" ]; then echo '  --sensitive  Hint that the content is sensitive'; exit 0; fi
case " $* " in *" --sensitive "*) ;; *) exit 4 ;; esac
cat > '{}'
"#,
            destination.display()
        );
        fs::write(&executable, script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

        let synthetic = "  fictional secret with newline\n";
        copy_sensitive_using(synthetic, executable.as_os_str()).unwrap();
        assert_eq!(fs::read(destination).unwrap(), synthetic.as_bytes());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn frozen_help_preflight_times_out_without_transmitting_any_secret() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "passflick-clipboard-hung-help-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        fs::create_dir(&dir).unwrap();
        let executable = dir.join("hung-help-wl-copy");
        fs::write(
            &executable,
            br#"#!/bin/sh
if [ "$1" = "--help" ]; then exec sleep 10; fi
echo unsafe > "$(dirname "$0")/unexpected-copy"
"#,
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

        let result = copy_sensitive_with_limits(
            "fictional-only-secret",
            executable.as_os_str(),
            Duration::from_millis(120),
            Duration::from_millis(120),
        );
        assert!(matches!(result, Err(ClipboardError::TimedOut)));
        assert!(!dir.join("unexpected-copy").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn frozen_copy_process_times_out_and_is_reaped() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "passflick-clipboard-hung-copy-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        fs::create_dir(&dir).unwrap();
        let executable = dir.join("hung-copy-wl-copy");
        fs::write(
            &executable,
            br#"#!/bin/sh
if [ "$1" = "--help" ]; then
    echo '  --sensitive  Hint that the content is sensitive'
    exit 0
fi
exec sleep 10
"#,
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

        let result = copy_sensitive_with_limits(
            "fictional-only-secret",
            executable.as_os_str(),
            Duration::from_secs(1),
            Duration::from_millis(120),
        );
        assert!(matches!(result, Err(ClipboardError::TimedOut)));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn blocked_stdin_write_times_out_and_reaps_the_helper() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "passflick-clipboard-blocked-stdin-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        fs::create_dir(&dir).unwrap();
        let executable = dir.join("nonreading-wl-copy");
        fs::write(
            &executable,
            br#"#!/bin/sh
if [ "$1" = "--help" ]; then
    echo '  --sensitive  Hint that the content is sensitive'
    exit 0
fi
exec sleep 10
"#,
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

        // Larger than the Linux pipe buffer, so write_all() would have
        // blocked indefinitely in the previous implementation.
        let synthetic = "fictional-data-only".repeat(20_000);
        let result = copy_sensitive_with_limits(
            &synthetic,
            executable.as_os_str(),
            Duration::from_secs(1),
            Duration::from_millis(150),
        );
        assert!(matches!(result, Err(ClipboardError::TimedOut)));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn clipboard_command_never_trims_password_newlines() {
        let command = wl_copy_command(OsStr::new("wl-copy"));
        let args: Vec<_> = command.get_args().collect();
        assert!(!args.contains(&std::ffi::OsStr::new("--trim-newline")));
        assert!(args.contains(&std::ffi::OsStr::new("--sensitive")));
    }
}
