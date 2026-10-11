use std::ffi::OsStr;
use std::io::{self, Write};
use std::process::{Command, Stdio};

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
    // A mention of the flag somewhere in prose is not a capability claim.
    // Recognize a documented option at the start of its help line, optionally
    // preceded by the short-option form used by wl-clipboard.
    output.split(|byte| matches!(byte, b'\n' | b'\r')).any(|line| {
        let line = line.trim_ascii_start();
        let option = line
            .strip_prefix(b"-s,")
            .map(|rest| rest.trim_ascii_start())
            .unwrap_or(line);
        option.strip_prefix(b"--sensitive").is_some_and(|tail| {
            tail.is_empty()
                || tail[0].is_ascii_whitespace()
                || matches!(tail[0], b',' | b'=')
        })
    })
}

/// Probe the installed helper *before* passing it any credential bytes.
/// An old or incompatible wl-copy must never get a chance to place an
/// unmarked secret on the clipboard, even if it tolerates unknown options.
fn require_sensitive_support(executable: &OsStr) -> Result<(), ClipboardError> {
    let help = Command::new(executable)
        .arg("--help")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(ClipboardError::Spawn)?;
    if !help.status.success()
        || !(has_sensitive_flag(&help.stdout) || has_sensitive_flag(&help.stderr))
    {
        return Err(ClipboardError::SensitiveUnsupported);
    }
    Ok(())
}

pub fn copy_sensitive(text: &str) -> Result<(), ClipboardError> {
    copy_sensitive_using(text, OsStr::new("wl-copy"))
}

fn copy_sensitive_using(text: &str, executable: &OsStr) -> Result<(), ClipboardError> {
    // Import validates new records, but old vaults and future adapters can
    // still reach this public boundary. Embedded NUL can be truncated by
    // clipboard consumers and silently copy a different password.
    if text.contains('\0') {
        return Err(ClipboardError::NulByte);
    }
    // This adds one short local helper invocation per copy. Password safety
    // takes precedence over avoiding that invocation.
    require_sensitive_support(executable)?;
    let mut child = wl_copy_command(executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(ClipboardError::Spawn)?;

    let mut stdin = child.stdin.take().ok_or(ClipboardError::MissingStdin)?;
    // An old wl-copy can reject --sensitive and exit before the pipe write
    // completes, producing EPIPE instead of a useful unsupported-flag error.
    // Always reap the child before diagnosing either write or exit failures.
    let write_result = stdin.write_all(text.as_bytes());
    drop(stdin);

    let status = child.wait().map_err(ClipboardError::Wait)?;
    if !status.success() {
        // The helper advertised --sensitive during preflight, but a runtime
        // failure still must not trigger a fallback to an ordinary copy.
        if let Err(error) = write_result {
            return Err(ClipboardError::Write(error));
        }
        return Err(ClipboardError::Failed);
    }

    write_result.map_err(ClipboardError::Write)
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
            b"  -s, --sensitive   Hint that clipboard data is sensitive"
        ));
        assert!(has_sensitive_flag(
            b"  --sensitive\tDo not save to history"
        ));
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
if [ "${{1:-}}" = "--help" ]; then echo '--type --sensitive'; exit 0; fi
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
    fn clipboard_command_never_trims_password_newlines() {
        let command = wl_copy_command(OsStr::new("wl-copy"));
        let args: Vec<_> = command.get_args().collect();
        assert!(!args.contains(&std::ffi::OsStr::new("--trim-newline")));
        assert!(args.contains(&std::ffi::OsStr::new("--sensitive")));
    }
}
