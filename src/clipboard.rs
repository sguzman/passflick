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
    #[error(
        "wl-clipboard 2.3 or newer is needed for sensitive password copying; upgrade wl-clipboard"
    )]
    SensitiveUnsupported,
}

/// Preserve every byte of a password, including intentional trailing newlines.
/// OTPick can safely trim a generated TOTP code; Passflick cannot.
fn wl_copy_command() -> Command {
    let mut command = Command::new("wl-copy");
    command.args(["--type", "text/plain;charset=utf-8", "--sensitive"]);
    command
}

fn has_sensitive_flag(output: &[u8]) -> bool {
    output
        .windows(b"--sensitive".len())
        .any(|window| window == b"--sensitive")
}

pub fn copy_sensitive(text: &str) -> Result<(), ClipboardError> {
    let mut child = wl_copy_command()
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
        // Fail closed rather than silently using the ordinary clipboard.
        // wl-clipboard <2.3 does not understand --sensitive; dropping the
        // flag without an explicit decision risks persistent secret history.
        if let Ok(help) = Command::new("wl-copy")
            .arg("--help")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
        {
            let supports_hint =
                has_sensitive_flag(&help.stdout) || has_sensitive_flag(&help.stderr);
            if !supports_hint {
                return Err(ClipboardError::SensitiveUnsupported);
            }
        }
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
            b"wl-copy --type --sensitive --paste-once"
        ));
    }

    #[test]
    fn clipboard_command_never_trims_password_newlines() {
        let command = wl_copy_command();
        let args: Vec<_> = command.get_args().collect();
        assert!(!args.contains(&std::ffi::OsStr::new("--trim-newline")));
        assert!(args.contains(&std::ffi::OsStr::new("--sensitive")));
    }
}
