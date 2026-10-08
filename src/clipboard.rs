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
}

/// Preserve every byte of a password, including intentional trailing newlines.
/// OTPick can safely trim a generated TOTP code; Passflick cannot.
pub fn copy_sensitive(text: &str) -> Result<(), ClipboardError> {
    let mut child = Command::new("wl-copy")
        .args([
            "--type",
            "text/plain;charset=utf-8",
            "--sensitive",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(ClipboardError::Spawn)?;

    let mut stdin = child.stdin.take().ok_or(ClipboardError::MissingStdin)?;
    stdin
        .write_all(text.as_bytes())
        .map_err(ClipboardError::Write)?;
    drop(stdin);

    let status = child.wait().map_err(ClipboardError::Wait)?;
    if !status.success() {
        return Err(ClipboardError::Failed);
    }

    Ok(())
}
