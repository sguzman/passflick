//! Full offline picker acceptance with entirely fictional credentials from
//! a disposable real Vaultwarden. Runs only under explicitly selected Linux
//! Xvfb CI, never in a shipped binary or against any user clipboard.
use std::ffi::OsString;
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const WINDOW: &str = "Passflick.*Offline Projection";
const TIMEOUT: Duration = Duration::from_secs(30);

struct PickerChild(Child, PathBuf);

impl Drop for PickerChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn launch(binary: &Path, data: &Path, legacy: &Path, clipboard: &Path, bin: &Path) -> PickerChild {
    let mut path = OsString::from(bin.as_os_str());
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    let diagnostics = bin.parent().unwrap().join("picker.stderr");
    let child = Command::new(binary)
        .args(["projection", "picker"])
        .env("XDG_DATA_HOME", data)
        .env("PASSFLICK_VAULT", legacy)
        .env("PASSFLICK_TEST_CLIPBOARD", clipboard)
        .env("WINIT_UNIX_BACKEND", "x11")
        .env("XDG_RUNTIME_DIR", bin.parent().unwrap().join("runtime"))
        .env("LIBGL_ALWAYS_SOFTWARE", "1")
        .env("PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(fs::File::create(&diagnostics).unwrap()))
        .spawn()
        .expect("fictional projection picker could not launch");
    PickerChild(child, diagnostics)
}

fn xdo(args: &[&str]) {
    let result = Command::new("xdotool")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("X11 test input tool was unavailable");
    assert!(result.success(), "fictional X11 input command failed");
}

fn visible_window(child: &mut PickerChild) {
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        let found = Command::new("xdotool")
            .args(["search", "--onlyvisible", "--name", WINDOW])
            .output()
            .expect("X11 window search failed");
        if found.status.success() {
            let names = String::from_utf8_lossy(&found.stdout);
            if let Some(id) = names.split_whitespace().next() {
                let owned = id.to_owned();
                thread::sleep(Duration::from_millis(300));
                xdo(&["windowfocus", "--sync", &owned]);
                return;
            }
        }
        if let Some(status) = child.0.try_wait().unwrap() {
            // Only output fixed diagnostics, never captured stderr: a future
            // error could quote the user's path or a fictional credential.
            let captured = fs::read(&child.1).unwrap_or_default();
            let lower = String::from_utf8_lossy(&captured).to_lowercase();
            panic!(
                "fictional projection picker exited before window: {status}; x11={}, xkb={}, gl={}, runtime={}, panic={}",
                lower.contains("x11") || lower.contains("display"),
                lower.contains("xkb"),
                lower.contains("glx") || lower.contains("egl") || lower.contains("opengl"),
                lower.contains("xdg_runtime_dir"),
                lower.contains("panicked")
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("fictional projection picker never displayed a window");
}

fn await_exit(child: &mut PickerChild) {
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if let Some(exit) = child.0.try_wait().unwrap() {
            assert!(
                exit.success(),
                "fictional projection picker exited unsuccessfully"
            );
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("fictional projection picker did not close after successful copy/Escape");
}

fn write_stub(dir: &Path) -> PathBuf {
    let bin = dir.join("bin");
    fs::create_dir(&bin).unwrap();
    fs::set_permissions(&bin, Permissions::from_mode(0o700)).unwrap();
    let stub = bin.join("wl-copy");
    // The helper only observes fictional test credentials; never print its
    // captured bytes to CI logs, and reject omission of --sensitive.
    fs::write(
        &stub,
        "#!/usr/bin/env bash\nset -euo pipefail\nif [[ \"${1:-}\" == \"--help\" ]]; then\n  echo '  --sensitive  Hint that clipboard content is sensitive'\n  exit 0\nfi\ncase \" $* \" in *' --sensitive '*) ;; *) exit 91 ;; esac\ncase \" $* \" in *' --trim-newline '*) exit 92 ;; esac\ncat > \"${PASSFLICK_TEST_CLIPBOARD}\"\n",
    )
    .unwrap();
    fs::set_permissions(&stub, Permissions::from_mode(0o700)).unwrap();
    bin
}

/// Exercises a populated snapshot through separate GUI processes and the
/// original sensitive Wayland copy adapter's CLI contract (stubbed on X11).
/// The private GUI reads local encrypted data, not network data.
pub(super) fn run(
    binary: &Path,
    data: &Path,
    legacy: &Path,
    first_id: &str,
    second_id: &str,
    local_passphrase: &str,
    refresh_selected: impl FnOnce(),
) {
    assert!(
        std::env::var_os("DISPLAY").is_some(),
        "Xvfb DISPLAY required"
    );
    assert!(binary.is_absolute());
    let dir = data.join("gui-acceptance");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, Permissions::from_mode(0o700)).unwrap();
    let runtime = dir.join("runtime");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, Permissions::from_mode(0o700)).unwrap();
    xdo(&["getdisplaygeometry"]);
    let bin = write_stub(&dir);
    let clipboard = dir.join("fictional-clipboard");

    // Shift+Enter preserves the actual Unicode username, not a rendered or
    // normalized label, and exits after the sensitive clipboard helper runs.
    {
        let mut child = launch(binary, data, legacy, &clipboard, &bin);
        visible_window(&mut child);
        xdo(&["key", "--clearmodifiers", "shift+Return"]);
        await_exit(&mut child);
    }
    assert_eq!(fs::read(&clipboard).unwrap(), "mañana用户".as_bytes());
    fs::remove_file(&clipboard).unwrap();

    // Both entries have identical title/username but different upstream IDs.
    // Their initial stable order is keyed by remote ID, not browser provider,
    // sync iteration order or password contents. Verify exact Unicode and
    // whitespace-preserving clipboard bytes on the first selected row.
    {
        let mut child = launch(binary, data, legacy, &clipboard, &bin);
        visible_window(&mut child);
        xdo(&[
            "type",
            "--clearmodifiers",
            "--delay",
            "20",
            "Synthetic Vaultwarden",
        ]);
        xdo(&["key", "--clearmodifiers", "Return"]);
        await_exit(&mut child);
    }
    let expected = if first_id < second_id {
        "  🗝️ contraseña  ".as_bytes()
    } else {
        "second secret".as_bytes()
    };
    assert_eq!(fs::read(&clipboard).unwrap(), expected);
    fs::remove_file(&clipboard).unwrap();

    // A successful remote update may replace the password under the same
    // upstream ID while this GUI still displays the old record. Such a GUI
    // must NOT copy the new, unseen value: the user must reopen first.
    {
        let mut child = launch(binary, data, legacy, &clipboard, &bin);
        visible_window(&mut child);
        refresh_selected();
        // Refocus after the separate CLI update process to guarantee this
        // Return key is received by the pre-refresh GUI instance.
        visible_window(&mut child);
        xdo(&["key", "--clearmodifiers", "Return"]);
        thread::sleep(Duration::from_millis(300));
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "stale picker unexpectedly closed after changed-record copy"
        );
        assert!(
            !clipboard.exists(),
            "stale picker copied a changed credential without reopening"
        );
        xdo(&["key", "--clearmodifiers", "Escape"]);
        await_exit(&mut child);
    }

    // An already-open picker cannot copy after another real process commits
    // a manual lock. No GUI copy may create a new keyring entry to bypass it.
    {
        let mut child = launch(binary, data, legacy, &clipboard, &bin);
        visible_window(&mut child);
        super::terminal_acceptance::run_projection_cli(
            binary,
            data,
            legacy,
            "lock",
            &[],
            true,
            "Offline projection manually locked.",
        );
        thread::sleep(Duration::from_millis(1000));
        xdo(&["key", "--clearmodifiers", "Return"]);
        thread::sleep(Duration::from_millis(300));
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "manual lock should keep the non-copying picker open"
        );
        assert!(
            !clipboard.exists(),
            "a manually locked picker transmitted a credential"
        );
        xdo(&["key", "--clearmodifiers", "Escape"]);
        await_exit(&mut child);
    }

    // The new masked GUI unlock is local-only and must not copy a password
    // on the same Enter event used to unlock. Wrong input must leave the
    // locked picker open, with no clipboard write. The correct local
    // passphrase is synthetic and is never printed to CI logs.
    {
        let mut child = launch(binary, data, legacy, &clipboard, &bin);
        visible_window(&mut child);
        xdo(&[
            "type",
            "--clearmodifiers",
            "--delay",
            "15",
            "fictional wrong offline passphrase",
        ]);
        xdo(&["key", "--clearmodifiers", "Return"]);
        thread::sleep(Duration::from_millis(350));
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "wrong local passphrase unexpectedly closed the picker"
        );
        assert!(
            !clipboard.exists(),
            "wrong local passphrase triggered a clipboard copy"
        );

        xdo(&[
            "type",
            "--clearmodifiers",
            "--delay",
            "15",
            local_passphrase,
        ]);
        xdo(&["key", "--clearmodifiers", "Return"]);
        thread::sleep(Duration::from_millis(400));
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "in-picker unlock also triggered a credential copy"
        );
        assert!(
            !clipboard.exists(),
            "Enter for GUI unlock unexpectedly wrote to clipboard"
        );

        // A second Enter intentionally copies the selected current secret.
        xdo(&["key", "--clearmodifiers", "Return"]);
        await_exit(&mut child);
    }
    assert_eq!(fs::read(&clipboard).unwrap(), b"fictional-UPDATED-password");
    fs::remove_file(&clipboard).unwrap();
}
