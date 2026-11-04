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

struct PickerChild(Child);

impl Drop for PickerChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn launch(
    binary: &Path,
    data: &Path,
    legacy: &Path,
    clipboard: &Path,
    bin: &Path,
) -> PickerChild {
    let mut path = OsString::from(bin.as_os_str());
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    let child = Command::new(binary)
        .args(["projection", "picker"])
        .env("XDG_DATA_HOME", data)
        .env("PASSFLICK_VAULT", legacy)
        .env("PASSFLICK_TEST_CLIPBOARD", clipboard)
        .env("WINIT_UNIX_BACKEND", "x11")
        .env("LIBGL_ALWAYS_SOFTWARE", "1")
        .env("PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("fictional projection picker could not launch");
    PickerChild(child)
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
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "fictional projection picker exited before its window opened"
        );
        thread::sleep(Duration::from_millis(100));
    }
    panic!("fictional projection picker never displayed a window");
}

fn await_exit(child: &mut PickerChild) {
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if let Some(exit) = child.0.try_wait().unwrap() {
            assert!(exit.success(), "fictional projection picker exited unsuccessfully");
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
) {
    assert!(std::env::var_os("DISPLAY").is_some(), "Xvfb DISPLAY required");
    assert!(binary.is_absolute());
    let dir = data.join("gui-acceptance");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, Permissions::from_mode(0o700)).unwrap();
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
        xdo(&["type", "--clearmodifiers", "--delay", "20", "Synthetic Vaultwarden"]);
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
}
