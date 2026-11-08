//! Resolve the opt-in Linux/Wayland picker's System appearance against
//! Darkman when it is active. eframe/winit does not reliably report the
//! desktop's current light/dark appearance on Linux.
//!
//! Darkman's documented local control protocol accepts `get\\n` and
//! answers `dark\\n` or `light\\n`. No shell command, D-Bus mutation,
//! external network access or host configuration is required.
//! If Darkman is absent or unreachable, defer to the toolkit preference.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use eframe::egui;

const SOCKET_TIMEOUT: Duration = Duration::from_millis(75);

fn read_darkman_socket(socket: &Path) -> Option<egui::Theme> {
    let mut stream = UnixStream::connect(socket).ok()?;
    stream.set_read_timeout(Some(SOCKET_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(SOCKET_TIMEOUT)).ok()?;
    stream.write_all(b"get\n").ok()?;
    let mut reply = [0_u8; 16];
    let length = stream.read(&mut reply).ok()?;
    match &reply[..length] {
        b"dark\n" => Some(egui::Theme::Dark),
        b"light\n" => Some(egui::Theme::Light),
        _ => None,
    }
}

/// Local user-session state only; never changes Darkman's setting.
pub(super) fn darkman_theme() -> Option<egui::Theme> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")?;
    if runtime.is_empty() {
        return None;
    }
    read_darkman_socket(&Path::new(&runtime).join("darkman/control.sock"))
}

/// Keep the preference button on System while applying the resolved theme.
/// Explicit Light and Dark never depend on Darkman or toolkit detection.
pub(super) fn effective_preference(
    choice: egui::ThemePreference,
    darkman: Option<egui::Theme>,
    toolkit: Option<egui::Theme>,
) -> egui::ThemePreference {
    if choice == egui::ThemePreference::System {
        darkman.or(toolkit).map_or(choice, Into::into)
    } else {
        choice
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::net::UnixListener;

    #[test]
    fn system_follows_darkman_before_unreliable_toolkit_signal() {
        let system = egui::ThemePreference::System;
        assert_eq!(
            effective_preference(system, Some(egui::Theme::Dark), Some(egui::Theme::Light)),
            egui::ThemePreference::Dark
        );
        assert_eq!(
            effective_preference(system, Some(egui::Theme::Light), Some(egui::Theme::Dark)),
            egui::ThemePreference::Light
        );
        assert_eq!(
            effective_preference(system, None, Some(egui::Theme::Light)),
            egui::ThemePreference::Light
        );
        assert_eq!(effective_preference(system, None, None), system);
    }

    #[test]
    fn explicit_themes_ignore_darkman() {
        for selection in [egui::ThemePreference::Light, egui::ThemePreference::Dark] {
            assert_eq!(
                effective_preference(selection, Some(egui::Theme::Dark), Some(egui::Theme::Light)),
                selection
            );
        }
    }

    #[test]
    fn socket_protocol_reads_dark_light_and_rejects_unknown_modes() {
        for (reply, expected) in [
            (&b"dark\n"[..], Some(egui::Theme::Dark)),
            (&b"light\n"[..], Some(egui::Theme::Light)),
            (&b"not-a-mode\n"[..], None),
        ] {
            let mut random = [0_u8; 8];
            getrandom::fill(&mut random).unwrap();
            let dir = std::env::temp_dir().join(format!(
                "passflick-darkman-test-{:016x}",
                u64::from_le_bytes(random)
            ));
            fs::create_dir(&dir).unwrap();
            let path = dir.join("control.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let server = std::thread::spawn(move || {
                let (mut connection, _) = listener.accept().unwrap();
                let mut command = [0_u8; 4];
                connection.read_exact(&mut command).unwrap();
                assert_eq!(&command, b"get\n");
                connection.write_all(reply).unwrap();
            });
            assert_eq!(read_darkman_socket(&path), expected);
            server.join().unwrap();
            fs::remove_dir_all(dir).unwrap();
        }
    }
}
