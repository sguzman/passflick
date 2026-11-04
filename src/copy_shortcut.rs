//! Keyboard actions shared by the historical picker and the experimental
//! offline Vaultwarden picker. A copy action must use the modifiers recorded
//! with the keypress, never the modifiers remaining at the end of a GUI frame.

use eframe::egui;

/// Some(true) copies a username; Some(false) copies a password. The result
/// comes from the Enter press event, ignoring later Shift release events.
pub(crate) fn enter_copy_username(events: &[egui::Event]) -> Option<bool> {
    events.iter().find_map(|event| match event {
        egui::Event::Key {
            key: egui::Key::Enter,
            pressed: true,
            modifiers,
            ..
        } => Some(modifiers.shift),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_uses_press_modifiers_even_after_shift_release() {
        let key = |pressed: bool, modifiers: egui::Modifiers| egui::Event::Key {
            key: egui::Key::Enter,
            physical_key: None,
            pressed,
            repeat: false,
            modifiers,
        };
        let events = [
            key(true, egui::Modifiers::SHIFT),
            key(false, egui::Modifiers::NONE),
            egui::Event::ModifiersChanged(egui::Modifiers::NONE),
        ];
        assert_eq!(enter_copy_username(&events), Some(true));
        assert_eq!(
            enter_copy_username(&[key(true, egui::Modifiers::NONE)]),
            Some(false)
        );
        assert_eq!(
            enter_copy_username(&[key(false, egui::Modifiers::SHIFT)]),
            None
        );
    }
}
