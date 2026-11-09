//! Experimental read-only offline Vaultwarden picker. No network access,
//! no browser source imports, and never opens the legacy encrypted vault.
//! The sensitive clipboard path is the existing Wayland --sensitive adapter.
//! The cached session is authenticated at startup and again under the shared
//! flock before each copy, so a completed manual lock cannot be bypassed by
//! a previously opened window.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui;
use zeroize::{Zeroize, Zeroizing};

use super::offline_command::{self, PickerBootstrap};
use super::projection_search::{display_row, rank_projection};
use super::system_theme;
use crate::projection::ProjectionSnapshot;

const POLL_INTERVAL: Duration = Duration::from_millis(800);
const THEME_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Generate a self-contained command for the same executable and projection
/// directory. A bare 'passflick update' could accidentally invoke an older
/// binary on PATH or write into a different XDG home than the QA preview.
fn quote_fish_argument(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn update_command_for(binary: &Path, snapshot: &Path) -> Option<String> {
    let data_home = snapshot.parent()?.parent()?.to_str()?;
    let binary = binary.to_str()?;
    Some(format!(
        "env XDG_DATA_HOME={} {} update",
        quote_fish_argument(data_home),
        quote_fish_argument(binary)
    ))
}

fn exact_update_command() -> Option<String> {
    update_command_for(
        &std::env::current_exe().ok()?,
        &crate::paths::projection_path().ok()?,
    )
}

/// Match text sizing, keyboard target size and layout rhythm in both themes.
/// Do not install dark-only visuals: System must continue following Darkman.
/// Keep the central panel opaque, in both themes. Frame::new() alone
/// defaults to a TRANSPARENT fill and can reveal the dark underlying desktop
/// beneath light-mode text: the host QA screenshot caught that regression.
fn preview_panel_frame(visuals: &egui::Visuals) -> egui::Frame {
    egui::Frame::new()
        .fill(visuals.panel_fill)
        .inner_margin(egui::Margin::same(18))
}

fn configure_appearance(ctx: &egui::Context) {
    for theme in [egui::Theme::Light, egui::Theme::Dark] {
        let mut style = (*ctx.style_of(theme)).clone();
        style
            .text_styles
            .insert(egui::TextStyle::Body, egui::FontId::proportional(16.0));
        style
            .text_styles
            .insert(egui::TextStyle::Button, egui::FontId::proportional(15.0));
        style
            .text_styles
            .insert(egui::TextStyle::Small, egui::FontId::proportional(13.0));
        style.spacing.item_spacing = egui::vec2(10.0, 8.0);
        style.spacing.interact_size.y = 34.0;
        ctx.set_style_of(theme, style);
    }
}

/// The opt-in picker is keyboard-first, including its appearance controls.
/// Consume the shortcut before the focused search editor can receive it.
fn shortcut_theme(ctx: &egui::Context) -> Option<egui::ThemePreference> {
    for (key, theme) in [
        (egui::Key::Num1, egui::ThemePreference::System),
        (egui::Key::Num2, egui::ThemePreference::Light),
        (egui::Key::Num3, egui::ThemePreference::Dark),
    ] {
        if ctx.input_mut(|input| input.consume_key(egui::Modifiers::CTRL, key)) {
            return Some(theme);
        }
    }
    None
}

fn snapshot_age(timestamp: u64, now: u64) -> (String, bool) {
    let age = now.saturating_sub(timestamp);
    let description = if timestamp > now {
        "Sync timestamp is in the future".to_owned()
    } else if age < 120 {
        "Synced less than 2 minutes ago".to_owned()
    } else if age < 7_200 {
        format!("Synced {} minutes ago", age / 60)
    } else if age < 172_800 {
        format!("Synced {} hours ago", age / 3_600)
    } else {
        format!("Synced {} days ago", age / 86_400)
    };
    (description, timestamp > now || age >= 86_400)
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn copy_value<'a>(
    snapshot: &'a ProjectionSnapshot,
    selected_id: &str,
    username: bool,
) -> Result<&'a str, &'static str> {
    let record = snapshot
        .items()
        .iter()
        .find(|record| record.id() == selected_id)
        .ok_or("The selected item was removed from the offline projection.")?;
    let value = if username {
        record.username()
    } else {
        record.password()
    };
    if value.is_empty() {
        return Err("The selected item has no value for this copy action.");
    }
    if value.contains('\0') {
        return Err("The selected value contains a NUL byte; copy was refused.");
    }
    Ok(value)
}

/// A selected remote ID alone does not guarantee the GUI's rendered row
/// still represents the data about to be copied. A synchronous refresh can
/// change an item without changing its upstream ID. Compare the original
/// in-memory record to the newly authenticated one before touching clipboard.
/// No password or URL bytes enter logs, labels, or error messages.
fn selected_item_unchanged(
    displayed: &ProjectionSnapshot,
    current: &ProjectionSnapshot,
    id: &str,
) -> bool {
    // Item IDs are meaningful only within an authenticated upstream source.
    // A cache replaced with another server/account must never authorize a
    // copy from a window that was displaying the previous source, even if
    // an item ID and its visible fields happen to collide.
    if displayed.server_identity() != current.server_identity()
        || displayed.account_id() != current.account_id()
    {
        return false;
    }
    let previous = displayed.items().iter().find(|item| item.id() == id);
    let updated = current.items().iter().find(|item| item.id() == id);
    match (previous, updated) {
        (Some(before), Some(after)) => {
            before.title() == after.title()
                && before.uris() == after.uris()
                && before.username() == after.username()
                && before.password() == after.password()
        }
        _ => false,
    }
}

struct ProjectionPicker {
    snapshot: Option<ProjectionSnapshot>,
    site_query: Zeroizing<String>,
    username_query: Zeroizing<String>,
    unlock_passphrase: Zeroizing<String>,
    rows: Vec<usize>,
    labels: HashMap<usize, Zeroizing<String>>,
    selected: usize,
    focused: bool,
    notice: Option<&'static str>,
    error: Option<&'static str>,
    bootstrap: PickerBootstrap,
    theme: egui::ThemePreference,
    darkman_theme: Option<egui::Theme>,
    last_theme_poll: Option<Instant>,
    last_poll: Instant,
}

impl ProjectionPicker {
    #[cfg(test)]
    fn new(snapshot: Option<ProjectionSnapshot>, notice: Option<&'static str>) -> Self {
        Self::with_bootstrap(snapshot, notice, PickerBootstrap::Existing)
    }

    fn with_bootstrap(
        snapshot: Option<ProjectionSnapshot>,
        notice: Option<&'static str>,
        bootstrap: PickerBootstrap,
    ) -> Self {
        let rows = snapshot
            .as_ref()
            .map(|data| rank_projection(data, "", ""))
            .unwrap_or_default();
        Self {
            snapshot,
            site_query: Zeroizing::new(String::new()),
            username_query: Zeroizing::new(String::new()),
            unlock_passphrase: Zeroizing::new(String::new()),
            rows,
            labels: HashMap::new(),
            selected: 0,
            focused: false,
            notice,
            error: None,
            bootstrap,
            theme: egui::ThemePreference::System,
            darkman_theme: None,
            last_theme_poll: None,
            last_poll: Instant::now(),
        }
    }

    fn clear_sensitive(&mut self) {
        self.snapshot = None;
        self.rows.clear();
        self.labels.clear();
        self.site_query.zeroize();
        self.username_query.zeroize();
        self.unlock_passphrase.zeroize();
        self.selected = 0;
        self.focused = false;
    }

    fn install_unlocked(&mut self, snapshot: ProjectionSnapshot) {
        self.bootstrap = PickerBootstrap::Existing;
        self.snapshot = Some(snapshot);
        self.unlock_passphrase.zeroize();
        self.notice = None;
        self.error = None;
        self.focused = false;
        self.labels.clear();
        self.update_matches();
    }

    fn update_matches(&mut self) {
        self.rows = self
            .snapshot
            .as_ref()
            .map(|snapshot| rank_projection(snapshot, &self.site_query, &self.username_query))
            .unwrap_or_default();
        self.selected = 0;
    }

    fn poll_lock(&mut self) {
        if self.last_poll.elapsed() < POLL_INTERVAL {
            return;
        }
        self.last_poll = Instant::now();
        self.bootstrap = offline_command::picker_bootstrap();
        if self.bootstrap != PickerBootstrap::Existing {
            if self.snapshot.is_some() {
                self.clear_sensitive();
            }
            self.notice = None;
            return;
        }
        match offline_command::session_present_for_picker() {
            Ok(false) | Err(_) => {
                if self.snapshot.is_some() {
                    self.clear_sensitive();
                }
                self.notice =
                    Some("Projection locked or unavailable. Unlock in this login session.");
            }
            Ok(true) if self.snapshot.is_none() => {
                if let Ok(Some(snapshot)) = offline_command::read_for_picker() {
                    self.install_unlocked(snapshot);
                }
            }
            Ok(true) => {}
        }
    }

    fn move_selection(&mut self, amount: isize) {
        if self.rows.is_empty() {
            self.selected = 0;
        } else if amount.is_negative() {
            self.selected = self.selected.saturating_sub(amount.unsigned_abs());
        } else {
            self.selected = self
                .selected
                .saturating_add(amount as usize)
                .min(self.rows.len() - 1);
        }
    }

    fn copy_selected(&mut self, ctx: &egui::Context, username: bool) {
        let id = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| {
                self.rows
                    .get(self.selected)
                    .and_then(|i| snapshot.items().get(*i))
            })
            .map(|item| Zeroizing::new(item.id().to_owned()));
        let Some(id) = id else { return };

        // A lock cannot report success while this action holds the same
        // cross-process file guard used by lock/unlock and publication.
        let result = (|| {
            let path = crate::paths::projection_path().map_err(|_| "Projection unavailable.")?;
            let _guard = crate::write_lock::acquire(&path)
                .map_err(|_| "Projection access could not be coordinated.")?;
            let current = offline_command::read_for_picker()
                .map_err(|_| "Projection locked or authentication failed.")?
                .ok_or("Projection is locked; unlock it before copying.")?;
            let displayed = self
                .snapshot
                .as_ref()
                .ok_or("Projection window is locked.")?;
            if !selected_item_unchanged(displayed, &current, &id) {
                return Err(
                    "Offline record changed during this picker session. Close and reopen before copying.",
                );
            }
            let text = copy_value(&current, &id, username)?;
            crate::clipboard::copy_sensitive(text)
                .map_err(|_| "Sensitive Wayland clipboard copy failed.")
        })();
        match result {
            Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
            Err(error) => {
                self.error = Some(error);
                // Do not retain an unlocked projection after an unexpected
                // cross-process authentication or clipboard failure.
                if offline_command::session_present_for_picker() != Ok(true) {
                    self.clear_sensitive();
                }
            }
        }
    }
}

impl eframe::App for ProjectionPicker {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        ctx.request_repaint_after(POLL_INTERVAL);
        self.poll_lock();
        if ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if ctx.input(|input| input.key_pressed(egui::Key::ArrowUp)) {
            self.move_selection(-1);
        }
        if ctx.input(|input| input.key_pressed(egui::Key::ArrowDown)) {
            self.move_selection(1);
        }
        if let Some(theme) = shortcut_theme(&ctx) {
            self.theme = theme;
        }
        let toggle =
            ctx.input_mut(|input| input.consume_key(egui::Modifiers::CTRL, egui::Key::Space));

        let mut request_unlock = false;
        let mut refresh_command_clicked = false;
        egui::CentralPanel::default()
            .frame(preview_panel_frame(ui.visuals()))
            .show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("PASSFLICK  /  VAULTWARDEN").strong().size(12.0));
                    let heading = if self.snapshot.is_none()
                        && self.bootstrap == PickerBootstrap::FirstRun
                    {
                        "Connect Vaultwarden"
                    } else {
                        "Find a credential"
                    };
                    ui.heading(egui::RichText::new(heading).size(25.0).strong());
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    self.theme.radio_buttons(ui);
                    ui.label(egui::RichText::new("Ctrl+1/2/3").size(10.0).weak())
                        .on_hover_text("Ctrl+1 System · Ctrl+2 Light · Ctrl+3 Dark");
                });
            });
            ui.add_space(5.0);
            ui.label(
                egui::RichText::new("OFFLINE · READ-ONLY · VAULTWARDEN PREVIEW")
                    .size(11.0)
                    .weak(),
            );
            ui.add_space(10.0);
            if let Some(snapshot) = self.snapshot.as_ref() {
                let (age, stale) = snapshot_age(snapshot.last_success_at(), now_epoch());
                let description = format!(
                    "{}   ·   {} separate login items   ·   Offline copy may be stale",
                    age, snapshot.items().len()
                );
                let info = egui::RichText::new(description).size(12.0);
                ui.label(if stale {
                    info.color(ui.visuals().warn_fg_color)
                } else {
                    info.weak()
                });
                // Refresh needs masked interactive terminal prompts. Offer an
                // explicit exact command instead of spawning a networked CLI
                // from this strictly offline picker or guessing XDG paths.
                ui.horizontal(|ui| {
                    if ui.small_button("Copy refresh command")
                        .on_hover_text("Copy the exact installed executable and XDG data path; run it in Kitty when you want to refresh.")
                        .clicked()
                    {
                        // Enter on a focused button must not also copy a
                        // selected password via the global picker shortcut.
                        refresh_command_clicked = true;
                        if let Some(command) = exact_update_command() {
                            ctx.copy_text(command);
                            self.notice = Some("Refresh command copied. Paste it into Kitty.");
                            self.error = None;
                        } else {
                            self.error = Some("Cannot construct the update command for this session.");
                        }
                    }
                    if let Some(notice) = self.notice {
                        ui.label(egui::RichText::new(notice).size(11.0).weak());
                    }
                });
                ui.add_space(10.0);

                let site = ui.horizontal(|ui| {
                    ui.label("Website");
                    ui.add(
                        egui::TextEdit::singleline(&mut *self.site_query)
                            .desired_width(f32::INFINITY)
                            .hint_text("Name or any website URI"),
                    )
                }).inner;
                let user = ui.horizontal(|ui| {
                    ui.label("Account");
                    ui.add(
                        egui::TextEdit::singleline(&mut *self.username_query)
                            .desired_width(f32::INFINITY)
                            .hint_text("Username within matching websites"),
                    )
                }).inner;
                if !self.focused {
                    site.request_focus();
                    self.focused = true;
                }
                if toggle {
                    if site.has_focus() { user.request_focus(); }
                    else { site.request_focus(); }
                }
                if site.changed() || user.changed() {
                    // Update disjoint fields while snapshot is immutably
                    // borrowed for rendering the selected rows below.
                    self.rows = rank_projection(snapshot, &self.site_query, &self.username_query);
                    self.selected = 0;
                    self.labels.clear();
                    self.error = None;
                }

                ui.add_space(8.0);
                ui.separator();
                ui.add_space(6.0);
                if self.rows.is_empty() {
                    ui.label(egui::RichText::new("No matching login items").weak());
                } else {
                    ui.label(
                        egui::RichText::new(format!("{} MATCHING ACCOUNTS", self.rows.len()))
                            .size(11.0)
                            .strong()
                            .weak(),
                    );
                    egui::ScrollArea::vertical()
                        .max_height(240.0)
                        .show(ui, |ui| {
                            let start = self.selected.saturating_sub(7);
                            for (pos, index) in self.rows.iter().copied().enumerate().skip(start).take(8) {
                                let label = self.labels
                                    .entry(index)
                                    .or_insert_with(|| {
                                        display_row(snapshot, index)
                                            .unwrap_or_else(|| Zeroizing::new("Unavailable".to_owned()))
                                    });
                                let selected = pos == self.selected;
                                let button = egui::Button::selectable(selected, label.as_str());
                                if ui.add_sized([ui.available_width(), 30.0], button).clicked() {
                                    self.selected = pos;
                                }
                            }
                        });
                }
            } else if self.bootstrap == PickerBootstrap::FirstRun {
                ui.add_space(12.0);
                ui.heading("No encrypted projection yet");
                ui.label(
                    "Passflick reads from one Vaultwarden server. It never changes upstream passwords.",
                );
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("FIRST SYNC  /  TERMINAL").size(12.0).strong(),
                );
                ui.horizontal(|ui| {
                    ui.monospace("passflick update");
                    if ui.button("Copy exact QA command").clicked() {
                        if let Some(command) = exact_update_command() {
                            ctx.copy_text(command);
                        } else {
                            self.error = Some("Cannot construct the update command for this session.");
                        }
                    }
                });
                ui.label(
                    "The copied command uses this release executable and the same isolated XDG_DATA_HOME. Paste it into Kitty.",
                );
                ui.label(
                    "The terminal securely asks for your server URL, account credentials, and a separate local passphrase.",
                );
                ui.label(
                    egui::RichText::new(
                        "QA: use a disposable Vaultwarden account with fictional passwords, not your personal vault.",
                    )
                    .weak(),
                );
            } else if self.bootstrap == PickerBootstrap::Incomplete {
                ui.add_space(12.0);
                ui.heading("Projection setup is incomplete");
                ui.label(
                    "Some projection files are present, missing, or unsafe. Offline unlock is unavailable.",
                );
                ui.label(
                    "Existing files have not been changed. Check the terminal diagnostics before attempting another update.",
                );
            } else {
                ui.add_space(12.0);
                ui.heading("Unlock offline projection");
                ui.label(
                    "Enter the independent local projection passphrase. No server connection is made.",
                );
                ui.add_space(10.0);
                let field = ui.add(
                    egui::TextEdit::singleline(&mut *self.unlock_passphrase)
                        .password(true)
                        .hint_text("Local projection passphrase")
                        .desired_width(f32::INFINITY),
                );
                if !self.focused {
                    field.request_focus();
                    self.focused = true;
                }
                let enter = ctx.input(|input| {
                    crate::copy_shortcut::enter_copy_username(&input.events).is_some()
                });
                // A single-line editor may relinquish focus while handling
                // Enter, before this branch observes the same key event.
                // In the locked view, Enter always submits the masked local
                // passphrase; otherwise a lost-focus frame silently ignores
                // the unlock and leaves subsequent typing unfocused.
                if ui.button("Unlock offline").clicked() || enter {
                    request_unlock = true;
                }
                if let Some(notice) = self.notice {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(notice).weak());
                }
            }
            if let Some(error) = self.error {
                ui.add_space(8.0);
                ui.label(egui::RichText::new(error).color(ui.visuals().error_fg_color));
            }
            ui.add_space(14.0);
            ui.separator();
            if self.snapshot.is_some() {
                ui.label(
                    egui::RichText::new(
                        "Ctrl+Space  Filter    ↑↓  Select    Enter  Password    Shift+Enter  Username    Esc  Close",
                    )
                    .size(12.0)
                    .weak(),
                );
            } else {
                ui.label(
                    egui::RichText::new("Ctrl+1/2/3  Appearance     Esc  Close")
                        .size(12.0)
                        .weak(),
                );
            }
        });
        // Wayland's toolkit theme signal is sometimes absent (or out of
        // sync with Darkman). Keep System selected in the UI while rendering
        // Darkman's live mode; manual Light/Dark always wins.
        if self.theme == egui::ThemePreference::System
            && self
                .last_theme_poll
                .is_none_or(|last| last.elapsed() >= THEME_POLL_INTERVAL)
        {
            self.darkman_theme = system_theme::darkman_theme();
            self.last_theme_poll = Some(Instant::now());
        }
        ctx.set_theme(system_theme::effective_preference(
            self.theme,
            self.darkman_theme,
            ctx.system_theme(),
        ));
        if request_unlock {
            let result = offline_command::unlock_for_picker(self.unlock_passphrase.as_bytes());
            self.unlock_passphrase.zeroize();
            match result {
                Ok(snapshot) => self.install_unlocked(snapshot),
                Err(_) => {
                    self.error =
                        Some("Offline unlock failed. Check the local passphrase and snapshot.");
                    self.focused = false;
                }
            }
            ctx.request_repaint();
            // Enter used to unlock must never also copy the first password.
            return;
        }
        // Prevent a keyboard-activated refresh button from also triggering
        // the picker's global Enter-to-copy secret action in this frame.
        if refresh_command_clicked {
            return;
        }
        let action = ctx.input(|input| crate::copy_shortcut::enter_copy_username(&input.events));
        if let Some(username) = action {
            self.copy_selected(&ctx, username);
        }
    }
}

pub fn run() -> eframe::Result {
    let (snapshot, notice) = match offline_command::read_for_picker() {
        Ok(Some(snapshot)) => (Some(snapshot), None),
        Ok(None) => (
            None,
            Some("No unlocked projection key is available in this session."),
        ),
        Err(_) => (
            None,
            Some("Offline projection is missing, locked or unauthenticated."),
        ),
    };
    let bootstrap = offline_command::picker_bootstrap();
    let options = eframe::NativeOptions {
        renderer: eframe::Renderer::Glow,
        viewport: egui::ViewportBuilder::default()
            .with_app_id("passflick-projection-preview")
            .with_title("Passflick · Offline Projection")
            .with_inner_size(if snapshot.is_some() {
                [740.0, 495.0]
            } else {
                [680.0, 370.0]
            })
            .with_resizable(true)
            .with_always_on_top(),
        ..Default::default()
    };
    eframe::run_native(
        "Passflick · Offline Projection",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_theme(egui::ThemePreference::System);
            configure_appearance(&cc.egui_ctx);
            Ok(Box::new(ProjectionPicker::with_bootstrap(
                snapshot, notice, bootstrap,
            )))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection::LoginItem;

    fn fixture() -> ProjectionSnapshot {
        ProjectionSnapshot::new(
            "https://vault.example.test/".to_owned(),
            "fictional-account".to_owned(),
            1_800_000_000,
            vec![
                LoginItem::new(
                    "distinct-a".to_owned(),
                    "Example".to_owned(),
                    vec!["https://example.test/login".to_owned()],
                    "alice".to_owned(),
                    "fictional-password".to_owned(),
                    None,
                ),
                LoginItem::new(
                    "distinct-z".to_owned(),
                    "Example".to_owned(),
                    vec!["https://example.test/login".to_owned()],
                    "alice".to_owned(),
                    "fictional-password".to_owned(),
                    None,
                ),
            ],
        )
        .unwrap()
    }

    #[test]
    fn central_panel_remains_opaque_and_uses_each_themes_panel_fill() {
        for visuals in [egui::Visuals::light(), egui::Visuals::dark()] {
            let frame = preview_panel_frame(&visuals);
            assert_eq!(frame.fill, visuals.panel_fill);
            assert_eq!(frame.fill.a(), 255);
        }
    }

    #[test]
    fn setup_command_targets_exact_binary_and_isolated_data_home() {
        let command = update_command_for(
            Path::new("/opt/qa build/passflick"),
            Path::new("/tmp/qa files/passflick/projection.pfsnapshot"),
        )
        .unwrap();
        assert_eq!(
            command,
            "env XDG_DATA_HOME='/tmp/qa files' '/opt/qa build/passflick' update"
        );
        assert!(update_command_for(Path::new("/opt/passflick"), Path::new("/")).is_none());
    }

    #[test]
    fn uninitialized_picker_does_not_offer_a_fake_passphrase_unlock() {
        let app = ProjectionPicker::with_bootstrap(None, None, PickerBootstrap::FirstRun);
        assert!(app.snapshot.is_none());
        assert_eq!(app.bootstrap, PickerBootstrap::FirstRun);
        assert!(app.unlock_passphrase.is_empty());
        assert!(app.rows.is_empty());
    }

    #[test]
    fn theme_shortcuts_change_the_resolved_theme_with_system_as_default() {
        let ctx = egui::Context::default();
        let mut picker = ProjectionPicker::new(Some(fixture()), None);
        assert_eq!(picker.theme, egui::ThemePreference::System);

        for (key, expected, resolved) in [
            (
                egui::Key::Num2,
                egui::ThemePreference::Light,
                egui::Theme::Light,
            ),
            (
                egui::Key::Num3,
                egui::ThemePreference::Dark,
                egui::Theme::Dark,
            ),
            (
                egui::Key::Num1,
                egui::ThemePreference::System,
                egui::Theme::Light,
            ),
        ] {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    system_theme: Some(egui::Theme::Light),
                    events: vec![egui::Event::Key {
                        key,
                        physical_key: None,
                        pressed: true,
                        repeat: false,
                        modifiers: egui::Modifiers::CTRL,
                    }],
                    ..Default::default()
                },
                |ui| {
                    if let Some(theme) = shortcut_theme(ui.ctx()) {
                        picker.theme = theme;
                        ui.ctx().set_theme(theme);
                    }
                },
            );
            // No GPU exists in this headless unit test: dispose of egui's
            // font-atlas upload explicitly instead of dropping live deltas.
            output.textures_delta.clear();
            assert_eq!(picker.theme, expected);
            assert_eq!(ctx.theme(), resolved);
        }
    }

    #[test]
    fn light_and_dark_panel_text_have_readable_default_contrast() {
        fn luminance(color: egui::Color32) -> f32 {
            let channel = |v: u8| {
                let s = f32::from(v) / 255.0;
                if s <= 0.04045 {
                    s / 12.92
                } else {
                    ((s + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * channel(color.r()) + 0.7152 * channel(color.g()) + 0.0722 * channel(color.b())
        }

        for theme in [egui::Theme::Light, egui::Theme::Dark] {
            let ctx = egui::Context::default();
            ctx.set_theme(theme);
            let style = ctx.style_of(theme);
            let visuals = &style.visuals;
            let foreground = luminance(visuals.widgets.noninteractive.fg_stroke.color);
            let background = luminance(visuals.panel_fill);
            let contrast =
                (foreground.max(background) + 0.05) / (foreground.min(background) + 0.05);
            assert!(contrast >= 4.5, "{theme:?} panel text contrast: {contrast}");
        }
    }

    #[test]
    fn installing_unlocked_snapshot_clears_masked_input_and_resets_focus() {
        let mut picker = ProjectionPicker::new(None, Some("Synthetic locked state"));
        picker
            .unlock_passphrase
            .push_str("fictional local passphrase");
        picker.error = Some("Synthetic failed unlock");
        picker.focused = true;
        picker.install_unlocked(fixture());
        assert!(picker.snapshot.is_some());
        assert_eq!(picker.rows.len(), 2);
        assert!(picker.unlock_passphrase.is_empty());
        assert!(picker.notice.is_none());
        assert!(picker.error.is_none());
        assert!(!picker.focused);
        picker.clear_sensitive();
        assert!(picker.snapshot.is_none());
        assert!(picker.unlock_passphrase.is_empty());
    }

    #[test]
    fn picker_preserves_distinct_upstream_ids_and_safe_secret_selection() {
        let snapshot = fixture();
        let mut app = ProjectionPicker::new(Some(snapshot), None);
        assert_eq!(app.rows.len(), 2);
        assert_eq!(
            app.snapshot.as_ref().unwrap().items()[app.rows[0]].id(),
            "distinct-a"
        );
        app.move_selection(1);
        let id = app.snapshot.as_ref().unwrap().items()[app.rows[app.selected]].id();
        assert_eq!(id, "distinct-z");
        assert_eq!(
            copy_value(app.snapshot.as_ref().unwrap(), id, false).unwrap(),
            "fictional-password"
        );
        assert_eq!(
            copy_value(app.snapshot.as_ref().unwrap(), id, true).unwrap(),
            "alice"
        );
        assert_eq!(
            copy_value(app.snapshot.as_ref().unwrap(), "unrelated-id", false),
            Err("The selected item was removed from the offline projection.")
        );
        app.site_query.push_str("different-domain");
        app.update_matches();
        assert!(app.rows.is_empty());
        app.clear_sensitive();
        assert!(app.snapshot.is_none());
        assert!(app.site_query.is_empty());
    }

    #[test]
    fn changed_selected_record_does_not_copy_unseen_updated_secrets() {
        let viewed = fixture();
        assert!(selected_item_unchanged(&viewed, &viewed, "distinct-a"));
        assert!(!selected_item_unchanged(&viewed, &viewed, "unrelated-id"));

        let changed = ProjectionSnapshot::new(
            viewed.server_identity().to_owned(),
            viewed.account_id().to_owned(),
            viewed.last_success_at() + 1,
            vec![
                LoginItem::new(
                    "distinct-a".to_owned(),
                    "Example".to_owned(),
                    vec!["https://example.test/login".to_owned()],
                    "alice".to_owned(),
                    "fictional-NEW-password".to_owned(),
                    None,
                ),
                LoginItem::new(
                    "distinct-z".to_owned(),
                    "Example".to_owned(),
                    vec!["https://example.test/login".to_owned()],
                    "alice".to_owned(),
                    "fictional-password".to_owned(),
                    None,
                ),
            ],
        )
        .unwrap();
        assert!(!selected_item_unchanged(&viewed, &changed, "distinct-a"));
        assert!(selected_item_unchanged(&viewed, &changed, "distinct-z"));

        let removed = ProjectionSnapshot::new(
            viewed.server_identity().to_owned(),
            viewed.account_id().to_owned(),
            viewed.last_success_at() + 1,
            vec![],
        )
        .unwrap();
        assert!(!selected_item_unchanged(&viewed, &removed, "distinct-a"));
    }

    #[test]
    fn same_upstream_id_and_secret_cannot_cross_server_or_account_boundaries() {
        let viewed = fixture();
        let other_source = |server: &str, account: &str| {
            ProjectionSnapshot::new(
                server.to_owned(),
                account.to_owned(),
                viewed.last_success_at() + 1,
                vec![LoginItem::new(
                    "distinct-a".to_owned(),
                    "Example".to_owned(),
                    vec!["https://example.test/login".to_owned()],
                    "alice".to_owned(),
                    "fictional-password".to_owned(),
                    None,
                )],
            )
            .unwrap()
        };

        let other_account = other_source(viewed.server_identity(), "another-fictional-account");
        assert!(!selected_item_unchanged(
            &viewed,
            &other_account,
            "distinct-a"
        ));
        let other_server =
            other_source("https://different-vault.example.test/", viewed.account_id());
        assert!(!selected_item_unchanged(
            &viewed,
            &other_server,
            "distinct-a"
        ));
    }

    #[test]
    fn stale_timestamp_is_not_confused_with_remote_account_revocation() {
        assert!(snapshot_age(1, 100_000).1);
        assert!(!snapshot_age(100_000, 100_100).1);
        assert!(snapshot_age(200_000, 100_000).1);
    }

    #[test]
    fn copy_validation_refuses_empty_and_nul_bytes() {
        let snapshot = ProjectionSnapshot::new(
            "https://vault.example.test/".to_owned(),
            "fictional-account".to_owned(),
            1_800_000_000,
            vec![LoginItem::new(
                "id".to_owned(),
                "Example".to_owned(),
                vec![],
                "".to_owned(),
                "nul\0credential".to_owned(),
                None,
            )],
        )
        .unwrap();
        assert!(copy_value(&snapshot, "id", false).is_err());
        assert!(copy_value(&snapshot, "id", true).is_err());
    }
}
