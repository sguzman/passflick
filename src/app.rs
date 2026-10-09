use crate::clipboard::copy_sensitive;
use crate::model::Credential;
use crate::search::{display_label_with_sources, rank_credentials};
use crate::startup::StartupTrace;
use crate::vault::Vault;
use crate::{passphrase, paths, session};
use eframe::egui;
use zeroize::Zeroizing;

pub struct PickerApp {
    records: Vec<Credential>,
    query: String,
    ranked: Vec<usize>,
    selected: usize,
    focused: bool,
    locked: bool,
    setup_required: bool,
    unlock_focused: bool,
    passphrase: Zeroizing<String>,
    confirmation: Zeroizing<String>,
    notice: Option<String>,
    error: Option<String>,
    startup_trace: StartupTrace,
    first_frame_traced: bool,
}

impl PickerApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        records: Vec<Credential>,
        notice: Option<String>,
        locked: bool,
        setup_required: bool,
        startup_trace: StartupTrace,
    ) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let mut style = (*cc.egui_ctx.style_of(egui::Theme::Dark)).clone();
        style
            .text_styles
            .insert(egui::TextStyle::Body, egui::FontId::proportional(18.0));
        style
            .text_styles
            .insert(egui::TextStyle::Button, egui::FontId::proportional(18.0));
        style
            .text_styles
            .insert(egui::TextStyle::Small, egui::FontId::proportional(15.0));
        cc.egui_ctx.set_style_of(egui::Theme::Dark, style);
        startup_trace.mark("egui-app-created");
        let ranked = rank_credentials(&records, "");
        Self {
            records,
            query: String::new(),
            ranked,
            selected: 0,
            focused: false,
            locked,
            setup_required,
            unlock_focused: false,
            passphrase: Zeroizing::new(String::new()),
            confirmation: Zeroizing::new(String::new()),
            notice,
            error: None,
            startup_trace,
            first_frame_traced: false,
        }
    }

    fn ready(&mut self, records: Vec<Credential>) {
        self.records = records;
        self.locked = false;
        self.setup_required = false;
        self.unlock_focused = false;
        self.focused = false;
        self.query.clear();
        self.notice = None;
        self.error = None;
        self.selected = 0;
        self.refresh();
    }

    fn attempt_setup(&mut self) {
        // Keep both entry fields in zeroizing storage and clear them even when
        // creation fails. Never call an external terminal or shell for setup.
        let first = std::mem::replace(&mut self.passphrase, Zeroizing::new(String::new()));
        let confirmation = std::mem::replace(&mut self.confirmation, Zeroizing::new(String::new()));
        self.unlock_focused = false;
        if let Err(error) = passphrase::validate_new(first.as_str(), confirmation.as_str()) {
            self.error = Some(error.to_string());
            return;
        }
        let path = match paths::vault_path() {
            Ok(path) => path,
            Err(error) => {
                self.error = Some(error.to_string());
                return;
            }
        };
        let vault = match Vault::create(&path, first.as_bytes()) {
            Ok(vault) => vault,
            Err(error) => {
                self.error = Some(format!("Vault creation failed: {error}"));
                return;
            }
        };
        self.setup_required = false;
        if session::store(&path, vault.key()).is_err() {
            // The encrypted vault was successfully created and must never be
            // overwritten on retry. Offer the normal unlock flow instead.
            self.locked = true;
            self.error = Some(
                "Vault created; session unlock failed. Enter your passphrase to retry.".to_owned(),
            );
            return;
        }
        self.ready(vault.into_records());
    }

    fn attempt_unlock(&mut self) {
        // The entered passphrase is owned by a zeroizing allocation and is
        // dropped before returning on both the success and failure paths.
        let entered = std::mem::replace(&mut self.passphrase, Zeroizing::new(String::new()));
        if entered.is_empty() {
            return;
        }
        let path = match paths::vault_path() {
            Ok(path) => path,
            Err(_) => {
                self.error = Some("Unable to locate the encrypted vault.".to_owned());
                return;
            }
        };
        let vault = match Vault::unlock(&path, entered.as_bytes()) {
            Ok(vault) => vault,
            Err(_) => {
                self.error =
                    Some("Unlock failed. Check passphrase and vault integrity.".to_owned());
                return;
            }
        };
        if session::store(&path, vault.key()).is_err() {
            self.error = Some("Unable to cache the unlock key in this login session.".to_owned());
            return;
        }

        self.ready(vault.into_records());
    }

    fn refresh(&mut self) {
        self.ranked = rank_credentials(&self.records, &self.query);
        self.selected = self.selected.min(self.ranked.len().saturating_sub(1));
    }

    fn move_selection(&mut self, delta: isize) {
        if self.ranked.is_empty() {
            self.selected = 0;
            return;
        }
        let last = self.ranked.len() - 1;
        self.selected = if delta.is_negative() {
            self.selected.saturating_sub(delta.unsigned_abs())
        } else {
            self.selected.saturating_add(delta as usize).min(last)
        };
    }

    fn copy_selected(&mut self, ctx: &egui::Context, username: bool) {
        let Some(&index) = self.ranked.get(self.selected) else {
            return;
        };
        let record = &self.records[index];
        let text = if username {
            record.username.as_str()
        } else {
            record.password()
        };
        if text.is_empty() {
            self.error = Some("Selected credential has no username to copy.".to_owned());
            return;
        }
        match copy_sensitive(text) {
            Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
            Err(error) => self.error = Some(error.to_string()),
        }
    }
}

impl eframe::App for PickerApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if !self.first_frame_traced {
            self.startup_trace.mark("first-frame");
            self.first_frame_traced = true;
        }
        let ctx = ui.ctx().clone();
        if ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if self.setup_required {
            egui::CentralPanel::default().show(ui, |ui| {
                ui.add_space(12.0);
                ui.heading("Create your Passflick vault");
                ui.label("This stores a separate, encrypted local copy of your credentials.");
                ui.label(format!(
                    "Choose a unique passphrase of at least {} characters.",
                    passphrase::MIN_LENGTH
                ));
                ui.add_space(8.0);
                let first = ui.add(
                    egui::TextEdit::singleline(&mut *self.passphrase)
                        .password(true)
                        .desired_width(f32::INFINITY)
                        .hint_text("New vault passphrase"),
                );
                if !self.unlock_focused {
                    first.request_focus();
                    self.unlock_focused = true;
                }
                let second = ui.add(
                    egui::TextEdit::singleline(&mut *self.confirmation)
                        .password(true)
                        .desired_width(f32::INFINITY)
                        .hint_text("Confirm passphrase"),
                );
                if first.changed() || second.changed() {
                    self.error = None;
                }
                let create = ui.button("Create encrypted vault").clicked()
                    || ctx.input(|input| input.key_pressed(egui::Key::Enter));
                if let Some(error) = &self.error {
                    ui.label(error);
                }
                if create {
                    self.attempt_setup();
                }
            });
            return;
        }
        if self.locked {
            egui::CentralPanel::default().show(ui, |ui| {
                ui.add_space(12.0);
                ui.heading("Unlock Passflick");
                ui.label("Enter your vault passphrase once for this login session.");
                ui.add_space(8.0);
                let response = ui.add(
                    egui::TextEdit::singleline(&mut *self.passphrase)
                        .password(true)
                        .desired_width(f32::INFINITY)
                        .hint_text("Vault passphrase"),
                );
                if !self.unlock_focused {
                    response.request_focus();
                    self.unlock_focused = true;
                }
                if response.changed() {
                    self.error = None;
                }
                let should_unlock = ui.button("Unlock").clicked()
                    || ctx.input(|input| input.key_pressed(egui::Key::Enter));
                if let Some(error) = &self.error {
                    ui.label(error);
                }
                if should_unlock {
                    self.attempt_unlock();
                }
            });
            return;
        }
        if ctx.input(|input| input.key_pressed(egui::Key::ArrowUp)) {
            self.move_selection(-1);
        }
        if ctx.input(|input| input.key_pressed(egui::Key::ArrowDown)) {
            self.move_selection(1);
        }

        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_space(10.0);
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.query)
                    .desired_width(f32::INFINITY)
                    .hint_text("Search passwords..."),
            );
            if !self.focused {
                response.request_focus();
                self.focused = true;
            }
            if response.changed() {
                self.selected = 0;
                self.refresh();
                self.error = None;
            }
            ui.add_space(8.0);
            ui.separator();
            ui.add_space(4.0);

            if let Some(notice) = &self.notice {
                ui.label(notice);
            } else if self.records.is_empty() {
                ui.label("No imported credentials.");
            } else if self.ranked.is_empty() {
                ui.label("No matches.");
            } else {
                let first_visible = self.selected.saturating_sub(7);
                for (row, index) in self
                    .ranked
                    .iter()
                    .copied()
                    .enumerate()
                    .skip(first_visible)
                    .take(8)
                {
                    if ui
                        .selectable_label(
                            row == self.selected,
                            display_label_with_sources(&self.records, index),
                        )
                        .clicked()
                    {
                        self.selected = row;
                    }
                }
            }
            if let Some(error) = &self.error {
                ui.add_space(8.0);
                ui.separator();
                ui.label(format!("Copy failed: {error}"));
            }
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new("Enter: password  ·  Shift+Enter: username  ·  Esc: close")
                    .size(12.0)
                    .weak(),
            );
        });

        let enter = ctx.input(|input| input.key_pressed(egui::Key::Enter));
        if enter {
            let shift = ctx.input(|input| input.modifiers.shift);
            self.copy_selected(&ctx, shift);
        }
    }
}
