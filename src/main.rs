mod app;
mod clipboard;
mod desktop_keyring;
mod r#import;
mod model;
mod paths;
mod search;
mod session;
mod startup;
mod vault;

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use app::PickerApp;
use eframe::egui;
use model::{Credential, Source};
use vault::Vault;
use zeroize::Zeroizing;

fn main() {
    let trace = startup::StartupTrace::from_env();
    trace.mark("process-entry");
    if let Err(error) = run(&trace) {
        eprintln!("passflick: {error}");
        std::process::exit(1);
    }
}

fn run(trace: &startup::StartupTrace) -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("-h" | "--help" | "help") => print_help(),
        Some("-V" | "--version") => println!("passflick {}", env!("CARGO_PKG_VERSION")),
        Some("init") => { no_extra_args(&mut args)?; init_vault()?; }
        Some("unlock") => { no_extra_args(&mut args)?; unlock_vault()?; }
        Some("lock") => { no_extra_args(&mut args)?; lock_vault()?; }
        Some("keyring") => match args.next().as_deref() {
            Some("enable") => { no_extra_args(&mut args)?; enable_keyring()?; }
            Some("disable") => { no_extra_args(&mut args)?; disable_keyring()?; }
            _ => return Err("keyring requires enable or disable".into()),
        },
        Some("status") => { no_extra_args(&mut args)?; status()?; }
        Some("list") => { no_extra_args(&mut args)?; list_credentials()?; }
        Some("import") => {
            let source: Source = args.next().ok_or("import requires SOURCE and FILE")?.parse()?;
            let input_path = args.next().ok_or("import requires a CSV file path")?;
            no_extra_args(&mut args)?;
            import_csv(source, Path::new(&input_path))?;
        }
        Some(other) => return Err(format!("unknown command: {other}").into()),
        None => run_picker(trace.clone())?,
    }
    Ok(())
}

fn no_extra_args(args: &mut impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    if args.next().is_some() { return Err("unexpected additional argument".into()); }
    Ok(())
}

fn run_picker(trace: startup::StartupTrace) -> eframe::Result {
    trace.mark("picker-entry");
    let (records, notice) = load_picker_records(&trace);
    trace.mark("records-loaded");
    let options = eframe::NativeOptions {
        renderer: eframe::Renderer::Glow,
        viewport: egui::ViewportBuilder::default()
            .with_app_id("passflick")
            .with_title("Passflick")
            .with_inner_size([570.0, 340.0])
            .with_resizable(false)
            .with_decorations(false)
            .with_always_on_top(),
        ..Default::default()
    };
    trace.mark("run-native-enter");
    eframe::run_native(
        "Passflick",
        options,
        Box::new(move |cc| {
            Ok(Box::new(PickerApp::new(cc, records, notice, trace.clone())))
        }),
    )
}

fn load_picker_records(trace: &startup::StartupTrace) -> (Vec<Credential>, Option<String>) {
    let path = match paths::vault_path() {
        Ok(path) => path,
        Err(error) => return (Vec::new(), Some(error.to_string())),
    };
    if !path.exists() {
        return (Vec::new(), Some("No vault. Run passflick init once.".to_owned()));
    }
    trace.mark("vault-path-ready");
    let key = match load_vault_key(&path) {
        Ok(Some(key)) => key,
        Ok(None) => return (Vec::new(), Some(
            "Vault locked. Run passflick unlock, or enable keyring integration.".to_owned())),
        Err(error) => return (Vec::new(), Some(error.to_string())),
    };
    trace.mark("session-key-loaded");
    match Vault::open_with_key(&path, key) {
        Ok(vault) => { trace.mark("vault-decrypted"); (vault.into_records(), None) }
        Err(error) => {
            let _ = session::clear();
            (Vec::new(), Some(format!("{error}. Session key cleared; unlock again.")))
        }
    }
}

fn init_vault() -> Result<(), Box<dyn Error>> {
    let path = paths::vault_path()?;
    let first = Zeroizing::new(rpassword::prompt_password("New Passflick passphrase: ")?);
    if first.is_empty() { return Err("passphrase cannot be empty".into()); }
    let confirm = Zeroizing::new(rpassword::prompt_password("Confirm passphrase: ")?);
    if first.as_str() != confirm.as_str() { return Err("passphrases do not match".into()); }
    let vault = Vault::create(&path, first.as_bytes())?;
    session::store(vault.key())?;
    println!("Initialized and unlocked {}.", path.display());
    Ok(())
}

fn unlock_vault() -> Result<(), Box<dyn Error>> {
    let path = paths::vault_path()?;
    session::clear_manual_lock()?;
    if let Ok(Some(key)) = desktop_keyring::load(&path) {
        if let Ok(vault) = Vault::open_with_key(&path, key) {
            session::store(vault.key())?;
            println!("Unlocked from desktop keyring for this login session.");
            return Ok(());
        }
    }
    let passphrase = Zeroizing::new(rpassword::prompt_password("Passflick passphrase: ")?);
    let vault = Vault::unlock(&path, passphrase.as_bytes())?;
    session::store(vault.key())?;
    println!("Unlocked for this login session.");
    Ok(())
}

fn lock_vault() -> Result<(), Box<dyn Error>> {
    session::clear()?;
    session::mark_locked()?;
    println!("Locked for this login session.");
    Ok(())
}

fn enable_keyring() -> Result<(), Box<dyn Error>> {
    let path = paths::vault_path()?;
    let vault = match session::load()? {
        Some(key) => Vault::open_with_key(&path, key)?,
        None => {
            let passphrase = Zeroizing::new(rpassword::prompt_password("Passflick passphrase: ")?);
            let vault = Vault::unlock(&path, passphrase.as_bytes())?;
            session::store(vault.key())?;
            vault
        }
    };
    desktop_keyring::store(&path, vault.key())?;
    println!("Desktop keyring integration enabled.");
    Ok(())
}

fn disable_keyring() -> Result<(), Box<dyn Error>> {
    let path = paths::vault_path()?;
    if desktop_keyring::remove(&path)? {
        println!("Desktop keyring integration disabled.");
    } else {
        println!("Desktop keyring integration was not enabled.");
    }
    Ok(())
}

fn status() -> Result<(), Box<dyn Error>> {
    let path = paths::vault_path()?;
    println!("Vault: {}", path.display());
    println!("Exists: {}", path.exists());
    println!("Session unlocked: {}", session::load()?.is_some());
    println!("Manual lock: {}", session::is_manually_locked()?);
    match desktop_keyring::exists(&path) {
        Ok(enabled) => println!("Desktop keyring: {enabled}"),
        Err(error) => println!("Desktop keyring: unavailable ({error})"),
    }
    Ok(())
}

fn list_credentials() -> Result<(), Box<dyn Error>> {
    let (_, vault) = open_unlocked_vault()?;
    for record in vault.records() {
        println!("{}", record.display_label());
    }
    Ok(())
}

fn import_csv(source: Source, path: &Path) -> Result<(), Box<dyn Error>> {
    // Import bytes never enter arguments or logs. Files should be deleted by the user
    // from their export location; the encrypted vault stores only parsed credentials.
    let bytes = Zeroizing::new(fs::read(path)?);
    let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let imported = r#import::parse_csv(&bytes, source, time)?;
    let (vault_path, mut vault) = open_unlocked_vault()?;
    let count = r#import::replace_snapshot(vault.records_mut(), source, imported);
    vault.save(&vault_path)?;
    println!("Imported {count} {} credential(s) into encrypted projection.", source);
    println!("Remove the plaintext export securely from its original location.");
    Ok(())
}

fn open_unlocked_vault() -> Result<(PathBuf, Vault), Box<dyn Error>> {
    let path = paths::vault_path()?;
    let key = load_vault_key(&path)?.ok_or_else(|| io::Error::new(
        io::ErrorKind::PermissionDenied, "vault locked; run passflick unlock"))?;
    Ok((path.clone(), Vault::open_with_key(&path, key)?))
}

fn load_vault_key(path: &Path) -> Result<Option<vault::VaultKey>, Box<dyn Error>> {
    if let Some(key) = session::load()? { return Ok(Some(key)); }
    if session::is_manually_locked()? { return Ok(None); }
    let key = match desktop_keyring::load(path) {
        Ok(Some(key)) => key,
        Ok(None) | Err(_) => return Ok(None),
    };
    session::store(&key)?;
    Ok(Some(key))
}

fn print_help() {
    println!("Passflick - one-shot password projection and picker");
    println!();
    println!("  passflick                   Open one-shot picker");
    println!("  passflick init              Create encrypted vault");
    println!("  passflick unlock            Unlock for login session");
    println!("  passflick lock              Lock for login session");
    println!("  passflick keyring enable    Enable desktop keyring integration");
    println!("  passflick keyring disable   Remove desktop keyring copy");
    println!("  passflick import SOURCE CSV Replace source projection from CSV");
    println!("  passflick list              Show labels only (never passwords)");
    println!("  passflick status            Display vault/keyring status");
    println!();
    println!("Sources: edge, chrome, firefox, apple");
    println!("Picker: Enter password; Shift+Enter username; Escape close.");
}
