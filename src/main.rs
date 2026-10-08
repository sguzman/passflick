mod app;
mod backup;
mod clipboard;
mod desktop_keyring;
mod discovery;
mod r#import;
mod model;
mod paths;
mod search;
mod session;
mod startup;
mod vault;

use std::error::Error;
use std::fs;
use std::io::{self, Read};
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
        Some("init") => {
            no_extra_args(&mut args)?;
            init_vault()?;
        }
        Some("unlock") => {
            no_extra_args(&mut args)?;
            unlock_vault()?;
        }
        Some("lock") => {
            no_extra_args(&mut args)?;
            lock_vault()?;
        }
        Some("keyring") => match args.next().as_deref() {
            Some("enable") => {
                no_extra_args(&mut args)?;
                enable_keyring()?;
            }
            Some("disable") => {
                no_extra_args(&mut args)?;
                disable_keyring()?;
            }
            _ => return Err("keyring requires enable or disable".into()),
        },
        Some("status") => {
            no_extra_args(&mut args)?;
            status()?;
        }
        Some("list") => {
            no_extra_args(&mut args)?;
            list_credentials()?;
        }
        Some("sources") => {
            no_extra_args(&mut args)?;
            list_source_status()?;
        }
        Some("discover") => {
            no_extra_args(&mut args)?;
            discover_browser_profiles();
        }
        Some("backup") => {
            no_extra_args(&mut args)?;
            backup_encrypted_vault()?;
        }
        Some("import") => {
            let source: Source = args
                .next()
                .ok_or("import requires SOURCE and FILE")?
                .parse()?;
            let input_path = args.next().ok_or("import requires a CSV file path")?;
            let allow_shrink = match args.next().as_deref() {
                None => false,
                Some("--allow-shrink") => true,
                Some(other) => return Err(format!("unknown import option: {other}").into()),
            };
            no_extra_args(&mut args)?;
            import_csv(source, Path::new(&input_path), allow_shrink)?;
        }
        Some(other) => return Err(format!("unknown command: {other}").into()),
        None => run_picker(trace.clone())?,
    }
    Ok(())
}

fn no_extra_args(args: &mut impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    if args.next().is_some() {
        return Err("unexpected additional argument".into());
    }
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
        Box::new(move |cc| Ok(Box::new(PickerApp::new(cc, records, notice, trace.clone())))),
    )
}

fn load_picker_records(trace: &startup::StartupTrace) -> (Vec<Credential>, Option<String>) {
    let path = match paths::vault_path() {
        Ok(path) => path,
        Err(error) => return (Vec::new(), Some(error.to_string())),
    };
    if !path.exists() {
        return (
            Vec::new(),
            Some("No vault. Run passflick init once.".to_owned()),
        );
    }
    trace.mark("vault-path-ready");
    let key = match load_vault_key(&path) {
        Ok(Some(key)) => key,
        Ok(None) => {
            return (
                Vec::new(),
                Some(
                    "Vault locked. Run passflick unlock, or enable keyring integration.".to_owned(),
                ),
            );
        }
        Err(error) => return (Vec::new(), Some(error.to_string())),
    };
    trace.mark("session-key-loaded");
    match Vault::open_with_key(&path, key) {
        Ok(vault) => {
            trace.mark("vault-decrypted");
            (vault.into_records(), None)
        }
        Err(error) => {
            let _ = session::clear();
            (
                Vec::new(),
                Some(format!("{error}. Session key cleared; unlock again.")),
            )
        }
    }
}

fn init_vault() -> Result<(), Box<dyn Error>> {
    let path = paths::vault_path()?;
    let first = Zeroizing::new(rpassword::prompt_password("New Passflick passphrase: ")?);
    if first.is_empty() {
        return Err("passphrase cannot be empty".into());
    }
    let confirm = Zeroizing::new(rpassword::prompt_password("Confirm passphrase: ")?);
    if first.as_str() != confirm.as_str() {
        return Err("passphrases do not match".into());
    }
    let vault = Vault::create(&path, first.as_bytes())?;
    session::store(vault.key())?;
    println!("Initialized and unlocked {}.", path.display());
    Ok(())
}

fn unlock_vault() -> Result<(), Box<dyn Error>> {
    let path = paths::vault_path()?;
    // Never lift an explicit lock until valid key material has been verified.
    // session::store clears the lock marker only after a successful unlock.
    if let Ok(Some(key)) = desktop_keyring::load(&path)
        && let Ok(vault) = Vault::open_with_key(&path, key)
    {
        session::store(vault.key())?;
        println!("Unlocked from desktop keyring for this login session.");
        return Ok(());
    }
    let passphrase = Zeroizing::new(rpassword::prompt_password("Passflick passphrase: ")?);
    let vault = Vault::unlock(&path, passphrase.as_bytes())?;
    session::store(vault.key())?;
    println!("Unlocked for this login session.");
    Ok(())
}

fn lock_vault() -> Result<(), Box<dyn Error>> {
    // Set the explicit lock marker first. A failure to clear the cached key
    // must not inadvertently enable desktop-keyring auto-rehydration.
    session::mark_locked()?;
    session::clear()?;
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

fn read_import_bytes(reader: impl Read) -> io::Result<Zeroizing<Vec<u8>>> {
    // Bound memory consumption even for untrusted pipes that never end.
    let mut input = Zeroizing::new(Vec::new());
    reader
        .take((r#import::MAX_IMPORT_BYTES + 1) as u64)
        .read_to_end(&mut input)?;
    Ok(input)
}

fn discover_browser_profiles() {
    let candidates = discovery::discover();
    if candidates.is_empty() {
        println!("No local supported browser credential profiles detected.");
        return;
    }
    for profile in candidates {
        println!("{}: {} / {} (read-only discovery)", profile.source, profile.browser, profile.profile);
    }
    println!("Discovery does not import, decrypt, or sync browser credentials.");
}

fn backup_encrypted_vault() -> Result<(), Box<dyn Error>> {
    // Demand a successful decrypt before preserving a vault snapshot.
    let (path, _) = open_unlocked_vault()?;
    let destination = backup::create(&path)?;
    println!("Created encrypted backup at {}", destination.display());
    Ok(())
}

fn list_source_status() -> Result<(), Box<dyn Error>> {
    let (_, vault) = open_unlocked_vault()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    for source in [Source::Edge, Source::Chrome, Source::Firefox, Source::Apple] {
        let matching = vault
            .records()
            .iter()
            .filter(|record| record.source == source);
        let count = matching.clone().count();
        let latest = matching.map(|record| record.imported_at).max();
        let age = match latest {
            None => "never imported".to_owned(),
            Some(0) => "import age unknown".to_owned(),
            Some(time) if time > now => "future timestamp".to_owned(),
            Some(time) => {
                let elapsed = now - time;
                if elapsed < 3_600 {
                    format!("refreshed {} minutes ago", elapsed / 60)
                } else if elapsed < 86_400 {
                    format!("refreshed {} hours ago", elapsed / 3_600)
                } else {
                    format!("refreshed {} days ago", elapsed / 86_400)
                }
            }
        };
        println!("{source}: {count} credentials ({age})");
    }
    Ok(())
}

fn import_csv(source: Source, path: &Path, allow_shrink: bool) -> Result<(), Box<dyn Error>> {
    // "-" permits a transient stdin stream without a persistent plaintext CSV file.
    let bytes = if path == Path::new("-") {
        read_import_bytes(io::stdin().lock())?
    } else {
        read_import_bytes(fs::File::open(path)?)?
    };
    let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let imported = r#import::parse_csv(&bytes, source, time)?;
    let (vault_path, mut vault) = open_unlocked_vault()?;
    r#import::validate_snapshot_refresh(vault.records(), source, imported.len(), allow_shrink)?;
    let count = r#import::replace_snapshot(vault.records_mut(), source, imported);
    vault.save(&vault_path)?;
    println!(
        "Imported {count} {} credential(s) into encrypted projection.",
        source
    );
    if path != Path::new("-") {
        println!("Remove the plaintext export from its original location.");
    }
    Ok(())
}

fn open_unlocked_vault() -> Result<(PathBuf, Vault), Box<dyn Error>> {
    let path = paths::vault_path()?;
    let key = load_vault_key(&path)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "vault locked; run passflick unlock",
        )
    })?;
    Ok((path.clone(), Vault::open_with_key(&path, key)?))
}

fn load_vault_key(path: &Path) -> Result<Option<vault::VaultKey>, Box<dyn Error>> {
    if session::is_manually_locked()? {
        return Ok(None);
    }
    if let Some(key) = session::load()? {
        return Ok(Some(key));
    }
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
    println!("  passflick import SOURCE CSV|- Replace source projection from CSV or stdin");
    println!("  passflick list              Show labels only (never passwords)");
    println!("  passflick status            Display vault/keyring status");
    println!("  passflick sources           Show per-source counts and refresh age");
    println!("  passflick discover          Find local browser profiles, no secret access");
    println!("  passflick backup            Create an encrypted vault backup");
    println!();
    println!("  import accepts optional --allow-shrink for intentional large deletions");
    println!("Sources: edge, chrome, firefox, apple");
    println!("Picker: Enter password; Shift+Enter username; Escape close.");
}
