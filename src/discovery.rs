use std::fs;
use std::path::{Path, PathBuf};

use crate::model::Source;

/// A non-secret profile locator. Discovery never reads a password database,
/// decrypts credentials, or unlocks any browser or desktop keyring.
#[derive(Debug, PartialEq, Eq)]
pub struct ProfileCandidate {
    pub source: Source,
    pub browser: &'static str,
    pub profile: String,
    pub path: PathBuf,
}

fn chromium_profiles(
    output: &mut Vec<ProfileCandidate>,
    root: &Path,
    source: Source,
    browser: &'static str,
) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != "Default"
            && !name
                .strip_prefix("Profile ")
                .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        let path = entry.path();
        if path.is_dir() && path.join("Login Data").is_file() {
            output.push(ProfileCandidate {
                source,
                browser,
                profile: name,
                path,
            });
        }
    }
}

fn firefox_profiles(output: &mut Vec<ProfileCandidate>, root: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir()
            && path.join("logins.json").is_file()
            && path.join("key4.db").is_file()
        {
            output.push(ProfileCandidate {
                source: Source::Firefox,
                browser: "Firefox",
                profile: entry.file_name().to_string_lossy().into_owned(),
                path,
            });
        }
    }
}

pub fn discover_from(config_root: &Path, firefox_root: &Path) -> Vec<ProfileCandidate> {
    let mut output = Vec::new();
    for (directory, source, label) in [
        ("microsoft-edge", Source::Edge, "Edge"),
        ("microsoft-edge-beta", Source::Edge, "Edge Beta"),
        ("microsoft-edge-dev", Source::Edge, "Edge Dev"),
        ("google-chrome", Source::Chrome, "Chrome"),
        ("google-chrome-beta", Source::Chrome, "Chrome Beta"),
        ("chromium", Source::Chrome, "Chromium"),
    ] {
        chromium_profiles(&mut output, &config_root.join(directory), source, label);
    }
    firefox_profiles(&mut output, firefox_root);
    output.sort_by(|a, b| {
        a.source
            .priority()
            .cmp(&b.source.priority())
            .then_with(|| a.browser.cmp(b.browser))
            .then_with(|| a.profile.cmp(&b.profile))
    });
    output
}

pub fn discover() -> Vec<ProfileCandidate> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    discover_from(&config, &home.join(".mozilla/firefox"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_browser_storage_without_opening_secret_content() {
        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let root = std::env::temp_dir().join(format!(
            "passflick-discovery-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        let edge = root.join("config/microsoft-edge/Default");
        let chrome = root.join("config/google-chrome/Profile 1");
        let firefox = root.join("firefox/random.default-release");
        for folder in [&edge, &chrome, &firefox] {
            fs::create_dir_all(folder).unwrap();
        }
        fs::write(edge.join("Login Data"), b"not a real browser database").unwrap();
        fs::write(chrome.join("Login Data"), b"not a real browser database").unwrap();
        fs::write(firefox.join("logins.json"), b"not real credentials").unwrap();
        fs::write(firefox.join("key4.db"), b"not a real NSS key").unwrap();

        let candidates = discover_from(&root.join("config"), &root.join("firefox"));
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].source, Source::Edge);
        assert_eq!(candidates[1].source, Source::Chrome);
        assert_eq!(candidates[2].source, Source::Firefox);
        assert_eq!(candidates[0].profile, "Default");

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn ignores_missing_or_partial_sources() {
        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let root = std::env::temp_dir().join(format!(
            "passflick-discovery-partial-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        let firefox = root.join("firefox/a.default");
        fs::create_dir_all(&firefox).unwrap();
        fs::write(firefox.join("logins.json"), b"unread").unwrap();
        let found = discover_from(&root.join("config"), &root.join("firefox"));
        assert!(found.is_empty());
        fs::remove_dir_all(&root).unwrap();
    }
}
