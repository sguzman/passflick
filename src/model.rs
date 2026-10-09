use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Edge,
    Chrome,
    Firefox,
    Apple,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Self::Edge => "Edge",
            Self::Chrome => "Chrome",
            Self::Firefox => "Firefox",
            Self::Apple => "Apple",
        }
    }
    pub fn priority(self) -> u8 {
        match self {
            Self::Edge => 0,
            Self::Chrome => 1,
            Self::Firefox => 2,
            Self::Apple => 3,
        }
    }
}
impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}
impl FromStr for Source {
    type Err = &'static str;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input.to_ascii_lowercase().as_str() {
            "edge" => Ok(Self::Edge),
            "chrome" | "chromium" => Ok(Self::Chrome),
            "firefox" => Ok(Self::Firefox),
            "apple" | "iphone" | "safari" => Ok(Self::Apple),
            _ => Err("source must be edge, chrome, firefox, or apple"),
        }
    }
}

/// Render account metadata without executable terminal escapes or bidi
/// spoofing controls. Stored data and values copied with Shift+Enter retain
/// their original exact bytes.
pub fn safe_display_text(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_control()
                || matches!(
                    ch,
                    '\u{061c}'
                        | '\u{200e}'..='\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
            {
                '\u{fffd}'
            } else {
                ch
            }
        })
        .collect()
}

#[derive(Serialize, Deserialize)]
pub struct Credential {
    pub source: Source,
    pub label: String,
    pub url: String,
    pub username: String,
    password: Zeroizing<String>,
    pub imported_at: u64,
}
impl Credential {
    pub fn new(
        source: Source,
        label: impl Into<String>,
        url: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        imported_at: u64,
    ) -> Self {
        Self {
            source,
            label: label.into(),
            url: url.into(),
            username: username.into(),
            password: Zeroizing::new(password.into()),
            imported_at,
        }
    }
    pub fn password(&self) -> &str {
        &self.password
    }
    pub fn title(&self) -> &str {
        if self.label.is_empty() {
            &self.url
        } else {
            &self.label
        }
    }
    pub fn display_label(&self) -> String {
        let title = safe_display_text(self.title());
        if self.username.is_empty() {
            format!("{}  ·  {}", title, self.source)
        } else {
            format!(
                "{}  ·  {}  ·  {}",
                title,
                safe_display_text(&self.username),
                self.source
            )
        }
    }
    /// Key borrows the original secret rather than creating another plaintext
    /// password allocation. A missing URL uses a labelled-site identity instead.
    pub fn identity_key(&self) -> (bool, &str, &str, &str) {
        if self.url.is_empty() {
            (false, &self.label, &self.username, self.password())
        } else {
            (true, &self.url, &self.username, self.password())
        }
    }

    pub fn same_identity_and_secret(&self, other: &Self) -> bool {
        self.identity_key() == other.identity_key()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn password_preserves_unicode_and_spaces() {
        let c = Credential::new(
            Source::Apple,
            "Example",
            "https://example.test",
            "hello",
            "  möt de passe  ",
            0,
        );
        assert_eq!(c.password(), "  möt de passe  ");
    }
    #[test]
    fn account_labels_cannot_emit_terminal_escapes_or_direction_controls() {
        let record = Credential::new(
            Source::Edge,
            "Site\u{001b}[31m",
            "https://example.test",
            "alice\u{202e}resu",
            "secret\u{001b}[0m",
            0,
        );
        let visible = record.display_label();
        assert!(visible.contains("Site\u{fffd}[31m"));
        assert!(visible.contains("alice\u{fffd}resu"));
        assert!(!visible.contains('\u{001b}'));
        assert!(!visible.contains('\u{202e}'));
        assert_eq!(record.password(), "secret\u{001b}[0m");
        assert_eq!(record.username, "alice\u{202e}resu");
    }

    #[test]
    fn url_path_case_is_not_silently_folded() {
        let upper = Credential::new(
            Source::Edge,
            "A",
            "https://example.test/Case",
            "me",
            "same-password",
            0,
        );
        let lower = Credential::new(
            Source::Chrome,
            "A",
            "https://example.test/case",
            "me",
            "same-password",
            0,
        );
        assert!(!upper.same_identity_and_secret(&lower));
    }

    #[test]
    fn title_only_entries_from_different_sites_do_not_merge() {
        let a = Credential::new(Source::Apple, "Example A", "", "me", "shared", 1);
        let b = Credential::new(Source::Firefox, "Example B", "", "me", "shared", 1);
        assert!(!a.same_identity_and_secret(&b));
        let c = Credential::new(Source::Firefox, "Example A", "", "me", "shared", 1);
        assert!(a.same_identity_and_secret(&c));
    }

    #[test]
    fn url_identity_does_not_merge_with_title_only_identity() {
        let url = Credential::new(
            Source::Edge,
            "Example",
            "https://example.test",
            "me",
            "shared",
            1,
        );
        let title = Credential::new(Source::Apple, "https://example.test", "", "me", "shared", 1);
        assert!(!url.same_identity_and_secret(&title));
    }

    #[test]
    fn recognizes_chromium_alias() {
        assert_eq!("Chromium".parse::<Source>().unwrap(), Source::Chrome);
    }
}
