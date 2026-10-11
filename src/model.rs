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
                    '\u{00ad}' // soft hyphen
                        | '\u{034f}' // combining grapheme joiner
                        | '\u{061c}' // Arabic letter mark
                        | '\u{180e}' // Mongolian vowel separator
                        | '\u{200b}'..='\u{200f}' // zero-width and bidi marks
                        | '\u{202a}'..='\u{202e}' // bidi embeddings and overrides
                        | '\u{2060}'..='\u{206f}' // word joiner, isolates and old bidi controls
                        | '\u{feff}' // zero-width no-break space
                )
            {
                '\u{fffd}'
            } else {
                ch
            }
        })
        .collect()
}

/// This is a display-only projection, not a URL normalizer. In particular,
/// dropping userinfo and all URL path/query/fragment components must never
/// alter stored credentials or the keys used for duplicate detection.
fn public_site_preview(url: &str) -> &str {
    let remainder = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = remainder.split(&['/', '?', '#'][..]).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    if host.is_empty() {
        "(local site)"
    } else {
        host
    }
}

fn is_web_url(value: &str) -> bool {
    ["http://", "https://"].into_iter().any(|prefix| {
        value
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    })
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
    /// Use the site authority rather than URL paths, query parameters, or
    /// fragments in visible picker/CLI labels. Some browser exports include
    /// session or password-reset tokens in URLs; full URLs are kept unchanged
    /// in the encrypted vault for identity and search.
    pub fn display_title(&self) -> String {
        let stripped = self.label.trim();
        let visible = if stripped.is_empty() {
            public_site_preview(&self.url)
        } else if is_web_url(stripped) {
            public_site_preview(stripped)
        } else {
            &self.label
        };
        safe_display_text(visible)
    }
    pub fn display_label(&self) -> String {
        let title = self.display_title();
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
    fn invisible_format_marks_cannot_disguise_account_metadata() {
        let hidden = "\u{200b}\u{200d}\u{206a}\u{206f}\u{034f}\u{feff}\u{00ad}";
        let label = format!("example{hidden}.test");
        let username = format!("alice{hidden}");
        let record = Credential::new(
            Source::Chrome,
            &label,
            "https://example.test",
            &username,
            "fictional-secret",
            1,
        );
        let visible = record.display_label();
        assert!(
            visible
                .contains("example\u{fffd}\u{fffd}\u{fffd}\u{fffd}\u{fffd}\u{fffd}\u{fffd}.test")
        );
        assert!(!visible.contains(hidden));
        assert_eq!(record.label, label);
        assert_eq!(record.username, username);
        assert_eq!(record.password(), "fictional-secret");
    }

    #[test]
    fn visible_site_title_omits_url_userinfo_path_and_tokens() {
        let url = "https://alice:fictional-userinfo@example.test/private/reset-token?access_token=fictional-query#fictional-fragment";
        let record = Credential::new(Source::Edge, "", url, "alice", "fictional-password", 1);
        let label = record.display_label();
        assert!(label.contains("example.test"));
        for hidden in [
            "fictional-userinfo",
            "private",
            "reset-token",
            "fictional-query",
            "fictional-fragment",
            "fictional-password",
        ] {
            assert!(!label.contains(hidden), "visible label exposed {hidden}");
        }
        // Only the display changes. URL-based identity and vault serialization
        // must retain the originally exported URL exactly.
        assert_eq!(record.url, url);
        assert_eq!(record.identity_key().1, url);
    }

    #[test]
    fn url_shaped_export_titles_are_redacted_without_changing_plain_titles() {
        let titled = Credential::new(
            Source::Apple,
            "https://bob:fictional-secret@example.test/token?private=value",
            "https://example.test",
            "bob",
            "fictional-password",
            1,
        );
        assert_eq!(titled.display_title(), "example.test");
        let mixed_case = Credential::new(
            Source::Apple,
            "HTTPS://bob:fictional-secret@example.test/token?private=value",
            "",
            "bob",
            "fictional-password",
            1,
        );
        assert_eq!(mixed_case.display_title(), "example.test");
        let padded = Credential::new(
            Source::Apple,
            "  HTTPS://bob:fictional-secret@example.test/token?private=value  ",
            "",
            "bob",
            "fictional-password",
            1,
        );
        assert_eq!(padded.display_title(), "example.test");
        assert_eq!(
            padded.label,
            "  HTTPS://bob:fictional-secret@example.test/token?private=value  "
        );
        assert_eq!(
            titled.title(),
            "https://bob:fictional-secret@example.test/token?private=value"
        );

        let plain = Credential::new(
            Source::Firefox,
            "Example / Accounts",
            "https://example.test",
            "bob",
            "fictional-password",
            1,
        );
        assert_eq!(plain.display_title(), "Example / Accounts");
        let local = Credential::new(
            Source::Chrome,
            "",
            "file:///home/fictional-user/secret-file",
            "bob",
            "fictional-password",
            1,
        );
        assert_eq!(local.display_title(), "(local site)");
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
