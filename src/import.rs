use crate::model::{Credential, Source};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::backup;
use crate::vault::{Vault, VaultError};

/// A defensive limit for a single explicit export snapshot.
pub const MAX_IMPORT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("CSV could not be parsed: {0}")]
    Csv(#[from] csv::Error),
    #[error("CSV export is larger than 32 MiB")]
    TooLarge,
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error("CSV has no password column")]
    MissingPassword,
    #[error("CSV has no username column; previous snapshot is unchanged")]
    MissingUsername,
    #[error("CSV has neither URL nor title column")]
    MissingSite,
    #[error("CSV contains duplicate normalized column names; previous snapshot is unchanged")]
    DuplicateColumn,
    #[error("CSV contains ambiguous {role} columns; previous snapshot is unchanged")]
    AmbiguousColumn { role: &'static str },
    #[error("CSV resembles a {detected} export, but a different source was selected")]
    WrongSource { detected: &'static str },
    #[error("CSV record {row} is incomplete: {reason}; previous snapshot is unchanged")]
    InvalidRow { row: usize, reason: &'static str },
    #[error("CSV contains no credentials; previous snapshot is unchanged")]
    Empty,
    #[error("import credential {position} is invalid: {reason}; previous snapshot is unchanged")]
    InvalidCredential {
        position: usize,
        reason: &'static str,
    },
    #[error(
        "import batch includes credentials attributed to a different source; previous snapshot is unchanged"
    )]
    MismatchedSource,
    #[error(
        "suspicious {provider} snapshot shrink: {existing} saved vs {incoming} imported; repeat with --allow-shrink if intentional"
    )]
    SuspiciousShrink {
        provider: Source,
        existing: usize,
        incoming: usize,
    },
}

fn normalize_header(value: &str) -> String {
    value
        .trim_start_matches('\u{feff}')
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

fn column(
    headers: &[String],
    candidates: &[&str],
    role: &'static str,
) -> Result<Option<usize>, ImportError> {
    let mut found = None;
    for (index, header) in headers.iter().enumerate() {
        if candidates.contains(&header.as_str()) {
            if found.is_some() {
                return Err(ImportError::AmbiguousColumn { role });
            }
            found = Some(index);
        }
    }
    Ok(found)
}

/// Parse the entire input, including every row, before permitting a snapshot replacement.
/// Unlike a generic best-effort importer, malformed records fail the import rather than
/// silently removing passwords that existed in an older source snapshot.
pub fn parse_csv(
    content: &[u8],
    source: Source,
    imported_at: u64,
) -> Result<Vec<Credential>, ImportError> {
    if content.len() > MAX_IMPORT_BYTES {
        return Err(ImportError::TooLarge);
    }

    let mut reader = csv::ReaderBuilder::new().from_reader(content);
    let headers: Vec<String> = reader.headers()?.iter().map(normalize_header).collect();
    let mut unique = HashSet::new();
    if headers.iter().any(|header| !unique.insert(header.as_str())) {
        return Err(ImportError::DuplicateColumn);
    }
    // Some provider exports have a recognizable signature. Avoid accidentally
    // replacing Edge's snapshot with a Firefox or Apple CSV mislabelled as Edge.
    // Edge and Chrome headers can be identical, so this is a guard, not proof.
    let looks_firefox = headers
        .iter()
        .any(|header| matches!(header.as_str(), "httprealm" | "formactionorigin" | "guid"));
    let looks_apple = headers.iter().any(|header| header == "title")
        && headers.iter().any(|header| header == "notes");
    if looks_firefox && source != Source::Firefox {
        return Err(ImportError::WrongSource {
            detected: "Firefox",
        });
    }
    if looks_apple && source != Source::Apple {
        return Err(ImportError::WrongSource {
            detected: "Apple Passwords",
        });
    }
    let password = column(&headers, &["password", "pass", "passwd"], "password")?
        .ok_or(ImportError::MissingPassword)?;
    let url = column(
        &headers,
        &[
            "url",
            "website",
            "origin",
            "hostname",
            "websiteurl",
            "loginuri",
        ],
        "site URL",
    )?;
    let title = column(&headers, &["name", "title", "sitename"], "site title")?;
    let username = column(
        &headers,
        &["username", "user", "login", "account", "userid"],
        "username",
    )?
    .ok_or(ImportError::MissingUsername)?;
    if url.is_none() && title.is_none() {
        return Err(ImportError::MissingSite);
    }

    let mut result: Vec<Credential> = Vec::new();
    // Index only the non-secret identity fields. Never duplicate plaintext passwords
    // into the deduplication index, and avoid quadratic scanning of entire exports.
    let mut seen: HashMap<(String, String, String), Vec<usize>> = HashMap::new();
    for (index, row) in reader.records().enumerate() {
        let row_number = index + 2; // Header is the first line for ordinary CSV exports.
        let row = row?;
        let field = |index: Option<usize>| index.and_then(|i| row.get(i)).unwrap_or("");
        let secret = row.get(password).unwrap_or("");
        let site_url = field(url).trim();
        let site_name = field(title).trim();
        // Usernames are copied verbatim: leading or trailing whitespace may
        // be part of the actual login, just as it may be in a password.
        let login = row.get(username).unwrap_or("");

        if secret.is_empty() {
            return Err(ImportError::InvalidRow {
                row: row_number,
                reason: "password field is empty",
            });
        }
        // The Wayland text clipboard is not a binary transport. Embedded NUL
        // can be truncated by clipboard consumers, silently copying the wrong
        // password or username. Fail the entire snapshot before any writes.
        if secret.contains('\0') || login.contains('\0') {
            return Err(ImportError::InvalidRow {
                row: row_number,
                reason: "password or username contains a NUL byte",
            });
        }
        if site_url.is_empty() && site_name.is_empty() {
            return Err(ImportError::InvalidRow {
                row: row_number,
                reason: "both website and title are empty",
            });
        }

        let identity = (site_name.to_owned(), site_url.to_owned(), login.to_owned());
        if seen.get(&identity).is_some_and(|indices| {
            indices
                .iter()
                .any(|&record_index| result[record_index].password() == secret)
        }) {
            continue;
        }
        seen.entry(identity).or_default().push(result.len());
        // Deliberately preserve ALL password characters, including whitespace.
        result.push(Credential::new(
            source,
            site_name,
            site_url,
            login,
            secret,
            imported_at,
        ));
    }
    if result.is_empty() {
        return Err(ImportError::Empty);
    }
    Ok(result)
}

/// Reject unexpectedly partial exports before any existing source records are removed.
/// Some legitimate password cleanups shrink a source dramatically; callers must opt in.
pub fn validate_snapshot_refresh(
    records: &[Credential],
    source: Source,
    incoming: usize,
    allow_shrink: bool,
) -> Result<(), ImportError> {
    let existing = records
        .iter()
        .filter(|record| record.source == source)
        .count();
    if !allow_shrink && existing >= 10 && incoming.saturating_mul(2) < existing {
        return Err(ImportError::SuspiciousShrink {
            provider: source,
            existing,
            incoming,
        });
    }
    Ok(())
}

#[cfg(test)]
pub fn replace_snapshot(
    records: &mut Vec<Credential>,
    source: Source,
    incoming: Vec<Credential>,
) -> usize {
    let count = incoming.len();
    records.retain(|record| record.source != source);
    records.extend(incoming);
    count
}

/// Result of one fully validated source refresh transaction.
pub struct SnapshotResult {
    pub count: usize,
    pub previous_backup: Option<PathBuf>,
}

/// Call this with the vault's write lock already held. Validation happens
/// before any backup or write, and a previous source is automatically backed
/// up in encrypted form before its snapshot can be replaced.
pub fn commit_snapshot(
    path: &Path,
    vault: &mut Vault,
    source: Source,
    incoming: Vec<Credential>,
    allow_shrink: bool,
) -> Result<SnapshotResult, ImportError> {
    // Enforce the non-destructive import contract here as well as in CSV
    // parsing. Future providers may call this directly without CSV input.
    if incoming.is_empty() {
        return Err(ImportError::Empty);
    }
    if incoming.iter().any(|record| record.source != source) {
        return Err(ImportError::MismatchedSource);
    }
    // CSV parsing is not the only possible entrypoint. Apply the same
    // non-destructive record checks to future authorized source adapters,
    // before preserving a backup or replacing any encrypted credentials.
    for (index, record) in incoming.iter().enumerate() {
        let invalid = if record.password().is_empty() {
            Some("password field is empty")
        } else if record.password().contains('\0') || record.username.contains('\0') {
            Some("password or username contains a NUL byte")
        } else if record.url.trim().is_empty() && record.label.trim().is_empty() {
            Some("both website and title are empty")
        } else {
            None
        };
        if let Some(reason) = invalid {
            return Err(ImportError::InvalidCredential {
                position: index + 1,
                reason,
            });
        }
    }
    validate_snapshot_refresh(vault.records(), source, incoming.len(), allow_shrink)?;
    let previous_backup = if vault.records().iter().any(|record| record.source == source) {
        Some(backup::create(path)?)
    } else {
        None
    };
    // Move records instead of cloning secrets. Keep the removed source
    // records and their original positions until the encrypted save succeeds.
    // If storage fails, reconstruct the exact previous in-memory projection.
    let count = incoming.len();
    let original = std::mem::take(vault.records_mut());
    let mut displaced = Vec::new();
    let mut candidate = Vec::with_capacity(original.len() + incoming.len());
    for (index, record) in original.into_iter().enumerate() {
        if record.source == source {
            displaced.push((index, record));
        } else {
            candidate.push(record);
        }
    }
    candidate.extend(incoming);
    *vault.records_mut() = candidate;
    if let Err(error) = vault.save(path) {
        let changed = std::mem::take(vault.records_mut());
        let total = changed.len() - count + displaced.len();
        let mut retained = changed.into_iter().filter(|record| record.source != source);
        let mut displaced = displaced.into_iter().peekable();
        let mut restored = Vec::with_capacity(total);
        for index in 0..total {
            if displaced
                .peek()
                .is_some_and(|(position, _)| *position == index)
            {
                restored.push(displaced.next().expect("displaced record").1);
            } else {
                restored.push(retained.next().expect("retained record"));
            }
        }
        *vault.records_mut() = restored;
        return Err(error.into());
    }
    Ok(SnapshotResult {
        count,
        previous_backup,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_csv_preserves_password_whitespace() {
        let data =
            b"name,url,username,password\nExample,https://example.test,alice,\"  hE!llo \"\n";
        let items = parse_csv(data, Source::Edge, 10).unwrap();
        assert_eq!(items[0].password(), "  hE!llo ");
    }

    #[test]
    fn username_whitespace_is_not_silently_removed() {
        let data =
            b"name,url,username,password\nExample,https://example.test,\"  alice  \",secret\n";
        let items = parse_csv(data, Source::Edge, 10).unwrap();
        assert_eq!(items[0].username, "  alice  ");
    }

    #[test]
    fn firefox_export() {
        let data =
            b"url,username,password,httpRealm,formActionOrigin\nhttps://example.test,bob,pazz,,\n";
        let items = parse_csv(data, Source::Firefox, 10).unwrap();
        assert_eq!(items[0].username, "bob");
    }

    #[test]
    fn apple_export() {
        let data =
            b"Title,URL,Username,Password,Notes\nPortal,https://example.test,me,secret,note\n";
        assert_eq!(parse_csv(data, Source::Apple, 10).unwrap().len(), 1);
    }

    #[test]
    fn complete_firefox_csv_export_with_timestamp_metadata() {
        let data = b"\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\r\n\"https://firefox.example.test\",\"fox-user\",\"fictional-firefox-password\",\"\",\"https://firefox.example.test/login\",\"{synthetic-guid}\",\"123456\",\"234567\",\"345678\"\r\n";
        let records = parse_csv(data, Source::Firefox, 42).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].source, Source::Firefox);
        assert_eq!(records[0].username, "fox-user");
        assert_eq!(records[0].password(), "fictional-firefox-password");
        assert_eq!(records[0].imported_at, 42);
    }

    #[test]
    fn apple_export_ignores_notes_and_otp_auth_secrets() {
        let data = b"Title,URL,Username,Password,Notes,OTPAuth\r\n\"Example, Apple\",https://apple.example.test,apple-user,fictional-apple-password,\"first note\nsecond note\",\"otpauth://totp/example?secret=FAKEOTPONLY\"\r\n";
        let records = parse_csv(data, Source::Apple, 13).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].label, "Example, Apple");
        assert_eq!(records[0].password(), "fictional-apple-password");
        let stored = serde_json::to_string(&records).unwrap();
        assert!(!stored.contains("FAKEOTPONLY"));
        assert!(!stored.contains("first note"));
    }

    #[test]
    fn malformed_export_is_rejected_before_snapshot_mutation() {
        let mut existing = vec![
            Credential::new(
                Source::Edge,
                "Primary",
                "https://example.test",
                "me",
                "old",
                1,
            ),
            Credential::new(
                Source::Apple,
                "Other",
                "https://apple.example.test",
                "me",
                "apple",
                1,
            ),
        ];
        let incomplete = b"name,url,username,password\nValid,https://one.example.test,me,good\nMissing,https://two.example.test,me,\n";
        assert!(matches!(
            parse_csv(incomplete, Source::Edge, 2),
            Err(ImportError::InvalidRow { row: 3, .. })
        ));
        assert_eq!(existing.len(), 2);
        assert_eq!(existing[0].password(), "old");
        assert_eq!(existing[1].source, Source::Apple);
        let replacement = parse_csv(
            b"name,url,username,password\nGood,https://new.example.test,me,new\n",
            Source::Edge,
            3,
        )
        .unwrap();
        replace_snapshot(&mut existing, Source::Edge, replacement);
        assert_eq!(existing.len(), 2);
        assert_eq!(existing[0].source, Source::Apple);
    }

    #[test]
    fn nul_in_password_or_username_cannot_commit_a_partial_export() {
        let valid = "name,url,username,password\nValid,https://one.example.test,me,valid\n";
        for malformed in [
            "Invalid,https://two.example.test,me,ab\0cd\n",
            "Invalid,https://two.example.test,m\0e,valid\n",
        ] {
            let mut csv = String::from(valid);
            csv.push_str(malformed);
            assert!(matches!(
                parse_csv(csv.as_bytes(), Source::Edge, 1),
                Err(ImportError::InvalidRow { row: 3, .. })
            ));
        }
    }

    #[test]
    fn rejects_uneven_column_count() {
        let bad =
            b"url,username,password\nhttps://example.test,user,valid\nhttps://example.test,user\n";
        assert!(matches!(
            parse_csv(bad, Source::Edge, 1),
            Err(ImportError::Csv(_))
        ));
    }

    #[test]
    fn rejects_empty_and_oversized_snapshots() {
        assert!(matches!(
            parse_csv(b"name,url,username,password\n", Source::Edge, 0),
            Err(ImportError::Empty)
        ));
        assert!(matches!(
            parse_csv(&vec![b'x'; MAX_IMPORT_BYTES + 1], Source::Edge, 0),
            Err(ImportError::TooLarge)
        ));
    }

    #[test]
    fn handles_quoted_multiline_and_bom_headers() {
        let data = "\u{feff}Name,URL,Username,Password\nExample,https://example.test,alice,\"first\nsecond\"\n";
        let records = parse_csv(data.as_bytes(), Source::Chrome, 0).unwrap();
        assert_eq!(records[0].password(), "first\nsecond");
    }

    #[test]
    fn unusually_small_snapshots_require_explicit_confirmation() {
        let existing: Vec<Credential> = (0..100)
            .map(|index| {
                Credential::new(
                    Source::Edge,
                    "Example",
                    format!("https://{index}.example.test"),
                    "person",
                    "synthetic-test",
                    1,
                )
            })
            .collect();
        assert!(matches!(
            validate_snapshot_refresh(&existing, Source::Edge, 2, false),
            Err(ImportError::SuspiciousShrink { .. })
        ));
        assert!(validate_snapshot_refresh(&existing, Source::Edge, 2, true).is_ok());
        assert!(validate_snapshot_refresh(&existing, Source::Firefox, 1, false).is_ok());
        let eleven = &existing[..11];
        assert!(matches!(
            validate_snapshot_refresh(eleven, Source::Edge, 5, false),
            Err(ImportError::SuspiciousShrink { .. })
        ));
    }

    #[test]
    fn replacing_a_source_preserves_its_old_encrypted_vault() {
        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let root = std::env::temp_dir().join(format!(
            "passflick-import-backup-test-{:016x}",
            u64::from_le_bytes(entropy),
        ));
        let path = root.join("vault.passvault");
        let passphrase = b"fictional-import-test-key";
        let mut vault = Vault::create(&path, passphrase).unwrap();

        let first = parse_csv(
            b"name,url,username,password\nFirst,https://example.test,alice,old-test-password\n",
            Source::Edge,
            1,
        )
        .unwrap();
        let initial = commit_snapshot(&path, &mut vault, Source::Edge, first, false).unwrap();
        assert_eq!(initial.count, 1);
        assert!(initial.previous_backup.is_none());

        // The transaction boundary protects the existing encrypted vault even
        // if a future importer bypasses parse_csv and opts into large shrinks.
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(
            commit_snapshot(&path, &mut vault, Source::Edge, Vec::new(), true),
            Err(ImportError::Empty)
        ));
        let firefox_batch = vec![Credential::new(
            Source::Firefox,
            "Wrong source",
            "https://wrong.example.test",
            "alice",
            "fixture",
            2,
        )];
        assert!(matches!(
            commit_snapshot(&path, &mut vault, Source::Edge, firefox_batch, true),
            Err(ImportError::MismatchedSource)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!root.join("backups").exists());

        let second = parse_csv(
            b"name,url,username,password\nSecond,https://example.test,alice,new-test-password\n",
            Source::Edge,
            2,
        )
        .unwrap();
        let updated = commit_snapshot(&path, &mut vault, Source::Edge, second, false).unwrap();
        let old_path = updated
            .previous_backup
            .expect("existing source must be backed up");
        let previous = Vault::unlock(&old_path, passphrase).unwrap();
        let current = Vault::unlock(&path, passphrase).unwrap();
        assert_eq!(previous.records()[0].password(), "old-test-password");
        assert_eq!(current.records()[0].password(), "new-test-password");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn direct_snapshot_callers_cannot_replace_valid_records_with_invalid_values() {
        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let root = std::env::temp_dir().join(format!(
            "passflick-direct-import-validation-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        let path = root.join("vault.passvault");
        let passphrase = b"fictional-import-validation-passphrase";
        let mut vault = Vault::create(&path, passphrase).unwrap();
        vault.records_mut().push(Credential::new(
            Source::Edge,
            "Preserved entry",
            "https://example.test",
            "fictional-user",
            "fictional-old-password",
            1,
        ));
        vault.save(&path).unwrap();
        let ciphertext = std::fs::read(&path).unwrap();

        for (label, url, username, password) in [
            ("Missing secret", "https://example.test", "user", ""),
            ("Has NUL", "https://example.test", "user", "ab\0cd"),
            ("Has NUL", "https://example.test", "user\0other", "secret"),
            ("  ", "  ", "user", "secret"),
        ] {
            let incoming = vec![Credential::new(
                Source::Edge,
                "Valid first",
                "https://first.example.test",
                "first",
                "good-value",
                2,
            ), Credential::new(
                Source::Edge, label, url, username, password, 2,
            )];
            assert!(matches!(
                commit_snapshot(&path, &mut vault, Source::Edge, incoming, false),
                Err(ImportError::InvalidCredential { position: 2, .. })
            ));
            assert_eq!(std::fs::read(&path).unwrap(), ciphertext);
            assert_eq!(vault.records().len(), 1);
            assert_eq!(vault.records()[0].password(), "fictional-old-password");
            assert!(!root.join("backups").exists());
        }

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn failed_save_restores_original_records_and_the_encrypted_file() {
        use std::os::unix::fs::PermissionsExt;
        let mut entropy = [0_u8; 8];
        getrandom::fill(&mut entropy).unwrap();
        let root = std::env::temp_dir().join(format!(
            "passflick-failed-save-{:016x}",
            u64::from_le_bytes(entropy)
        ));
        let path = root.join("vault.passvault");
        let mut vault = Vault::create(&path, b"fictional-key-for-failure-test").unwrap();
        vault.records_mut().push(Credential::new(
            Source::Apple,
            "Apple",
            "https://apple.example.test",
            "apple-user",
            "apple-original",
            1,
        ));
        vault.records_mut().push(Credential::new(
            Source::Edge,
            "Edge",
            "https://edge.example.test",
            "edge-user",
            "edge-original",
            1,
        ));
        vault.records_mut().push(Credential::new(
            Source::Firefox,
            "Firefox",
            "https://firefox.example.test",
            "fox-user",
            "firefox-original",
            1,
        ));
        vault.save(&path).unwrap();
        let encrypted_before = std::fs::read(&path).unwrap();

        // The existing vault is no longer private, so write_atomic must
        // reject the replacement. Keep original order and contents in memory.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let incoming = vec![Credential::new(
            Source::Chrome,
            "New",
            "https://new.example.test",
            "new-user",
            "new-secret",
            2,
        )];
        let result = commit_snapshot(&path, &mut vault, Source::Chrome, incoming, false);
        assert!(matches!(
            result,
            Err(ImportError::Vault(VaultError::UnsafeFile))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), encrypted_before);
        let labels: Vec<_> = vault
            .records()
            .iter()
            .map(|record| record.title())
            .collect();
        assert_eq!(labels, ["Apple", "Edge", "Firefox"]);
        assert_eq!(vault.records()[0].password(), "apple-original");
        assert_eq!(vault.records()[1].password(), "edge-original");
        assert_eq!(vault.records()[2].password(), "firefox-original");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn encrypted_multi_source_refresh_survives_reopen() {
        use crate::vault::Vault;
        use std::fs;

        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "passflick-source-refresh-{:016x}",
            u64::from_le_bytes(random)
        ));
        let path = dir.join("vault.passvault");

        let mut vault = Vault::create(&path, b"fixture-only-test-passphrase").unwrap();
        let edge = parse_csv(
            b"name,url,username,password\nEdge,https://example.test,person,old-password\n",
            Source::Edge,
            1,
        )
        .unwrap();
        replace_snapshot(vault.records_mut(), Source::Edge, edge);
        let firefox = parse_csv(
            b"url,username,password\nhttps://mozilla.example.test,person,firefox-password\n",
            Source::Firefox,
            2,
        )
        .unwrap();
        replace_snapshot(vault.records_mut(), Source::Firefox, firefox);
        vault.save(&path).unwrap();

        let replacement = parse_csv(
            b"name,url,username,password\nEdge,https://example.test,person,new-password\n",
            Source::Edge,
            3,
        )
        .unwrap();
        replace_snapshot(vault.records_mut(), Source::Edge, replacement);
        vault.save(&path).unwrap();
        drop(vault);

        let reopened = Vault::unlock(&path, b"fixture-only-test-passphrase").unwrap();
        assert_eq!(reopened.records().len(), 2);
        assert!(reopened.records().iter().any(|record| {
            record.source == Source::Edge && record.password() == "new-password"
        }));
        assert!(reopened.records().iter().any(|record| {
            record.source == Source::Firefox && record.password() == "firefox-password"
        }));
        assert!(
            !reopened
                .records()
                .iter()
                .any(|record| record.password() == "old-password")
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn duplicate_password_columns_fail_instead_of_guessing() {
        let data = b"url,username,password,Password\nhttps://example.test,user,first,second\n";
        assert!(matches!(
            parse_csv(data, Source::Edge, 0),
            Err(ImportError::DuplicateColumn)
        ));
    }

    #[test]
    fn missing_username_column_never_creates_silent_empty_accounts() {
        let data = b"name,url,password\nExample,https://example.test,fictional-secret\n";
        assert!(matches!(
            parse_csv(data, Source::Edge, 1),
            Err(ImportError::MissingUsername)
        ));

        // Missing values in an existing username field remain valid:
        // some providers legitimately export credentials without usernames.
        let no_username_value =
            b"name,url,username,password\nExample,https://example.test,,fictional-secret\n";
        let records = parse_csv(no_username_value, Source::Edge, 1).unwrap();
        assert_eq!(records[0].username, "");
    }

    #[test]
    fn ambiguous_alias_columns_fail_before_any_credentials_are_replaced() {
        for (csv, role) in [
            (
                "url,username,password,pass\nhttps://example.test,user,correct,wrong\n",
                "password",
            ),
            (
                "url,website,username,password\nhttps://example.test,https://other.example.test,user,secret\n",
                "site URL",
            ),
            (
                "name,title,username,password\nFirst,Second,user,secret\n",
                "site title",
            ),
            (
                "url,username,user,password\nhttps://example.test,alice,bob,secret\n",
                "username",
            ),
        ] {
            assert!(matches!(
                parse_csv(csv.as_bytes(), Source::Edge, 0),
                Err(ImportError::AmbiguousColumn { role: found }) if found == role
            ));
        }
    }

    #[test]
    fn rejects_obvious_cross_provider_source_mismatch() {
        let firefox = b"url,username,password,httpRealm\nhttps://example.test,user,pass,\n";
        assert!(matches!(
            parse_csv(firefox, Source::Edge, 0),
            Err(ImportError::WrongSource { .. })
        ));
        let apple = b"Title,URL,Username,Password,Notes\nExample,https://example.test,user,pass,\n";
        assert!(matches!(
            parse_csv(apple, Source::Chrome, 0),
            Err(ImportError::WrongSource { .. })
        ));
        assert_eq!(parse_csv(apple, Source::Apple, 0).unwrap().len(), 1);
        assert_eq!(parse_csv(firefox, Source::Firefox, 0).unwrap().len(), 1);
    }

    #[test]
    fn different_passwords_remain_distinct() {
        let data = b"name,url,username,password\nA,https://example.test,me,one\nA,https://example.test,me,two\n";
        assert_eq!(parse_csv(data, Source::Edge, 10).unwrap().len(), 2);
    }
}
