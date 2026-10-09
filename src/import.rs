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
    #[error("CSV has neither URL nor title column")]
    MissingSite,
    #[error("CSV contains duplicate normalized column names; previous snapshot is unchanged")]
    DuplicateColumn,
    #[error("CSV resembles a {detected} export, but a different source was selected")]
    WrongSource { detected: &'static str },
    #[error("CSV record {row} is incomplete: {reason}; previous snapshot is unchanged")]
    InvalidRow { row: usize, reason: &'static str },
    #[error("CSV contains no credentials; previous snapshot is unchanged")]
    Empty,
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

fn column(headers: &[String], candidates: &[&str]) -> Option<usize> {
    headers
        .iter()
        .position(|h| candidates.contains(&h.as_str()))
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
    let password =
        column(&headers, &["password", "pass", "passwd"]).ok_or(ImportError::MissingPassword)?;
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
    );
    let title = column(&headers, &["name", "title", "sitename"]);
    let username = column(
        &headers,
        &["username", "user", "login", "account", "userid"],
    );
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
        let login = field(username).trim();

        if secret.is_empty() {
            return Err(ImportError::InvalidRow {
                row: row_number,
                reason: "password field is empty",
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
    validate_snapshot_refresh(vault.records(), source, incoming.len(), allow_shrink)?;
    let previous_backup = if vault.records().iter().any(|record| record.source == source) {
        Some(backup::create(path)?)
    } else {
        None
    };
    let count = replace_snapshot(vault.records_mut(), source, incoming);
    vault.save(path)?;
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
