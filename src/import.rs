use crate::model::{Credential, Source};

/// A defensive limit for a single explicit export snapshot.
pub const MAX_IMPORT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("CSV could not be parsed: {0}")]
    Csv(#[from] csv::Error),
    #[error("CSV export is larger than 32 MiB")]
    TooLarge,
    #[error("CSV has no password column")]
    MissingPassword,
    #[error("CSV has neither URL nor title column")]
    MissingSite,
    #[error("CSV record {row} is incomplete: {reason}; previous snapshot is unchanged")]
    InvalidRow { row: usize, reason: &'static str },
    #[error("CSV contains no credentials; previous snapshot is unchanged")]
    Empty,
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

        if result.iter().any(|record| {
            record.url == site_url
                && record.label == site_name
                && record.username == login
                && record.password() == secret
        }) {
            continue;
        }
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
    fn different_passwords_remain_distinct() {
        let data = b"name,url,username,password\nA,https://example.test,me,one\nA,https://example.test,me,two\n";
        assert_eq!(parse_csv(data, Source::Edge, 10).unwrap().len(), 2);
    }
}
