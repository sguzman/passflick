use crate::model::{Credential, Source};

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("CSV could not be parsed: {0}")]
    Csv(#[from] csv::Error),
    #[error("CSV has no password column")]
    MissingPassword,
    #[error("CSV has neither URL nor title column")]
    MissingSite,
    #[error("CSV contains no credentials with a site and password; existing snapshot preserved")]
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

pub fn parse_csv(
    content: &[u8],
    source: Source,
    imported_at: u64,
) -> Result<Vec<Credential>, ImportError> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(content);
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
    for row in reader.records() {
        let row = row?;
        let field = |index: Option<usize>| index.and_then(|i| row.get(i)).unwrap_or("");
        let secret = row.get(password).unwrap_or("");
        let site_url = field(url).trim();
        let site_name = field(title).trim();
        let login = field(username).trim();
        if secret.is_empty() || (site_url.is_empty() && site_name.is_empty()) {
            continue;
        }
        if result.iter().any(|rec| {
            rec.url == site_url
                && rec.label == site_name
                && rec.username == login
                && rec.password() == secret
        }) {
            continue;
        }
        // The password value is intentionally NOT trimmed, normalized or logged.
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
    fn empty_file_fails_without_mutating_old_records() {
        assert!(matches!(
            parse_csv(b"name,url,username,password\n", Source::Edge, 0),
            Err(ImportError::Empty)
        ));
    }
    #[test]
    fn different_passwords_remain_distinct() {
        let data = b"name,url,username,password\nA,https://example.test,me,one\nA,https://example.test,me,two\n";
        assert_eq!(parse_csv(data, Source::Edge, 10).unwrap().len(), 2);
    }
}
