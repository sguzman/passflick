use crate::model::{Credential, safe_display_text};
use std::collections::HashSet;

pub fn rank_credentials(records: &[Credential], query: &str) -> Vec<usize> {
    let needle = query.trim().to_lowercase();
    let mut ranked: Vec<(usize, i32)> = records
        .iter()
        .enumerate()
        .filter_map(|(i, rec)| score(rec, &needle).map(|s| (i, s)))
        .collect();
    ranked.sort_by(|(a, sa), (b, sb)| {
        sb.cmp(sa)
            .then_with(|| {
                records[*a]
                    .source
                    .priority()
                    .cmp(&records[*b].source.priority())
            })
            .then_with(|| {
                records[*a]
                    .title()
                    .to_lowercase()
                    .cmp(&records[*b].title().to_lowercase())
            })
            .then_with(|| records[*a].username.cmp(&records[*b].username))
    });
    // Borrow identity and secret references from the encrypted-vault records.
    // No second plaintext password copy, and duplicate folding is O(n) expected
    // rather than the former quadratic pass.
    let mut seen = HashSet::new();
    ranked
        .into_iter()
        .filter_map(|(index, _)| seen.insert(records[index].identity_key()).then_some(index))
        .collect()
}

/// Summarize all identical source records on a single visible row.
/// Neither this string nor search ranking contains password material.
pub fn display_label_with_sources(records: &[Credential], selected: usize) -> String {
    let credential = &records[selected];
    let mut sources = vec![credential.source];
    for record in records {
        if record.source != credential.source
            && record.same_identity_and_secret(credential)
            && !sources.contains(&record.source)
        {
            sources.push(record.source);
        }
    }
    sources.sort_by_key(|source| source.priority());
    let source_labels = sources
        .into_iter()
        .map(|source| source.label())
        .collect::<Vec<_>>()
        .join(" + ");

    let title = safe_display_text(credential.title());
    let mut label = if credential.username.is_empty() {
        format!("{title}  ·  {source_labels}")
    } else {
        format!(
            "{title}  ·  {}  ·  {source_labels}",
            safe_display_text(&credential.username)
        )
    };
    if has_secret_conflict(records, selected) {
        label.push_str("  ·  Conflict");
    }
    label
}

/// Detect competing passwords for one URL-or-title and username identity.
/// Passwords are compared only in memory, never incorporated into the label.
pub fn has_secret_conflict(records: &[Credential], selected: usize) -> bool {
    let credential = &records[selected];
    let (url_based, site, username, _) = credential.identity_key();
    records.iter().any(|other| {
        let (other_url_based, other_site, other_username, _) = other.identity_key();
        other_url_based == url_based
            && other_site == site
            && other_username == username
            && other.password() != credential.password()
    })
}

fn score(rec: &Credential, query: &str) -> Option<i32> {
    if query.is_empty() {
        return Some(0);
    }
    [
        (rec.title(), 35),
        (rec.url.as_str(), 25),
        (rec.username.as_str(), 0),
    ]
    .iter()
    .filter_map(|(field, weight)| field_score(&field.to_lowercase(), query).map(|s| s + weight))
    .max()
}

fn field_score(field: &str, query: &str) -> Option<i32> {
    if field == query {
        return Some(1000);
    }
    if field.starts_with(query) {
        return Some(900);
    }
    if field
        .split(|c: char| !c.is_alphanumeric())
        .any(|part| part.starts_with(query))
    {
        return Some(800);
    }
    if field.contains(query) {
        return Some(650);
    }

    let mut chars = query.chars();
    let mut wanted = chars.next()?;
    let mut matched = 0;
    let mut gaps = 0;
    for ch in field.chars() {
        if ch == wanted {
            matched += 1;
            match chars.next() {
                Some(next) => wanted = next,
                None => return Some(400 + matched * 5 - gaps),
            }
        } else if matched > 0 {
            gaps += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Source;
    fn record(source: Source, name: &str, password: &str) -> Credential {
        Credential::new(source, name, "https://example.test", "me", password, 0)
    }
    #[test]
    fn edge_wins_exact_duplicate() {
        let records = vec![
            record(Source::Firefox, "GitHub", "shared"),
            record(Source::Edge, "GitHub", "shared"),
        ];
        assert_eq!(rank_credentials(&records, "git"), vec![1]);
    }
    #[test]
    fn display_shows_duplicate_provenance_without_secret() {
        let records = vec![
            record(Source::Firefox, "GitHub", "password-that-must-not-appear"),
            record(Source::Edge, "GitHub", "password-that-must-not-appear"),
        ];
        let label = display_label_with_sources(&records, 1);
        assert!(label.contains("Edge + Firefox"));
        assert!(!label.contains("password-that-must-not-appear"));
    }

    #[test]
    fn title_only_accounts_with_distinct_sites_stay_visible() {
        let entries = vec![
            Credential::new(Source::Apple, "Example A", "", "me", "shared", 0),
            Credential::new(Source::Firefox, "Example B", "", "me", "shared", 0),
        ];
        assert_eq!(rank_credentials(&entries, ""), vec![1, 0]);
    }

    #[test]
    fn conflicting_secrets_are_marked_without_displaying_passwords() {
        let records = vec![
            record(Source::Firefox, "GitHub", "old-test-secret"),
            record(Source::Edge, "GitHub", "new-test-secret"),
        ];
        for selected in 0..2 {
            let label = display_label_with_sources(&records, selected);
            assert!(label.contains("Conflict"));
            assert!(!label.contains("old-test-secret"));
            assert!(!label.contains("new-test-secret"));
        }
    }

    #[test]
    fn matching_secrets_and_unrelated_sites_are_not_marked() {
        let same = vec![
            record(Source::Firefox, "GitHub", "shared"),
            record(Source::Edge, "GitHub", "shared"),
        ];
        assert!(!has_secret_conflict(&same, 0));
        let unrelated = vec![
            Credential::new(Source::Apple, "Site A", "", "me", "old", 0),
            Credential::new(Source::Edge, "Site B", "", "me", "new", 0),
        ];
        assert!(!has_secret_conflict(&unrelated, 0));
    }

    #[test]
    fn visible_picker_rows_sanitize_metadata_without_modifying_records() {
        let records = vec![Credential::new(
            Source::Edge,
            "Bad\u{001b}[2J",
            "https://example.test",
            "test\u{202e}eman",
            "passphrase-value",
            0,
        )];
        let row = display_label_with_sources(&records, 0);
        assert!(!row.contains('\u{001b}'));
        assert!(!row.contains('\u{202e}'));
        assert!(row.contains("Bad\u{fffd}[2J"));
        assert_eq!(records[0].username, "test\u{202e}eman");
        assert_eq!(records[0].password(), "passphrase-value");
    }

    #[test]
    fn conflicts_remain_selectable() {
        let records = vec![
            record(Source::Firefox, "GitHub", "old"),
            record(Source::Edge, "GitHub", "new"),
        ];
        assert_eq!(rank_credentials(&records, "git"), vec![1, 0]);
    }
}
