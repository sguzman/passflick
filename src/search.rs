use crate::model::Credential;
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

    if credential.username.is_empty() {
        format!("{}  ·  {source_labels}", credential.title())
    } else {
        format!(
            "{}  ·  {}  ·  {source_labels}",
            credential.title(),
            credential.username
        )
    }
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
    fn conflicts_remain_selectable() {
        let records = vec![
            record(Source::Firefox, "GitHub", "old"),
            record(Source::Edge, "GitHub", "new"),
        ];
        assert_eq!(rank_credentials(&records, "git"), vec![1, 0]);
    }
}
