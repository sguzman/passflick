use crate::model::{Credential, safe_display_text};
use std::collections::HashSet;
use zeroize::Zeroizing;

pub fn rank_credentials(records: &[Credential], query: &str) -> Vec<usize> {
    // Keep the combined search for callers that already use it.
    let needle = Zeroizing::new(query.trim().to_lowercase());
    rank_with_score(records, |record| score(record, needle.as_str()))
}

/// First narrow by website/title/URL, then independently by username.
/// Each query must match its own field; both must match when both are set.
pub fn rank_credentials_by_site_and_username(
    records: &[Credential],
    site_query: &str,
    username_query: &str,
) -> Vec<usize> {
    let site = Zeroizing::new(site_query.trim().to_lowercase());
    let username = Zeroizing::new(username_query.trim().to_lowercase());
    rank_with_score(records, |record| {
        let site_score = if site.is_empty() {
            Some(0)
        } else {
            [(record.title(), 35), (record.url.as_str(), 25)]
                .iter()
                .filter_map(|(field, weight)| {
                    let lowered = Zeroizing::new(field.to_lowercase());
                    field_score(lowered.as_str(), site.as_str()).map(|score| score + weight)
                })
                .max()
        }?;
        let username_score = if username.is_empty() {
            Some(0)
        } else {
            let lowered = Zeroizing::new(record.username.to_lowercase());
            field_score(lowered.as_str(), username.as_str())
        }?;
        Some(site_score + username_score)
    })
}

fn rank_with_score(
    records: &[Credential],
    mut score_record: impl FnMut(&Credential) -> Option<i32>,
) -> Vec<usize> {
    // Sort keys can contain sensitive URL components and are zeroizing.
    let mut ranked: Vec<(usize, i32, Zeroizing<String>)> = records
        .iter()
        .enumerate()
        .filter_map(|(i, rec)| {
            score_record(rec).map(|s| (i, s, Zeroizing::new(rec.title().to_lowercase())))
        })
        .collect();
    ranked.sort_by(|(a, sa, ta), (b, sb, tb)| {
        sb.cmp(sa)
            .then_with(|| {
                records[*a]
                    .source
                    .priority()
                    .cmp(&records[*b].source.priority())
            })
            .then_with(|| ta.as_str().cmp(tb.as_str()))
            .then_with(|| records[*a].username.cmp(&records[*b].username))
    });
    // Borrow identity and secret references from the encrypted-vault records.
    // No second plaintext password copy, and duplicate folding is O(n) expected
    // rather than the former quadratic pass.
    let mut seen = HashSet::new();
    ranked
        .into_iter()
        .filter_map(|(index, _, _)| seen.insert(records[index].identity_key()).then_some(index))
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

    let title = credential.display_title();
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
    if let Some((ordinal, total)) = visible_variant_position(records, selected) {
        label.push_str(&format!("  ·  Variant {ordinal}/{total}"));
    }
    label
}

/// Different URL paths or passwords can result in the same safe title and
/// username. Mark distinct credentials without exposing URL components.
/// Identical records across providers share one ordinal even if ranking
/// chooses a later stored record.
fn visible_variant_position(records: &[Credential], selected: usize) -> Option<(usize, usize)> {
    let target = &records[selected];
    let visible_title = target.display_title();
    let target_key = target.identity_key();
    let mut seen = HashSet::new();
    let mut total = 0;
    let mut ordinal = 0;

    for record in records {
        if record.username != target.username || record.display_title() != visible_title {
            continue;
        }
        let key = record.identity_key();
        if seen.insert(key) {
            total += 1;
            if key == target_key {
                ordinal = total;
            }
        }
    }
    (total > 1).then_some((ordinal, total))
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
    .filter_map(|(field, weight)| {
        let lowered = Zeroizing::new(field.to_lowercase());
        field_score(lowered.as_str(), query).map(|s| s + weight)
    })
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
    fn site_then_username_filters_within_matching_websites() {
        let records = vec![
            Credential::new(
                Source::Edge,
                "GitHub",
                "https://github.com/login",
                "alice@example.test",
                "fictional-alice",
                0,
            ),
            Credential::new(
                Source::Edge,
                "GitHub",
                "https://github.com/login",
                "bob@example.test",
                "fictional-bob",
                0,
            ),
            Credential::new(
                Source::Edge,
                "GitLab",
                "https://gitlab.com",
                "alice@example.test",
                "fictional-gitlab",
                0,
            ),
        ];
        assert_eq!(
            rank_credentials_by_site_and_username(&records, "GITHUB", "ALICE"),
            vec![0]
        );
        assert_eq!(
            rank_credentials_by_site_and_username(&records, "github", "bob"),
            vec![1]
        );
        assert!(rank_credentials_by_site_and_username(&records, "github", "nobody").is_empty());
        assert_eq!(
            rank_credentials_by_site_and_username(&records, "gitlab", "alice"),
            vec![2]
        );
    }

    #[test]
    fn site_and_username_terms_do_not_match_each_others_fields() {
        let records = vec![
            Credential::new(
                Source::Edge,
                "Mail",
                "https://mail.example.test",
                "github-user",
                "fictional-mail",
                0,
            ),
            Credential::new(
                Source::Chrome,
                "GitHub",
                "https://github.com",
                "mail-user",
                "fictional-github",
                0,
            ),
        ];
        assert_eq!(
            rank_credentials_by_site_and_username(&records, "github", ""),
            vec![1]
        );
        assert_eq!(
            rank_credentials_by_site_and_username(&records, "", "github"),
            vec![0]
        );
        assert_eq!(
            rank_credentials_by_site_and_username(&records, "mail", "github"),
            vec![0]
        );
        assert!(rank_credentials_by_site_and_username(&records, "github", "github").is_empty());
    }

    #[test]
    fn staged_search_keeps_cross_source_deduplication() {
        let records = vec![
            Credential::new(Source::Firefox, "GitHub", "https://github.com", "alice", "same", 0),
            Credential::new(Source::Edge, "GitHub", "https://github.com", "alice", "same", 0),
            Credential::new(Source::Edge, "GitHub", "https://github.com", "bob", "other", 0),
        ];
        assert_eq!(
            rank_credentials_by_site_and_username(&records, "git", "alice"),
            vec![1]
        );
        assert_eq!(rank_credentials_by_site_and_username(&records, "", ""), vec![1, 2]);
    }

    #[test]
    fn searches_with_full_url_query_remain_exact_after_zeroizing_normalization() {
        let records = vec![
            Credential::new(
                Source::Edge,
                "",
                "https://example.test/reset/fictional-token-a",
                "person",
                "synthetic-secret",
                1,
            ),
            Credential::new(
                Source::Firefox,
                "",
                "https://example.test/reset/fictional-token-b",
                "person",
                "different-synthetic-secret",
                1,
            ),
        ];
        assert_eq!(rank_credentials(&records, "  FICTIONAL-TOKEN-B  "), vec![1]);
        let label = display_label_with_sources(&records, 1);
        assert!(!label.contains("fictional-token-b"));
    }

    #[test]
    fn ranking_preserves_source_priority_and_case_insensitive_title_ties() {
        let records = vec![
            Credential::new(
                Source::Firefox,
                "zulu",
                "https://a.example.test",
                "u",
                "a",
                0,
            ),
            Credential::new(
                Source::Firefox,
                "Alpha",
                "https://b.example.test",
                "u",
                "b",
                0,
            ),
            Credential::new(Source::Edge, "zulu", "https://c.example.test", "u", "c", 0),
            Credential::new(
                Source::Firefox,
                "alpha",
                "https://d.example.test",
                "v",
                "d",
                0,
            ),
        ];
        // All results have the same empty-query score. Source priority sorts
        // first; within Firefox titles compare case-insensitively, and equal
        // lowercase titles fall back to username.
        assert_eq!(rank_credentials(&records, ""), vec![2, 1, 3, 0]);
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
    fn picker_rows_do_not_render_url_embedded_secrets() {
        let url = "https://alice:fictional-userinfo@example.test/reset-token?token=fictional-query#fictional-fragment";
        let records = vec![Credential::new(
            Source::Edge,
            "",
            url,
            "alice",
            "fictional-password",
            1,
        )];
        let visible = display_label_with_sources(&records, 0);
        assert!(visible.contains("example.test"));
        for hidden in [
            "fictional-userinfo",
            "reset-token",
            "fictional-query",
            "fictional-fragment",
            "fictional-password",
        ] {
            assert!(!visible.contains(hidden), "picker exposed {hidden}");
        }
        assert_eq!(records[0].url, url);
        // Search is intentionally against the original URL identity.
        assert_eq!(rank_credentials(&records, "reset-token"), vec![0]);
    }

    #[test]
    fn redacted_url_collisions_get_distinct_non_secret_variant_labels() {
        let records = vec![
            Credential::new(
                Source::Edge,
                "",
                "https://example.test/account/first?token=private-a",
                "shared-user",
                "fictional-first-password",
                1,
            ),
            Credential::new(
                Source::Edge,
                "",
                "https://example.test/account/second?token=private-b",
                "shared-user",
                "fictional-second-password",
                1,
            ),
        ];
        let first = display_label_with_sources(&records, 0);
        let second = display_label_with_sources(&records, 1);
        assert!(first.contains("Variant 1/2"));
        assert!(second.contains("Variant 2/2"));
        assert_ne!(first, second);
        for label in [&first, &second] {
            assert!(label.contains("example.test"));
            for private in [
                "account",
                "private-a",
                "private-b",
                "fictional-first-password",
                "fictional-second-password",
            ] {
                assert!(!label.contains(private));
            }
        }
        assert_eq!(rank_credentials(&records, "first"), vec![0]);
        assert_eq!(rank_credentials(&records, "second"), vec![1]);
    }

    #[test]
    fn cross_source_exact_duplicate_does_not_create_extra_variant() {
        let records = vec![
            Credential::new(
                Source::Firefox,
                "Example",
                "https://example.test",
                "me",
                "shared",
                1,
            ),
            Credential::new(
                Source::Edge,
                "Example",
                "https://example.test",
                "me",
                "shared",
                1,
            ),
            Credential::new(
                Source::Edge,
                "Example",
                "https://example.test",
                "me",
                "different",
                1,
            ),
        ];
        assert_eq!(rank_credentials(&records, ""), vec![1, 2]);
        assert!(display_label_with_sources(&records, 1).contains("Variant 1/2"));
        assert!(display_label_with_sources(&records, 2).contains("Variant 2/2"));
        let unrelated = vec![
            Credential::new(
                Source::Edge,
                "Example",
                "https://example.test",
                "one",
                "first",
                1,
            ),
            Credential::new(
                Source::Edge,
                "Example",
                "https://example.test",
                "two",
                "second",
                1,
            ),
        ];
        assert!(!display_label_with_sources(&unrelated, 0).contains("Variant"));
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
