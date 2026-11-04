//! Native offline picker search. Upstream IDs, not browser-provider or
//! (site, username, password) identity, distinguish records. Metadata is
//! searched only after an authenticated encrypted snapshot has been loaded.
//! Visible rows never contain protected URL query/path/fragment or passwords.

use zeroize::Zeroizing;

use crate::model::{safe_display_text, safe_site_title};
use crate::projection::{LoginItem, ProjectionSnapshot};
use crate::search::field_score;

fn fallback_uri(item: &LoginItem) -> &str {
    item.uris()
        .iter()
        .find(|uri| !uri.trim().is_empty())
        .map(String::as_str)
        .unwrap_or("")
}

fn visible_title(item: &LoginItem) -> Zeroizing<String> {
    Zeroizing::new(safe_site_title(item.title(), fallback_uri(item)))
}

/// Search site/title/URI and username independently, without reading secret
/// bytes. Every authenticated upstream ID remains a distinct result.
pub fn rank_projection(
    snapshot: &ProjectionSnapshot,
    site_query: &str,
    username_query: &str,
) -> Vec<usize> {
    let site = Zeroizing::new(site_query.trim().to_lowercase());
    let username = Zeroizing::new(username_query.trim().to_lowercase());
    let mut matches: Vec<(usize, i32)> = snapshot
        .items()
        .iter()
        .enumerate()
        .filter_map(|(index, item)| {
            let site_score = if site.is_empty() {
                Some(0)
            } else {
                std::iter::once((item.title(), 35))
                    .chain(item.uris().iter().map(|uri| (uri.as_str(), 25)))
                    .filter_map(|(value, weight)| {
                        let field = Zeroizing::new(value.to_lowercase());
                        field_score(field.as_str(), site.as_str()).map(|score| score + weight)
                    })
                    .max()
            }?;
            let user_score = if username.is_empty() {
                Some(0)
            } else {
                let field = Zeroizing::new(item.username().to_lowercase());
                field_score(field.as_str(), username.as_str())
            }?;
            Some((index, site_score + user_score))
        })
        .collect();
    matches.sort_by(|(a, score_a), (b, score_b)| {
        score_b.cmp(score_a).then_with(|| snapshot.items()[*a].id().cmp(snapshot.items()[*b].id()))
    });
    matches.into_iter().map(|(index, _)| index).collect()
}

/// Render a visible non-secret label. If several items have the same visible
/// site and username, distinguish them with stable upstream-ID order instead
/// of collapsing them or showing sensitive raw upstream IDs.
pub fn display_row(
    snapshot: &ProjectionSnapshot,
    index: usize,
) -> Option<Zeroizing<String>> {
    let item = snapshot.items().get(index)?;
    let title = visible_title(item);
    let user = Zeroizing::new(safe_display_text(item.username()));
    let peers: Vec<&LoginItem> = snapshot
        .items()
        .iter()
        .filter(|other| {
            visible_title(other).as_str() == title.as_str()
                && safe_display_text(other.username()) == user.as_str()
        })
        .collect();
    let ordinal = peers.iter().filter(|other| other.id() < item.id()).count() + 1;
    let mut row = Zeroizing::new(if user.is_empty() {
        title.to_string()
    } else {
        format!("{}  ·  {}", title.as_str(), user.as_str())
    });
    if peers.len() > 1 {
        row.push_str(&format!("  ·  Variant {ordinal}/{}", peers.len()));
    }
    Some(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, title: &str, uris: &[&str], username: &str, password: &str) -> LoginItem {
        LoginItem::new(
            id.to_owned(),
            title.to_owned(),
            uris.iter().map(|uri| (*uri).to_owned()).collect(),
            username.to_owned(),
            password.to_owned(),
            None,
        )
    }

    fn fixture(items: Vec<LoginItem>) -> ProjectionSnapshot {
        ProjectionSnapshot::new(
            "https://vault.example.test/".to_owned(),
            "fictional-account-id".to_owned(),
            1_800_000_001,
            items,
        )
        .unwrap()
    }

    #[test]
    fn different_upstream_ids_remain_separate_even_with_identical_passwords() {
        let data = fixture(vec![
            entry("z", "Shared", &["https://example.test/login"], "alice", "same-secret"),
            entry("a", "Shared", &["https://example.test/login"], "alice", "same-secret"),
            entry("q", "Shared", &["https://example.test/login"], "alice", "other-secret"),
        ]);
        let hits = rank_projection(&data, "shared", "alice");
        assert_eq!(
            hits.iter().map(|i| data.items()[*i].id()).collect::<Vec<_>>(),
            vec!["a", "q", "z"]
        );
        assert!(display_row(&data, 1).unwrap().ends_with("Variant 1/3"));
        assert!(display_row(&data, 2).unwrap().ends_with("Variant 2/3"));
        assert!(display_row(&data, 0).unwrap().ends_with("Variant 3/3"));
        for index in hits {
            let row = display_row(&data, index).unwrap();
            assert!(!row.contains("same-secret"));
            assert!(!row.contains("other-secret"));
        }
    }

    #[test]
    fn separate_site_and_username_queries_cover_all_uris() {
        let data = fixture(vec![
            entry("first", "One", &["https://unrelated.test", "https://second.test/login"], "alice", "secret-never-search"),
            entry("second", "Another", &["https://second.test/"], "bob", "another-secret"),
        ]);
        assert_eq!(rank_projection(&data, "second.test", "alice"), vec![0]);
        assert_eq!(rank_projection(&data, "second.test", "bob"), vec![1]);
        assert!(rank_projection(&data, "another", "alice").is_empty());
        assert!(rank_projection(&data, "secret-never-search", "").is_empty());
    }

    #[test]
    fn labels_hide_private_uri_tokens_and_control_characters() {
        let data = fixture(vec![
            entry("id1", "https://user:secret@accounts.example.test/reset?token=PRIVATE_TOKEN",
                  &["https://accounts.example.test/"], "alice\u{202e}admin", "fictional-private"),
            entry("id2", "", &["https://site.example.test/path?token=OTHER_TOKEN"], "", "secret"),
        ]);
        assert_eq!(rank_projection(&data, "private_token", "").len(), 1);
        assert_eq!(rank_projection(&data, "other_token", "").len(), 1);
        let label = display_row(&data, 0).unwrap();
        assert!(label.contains("accounts.example.test"));
        assert!(label.contains("alice"));
        assert!(!label.contains("PRIVATE_TOKEN"));
        assert!(!label.contains("user:secret"));
        assert!(!label.contains("\u{202e}"));
        assert!(!label.contains("fictional-private"));
        let other = display_row(&data, 1).unwrap();
        assert!(other.contains("site.example.test"));
        assert!(!other.contains("OTHER_TOKEN"));
        assert!(!other.contains("/path"));
    }

    #[test]
    fn result_order_does_not_depend_on_sync_iteration_order() {
        let forward = fixture(vec![
            entry("z", "Same", &[], "person", "synthetic"),
            entry("a", "Same", &[], "person", "synthetic"),
        ]);
        let reverse = fixture(vec![
            entry("a", "Same", &[], "person", "synthetic"),
            entry("z", "Same", &[], "person", "synthetic"),
        ]);
        for snapshot in [&forward, &reverse] {
            let ordered = rank_projection(snapshot, "", "");
            assert_eq!(
                ordered.iter().map(|i| snapshot.items()[*i].id()).collect::<Vec<_>>(),
                vec!["a", "z"]
            );
        }
    }

    #[test]
    fn labels_have_no_invalid_index_or_spurious_variant() {
        let data = fixture(vec![entry("id", "Example", &[], "", "secret")]);
        assert_eq!(display_row(&data, 0).unwrap().as_str(), "Example");
        assert!(display_row(&data, 1).is_none());
    }
}
