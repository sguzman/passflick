//! Non-secret source refresh summaries, computed from encrypted snapshot metadata.
//! These ages measure the last *import*, never live browser synchronization.
use std::time::{SystemTime, UNIX_EPOCH};

use crate::model::{Credential, Source};

const SECONDS_PER_DAY: u64 = 24 * 60 * 60;
const STALE_AFTER_DAYS: u64 = 30;

#[derive(Debug, Clone, Copy)]
pub struct SourceSnapshot {
    pub source: Source,
    pub count: usize,
    pub newest_import: Option<u64>,
}

impl SourceSnapshot {
    pub fn age_label(&self, now: u64) -> String {
        match self.newest_import {
            None => "never imported".to_owned(),
            Some(0) => "import age unknown".to_owned(),
            Some(time) if time > now => "future timestamp".to_owned(),
            Some(time) => {
                let elapsed = now - time;
                if elapsed < 3_600 {
                    format!("refreshed {} minutes ago", elapsed / 60)
                } else if elapsed < SECONDS_PER_DAY {
                    format!("refreshed {} hours ago", elapsed / 3_600)
                } else {
                    format!("refreshed {} days ago", elapsed / SECONDS_PER_DAY)
                }
            }
        }
    }

    /// An import at least thirty full days old deserves a caution, not a
    /// claim that the password is invalid. Unknown/future times are separate.
    pub fn is_stale(&self, now: u64) -> bool {
        self.newest_import.is_some_and(|time| {
            time != 0 && time <= now && now - time >= STALE_AFTER_DAYS * SECONDS_PER_DAY
        })
    }
}

pub fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// One O(n) pass at picker startup/unlock rather than scanning decrypted
/// records on every frame. Counts include conflicting password variants,
/// matching the established `passflick sources` CLI semantics.
pub fn summarize(records: &[Credential]) -> [SourceSnapshot; 4] {
    let mut sources = [
        SourceSnapshot {
            source: Source::Edge,
            count: 0,
            newest_import: None,
        },
        SourceSnapshot {
            source: Source::Chrome,
            count: 0,
            newest_import: None,
        },
        SourceSnapshot {
            source: Source::Firefox,
            count: 0,
            newest_import: None,
        },
        SourceSnapshot {
            source: Source::Apple,
            count: 0,
            newest_import: None,
        },
    ];
    for record in records {
        let snapshot = &mut sources[record.source.priority() as usize];
        snapshot.count += 1;
        snapshot.newest_import = Some(
            snapshot
                .newest_import
                .map_or(record.imported_at, |last| last.max(record.imported_at)),
        );
    }
    sources
}

/// A single compact row with optional mouse-hover detail. Only fixed source
/// names, counts and rounded ages are displayed; no URL or username copies.
pub fn picker_preview(sources: &[SourceSnapshot; 4], now: u64) -> (String, String, bool) {
    let present = sources.iter().filter(|source| source.count > 0).count();
    let stale = sources
        .iter()
        .filter(|source| source.count > 0 && source.is_stale(now))
        .count();
    let caption = if stale == 0 {
        format!("Sources: {present} imported · hover for refresh ages")
    } else {
        format!("Sources: {present} imported · {stale} stale (30+ days)")
    };
    let details = sources
        .iter()
        .map(|source| {
            format!(
                "{}: {} credentials ({})",
                source.source,
                source.count,
                source.age_label(now)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    (caption, details, stale > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(source: Source, imported_at: u64) -> Credential {
        Credential::new(
            source,
            "Example",
            "https://example.test/private/fictional-token",
            "fictional-user",
            "fictional-password",
            imported_at,
        )
    }

    #[test]
    fn summaries_follow_provider_order_and_latest_import_date() {
        let records = vec![
            record(Source::Firefox, 12),
            record(Source::Edge, 10),
            record(Source::Edge, 15),
            record(Source::Firefox, 4),
        ];
        let sources = summarize(&records);
        assert_eq!(sources[0].source, Source::Edge);
        assert_eq!(sources[0].count, 2);
        assert_eq!(sources[0].newest_import, Some(15));
        assert_eq!(sources[1].source, Source::Chrome);
        assert_eq!(sources[1].count, 0);
        assert_eq!(sources[1].newest_import, None);
        assert_eq!(sources[2].source, Source::Firefox);
        assert_eq!(sources[2].newest_import, Some(12));
        assert_eq!(sources[3].source, Source::Apple);
    }

    #[test]
    fn stale_boundary_and_unknown_or_future_timestamps_are_distinct() {
        let now = 100 * SECONDS_PER_DAY;
        let sources = summarize(&[
            record(Source::Edge, now - 30 * SECONDS_PER_DAY),
            record(Source::Chrome, now - 29 * SECONDS_PER_DAY),
            record(Source::Firefox, 0),
            record(Source::Apple, now + 5),
        ]);
        assert!(sources[0].is_stale(now));
        assert!(!sources[1].is_stale(now));
        assert!(!sources[2].is_stale(now));
        assert!(!sources[3].is_stale(now));
        assert_eq!(sources[2].age_label(now), "import age unknown");
        assert_eq!(sources[3].age_label(now), "future timestamp");
        assert_eq!(summarize(&[])[0].age_label(now), "never imported");
    }

    #[test]
    fn picker_metadata_never_displays_password_or_private_url() {
        let now = 100 * SECONDS_PER_DAY;
        let sources = summarize(&[record(Source::Edge, now - 31 * SECONDS_PER_DAY)]);
        let (caption, details, warning) = picker_preview(&sources, now);
        assert!(warning);
        assert!(caption.contains("1 stale"));
        assert!(details.contains("Edge: 1 credentials (refreshed 31 days ago)"));
        assert!(details.contains("Apple: 0 credentials (never imported)"));
        for sensitive in ["fictional-token", "fictional-user", "fictional-password"] {
            assert!(!caption.contains(sensitive));
            assert!(!details.contains(sensitive));
        }
    }
}
