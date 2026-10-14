use std::collections::HashMap;

use uuid::Uuid;

use crate::policy::{self, Weakness};
use crate::Entry;

pub const STALE_AFTER_DAYS: i64 = 365;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub checked: usize,
    pub reused: Vec<Vec<Uuid>>,
    pub weak: Vec<(Uuid, Weakness)>,
    pub stale: Vec<(Uuid, i64)>,
}

#[must_use]
pub fn examine(entries: &[Entry]) -> Report {
    let mut ordered: Vec<&Entry> = entries
        .iter()
        .filter(|entry| !entry.password.expose().is_empty())
        .collect();
    ordered.sort_by_cached_key(|entry| entry.title.to_lowercase());

    let mut report = Report {
        checked: ordered.len(),
        ..Report::default()
    };
    let mut sharing: HashMap<&str, Vec<Uuid>> = HashMap::new();

    for entry in &ordered {
        let password = entry.password.expose();
        sharing.entry(password).or_default().push(entry.id);
        if let Some(weakness) = policy::entry_weakness(password) {
            report.weak.push((entry.id, weakness));
        }
        if let Some(days) = entry
            .password_age_days()
            .filter(|days| *days >= STALE_AFTER_DAYS)
        {
            report.stale.push((entry.id, days));
        }
    }

    let mut groups: Vec<Vec<Uuid>> = sharing.into_values().filter(|ids| ids.len() > 1).collect();
    let rank = |id: &Uuid| ordered.iter().position(|entry| entry.id == *id);
    groups.sort_by_key(|ids| ids.first().and_then(rank));
    report.reused = groups;
    report
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use time::{Duration, OffsetDateTime};

    fn login(title: &str, password: &str) -> Entry {
        let mut entry = Entry::new_login(title, "someone");
        entry.set_password(password);
        entry
    }

    #[test]
    fn a_password_shared_by_entries_is_reported_once_as_a_group() {
        let entries = vec![
            login("Mail", "lantern-mango-quiet-orbit"),
            login("Bank", "lantern-mango-quiet-orbit"),
            login("Forum", "tamarind-velvet-harbour-9"),
            login("Shop", "lantern-mango-quiet-orbit"),
        ];

        let report = examine(&entries);

        assert_eq!(report.reused.len(), 1);
        assert_eq!(
            report.reused[0],
            vec![entries[1].id, entries[0].id, entries[3].id],
            "a group lists its entries in title order"
        );
    }

    #[test]
    fn groups_come_in_the_order_of_their_first_title() {
        let entries = vec![
            login("Zebra", "first-shared-password-1"),
            login("Yak", "first-shared-password-1"),
            login("Apple", "second-shared-password-2"),
            login("Mango", "second-shared-password-2"),
        ];

        let report = examine(&entries);

        assert_eq!(
            report.reused,
            vec![
                vec![entries[2].id, entries[3].id],
                vec![entries[1].id, entries[0].id],
            ]
        );
    }

    #[test]
    fn entries_without_a_password_are_not_counted_or_reported() {
        let note = Entry::new_login("A note", "");
        let other = Entry::new_login("Another note", "");
        let entries = vec![note, other, login("Mail", "tamarind-velvet-harbour-9")];

        let report = examine(&entries);

        assert_eq!(report.checked, 1);
        assert_eq!(report.reused, Vec::<Vec<Uuid>>::new());
        assert_eq!(report.weak, Vec::new());
    }

    #[test]
    fn short_common_and_patterned_passwords_are_called_weak() {
        let entries = vec![
            login("Short", "abc123x"),
            login("Common", "iloveyou123"),
            login("Pattern", "qwertyuiop"),
            login("Fine", "tamarind-velvet-harbour-9"),
        ];

        let report = examine(&entries);

        let weak: Vec<(Uuid, Weakness)> = report.weak;
        assert!(weak.contains(&(entries[0].id, Weakness::TooShort)));
        assert!(weak.iter().any(|(id, _)| *id == entries[1].id));
        assert!(weak.iter().any(|(id, _)| *id == entries[2].id));
        assert!(!weak.iter().any(|(id, _)| *id == entries[3].id));
    }

    #[test]
    fn a_password_is_stale_after_a_year_and_not_a_day_before() {
        let mut old = login("Old", "tamarind-velvet-harbour-9");
        old.password_changed_at = OffsetDateTime::now_utc() - Duration::days(400);
        let mut recent = login("Recent", "lantern-mango-quiet-orbit");
        recent.password_changed_at = OffsetDateTime::now_utc() - Duration::days(364);
        let entries = vec![old, recent];

        let report = examine(&entries);

        assert_eq!(report.stale, vec![(entries[0].id, 400)]);
    }

    #[test]
    fn a_healthy_vault_reports_nothing_to_fix() {
        let entries = vec![
            login("Mail", "lantern-mango-quiet-orbit"),
            login("Bank", "tamarind-velvet-harbour-9"),
        ];

        let report = examine(&entries);

        assert_eq!(
            report,
            Report {
                checked: 2,
                ..Report::default()
            }
        );
    }
}
