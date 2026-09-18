use obscura_vault::{Entry, EntryKind};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntrySummary {
    pub id: Uuid,
    pub kind: EntryKind,
    pub title: String,
    pub username: String,
    pub url: Option<String>,
    pub has_totp: bool,
    pub favorite: bool,
    pub password_age_days: Option<i64>,
    pub tags: Vec<String>,
}

impl From<&Entry> for EntrySummary {
    fn from(entry: &Entry) -> Self {
        Self {
            id: entry.id,
            kind: entry.kind,
            title: entry.title.clone(),
            username: entry.username.clone(),
            url: entry.urls.first().cloned(),
            has_totp: entry.totp.is_some(),
            favorite: entry.favorite,
            password_age_days: entry.password_age_days(),
            tags: entry.tags.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryDetail {
    #[serde(flatten)]
    pub summary: EntrySummary,
    pub urls: Vec<String>,
    pub notes: String,
    pub custom_fields: Vec<CustomFieldView>,
    pub password_len: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResult {
    pub path: String,
    pub entries: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub path: String,
    pub source: String,
    pub added: usize,
    pub renumbered: usize,
    pub skipped: usize,
    pub totp_dropped: usize,
    pub info: VaultInfo,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomFieldView {
    pub name: String,
    pub value: Option<String>,
    pub hidden: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomFieldInput {
    pub name: String,
    pub value: Option<String>,
    pub hidden: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryInput {
    pub id: Option<Uuid>,
    pub kind: EntryKind,
    pub title: String,
    pub username: String,
    pub password: Option<String>,
    pub urls: Vec<String>,
    pub notes: String,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub totp_uri: Option<String>,
    #[serde(default)]
    pub custom_fields: Vec<CustomFieldInput>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    pub id: Uuid,
    pub revision: u64,
    pub entry_count: usize,
    pub slots: Vec<SlotView>,
    pub path: String,
    pub auto_lock_secs: u64,
    pub has_password: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotView {
    pub id: Uuid,
    pub kind: String,
    pub label: String,
    pub created_at: String,
    pub portable: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedPassword {
    pub password: String,
    pub entropy_bits: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    pub code: String,
    pub remaining: u64,
    pub period: u64,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocationProbe {
    pub path: String,
    pub parent: String,
    pub exists: bool,
    pub is_vault: bool,
    pub parent_exists: bool,
    pub writable: bool,
    pub remembered: bool,
    pub is_default: bool,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelocateResult {
    pub info: VaultInfo,
    pub previous: String,
    pub previous_removed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedRecoveryCode {
    pub slot: Uuid,
    pub code: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmRevision {
    pub reason: String,
    pub found: u64,
    pub expected: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockError {
    pub message: String,
    pub confirm: Option<ConfirmRevision>,
}

impl UnlockError {
    pub fn message(text: impl Into<String>) -> Self {
        Self {
            message: text.into(),
            confirm: None,
        }
    }

    pub fn rollback(found: u64, expected: u64) -> Self {
        Self {
            message: format!(
                "This vault file is at revision {found}, but Obscura last saw revision {expected} on this computer. Opening it would discard every change made after revision {found}."
            ),
            confirm: Some(ConfirmRevision {
                reason: "rollback".to_owned(),
                found,
                expected: Some(expected),
            }),
        }
    }

    pub fn damaged(found: u64) -> Self {
        Self {
            message: format!(
                "The rollback record for this vault is damaged or does not belong to it, so Obscura cannot tell whether this file has been rolled back. The file itself is at revision {found}."
            ),
            confirm: Some(ConfirmRevision {
                reason: "damaged".to_owned(),
                found,
                expected: None,
            }),
        }
    }

    pub fn unreadable(found: u64, detail: impl Into<String>) -> Self {
        Self {
            message: format!(
                "Obscura keeps a rollback record for every vault it has opened on this computer, and that file could not be read: {}. Until it is rebuilt, Obscura cannot tell whether this file has been rolled back. The file itself is at revision {found}. Continuing sets the unreadable record aside as watermarks.damaged.json and starts a new one holding this vault alone, so any other vault you open afterwards will look new to Obscura.",
                detail.into()
            ),
            confirm: Some(ConfirmRevision {
                reason: "unreadable".to_owned(),
                found,
                expected: None,
            }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use obscura_vault::{CustomField, SecretString};

    fn an_entry() -> Entry {
        let mut entry = Entry::new_login("GitHub", "saheb");
        entry.password = SecretString::from("correct-horse-battery-staple");
        entry.notes = SecretString::from("a private note");
        entry.urls = vec!["https://github.com".to_owned()];
        entry.tags = vec!["work".to_owned()];
        entry.custom_fields = vec![CustomField {
            name: "recovery".to_owned(),
            value: SecretString::from("a hidden value"),
            hidden: true,
        }];
        entry
    }

    #[test]
    fn a_summary_carries_what_the_list_needs() {
        let entry = an_entry();
        let summary = EntrySummary::from(&entry);

        assert_eq!(summary.id, entry.id);
        assert_eq!(summary.title, "GitHub");
        assert_eq!(summary.username, "saheb");
        assert_eq!(summary.url.as_deref(), Some("https://github.com"));
        assert_eq!(summary.tags, vec!["work".to_owned()]);
        assert!(!summary.has_totp);
        assert!(!summary.favorite);
    }

    #[test]
    fn a_summary_never_serialises_a_secret() {
        let json = serde_json::to_string(&EntrySummary::from(&an_entry())).unwrap();

        assert!(!json.contains("correct-horse-battery-staple"));
        assert!(!json.contains("a private note"));
        assert!(!json.contains("a hidden value"));
    }

    #[test]
    fn an_unlock_error_asks_for_confirmation_only_when_it_should() {
        let plain = UnlockError::message("nope");
        assert_eq!(plain.message, "nope");
        assert!(plain.confirm.is_none());

        let rollback = UnlockError::rollback(4, 9);
        let confirm = rollback.confirm.expect("a rollback is confirmable");
        assert_eq!(confirm.reason, "rollback");
        assert_eq!(confirm.found, 4);
        assert_eq!(confirm.expected, Some(9));

        let damaged = UnlockError::damaged(7);
        let confirm = damaged.confirm.expect("a damaged record is confirmable");
        assert_eq!(confirm.reason, "damaged");
        assert_eq!(confirm.found, 7);
        assert_eq!(confirm.expected, None);

        let unreadable = UnlockError::unreadable(3, "the disk is on fire");
        let confirm = unreadable
            .confirm
            .expect("an unreadable record is confirmable");
        assert_eq!(confirm.reason, "unreadable");
        assert_eq!(confirm.found, 3);
        assert_eq!(confirm.expected, None);
        assert!(unreadable.message.contains("the disk is on fire"));
    }
}
