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
pub struct CustomFieldView {
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
