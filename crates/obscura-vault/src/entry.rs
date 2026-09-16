use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{error::VaultError, secret::SecretString, totp::Totp};

pub const MAX_FIELD_LEN: usize = 64 * 1024;

pub const MAX_NOTES_LEN: usize = 256 * 1024;

pub const MAX_CUSTOM_FIELDS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EntryKind {
    #[default]
    Login,
    Note,
    Card,
    Identity,
    Key,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value: SecretString,
    pub hidden: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    pub kind: EntryKind,
    pub title: String,
    pub username: String,
    pub password: SecretString,
    pub urls: Vec<String>,
    pub totp: Option<Totp>,
    pub notes: SecretString,
    pub tags: Vec<String>,
    pub custom_fields: Vec<CustomField>,
    pub favorite: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub password_changed_at: OffsetDateTime,
}

impl Entry {
    #[must_use]
    pub fn new_login(title: impl Into<String>, username: impl Into<String>) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: Uuid::new_v4(),
            kind: EntryKind::Login,
            title: title.into(),
            username: username.into(),
            password: SecretString::default(),
            urls: Vec::new(),
            totp: None,
            notes: SecretString::default(),
            tags: Vec::new(),
            custom_fields: Vec::new(),
            favorite: false,
            created_at: now,
            updated_at: now,
            password_changed_at: now,
        }
    }

    pub fn set_password(&mut self, password: impl Into<SecretString>) {
        let now = OffsetDateTime::now_utc();
        self.password = password.into();
        self.password_changed_at = now;
        self.updated_at = now;
    }

    pub fn touch(&mut self) {
        self.updated_at = OffsetDateTime::now_utc();
    }

    #[must_use]
    pub fn password_age_days(&self) -> Option<i64> {
        let elapsed = OffsetDateTime::now_utc() - self.password_changed_at;
        (!elapsed.is_negative()).then(|| elapsed.whole_days())
    }

    #[must_use]
    pub fn matches(&self, needle: &str) -> bool {
        if needle.is_empty() {
            return true;
        }
        let needle = needle.to_lowercase();
        let haystacks = [self.title.as_str(), self.username.as_str()];

        haystacks
            .iter()
            .any(|field| field.to_lowercase().contains(&needle))
            || self.urls.iter().any(|u| u.to_lowercase().contains(&needle))
            || self.tags.iter().any(|t| t.to_lowercase().contains(&needle))
    }

    pub fn validate(&self) -> Result<(), VaultError> {
        if self.title.len() > MAX_FIELD_LEN {
            return Err(VaultError::TooLong("title"));
        }
        if self.username.len() > MAX_FIELD_LEN {
            return Err(VaultError::TooLong("username"));
        }
        if self.password.len() > MAX_FIELD_LEN {
            return Err(VaultError::TooLong("password"));
        }
        if self.notes.len() > MAX_NOTES_LEN {
            return Err(VaultError::TooLong("notes"));
        }
        if self.custom_fields.len() > MAX_CUSTOM_FIELDS {
            return Err(VaultError::TooLong("custom field list"));
        }
        for field in &self.custom_fields {
            if field.name.len() > MAX_FIELD_LEN || field.value.len() > MAX_FIELD_LEN {
                return Err(VaultError::TooLong("custom field"));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn key_info(&self) -> Vec<u8> {
        let mut info = Vec::with_capacity(32);
        info.extend_from_slice(b"obscura/entry/");
        info.extend_from_slice(self.id.as_bytes());
        info
    }
}

fn wipe_plain_fields(entry: &mut Entry) {
    entry.title.zeroize();
    entry.username.zeroize();
    entry.urls.zeroize();
    entry.tags.zeroize();
}

impl Drop for Entry {
    fn drop(&mut self) {
        wipe_plain_fields(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn an_entry() -> Entry {
        Entry::new_login("a title", "a username")
    }

    fn filler(len: usize) -> String {
        "a".repeat(len)
    }

    fn a_field(name: &str, value: &str) -> CustomField {
        CustomField {
            name: String::from(name),
            value: SecretString::from(String::from(value)),
            hidden: false,
        }
    }

    #[test]
    fn the_field_limits_are_the_sizes_they_claim() {
        assert_eq!(MAX_FIELD_LEN, 65_536);
        assert_eq!(MAX_NOTES_LEN, 262_144);
        assert_eq!(MAX_CUSTOM_FIELDS, 128);
    }

    #[test]
    fn a_title_is_accepted_at_the_limit_and_refused_one_byte_past_it() {
        let mut entry = an_entry();
        entry.title = filler(MAX_FIELD_LEN);
        assert!(entry.validate().is_ok());
        entry.title = filler(MAX_FIELD_LEN + 1);
        assert!(matches!(
            entry.validate(),
            Err(VaultError::TooLong("title"))
        ));
    }

    #[test]
    fn a_username_is_accepted_at_the_limit_and_refused_one_byte_past_it() {
        let mut entry = an_entry();
        entry.username = filler(MAX_FIELD_LEN);
        assert!(entry.validate().is_ok());
        entry.username = filler(MAX_FIELD_LEN + 1);
        assert!(matches!(
            entry.validate(),
            Err(VaultError::TooLong("username"))
        ));
    }

    #[test]
    fn a_password_is_accepted_at_the_limit_and_refused_one_byte_past_it() {
        let mut entry = an_entry();
        entry.password = SecretString::from(filler(MAX_FIELD_LEN));
        assert!(entry.validate().is_ok());
        entry.password = SecretString::from(filler(MAX_FIELD_LEN + 1));
        assert!(matches!(
            entry.validate(),
            Err(VaultError::TooLong("password"))
        ));
    }

    #[test]
    fn notes_are_accepted_at_the_limit_and_refused_one_byte_past_it() {
        let mut entry = an_entry();
        entry.notes = SecretString::from(filler(MAX_NOTES_LEN));
        assert!(entry.validate().is_ok());
        entry.notes = SecretString::from(filler(MAX_NOTES_LEN + 1));
        assert!(matches!(
            entry.validate(),
            Err(VaultError::TooLong("notes"))
        ));
    }

    #[test]
    fn the_custom_field_list_is_accepted_at_the_limit_and_refused_one_past_it() {
        let mut entry = an_entry();
        entry.custom_fields = (0..MAX_CUSTOM_FIELDS).map(|_| a_field("n", "v")).collect();
        assert!(entry.validate().is_ok());
        entry.custom_fields.push(a_field("n", "v"));
        assert!(matches!(
            entry.validate(),
            Err(VaultError::TooLong("custom field list"))
        ));
    }

    #[test]
    fn a_custom_field_is_refused_when_either_half_is_one_byte_too_long() {
        let mut entry = an_entry();

        entry.custom_fields = vec![a_field(&filler(MAX_FIELD_LEN), &filler(MAX_FIELD_LEN))];
        assert!(entry.validate().is_ok());

        entry.custom_fields = vec![a_field(&filler(MAX_FIELD_LEN + 1), "v")];
        assert!(matches!(
            entry.validate(),
            Err(VaultError::TooLong("custom field"))
        ));

        entry.custom_fields = vec![a_field("n", &filler(MAX_FIELD_LEN + 1))];
        assert!(matches!(
            entry.validate(),
            Err(VaultError::TooLong("custom field"))
        ));
    }

    #[test]
    fn touching_an_entry_moves_its_modification_time_forward() {
        let mut entry = an_entry();
        entry.updated_at = OffsetDateTime::UNIX_EPOCH;
        entry.touch();
        assert!(entry.updated_at > OffsetDateTime::UNIX_EPOCH);
    }

    #[test]
    fn the_password_age_counts_whole_days_and_never_looks_forwards() {
        let mut entry = an_entry();
        entry.password_changed_at = OffsetDateTime::now_utc() - time::Duration::days(10);
        assert_eq!(entry.password_age_days(), Some(10));

        entry.password_changed_at = OffsetDateTime::now_utc() + time::Duration::days(10);
        assert_eq!(entry.password_age_days(), None);
    }

    #[test]
    fn wiping_an_entry_clears_every_plain_text_field() {
        let mut entry = an_entry();
        entry.urls.push(String::from("https://example.test"));
        entry.tags.push(String::from("a tag"));

        wipe_plain_fields(&mut entry);

        assert!(entry.title.is_empty());
        assert!(entry.username.is_empty());
        assert!(entry.urls.is_empty());
        assert!(entry.tags.is_empty());
    }
}
