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

impl Drop for Entry {
    fn drop(&mut self) {
        self.title.zeroize();
        self.username.zeroize();
        self.urls.zeroize();
        self.tags.zeroize();
    }
}
