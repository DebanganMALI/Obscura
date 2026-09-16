#![forbid(unsafe_code)]

pub mod entry;
pub mod error;
pub mod format;
pub mod generator;
pub mod portable;
pub mod recovery;
pub mod secret;
pub mod totp;
pub mod vault;

pub use entry::{CustomField, Entry, EntryKind};
pub use error::VaultError;
pub use format::{KeySlot, SlotKind, VaultHeader};
pub use generator::{PasswordPolicy, Separator};
pub use portable::{ImportReport, Portable};
pub use recovery::RecoveryCode;
pub use secret::SecretString;
pub use totp::{Totp, TotpAlgorithm};
pub use vault::{backup_path, temp_path, Credential, Vault};
