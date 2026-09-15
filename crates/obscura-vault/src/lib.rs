#![forbid(unsafe_code)]

pub mod entry;
pub mod error;
pub mod format;
pub mod generator;
pub mod secret;
pub mod totp;
pub mod vault;

pub use entry::{CustomField, Entry, EntryKind};
pub use error::VaultError;
pub use format::{KeySlot, SlotKind, VaultHeader};
pub use generator::{PasswordPolicy, Separator};
pub use secret::SecretString;
pub use totp::{Totp, TotpAlgorithm};
pub use vault::{Credential, Vault};
