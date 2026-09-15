#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    #[error(transparent)]
    Crypto(#[from] obscura_crypto::CryptoError),

    #[error("invalid Base32 in the TOTP secret")]
    Base32,

    #[error("invalid TOTP configuration: {0}")]
    TotpConfig(&'static str),

    #[error("invalid otpauth URI: {0}")]
    OtpAuthUri(&'static str),

    #[error("invalid password policy: {0}")]
    Policy(&'static str),

    #[error("{0} is too long")]
    TooLong(&'static str),

    #[error("the system clock is before the Unix epoch")]
    Clock,

    #[error("{0}")]
    Io(String),

    #[error("not an Obscura vault")]
    BadMagic,

    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u16),

    #[error("the vault file is corrupt: {0}")]
    Corrupt(&'static str),

    #[error("could not unlock the vault with that credential")]
    NoMatchingSlot,

    #[error("vault rolled back: file is at revision {found}, expected at least {expected}")]
    Rollback { found: u64, expected: u64 },

    #[error("cannot remove the last unlock slot")]
    LastSlot,
}
