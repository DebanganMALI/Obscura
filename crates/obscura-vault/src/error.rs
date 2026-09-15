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
}
