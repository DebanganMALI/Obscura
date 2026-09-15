#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    #[error("the system random number generator failed")]
    Rng,

    #[error("unsafe Argon2id parameters: {0}")]
    KdfParams(&'static str),

    #[error("key derivation failed")]
    KdfFailed,

    #[error("key expansion failed")]
    ExpandFailed,

    #[error("authentication failed")]
    Authentication,

    #[error("malformed {0}")]
    Malformed(&'static str),
}
