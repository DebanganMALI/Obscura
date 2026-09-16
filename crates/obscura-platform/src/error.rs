#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlatformError {
    #[error("hardware unlock is not available on this platform")]
    Unsupported,

    #[error("this machine has no usable Windows Hello credential provider")]
    NotConfigured,

    #[error("the unlock prompt was dismissed")]
    Cancelled,

    #[error("the hardware credential for this vault no longer exists")]
    CredentialMissing,

    #[error("a hardware credential for this vault already exists - remove it deliberately before enrolling again")]
    CredentialExists,

    #[error("the security device is locked")]
    DeviceLocked,

    #[error("this machine's signatures are not reproducible, so a hardware slot could never be reopened")]
    NonDeterministicSignature,

    #[error("the platform refused the request (HRESULT 0x{0:08X})")]
    Platform(u32),

    #[error("Windows Hello returned an unrecognised status ({0})")]
    UnknownStatus(i32),

    #[error(transparent)]
    Crypto(#[from] obscura_crypto::CryptoError),
}
