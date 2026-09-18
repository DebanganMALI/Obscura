#![allow(unsafe_code)]

#[cfg(target_os = "windows")]
mod imp;

#[cfg(target_os = "windows")]
pub use imp::{api_version, console_window, enroll, prf_secret, transport_name, Enrolled};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WebAuthnError {
    #[error("this build of Windows has WebAuthn API version {0}, which is too old for PRF")]
    ApiTooOld(u32),

    #[error("the authenticator did not return a PRF secret")]
    NoPrfSecret,

    #[error("the authenticator returned {0} bytes of PRF secret rather than 32")]
    PrfSecretLength(u32),

    #[error("this platform has no WebAuthn support")]
    Unsupported,

    #[error("the platform refused the request (HRESULT 0x{0:08X})")]
    Platform(u32),
}
