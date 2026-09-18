use obscura_crypto::SecretBytes;

use crate::{Enrolled, WebAuthnError};

#[must_use]
pub const fn api_version() -> u32 {
    0
}

#[must_use]
pub const fn transport_name(_transport: u32) -> &'static str {
    "unsupported"
}

pub fn enroll(
    _window: isize,
    _rp_id: &str,
    _rp_name: &str,
    _user_name: &str,
    _user_id: &[u8],
) -> Result<Enrolled, WebAuthnError> {
    Err(WebAuthnError::Unsupported)
}

pub fn prf_secret(
    _window: isize,
    _rp_id: &str,
    _salt: &[u8; 32],
) -> Result<SecretBytes<32>, WebAuthnError> {
    Err(WebAuthnError::Unsupported)
}
