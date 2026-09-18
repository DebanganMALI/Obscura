#![allow(unsafe_code)]

use obscura_crypto::derive;

#[cfg(target_os = "windows")]
mod imp;

#[cfg(not(target_os = "windows"))]
mod stub;

#[cfg(target_os = "windows")]
pub use imp::{api_version, console_window, enroll, prf_secret, transport_name};

#[cfg(not(target_os = "windows"))]
pub use stub::{api_version, enroll, prf_secret, transport_name};

pub const PRF_API_VERSION: u32 = 4;

pub const RP_ID: &str = "spike.obscura.invalid";

const SALT_INFO: &[u8] = b"obscura/passkey/salt/v1";

#[derive(Debug, Clone)]
pub struct Enrolled {
    pub credential_id: Vec<u8>,
    pub prf_enabled: bool,
    pub transport: u32,
}

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

    #[error(transparent)]
    Crypto(#[from] obscura_crypto::CryptoError),
}

#[must_use]
pub fn is_available() -> bool {
    api_version() >= PRF_API_VERSION
}

pub fn salt_for(vault_id: &str) -> Result<[u8; 32], WebAuthnError> {
    let derived = derive::subkey_from_ikm::<32>(vault_id.as_bytes(), None, SALT_INFO)?;
    Ok(*derived.expose())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::salt_for;

    #[test]
    fn a_salt_is_bound_to_the_vault_it_was_derived_for() {
        let one = "11111111-1111-1111-1111-111111111111";
        let two = "22222222-2222-2222-2222-222222222222";

        assert_eq!(
            salt_for(one).unwrap(),
            salt_for(one).unwrap(),
            "the same vault has to derive the same salt every time, or a passkey would open the \
             vault once and never again"
        );
        assert_ne!(
            salt_for(one).unwrap(),
            salt_for(two).unwrap(),
            "one phone credential enrolled against two vaults must derive a different key for \
             each, so opening one never yields the key to the other"
        );
    }
}
