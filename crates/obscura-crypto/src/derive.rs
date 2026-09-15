use hkdf::Hkdf;
use sha2::Sha512;

use crate::{
    error::CryptoError,
    secret::{SecretBytes, SecretKey},
};

pub fn subkey<const N: usize>(
    ikm: &SecretKey,
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<SecretBytes<N>, CryptoError> {
    let hk = Hkdf::<Sha512>::new(salt, ikm.expose());
    let mut out = SecretBytes::<N>::zeroed();
    hk.expand(info, out.expose_mut())
        .map_err(|_| CryptoError::ExpandFailed)?;
    Ok(out)
}

pub fn subkey_from_ikm<const N: usize>(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<SecretBytes<N>, CryptoError> {
    let hk = Hkdf::<Sha512>::new(salt, ikm);
    let mut out = SecretBytes::<N>::zeroed();
    hk.expand(info, out.expose_mut())
        .map_err(|_| CryptoError::ExpandFailed)?;
    Ok(out)
}
