use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroizing;

use crate::{error::CryptoError, secret::SecretKey};

pub const NONCE_LEN: usize = 24;

pub const TAG_LEN: usize = 16;

pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN;

pub fn seal(key: &SecretKey, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use rand_core::{OsRng, TryRngCore};

    let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
        .map_err(|_| CryptoError::Malformed("AEAD key"))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| CryptoError::Rng)?;
    let nonce = XNonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Authentication)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open(key: &SecretKey, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if sealed.len() < OVERHEAD {
        return Err(CryptoError::Authentication);
    }

    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);

    let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
        .map_err(|_| CryptoError::Malformed("AEAD key"))?;

    let nonce = XNonce::try_from(nonce_bytes).map_err(|_| CryptoError::Authentication)?;

    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Authentication)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )]

    use super::*;

    #[test]
    fn a_sealed_message_costs_exactly_the_stated_overhead() {
        let key = SecretKey::zeroed();
        let plaintext = b"a message of some length";
        let sealed = seal(&key, b"tag", plaintext).expect("sealing");
        assert_eq!(sealed.len(), plaintext.len() + OVERHEAD);
        assert_eq!(OVERHEAD, 40);
    }

    #[test]
    fn an_empty_message_seals_to_exactly_the_overhead_and_still_opens() {
        let key = SecretKey::zeroed();
        let sealed = seal(&key, b"tag", b"").expect("sealing");
        assert_eq!(sealed.len(), OVERHEAD);

        let opened = open(&key, b"tag", &sealed).expect("opening a sealed empty message");
        assert!(opened.is_empty());

        assert!(open(&key, b"tag", &sealed[..OVERHEAD - 1]).is_err());
    }
}
