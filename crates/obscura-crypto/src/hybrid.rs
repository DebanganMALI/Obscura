use ml_kem::{
    array::Array,
    kem::{Decapsulate, Encapsulate, KeyExport, TryKeyInit},
    Ciphertext as KemCiphertext, EncapsulationKey, FromSeed, MlKem768,
};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XSecret};
use zeroize::Zeroize;

use crate::{
    aead,
    derive::subkey_from_ikm,
    error::CryptoError,
    secret::{SecretBytes, SecretKey},
};

pub const X25519_LEN: usize = 32;

pub const MLKEM_EK_LEN: usize = 1184;

pub const MLKEM_CT_LEN: usize = 1088;

pub const PUBLIC_KEY_LEN: usize = X25519_LEN + MLKEM_EK_LEN;

pub const CIPHERTEXT_LEN: usize = X25519_LEN + MLKEM_CT_LEN;

const INFO_X25519: &[u8] = b"obscura/hybrid/x25519/v1";
const INFO_MLKEM: &[u8] = b"obscura/hybrid/ml-kem-768/v1";
const INFO_COMBINE: &[u8] = b"obscura/hybrid/combine/v1";
const INFO_WRAP: &[u8] = b"obscura/hybrid/wrap/v1";

#[derive(Clone)]
pub struct HybridSecretKey {
    seed: SecretBytes<32>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct HybridPublicKey {
    x25519: [u8; X25519_LEN],
    mlkem: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct HybridCiphertext {
    x25519: [u8; X25519_LEN],
    mlkem: Vec<u8>,
}

impl HybridSecretKey {
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self {
            seed: SecretBytes::<32>::random()?,
        })
    }

    #[must_use]
    pub const fn from_seed(seed: SecretBytes<32>) -> Self {
        Self { seed }
    }

    #[must_use]
    pub const fn seed(&self) -> &SecretBytes<32> {
        &self.seed
    }

    fn x25519_secret(&self) -> Result<XSecret, CryptoError> {
        let derived = subkey_from_ikm::<32>(self.seed.expose(), None, INFO_X25519)?;
        Ok(XSecret::from(*derived.expose()))
    }

    fn mlkem_seed(&self) -> Result<SecretBytes<64>, CryptoError> {
        subkey_from_ikm::<64>(self.seed.expose(), None, INFO_MLKEM)
    }

    pub fn public_key(&self) -> Result<HybridPublicKey, CryptoError> {
        let x_secret = self.x25519_secret()?;
        let x_public = XPublicKey::from(&x_secret);

        let seed = self.mlkem_seed()?;
        let (_dk, ek) = MlKem768::from_seed(&Array(*seed.expose()));

        Ok(HybridPublicKey {
            x25519: *x_public.as_bytes(),
            mlkem: ek.to_bytes().to_vec(),
        })
    }

    pub fn decapsulate(&self, ct: &HybridCiphertext) -> Result<SecretKey, CryptoError> {
        let x_secret = self.x25519_secret()?;
        let peer = XPublicKey::from(ct.x25519);
        let mut x_shared = x_secret.diffie_hellman(&peer).to_bytes();

        let seed = self.mlkem_seed()?;
        let (dk, _ek) = MlKem768::from_seed(&Array(*seed.expose()));

        let kem_ct: KemCiphertext<MlKem768> = Array::try_from(ct.mlkem.as_slice())
            .map_err(|_| CryptoError::Malformed("ML-KEM ciphertext"))?;
        let mut kem_shared = dk.decapsulate(&kem_ct);

        let public = self.public_key()?;
        let result = combine(&x_shared, &kem_shared, ct, &public);

        x_shared.zeroize();
        kem_shared.zeroize();
        result
    }
}

impl HybridPublicKey {
    pub fn encapsulate(&self) -> Result<(HybridCiphertext, SecretKey), CryptoError> {
        let ephemeral_bytes = SecretBytes::<32>::random()?;
        let ephemeral = XSecret::from(*ephemeral_bytes.expose());
        let ephemeral_public = XPublicKey::from(&ephemeral);

        let peer = XPublicKey::from(self.x25519);
        let mut x_shared = ephemeral.diffie_hellman(&peer).to_bytes();

        let ek = EncapsulationKey::<MlKem768>::new_from_slice(&self.mlkem)
            .map_err(|_| CryptoError::Malformed("ML-KEM encapsulation key"))?;
        let (kem_ct, mut kem_shared) = ek.encapsulate();

        let ciphertext = HybridCiphertext {
            x25519: *ephemeral_public.as_bytes(),
            mlkem: kem_ct.to_vec(),
        };

        let shared = combine(&x_shared, &kem_shared, &ciphertext, self);

        x_shared.zeroize();
        kem_shared.zeroize();
        Ok((ciphertext, shared?))
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_KEY_LEN);
        out.extend_from_slice(&self.x25519);
        out.extend_from_slice(&self.mlkem);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::Malformed("hybrid public key"));
        }
        let (x, kem) = bytes.split_at(X25519_LEN);
        EncapsulationKey::<MlKem768>::new_from_slice(kem)
            .map_err(|_| CryptoError::Malformed("ML-KEM encapsulation key"))?;
        Ok(Self {
            x25519: x
                .try_into()
                .map_err(|_| CryptoError::Malformed("hybrid public key"))?,
            mlkem: kem.to_vec(),
        })
    }
}

impl HybridCiphertext {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CIPHERTEXT_LEN);
        out.extend_from_slice(&self.x25519);
        out.extend_from_slice(&self.mlkem);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != CIPHERTEXT_LEN {
            return Err(CryptoError::Malformed("hybrid ciphertext"));
        }
        let (x, kem) = bytes.split_at(X25519_LEN);
        Ok(Self {
            x25519: x
                .try_into()
                .map_err(|_| CryptoError::Malformed("hybrid ciphertext"))?,
            mlkem: kem.to_vec(),
        })
    }
}

fn combine(
    x_shared: &[u8; 32],
    kem_shared: &[u8],
    ct: &HybridCiphertext,
    pk: &HybridPublicKey,
) -> Result<SecretKey, CryptoError> {
    let mut ikm = Vec::with_capacity(32 + kem_shared.len());
    ikm.extend_from_slice(x_shared);
    ikm.extend_from_slice(kem_shared);

    let mut info = Vec::with_capacity(INFO_COMBINE.len() + CIPHERTEXT_LEN + PUBLIC_KEY_LEN);
    info.extend_from_slice(INFO_COMBINE);
    info.extend_from_slice(&ct.to_bytes());
    info.extend_from_slice(&pk.to_bytes());

    let result = subkey_from_ikm::<32>(&ikm, None, &info);
    ikm.zeroize();
    result
}

pub fn wrap_key(
    recipient: &HybridPublicKey,
    key: &SecretKey,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (ct, shared) = recipient.encapsulate()?;
    let wrapping_key = crate::derive::subkey::<32>(&shared, None, INFO_WRAP)?;
    let sealed = aead::seal(&wrapping_key, aad, key.expose())?;

    let mut out = Vec::with_capacity(CIPHERTEXT_LEN + sealed.len());
    out.extend_from_slice(&ct.to_bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

pub fn unwrap_key(
    identity: &HybridSecretKey,
    wrapped: &[u8],
    aad: &[u8],
) -> Result<SecretKey, CryptoError> {
    if wrapped.len() < CIPHERTEXT_LEN + aead::OVERHEAD {
        return Err(CryptoError::Malformed("wrapped key"));
    }
    let (ct_bytes, sealed) = wrapped.split_at(CIPHERTEXT_LEN);

    let ct = HybridCiphertext::from_bytes(ct_bytes)?;
    let shared = identity.decapsulate(&ct)?;
    let wrapping_key = crate::derive::subkey::<32>(&shared, None, INFO_WRAP)?;

    let plain = aead::open(&wrapping_key, aad, sealed)?;
    let key = SecretKey::try_from_slice(&plain, "wrapped key")?;
    Ok(key)
}

impl core::fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HybridSecretKey(<redacted>)")
    }
}

impl core::fmt::Debug for HybridPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HybridPublicKey")
    }
}

impl core::fmt::Debug for HybridCiphertext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HybridCiphertext")
    }
}

#[cfg(test)]
mod wrapped_key_bounds {
    use super::*;

    fn identity() -> HybridSecretKey {
        HybridSecretKey::from_seed(SecretBytes::zeroed())
    }

    #[test]
    fn a_buffer_one_byte_short_of_the_minimum_is_refused_on_length() {
        let wrapped = vec![0u8; CIPHERTEXT_LEN + aead::OVERHEAD - 1];
        let result = unwrap_key(&identity(), &wrapped, b"tag");
        assert!(
            matches!(result, Err(CryptoError::Malformed("wrapped key"))),
            "a buffer below the minimum was not refused on length"
        );
    }

    #[test]
    fn a_buffer_at_the_minimum_gets_past_the_length_check() {
        let wrapped = vec![0u8; CIPHERTEXT_LEN + aead::OVERHEAD];
        let result = unwrap_key(&identity(), &wrapped, b"tag");
        assert!(
            !matches!(result, Err(CryptoError::Malformed("wrapped key"))),
            "a buffer at the minimum was refused on length"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod redaction {
    use super::*;

    #[test]
    fn a_secret_key_says_it_is_redacted_rather_than_printing_nothing() {
        let identity = HybridSecretKey::from_seed(SecretBytes::zeroed());
        let shown = format!("{identity:?}");
        assert!(shown.contains("redacted"));
    }

    #[test]
    fn the_public_halves_describe_themselves_rather_than_printing_nothing() {
        let identity = HybridSecretKey::from_seed(SecretBytes::zeroed());
        let public = identity.public_key().unwrap();
        let ciphertext = HybridCiphertext::from_bytes(&[0u8; CIPHERTEXT_LEN]).unwrap();

        assert!(!format!("{public:?}").is_empty());
        assert!(!format!("{ciphertext:?}").is_empty());
    }
}
