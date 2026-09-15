use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

pub const KEY_LEN: usize = 32;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecretBytes<N> {
    #[must_use]
    pub const fn zeroed() -> Self {
        Self { bytes: [0u8; N] }
    }

    #[must_use]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    pub fn random() -> Result<Self, CryptoError> {
        use rand_core::{OsRng, TryRngCore};
        let mut out = Self::zeroed();
        OsRng
            .try_fill_bytes(&mut out.bytes)
            .map_err(|_| CryptoError::Rng)?;
        Ok(out)
    }

    pub fn try_from_slice(slice: &[u8], what: &'static str) -> Result<Self, CryptoError> {
        let bytes: [u8; N] = slice.try_into().map_err(|_| CryptoError::Malformed(what))?;
        Ok(Self { bytes })
    }

    #[must_use]
    pub const fn expose(&self) -> &[u8; N] {
        &self.bytes
    }

    #[must_use]
    pub const fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        N
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> ConstantTimeEq for SecretBytes<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

impl<const N: usize> core::fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretBytes<{N}>(<redacted>)")
    }
}

pub type SecretKey = SecretBytes<KEY_LEN>;
