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

pub struct LockedBytes<const N: usize> {
    value: Box<SecretBytes<N>>,
    region: obscura_memlock::Region,
}

impl<const N: usize> LockedBytes<N> {
    #[must_use]
    pub fn copy_of(source: &SecretBytes<N>) -> Self {
        let mut value = Box::new(SecretBytes::zeroed());
        let region = obscura_memlock::lock(&*value);
        value.expose_mut().copy_from_slice(source.expose());
        Self { value, region }
    }

    pub fn random() -> Result<Self, CryptoError> {
        use rand_core::{OsRng, TryRngCore};
        let mut value = Box::new(SecretBytes::zeroed());
        let region = obscura_memlock::lock(&*value);
        OsRng
            .try_fill_bytes(value.expose_mut())
            .map_err(|_| CryptoError::Rng)?;
        Ok(Self { value, region })
    }

    #[must_use]
    pub const fn is_locked(&self) -> bool {
        self.region.is_locked()
    }
}

impl<const N: usize> core::ops::Deref for LockedBytes<N> {
    type Target = SecretBytes<N>;

    fn deref(&self) -> &SecretBytes<N> {
        &self.value
    }
}

impl<const N: usize> Drop for LockedBytes<N> {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl<const N: usize> ZeroizeOnDrop for LockedBytes<N> {}

impl<const N: usize> core::fmt::Debug for LockedBytes<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "LockedBytes<{N}>(<redacted>)")
    }
}

pub type LockedKey = LockedBytes<KEY_LEN>;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_reports_the_size_it_was_given() {
        let full = SecretBytes::<32>::zeroed();
        let none = SecretBytes::<0>::zeroed();
        assert_eq!((full.len(), full.is_empty()), (32, false));
        assert_eq!((none.len(), none.is_empty()), (0, true));
    }

    #[test]
    fn a_locked_copy_holds_the_same_bytes_in_locked_memory() {
        let source = SecretKey::from_bytes([7u8; KEY_LEN]);
        let locked = LockedKey::copy_of(&source);
        assert!(locked.is_locked());
        assert_eq!(*locked, source);
        assert_eq!(format!("{locked:?}"), "LockedBytes<32>(<redacted>)");
    }

    #[test]
    fn a_random_locked_key_is_locked_and_not_zero() {
        let key = LockedKey::random().unwrap();
        assert!(key.is_locked());
        assert_ne!(*key, SecretKey::zeroed());
    }
}
