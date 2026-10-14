use core::fmt;

use obscura_memlock::Region;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Default)]
pub struct SecretString {
    text: String,
    region: Region,
}

impl SecretString {
    #[must_use]
    pub fn new(text: String) -> Self {
        let region = obscura_memlock::lock_range(text.as_ptr().addr(), text.capacity());
        Self { text, region }
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.text.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    #[must_use]
    pub const fn is_locked(&self) -> bool {
        self.region.is_locked()
    }
}

impl From<String> for SecretString {
    fn from(text: String) -> Self {
        Self::new(text)
    }
}

impl From<&str> for SecretString {
    fn from(text: &str) -> Self {
        Self::new(text.to_owned())
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self::new(self.text.clone())
    }
}

impl Zeroize for SecretString {
    fn zeroize(&mut self) {
        self.text.zeroize();
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

impl ZeroizeOnDrop for SecretString {}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.text)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.text.as_bytes().ct_eq(other.text.as_bytes()).into()
    }
}

impl Eq for SecretString {}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

pub(crate) struct SecretBuf {
    bytes: Vec<u8>,
    _region: Region,
}

impl SecretBuf {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        let region = obscura_memlock::lock_range(bytes.as_ptr().addr(), bytes.capacity());
        Self {
            bytes,
            _region: region,
        }
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.bytes
    }
}

impl Clone for SecretBuf {
    fn clone(&self) -> Self {
        Self::new(self.bytes.clone())
    }
}

impl Zeroize for SecretBuf {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl Serialize for SecretBuf {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretBuf {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Vec::<u8>::deserialize(deserializer).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_string_reports_the_text_it_was_given() {
        let secret = SecretString::from(String::from("hunter2"));
        assert_eq!(secret.expose(), "hunter2");
        assert_eq!((secret.len(), secret.is_empty()), (7, false));

        let empty = SecretString::from(String::new());
        assert_eq!(empty.expose(), "");
        assert_eq!((empty.len(), empty.is_empty()), (0, true));
    }

    #[test]
    fn a_secret_string_lives_in_locked_memory_and_so_does_its_copy() {
        obscura_memlock::harden();
        let secret = SecretString::from("correct horse battery staple");
        let copy = secret.clone();
        assert!(secret.is_locked());
        assert!(copy.is_locked());
        assert_eq!(copy, secret);
        assert!(!SecretString::default().is_locked());
    }

    #[test]
    fn a_secret_string_survives_a_round_trip_and_is_locked_again() {
        obscura_memlock::harden();
        let secret = SecretString::from("tamarind orbit");
        let json = serde_json::to_string(&secret).unwrap_or_default();
        assert_eq!(json, "\"tamarind orbit\"");
        let back: SecretString = serde_json::from_str(&json).unwrap_or_default();
        assert_eq!(back, secret);
        assert!(back.is_locked());
    }

    #[test]
    fn secret_bytes_keep_their_wire_form_and_are_locked() {
        let secret = SecretBuf::new(vec![1, 2, 3]);
        let json = serde_json::to_string(&secret).unwrap_or_default();
        assert_eq!(json, "[1,2,3]");
        let back: SecretBuf =
            serde_json::from_str(&json).unwrap_or_else(|_| SecretBuf::new(Vec::new()));
        let copy = back.clone();
        assert_eq!(copy.expose(), [1, 2, 3]);
        assert!(obscura_memlock::locked_pages() > 0);
    }
}
