use subtle::ConstantTimeEq;

use crate::secret::SecretKey;

pub const TAG_LEN: usize = 32;

#[must_use]
pub fn tag(key: &SecretKey, data: &[u8]) -> [u8; TAG_LEN] {
    *blake3::keyed_hash(key.expose(), data).as_bytes()
}

#[must_use]
pub fn verify(key: &SecretKey, data: &[u8], expected: &[u8; TAG_LEN]) -> bool {
    tag(key, data).ct_eq(expected).into()
}
