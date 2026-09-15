use obscura_crypto::KdfParams;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::VaultError;

pub const MAGIC: &[u8; 8] = b"OBSCURA\0";

pub const FORMAT_VERSION: u16 = 1;

pub const MAX_HEADER_LEN: u32 = 1024 * 1024;

pub const PREFIX_LEN: usize = 8 + 2 + 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredKdf {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl From<KdfParams> for StoredKdf {
    fn from(value: KdfParams) -> Self {
        Self {
            m_cost_kib: value.m_cost_kib,
            t_cost: value.t_cost,
            p_cost: value.p_cost,
        }
    }
}

impl From<StoredKdf> for KdfParams {
    fn from(value: StoredKdf) -> Self {
        Self {
            m_cost_kib: value.m_cost_kib,
            t_cost: value.t_cost,
            p_cost: value.p_cost,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SlotKind {
    Password,
    Recovery,
    Hardware,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySlot {
    pub id: Uuid,
    pub kind: SlotKind,
    pub label: String,
    pub wrapped_key: Vec<u8>,
    pub public_key: Option<Vec<u8>>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl KeySlot {
    #[must_use]
    pub fn aad(&self, vault_id: Uuid) -> Vec<u8> {
        let mut aad = Vec::with_capacity(64);
        aad.extend_from_slice(b"obscura/slot/v1/");
        aad.extend_from_slice(vault_id.as_bytes());
        aad.extend_from_slice(self.id.as_bytes());
        aad
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultHeader {
    pub vault_id: Uuid,
    pub kdf: StoredKdf,
    pub salt: [u8; 16],
    pub revision: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub slots: Vec<KeySlot>,
}

pub fn encode_header(header: &VaultHeader) -> Result<Vec<u8>, VaultError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(header, &mut bytes)
        .map_err(|_| VaultError::Corrupt("the header could not be encoded"))?;
    Ok(bytes)
}

pub fn decode_header(file: &[u8]) -> Result<(VaultHeader, Vec<u8>, usize), VaultError> {
    let magic = file
        .get(0..8)
        .ok_or(VaultError::Corrupt("the file is shorter than the magic"))?;
    if magic != MAGIC {
        return Err(VaultError::BadMagic);
    }

    let version_bytes: [u8; 2] = file
        .get(8..10)
        .and_then(|s| s.try_into().ok())
        .ok_or(VaultError::Corrupt("truncated version field"))?;
    let version = u16::from_le_bytes(version_bytes);
    if version != FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion(version));
    }

    let len_bytes: [u8; 4] = file
        .get(10..PREFIX_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(VaultError::Corrupt("truncated header length"))?;
    let header_len = u32::from_le_bytes(len_bytes);

    if header_len > MAX_HEADER_LEN {
        return Err(VaultError::Corrupt("the header length is implausible"));
    }
    let header_len = header_len as usize;
    let body_start = PREFIX_LEN + header_len;

    let header_bytes = file
        .get(PREFIX_LEN..body_start)
        .ok_or(VaultError::Corrupt("the header is truncated"))?
        .to_vec();

    let header: VaultHeader = ciborium::from_reader(header_bytes.as_slice())
        .map_err(|_| VaultError::Corrupt("the header could not be decoded"))?;

    Ok((header, header_bytes, body_start))
}

pub fn encode_prefix(header_len: usize) -> Result<Vec<u8>, VaultError> {
    let len = u32::try_from(header_len)
        .ok()
        .filter(|&l| l <= MAX_HEADER_LEN)
        .ok_or(VaultError::Corrupt("the header is too large to store"))?;

    let mut prefix = Vec::with_capacity(PREFIX_LEN);
    prefix.extend_from_slice(MAGIC);
    prefix.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    prefix.extend_from_slice(&len.to_le_bytes());
    Ok(prefix)
}

#[must_use]
pub fn body_aad(prefix: &[u8], header_bytes: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(prefix.len() + header_bytes.len());
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(header_bytes);
    aad
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedEntry {
    pub id: Uuid,
    pub blob: Vec<u8>,
}

#[must_use]
pub fn entry_aad(vault_id: Uuid, entry_id: Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(48);
    aad.extend_from_slice(b"obscura/entry/v1/");
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(entry_id.as_bytes());
    aad
}
