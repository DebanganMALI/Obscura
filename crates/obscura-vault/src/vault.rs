use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use obscura_crypto::{
    aead, derive,
    hybrid::{self, HybridSecretKey},
    kdf, mac, KdfParams, SecretBytes, SecretKey, KEY_LEN,
};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    entry::Entry,
    error::VaultError,
    format::{
        self, KeySlot, SealedEntry, SlotKind, StoredKdf, VaultHeader, FORMAT_VERSION, PREFIX_LEN,
    },
    recovery::RecoveryCode,
};

const WATERMARK_INFO: &[u8] = b"obscura/anti-rollback/v1";

fn watermark_data(vault_id: Uuid, revision: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(24);
    data.extend_from_slice(vault_id.as_bytes());
    data.extend_from_slice(&revision.to_le_bytes());
    data
}

#[cfg(unix)]
const OWNER_ONLY: u32 = 0o600;

#[cfg(unix)]
pub(crate) fn restrict_to_owner(path: &Path) -> Result<(), VaultError> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY)).map_err(|e| {
        VaultError::Io(format!(
            "cannot restrict permissions on {}: {e}",
            path.display()
        ))
    })
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn restrict_to_owner(_path: &Path) -> Result<(), VaultError> {
    Ok(())
}

#[must_use]
pub fn backup_path(vault: &Path) -> PathBuf {
    vault.with_extension("obscura.bak")
}

#[must_use]
pub fn temp_path(vault: &Path) -> PathBuf {
    vault.with_extension("obscura.tmp")
}

pub struct Vault {
    header: VaultHeader,
    key: SecretKey,
    entries: Vec<Entry>,
}

pub enum Credential<'a> {
    Password(&'a [u8]),
    Identity(&'a HybridSecretKey),
}

impl Vault {
    pub fn create(password: &[u8], kdf_params: KdfParams) -> Result<Self, VaultError> {
        kdf_params.validate()?;

        let vault_id = Uuid::new_v4();
        let salt = kdf::random_salt()?;
        let vault_key = SecretKey::random()?;
        let now = OffsetDateTime::now_utc();

        let mut slot = KeySlot {
            id: Uuid::new_v4(),
            kind: SlotKind::Password,
            label: "Master password".to_owned(),
            wrapped_key: Vec::new(),
            public_key: None,
            created_at: now,
        };

        let kek = kdf::derive_key(password, &salt, kdf_params)?;
        slot.wrapped_key = aead::seal(&kek, &slot.aad(vault_id), vault_key.expose())?;

        Ok(Self {
            header: VaultHeader {
                vault_id,
                kdf: StoredKdf::from(kdf_params),
                salt,
                revision: 1,
                created_at: now,
                updated_at: now,
                slots: vec![slot],
            },
            key: vault_key,
            entries: Vec::new(),
        })
    }

    pub fn open(
        path: &Path,
        credential: &Credential<'_>,
        minimum_revision: Option<u64>,
    ) -> Result<Self, VaultError> {
        let bytes =
            fs::read(path).map_err(|e| VaultError::Io(format!("cannot read vault: {e}")))?;
        Self::from_bytes(&bytes, credential, minimum_revision)
    }

    pub fn from_bytes(
        bytes: &[u8],
        credential: &Credential<'_>,
        minimum_revision: Option<u64>,
    ) -> Result<Self, VaultError> {
        let (header, header_bytes, body_start) = format::decode_header(bytes)?;

        if let Some(expected) = minimum_revision {
            if header.revision < expected {
                return Err(VaultError::Rollback {
                    found: header.revision,
                    expected,
                });
            }
        }

        let kdf_params = KdfParams::from(header.kdf);
        kdf_params.validate()?;

        let vault_key = unlock(&header, credential, kdf_params)?;

        let prefix = format::encode_prefix(header_bytes.len())?;
        let aad = format::body_aad(&prefix, &header_bytes);
        let body = bytes
            .get(body_start..)
            .ok_or(VaultError::Corrupt("the body is missing"))?;

        let plaintext = aead::open(&vault_key, &aad, body)?;
        let sealed: Vec<SealedEntry> = ciborium::from_reader(plaintext.as_slice())
            .map_err(|_| VaultError::Corrupt("the entry table could not be decoded"))?;

        let mut entries = Vec::with_capacity(sealed.len());
        for record in sealed {
            let key = entry_key(&vault_key, record.id)?;
            let aad = format::entry_aad(header.vault_id, record.id);
            let bytes = aead::open(&key, &aad, &record.blob)?;
            let entry: Entry = ciborium::from_reader(bytes.as_slice())
                .map_err(|_| VaultError::Corrupt("an entry could not be decoded"))?;
            entries.push(entry);
        }

        Ok(Self {
            header,
            key: vault_key,
            entries,
        })
    }

    pub fn to_bytes(&mut self) -> Result<Vec<u8>, VaultError> {
        for entry in &self.entries {
            entry.validate()?;
        }

        self.header.revision = self.header.revision.saturating_add(1);
        self.header.updated_at = OffsetDateTime::now_utc();

        let mut sealed = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let key = entry_key(&self.key, entry.id)?;
            let aad = format::entry_aad(self.header.vault_id, entry.id);
            let mut plaintext = Zeroizing::new(Vec::new());
            ciborium::into_writer(entry, &mut *plaintext)
                .map_err(|_| VaultError::Corrupt("an entry could not be encoded"))?;
            sealed.push(SealedEntry {
                id: entry.id,
                blob: aead::seal(&key, &aad, &plaintext)?,
            });
        }

        let mut table = Zeroizing::new(Vec::new());
        ciborium::into_writer(&sealed, &mut *table)
            .map_err(|_| VaultError::Corrupt("the entry table could not be encoded"))?;

        let header_bytes = format::encode_header(&self.header)?;
        let prefix = format::encode_prefix(header_bytes.len())?;
        let aad = format::body_aad(&prefix, &header_bytes);

        let body = aead::seal(&self.key, &aad, &table)?;

        let mut out = Vec::with_capacity(prefix.len() + header_bytes.len() + body.len());
        out.extend_from_slice(&prefix);
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub fn save(&mut self, path: &Path) -> Result<(), VaultError> {
        let bytes = self.to_bytes()?;

        let temp = temp_path(path);
        {
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(OWNER_ONLY);
            }
            let mut file = options
                .open(&temp)
                .map_err(|e| VaultError::Io(format!("cannot create temporary file: {e}")))?;
            file.write_all(&bytes)
                .map_err(|e| VaultError::Io(format!("cannot write vault: {e}")))?;
            file.sync_all()
                .map_err(|e| VaultError::Io(format!("cannot flush vault to disk: {e}")))?;
        }

        if path.exists() {
            let backup = backup_path(path);
            fs::copy(path, &backup)
                .map_err(|e| VaultError::Io(format!("cannot write backup: {e}")))?;
            restrict_to_owner(&backup)?;
        }

        fs::rename(&temp, path)
            .map_err(|e| VaultError::Io(format!("cannot replace vault: {e}")))?;
        Ok(())
    }

    pub fn add_identity_slot(
        &mut self,
        kind: SlotKind,
        label: impl Into<String>,
        identity: &HybridSecretKey,
    ) -> Result<Uuid, VaultError> {
        let public = identity.public_key()?;
        let mut slot = KeySlot {
            id: Uuid::new_v4(),
            kind,
            label: label.into(),
            wrapped_key: Vec::new(),
            public_key: Some(public.to_bytes()),
            created_at: OffsetDateTime::now_utc(),
        };
        slot.wrapped_key = hybrid::wrap_key(&public, &self.key, &slot.aad(self.header.vault_id))?;

        let id = slot.id;
        self.header.slots.push(slot);
        Ok(id)
    }

    pub fn add_recovery_slot(
        &mut self,
        label: impl Into<String>,
    ) -> Result<(Uuid, RecoveryCode), VaultError> {
        let code = RecoveryCode::generate()?;
        let id = self.add_identity_slot(SlotKind::Recovery, label, &code.identity())?;
        Ok((id, code))
    }

    #[must_use]
    pub fn portable_slots(&self) -> usize {
        self.header
            .slots
            .iter()
            .filter(|slot| matches!(slot.kind, SlotKind::Password | SlotKind::Recovery))
            .count()
    }

    pub fn accepts(&self, credential: &Credential<'_>) -> Result<bool, VaultError> {
        match unlock(&self.header, credential, KdfParams::from(self.header.kdf)) {
            Ok(key) => Ok(key == self.key),
            Err(VaultError::NoMatchingSlot) => Ok(false),
            Err(other) => Err(other),
        }
    }

    pub fn remove_slot(&mut self, id: Uuid) -> Result<(), VaultError> {
        if self.header.slots.len() <= 1 {
            return Err(VaultError::LastSlot);
        }

        let Some(target) = self.header.slots.iter().find(|slot| slot.id == id) else {
            return Err(VaultError::NoMatchingSlot);
        };
        let removing_portable = matches!(target.kind, SlotKind::Password | SlotKind::Recovery);

        if removing_portable && self.portable_slots() <= 1 {
            return Err(VaultError::LastPortableSlot);
        }

        self.header.slots.retain(|slot| slot.id != id);
        Ok(())
    }

    pub fn change_password(
        &mut self,
        new_password: &[u8],
        kdf_params: Option<KdfParams>,
    ) -> Result<(), VaultError> {
        let params = kdf_params.unwrap_or_else(|| KdfParams::from(self.header.kdf));
        params.validate()?;

        let salt = kdf::random_salt()?;
        let kek = kdf::derive_key(new_password, &salt, params)?;

        let vault_id = self.header.vault_id;
        let vault_key = self.key.clone();
        let mut rewrapped = 0usize;

        for slot in &mut self.header.slots {
            if slot.kind == SlotKind::Password {
                slot.wrapped_key = aead::seal(&kek, &slot.aad(vault_id), vault_key.expose())?;
                rewrapped += 1;
            }
        }

        if rewrapped == 0 {
            return Err(VaultError::NoMatchingSlot);
        }

        self.header.salt = salt;
        self.header.kdf = StoredKdf::from(params);
        Ok(())
    }

    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.header.vault_id
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.header.revision
    }

    pub fn watermark_tag(&self, revision: u64) -> Result<[u8; mac::TAG_LEN], VaultError> {
        let key = derive::subkey::<KEY_LEN>(&self.key, None, WATERMARK_INFO)?;
        Ok(mac::tag(
            &key,
            &watermark_data(self.header.vault_id, revision),
        ))
    }

    pub fn verify_watermark(
        &self,
        revision: u64,
        expected: &[u8; mac::TAG_LEN],
    ) -> Result<bool, VaultError> {
        let key = derive::subkey::<KEY_LEN>(&self.key, None, WATERMARK_INFO)?;
        Ok(mac::verify(
            &key,
            &watermark_data(self.header.vault_id, revision),
            expected,
        ))
    }

    #[must_use]
    pub fn slots(&self) -> &[KeySlot] {
        &self.header.slots
    }

    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&Entry> {
        self.entries.iter().filter(|e| e.matches(query)).collect()
    }

    #[must_use]
    pub fn get(&self, id: Uuid) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn get_mut(&mut self, id: Uuid) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.id == id)
    }

    pub fn add(&mut self, entry: Entry) -> Result<Uuid, VaultError> {
        entry.validate()?;
        let id = entry.id;
        self.entries.push(entry);
        Ok(id)
    }

    pub fn remove(&mut self, id: Uuid) -> Result<(), VaultError> {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        if self.entries.len() == before {
            return Err(VaultError::NoMatchingSlot);
        }
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl core::fmt::Debug for Vault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vault")
            .field("id", &self.header.vault_id)
            .field("revision", &self.header.revision)
            .field("entries", &self.entries.len())
            .field("slots", &self.header.slots.len())
            .field("key", &"<redacted>")
            .finish()
    }
}

fn unlock(
    header: &VaultHeader,
    credential: &Credential<'_>,
    kdf_params: KdfParams,
) -> Result<SecretKey, VaultError> {
    match credential {
        Credential::Password(password) => {
            let kek = kdf::derive_key(password, &header.salt, kdf_params)?;
            for slot in header.slots.iter().filter(|s| s.kind == SlotKind::Password) {
                if let Ok(bytes) = aead::open(&kek, &slot.aad(header.vault_id), &slot.wrapped_key) {
                    return Ok(SecretKey::try_from_slice(&bytes, "vault key")?);
                }
            }
            Err(VaultError::NoMatchingSlot)
        }
        Credential::Identity(identity) => {
            for slot in header.slots.iter().filter(|s| s.kind != SlotKind::Password) {
                if let Ok(key) =
                    hybrid::unwrap_key(identity, &slot.wrapped_key, &slot.aad(header.vault_id))
                {
                    return Ok(key);
                }
            }
            Err(VaultError::NoMatchingSlot)
        }
    }
}

fn entry_key(vault_key: &SecretKey, entry_id: Uuid) -> Result<SecretKey, VaultError> {
    let mut info = Vec::with_capacity(32);
    info.extend_from_slice(b"obscura/entry/");
    info.extend_from_slice(entry_id.as_bytes());
    let key: SecretBytes<32> = derive::subkey(vault_key, None, &info)?;
    Ok(key)
}

pub fn new_recovery_identity() -> Result<HybridSecretKey, VaultError> {
    Ok(HybridSecretKey::generate()?)
}

#[must_use]
pub const fn format_version() -> u16 {
    FORMAT_VERSION
}

#[must_use]
pub const fn prefix_len() -> usize {
    PREFIX_LEN
}
