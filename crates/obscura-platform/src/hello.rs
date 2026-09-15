#![cfg_attr(
    not(target_os = "windows"),
    allow(dead_code, clippy::unnecessary_wraps)
)]

use obscura_crypto::SecretBytes;

use crate::error::PlatformError;

const HKDF_INFO: &[u8] = b"obscura/windows-hello/slot-seed/v1";

const CHALLENGE: &[u8] = b"obscura/windows-hello/challenge/v1";

const FINGERPRINT_INFO: &[u8] = b"obscura/windows-hello/public-fingerprint/v1";

#[must_use]
pub fn credential_name(vault_id: &str) -> String {
    format!("Obscura/{vault_id}")
}

#[must_use]
fn fingerprint_of(public_key: &[u8]) -> String {
    match derive_fingerprint(public_key) {
        Ok(text) => text,
        Err(_) => "unavailable".to_owned(),
    }
}

fn derive_fingerprint(public_key: &[u8]) -> Result<String, PlatformError> {
    use std::fmt::Write as _;

    let digest = obscura_crypto::derive::subkey_from_ikm::<16>(public_key, None, FINGERPRINT_INFO)?;
    let mut text = String::with_capacity(35);
    for (index, byte) in digest.expose().iter().enumerate() {
        if index > 0 && index % 4 == 0 {
            text.push('-');
        }
        let _ = write!(text, "{byte:02X}");
    }
    Ok(text)
}

#[cfg(target_os = "windows")]
mod imp {
    use super::{credential_name, fingerprint_of, PlatformError, CHALLENGE, HKDF_INFO};
    use obscura_crypto::{derive, SecretBytes};
    use windows::{
        core::HSTRING,
        Security::Credentials::{
            KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
        },
        Security::Cryptography::CryptographicBuffer,
        Storage::Streams::DataReader,
    };

    fn win(error: windows::core::Error) -> PlatformError {
        #[allow(clippy::cast_sign_loss)]
        PlatformError::Platform(error.code().0 as u32)
    }

    fn status_error(status: KeyCredentialStatus) -> PlatformError {
        if status == KeyCredentialStatus::UserCanceled
            || status == KeyCredentialStatus::UserPrefersPassword
        {
            PlatformError::Cancelled
        } else if status == KeyCredentialStatus::NotFound {
            PlatformError::CredentialMissing
        } else if status == KeyCredentialStatus::SecurityDeviceLocked {
            PlatformError::DeviceLocked
        } else {
            PlatformError::UnknownStatus(status.0)
        }
    }

    pub fn is_available() -> Result<bool, PlatformError> {
        KeyCredentialManager::IsSupportedAsync()
            .map_err(win)?
            .get()
            .map_err(win)
    }

    fn buffer_bytes(buffer: &windows::Storage::Streams::IBuffer) -> Result<Vec<u8>, PlatformError> {
        let reader = DataReader::FromBuffer(buffer).map_err(win)?;
        let len = reader.UnconsumedBufferLength().map_err(win)?;
        let mut bytes = vec![0u8; len as usize];
        reader.ReadBytes(&mut bytes).map_err(win)?;
        Ok(bytes)
    }

    fn sign(credential: &KeyCredential) -> Result<Vec<u8>, PlatformError> {
        let challenge = CryptographicBuffer::CreateFromByteArray(CHALLENGE).map_err(win)?;
        let outcome = credential
            .RequestSignAsync(&challenge)
            .map_err(win)?
            .get()
            .map_err(win)?;

        let status = outcome.Status().map_err(win)?;
        if status != KeyCredentialStatus::Success {
            return Err(status_error(status));
        }
        let signature = outcome.Result().map_err(win)?;
        buffer_bytes(&signature)
    }

    fn seed_from(signature: &[u8]) -> Result<SecretBytes<32>, PlatformError> {
        Ok(derive::subkey_from_ikm::<32>(signature, None, HKDF_INFO)?)
    }

    fn delete(name: &HSTRING) {
        if let Ok(action) = KeyCredentialManager::DeleteAsync(name) {
            let _ = action.get();
        }
    }

    pub fn enroll(vault_id: &str) -> Result<SecretBytes<32>, PlatformError> {
        if !is_available()? {
            return Err(PlatformError::NotConfigured);
        }
        let name = HSTRING::from(credential_name(vault_id));

        let mut result = KeyCredentialManager::RequestCreateAsync(
            &name,
            KeyCredentialCreationOption::FailIfExists,
        )
        .map_err(win)?
        .get()
        .map_err(win)?;

        if result.Status().map_err(win)? == KeyCredentialStatus::CredentialAlreadyExists {
            delete(&name);
            result = KeyCredentialManager::RequestCreateAsync(
                &name,
                KeyCredentialCreationOption::FailIfExists,
            )
            .map_err(win)?
            .get()
            .map_err(win)?;
        }

        let status = result.Status().map_err(win)?;
        if status != KeyCredentialStatus::Success {
            return Err(status_error(status));
        }
        let credential = result.Credential().map_err(win)?;

        let first = sign(&credential)?;
        let second = sign(&credential)?;
        if first != second {
            delete(&name);
            return Err(PlatformError::NonDeterministicSignature);
        }

        seed_from(&first)
    }

    pub fn unlock(vault_id: &str) -> Result<SecretBytes<32>, PlatformError> {
        let name = HSTRING::from(credential_name(vault_id));
        let result = KeyCredentialManager::OpenAsync(&name)
            .map_err(win)?
            .get()
            .map_err(win)?;

        let status = result.Status().map_err(win)?;
        if status != KeyCredentialStatus::Success {
            return Err(status_error(status));
        }
        let credential = result.Credential().map_err(win)?;
        seed_from(&sign(&credential)?)
    }

    pub fn forget(vault_id: &str) -> Result<(), PlatformError> {
        delete(&HSTRING::from(credential_name(vault_id)));
        Ok(())
    }

    pub fn public_fingerprint_by_name(name: &str) -> Result<String, PlatformError> {
        let name = HSTRING::from(name);
        let result = KeyCredentialManager::OpenAsync(&name)
            .map_err(win)?
            .get()
            .map_err(win)?;

        let status = result.Status().map_err(win)?;
        if status != KeyCredentialStatus::Success {
            return Err(status_error(status));
        }
        let credential = result.Credential().map_err(win)?;
        let key = credential
            .RetrievePublicKeyWithDefaultBlobType()
            .map_err(win)?;
        Ok(fingerprint_of(&buffer_bytes(&key)?))
    }

    pub fn forget_by_name(name: &str) -> Result<(), PlatformError> {
        delete(&HSTRING::from(name));
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
mod imp {
    use super::{PlatformError, SecretBytes};

    pub fn is_available() -> Result<bool, PlatformError> {
        Ok(false)
    }

    pub fn enroll(_vault_id: &str) -> Result<SecretBytes<32>, PlatformError> {
        Err(PlatformError::Unsupported)
    }

    pub fn unlock(_vault_id: &str) -> Result<SecretBytes<32>, PlatformError> {
        Err(PlatformError::Unsupported)
    }

    pub fn forget(_vault_id: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }

    pub fn public_fingerprint_by_name(_name: &str) -> Result<String, PlatformError> {
        Err(PlatformError::Unsupported)
    }

    pub fn forget_by_name(_name: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }
}

pub fn is_available() -> Result<bool, PlatformError> {
    imp::is_available()
}

pub fn enroll(vault_id: &str) -> Result<SecretBytes<32>, PlatformError> {
    imp::enroll(vault_id)
}

pub fn unlock(vault_id: &str) -> Result<SecretBytes<32>, PlatformError> {
    imp::unlock(vault_id)
}

pub fn forget(vault_id: &str) -> Result<(), PlatformError> {
    imp::forget(vault_id)
}

pub fn public_fingerprint_by_name(name: &str) -> Result<String, PlatformError> {
    imp::public_fingerprint_by_name(name)
}

pub fn public_fingerprint(vault_id: &str) -> Result<String, PlatformError> {
    imp::public_fingerprint_by_name(&credential_name(vault_id))
}

pub fn forget_by_name(name: &str) -> Result<(), PlatformError> {
    imp::forget_by_name(name)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use obscura_crypto::derive;

    use super::*;

    #[test]
    fn credential_names_are_scoped_per_vault() {
        let a = credential_name("8f1c0000-0000-0000-0000-000000000001");
        let b = credential_name("8f1c0000-0000-0000-0000-000000000002");
        assert_ne!(a, b);
        assert!(a.starts_with("Obscura/"));
    }

    #[test]
    fn the_challenge_and_info_are_domain_separated() {
        assert_ne!(CHALLENGE, HKDF_INFO);
        assert!(CHALLENGE.starts_with(b"obscura/"));
        assert!(HKDF_INFO.starts_with(b"obscura/"));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn platforms_without_a_backend_say_so_rather_than_pretending() {
        assert_eq!(is_available(), Ok(false));
        assert_eq!(enroll("x").err(), Some(PlatformError::Unsupported));
        assert_eq!(unlock("x").err(), Some(PlatformError::Unsupported));
    }

    #[test]
    fn fingerprints_are_stable_readable_and_key_specific() {
        let key = [0x11u8; 270];
        assert_eq!(fingerprint_of(&key), fingerprint_of(&key));
        assert_ne!(fingerprint_of(&key), fingerprint_of(&[0x12u8; 270]));

        let text = fingerprint_of(&key);
        assert_eq!(text.len(), 35, "16 bytes as 32 hex digits and 3 dashes");
        assert_eq!(text.matches('-').count(), 3);
        assert!(text
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_lowercase() || c == '-'));
    }

    #[test]
    fn a_fingerprint_is_not_a_seed() {
        let material = [0x5au8; 64];
        let seed = derive::subkey_from_ikm::<16>(&material, None, HKDF_INFO).unwrap();
        let print = derive::subkey_from_ikm::<16>(&material, None, FINGERPRINT_INFO).unwrap();
        assert_ne!(seed.expose(), print.expose());
    }

    #[test]
    fn a_signature_derives_a_stable_seed() {
        let signature = [0x9au8; 256];
        let first = derive::subkey_from_ikm::<32>(&signature, None, HKDF_INFO).unwrap();
        let second = derive::subkey_from_ikm::<32>(&signature, None, HKDF_INFO).unwrap();
        assert_eq!(first.expose(), second.expose());

        let other = derive::subkey_from_ikm::<32>(&[0x9bu8; 256], None, HKDF_INFO).unwrap();
        assert_ne!(first.expose(), other.expose());
    }
}
