use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::HWND;
use windows::Win32::Networking::WindowsWebServices::{
    WebAuthNAuthenticatorGetAssertion, WebAuthNAuthenticatorMakeCredential, WebAuthNFreeAssertion,
    WebAuthNFreeCredentialAttestation, WebAuthNGetApiVersionNumber,
    WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
    WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM, WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION,
    WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG, WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION, WEBAUTHN_CLIENT_DATA,
    WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER, WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
    WEBAUTHN_CTAP_TRANSPORT_BLE, WEBAUTHN_CTAP_TRANSPORT_HYBRID, WEBAUTHN_CTAP_TRANSPORT_INTERNAL,
    WEBAUTHN_CTAP_TRANSPORT_NFC, WEBAUTHN_CTAP_TRANSPORT_USB, WEBAUTHN_HASH_ALGORITHM_SHA_256,
    WEBAUTHN_HMAC_SECRET_SALT, WEBAUTHN_HMAC_SECRET_SALT_VALUES, WEBAUTHN_RP_ENTITY_INFORMATION,
    WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION, WEBAUTHN_USER_ENTITY_INFORMATION,
    WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
};
use windows::Win32::System::Console::GetConsoleWindow;

use obscura_crypto::{derive, SecretBytes};

use crate::WebAuthnError;

const PRF_API_VERSION: u32 = 4;
const TIMEOUT_MS: u32 = 120_000;
const SECRET_LEN: u32 = 32;
const SALT_INFO: &[u8] = b"obscura/passkey/salt/v1";

pub const RP_ID: &str = "spike.obscura.invalid";

#[derive(Debug, Clone)]
pub struct Enrolled {
    pub credential_id: Vec<u8>,
    pub prf_enabled: bool,
    pub transport: u32,
}

#[allow(clippy::cast_sign_loss)]
fn win(error: &windows::core::Error) -> WebAuthnError {
    WebAuthnError::Platform(error.code().0 as u32)
}

fn client_data(kind: &str, rp_id: &str) -> Vec<u8> {
    format!("{{\"type\":\"{kind}\",\"challenge\":\"b2JzY3VyYQ\",\"origin\":\"https://{rp_id}\",\"crossOrigin\":false}}")
        .into_bytes()
}

#[must_use]
pub fn api_version() -> u32 {
    unsafe { WebAuthNGetApiVersionNumber() }
}

#[must_use]
pub fn console_window() -> isize {
    unsafe { GetConsoleWindow() }.0 as isize
}

fn window_handle(window: isize) -> HWND {
    HWND(window as *mut core::ffi::c_void)
}

#[must_use]
pub fn transport_name(transport: u32) -> &'static str {
    match transport {
        WEBAUTHN_CTAP_TRANSPORT_USB => "usb",
        WEBAUTHN_CTAP_TRANSPORT_NFC => "nfc",
        WEBAUTHN_CTAP_TRANSPORT_BLE => "ble",
        WEBAUTHN_CTAP_TRANSPORT_INTERNAL => "internal",
        WEBAUTHN_CTAP_TRANSPORT_HYBRID => "hybrid (phone over QR)",
        _ => "unrecognised",
    }
}

pub fn salt_for(vault_id: &str) -> Result<[u8; 32], WebAuthnError> {
    let derived = derive::subkey_from_ikm::<32>(vault_id.as_bytes(), None, SALT_INFO)?;
    Ok(*derived.expose())
}

pub fn enroll(
    window: isize,
    rp_id: &str,
    rp_name: &str,
    user_name: &str,
    user_id: &[u8],
) -> Result<Enrolled, WebAuthnError> {
    let version = api_version();
    if version < PRF_API_VERSION {
        return Err(WebAuthnError::ApiTooOld(version));
    }

    let rp_id_w = HSTRING::from(rp_id);
    let rp_name_w = HSTRING::from(rp_name);
    let user_w = HSTRING::from(user_name);
    let mut user_bytes = user_id.to_vec();
    let mut data = client_data("webauthn.create", rp_id);

    let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
        pwszId: PCWSTR(rp_id_w.as_ptr()),
        pwszName: PCWSTR(rp_name_w.as_ptr()),
        pwszIcon: PCWSTR::null(),
    };

    let user = WEBAUTHN_USER_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
        cbId: u32::try_from(user_bytes.len()).unwrap_or(0),
        pbId: user_bytes.as_mut_ptr(),
        pwszName: PCWSTR(user_w.as_ptr()),
        pwszIcon: PCWSTR::null(),
        pwszDisplayName: PCWSTR(user_w.as_ptr()),
    };

    let mut algorithms = [WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
        dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
    }];
    let cose = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
        cCredentialParameters: 1,
        pCredentialParameters: algorithms.as_mut_ptr(),
    };

    let client = WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: u32::try_from(data.len()).unwrap_or(0),
        pbClientDataJSON: data.as_mut_ptr(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };

    let options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
        dwTimeoutMilliseconds: TIMEOUT_MS,
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
        bRequireResidentKey: true.into(),
        dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
        dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        bEnablePrf: true.into(),
        ..Default::default()
    };

    let attestation = unsafe {
        WebAuthNAuthenticatorMakeCredential(
            window_handle(window),
            &raw const rp,
            &raw const user,
            &raw const cose,
            &raw const client,
            Some(&raw const options),
        )
    }
    .map_err(|error| win(&error))?;

    let outcome = unsafe {
        let made = &*attestation;
        if made.pbCredentialId.is_null() || made.cbCredentialId == 0 {
            Err(WebAuthnError::NoPrfSecret)
        } else {
            Ok(Enrolled {
                credential_id: std::slice::from_raw_parts(
                    made.pbCredentialId,
                    made.cbCredentialId as usize,
                )
                .to_vec(),
                prf_enabled: made.bPrfEnabled.as_bool(),
                transport: made.dwUsedTransport,
            })
        }
    };

    unsafe { WebAuthNFreeCredentialAttestation(Some(attestation)) };
    outcome
}

pub fn prf_secret(
    window: isize,
    rp_id: &str,
    salt: &[u8; 32],
) -> Result<SecretBytes<32>, WebAuthnError> {
    let rp_id_w = HSTRING::from(rp_id);
    let mut data = client_data("webauthn.get", rp_id);
    let mut salt_bytes = salt.to_vec();

    let mut hmac_salt = WEBAUTHN_HMAC_SECRET_SALT {
        cbFirst: SECRET_LEN,
        pbFirst: salt_bytes.as_mut_ptr(),
        cbSecond: 0,
        pbSecond: std::ptr::null_mut(),
    };

    let mut salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
        pGlobalHmacSalt: &raw mut hmac_salt,
        cCredWithHmacSecretSaltList: 0,
        pCredWithHmacSecretSaltList: std::ptr::null_mut(),
    };

    let client = WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: u32::try_from(data.len()).unwrap_or(0),
        pbClientDataJSON: data.as_mut_ptr(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };

    let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION,
        dwTimeoutMilliseconds: TIMEOUT_MS,
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
        dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
        dwFlags: WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG,
        pHmacSecretSaltValues: &raw mut salt_values,
        ..Default::default()
    };

    let assertion = unsafe {
        WebAuthNAuthenticatorGetAssertion(
            window_handle(window),
            PCWSTR(rp_id_w.as_ptr()),
            &raw const client,
            Some(&raw const options),
        )
    }
    .map_err(|error| win(&error))?;

    let outcome = unsafe {
        let given = &*assertion;
        if given.pHmacSecret.is_null() {
            Err(WebAuthnError::NoPrfSecret)
        } else {
            let secret = &*given.pHmacSecret;
            if secret.cbFirst != SECRET_LEN || secret.pbFirst.is_null() {
                Err(WebAuthnError::PrfSecretLength(secret.cbFirst))
            } else {
                let mut out = [0u8; 32];
                out.copy_from_slice(std::slice::from_raw_parts(
                    secret.pbFirst,
                    SECRET_LEN as usize,
                ));
                Ok(SecretBytes::from_bytes(out))
            }
        }
    };

    unsafe { WebAuthNFreeAssertion(assertion) };
    outcome
}
