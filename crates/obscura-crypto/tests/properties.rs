#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use obscura_crypto::{
    aead, derive, hybrid, kdf, mac,
    secret::{SecretBytes, SecretKey},
    CryptoError,
};

const TEST_PARAMS: kdf::KdfParams = kdf::KdfParams {
    m_cost_kib: 64 * 1024,
    t_cost: 2,
    p_cost: 1,
};

#[test]
fn aead_round_trips() {
    let key = SecretKey::random().unwrap();
    let sealed = aead::seal(&key, b"header", b"attack at dawn").unwrap();
    assert_eq!(
        aead::open(&key, b"header", &sealed).unwrap(),
        b"attack at dawn"
    );
}

#[test]
fn aead_rejects_a_different_key() {
    let sealed = aead::seal(&SecretKey::random().unwrap(), b"", b"secret").unwrap();
    let other = SecretKey::random().unwrap();
    assert_eq!(
        aead::open(&other, b"", &sealed).unwrap_err(),
        CryptoError::Authentication
    );
}

#[test]
fn aead_rejects_mismatched_associated_data() {
    let key = SecretKey::random().unwrap();
    let sealed = aead::seal(&key, b"vault-v3", b"secret").unwrap();
    assert_eq!(
        aead::open(&key, b"vault-v2", &sealed).unwrap_err(),
        CryptoError::Authentication
    );
}

#[test]
fn aead_rejects_a_flip_of_any_single_bit() {
    let key = SecretKey::random().unwrap();
    let sealed = aead::seal(&key, b"aad", b"the quick brown fox").unwrap();

    for byte in 0..sealed.len() {
        for bit in 0..8u8 {
            let mut corrupted = sealed.clone();
            corrupted[byte] ^= 1 << bit;
            assert!(
                aead::open(&key, b"aad", &corrupted).is_err(),
                "flipping bit {bit} of byte {byte} was not detected"
            );
        }
    }
}

#[test]
fn aead_rejects_truncated_input() {
    let key = SecretKey::random().unwrap();
    for len in 0..aead::OVERHEAD {
        assert!(aead::open(&key, b"", &vec![0u8; len]).is_err());
    }
}

#[test]
fn aead_never_reuses_a_nonce() {
    let key = SecretKey::random().unwrap();
    let a = aead::seal(&key, b"", b"same plaintext").unwrap();
    let b = aead::seal(&key, b"", b"same plaintext").unwrap();
    assert_ne!(a, b, "identical plaintexts produced identical ciphertexts");
    assert_ne!(a[..aead::NONCE_LEN], b[..aead::NONCE_LEN]);
}

#[test]
fn kdf_is_deterministic_and_salt_sensitive() {
    let a = kdf::derive_key(b"password", &[1; 16], TEST_PARAMS).unwrap();
    let b = kdf::derive_key(b"password", &[1; 16], TEST_PARAMS).unwrap();
    let c = kdf::derive_key(b"password", &[2; 16], TEST_PARAMS).unwrap();

    assert_eq!(a, b);
    assert_ne!(a, c, "a different salt must give a different key");
}

#[test]
fn kdf_refuses_weak_parameters() {
    let weak_memory = kdf::KdfParams {
        m_cost_kib: 8 * 1024,
        ..TEST_PARAMS
    };
    let weak_time = kdf::KdfParams {
        t_cost: 1,
        ..TEST_PARAMS
    };
    let no_lanes = kdf::KdfParams {
        p_cost: 0,
        ..TEST_PARAMS
    };

    assert!(weak_memory.validate().is_err());
    assert!(weak_time.validate().is_err());
    assert!(no_lanes.validate().is_err());
    assert!(kdf::derive_key(b"pw", &[0; 16], weak_memory).is_err());
}

#[test]
fn default_parameters_are_safe() {
    assert!(kdf::KdfParams::default().validate().is_ok());
}

#[test]
fn salts_are_unpredictable() {
    assert_ne!(kdf::random_salt().unwrap(), kdf::random_salt().unwrap());
}

#[cfg(feature = "calibrate")]
#[test]
fn calibration_never_returns_unsafe_parameters() {
    assert!(kdf::calibrate(1).validate().is_ok());
    assert!(kdf::calibrate(500).validate().is_ok());
}

#[test]
fn subkeys_are_domain_separated() {
    let vault_key = SecretKey::random().unwrap();
    let one = derive::subkey::<32>(&vault_key, None, b"obscura/entry/aaaa").unwrap();
    let two = derive::subkey::<32>(&vault_key, None, b"obscura/entry/bbbb").unwrap();
    let index = derive::subkey::<32>(&vault_key, None, b"obscura/index/v1").unwrap();

    assert_ne!(one, two);
    assert_ne!(one, index);
}

#[test]
fn subkeys_of_different_lengths_are_supported() {
    let key = SecretKey::random().unwrap();
    assert_eq!(derive::subkey::<64>(&key, None, b"x").unwrap().len(), 64);
    assert_eq!(derive::subkey::<16>(&key, None, b"x").unwrap().len(), 16);
}

#[test]
fn mac_verifies_and_detects_tampering() {
    let key = SecretKey::random().unwrap();
    let header = b"version=1;m_cost=262144;t_cost=3";
    let tag = mac::tag(key_ref(&key), header);

    assert!(mac::verify(&key, header, &tag));
    assert!(!mac::verify(&key, b"version=1;m_cost=8192;t_cost=1", &tag));
    assert!(!mac::verify(&SecretKey::random().unwrap(), header, &tag));
}

fn key_ref(k: &SecretKey) -> &SecretKey {
    k
}

#[test]
fn hybrid_kem_round_trips() {
    let identity = hybrid::HybridSecretKey::generate().unwrap();
    let public = identity.public_key().unwrap();

    let (ciphertext, sent) = public.encapsulate().unwrap();
    let received = identity.decapsulate(&ciphertext).unwrap();

    assert_eq!(sent, received);
}

#[test]
fn hybrid_kem_gives_a_different_secret_to_the_wrong_holder() {
    let alice = hybrid::HybridSecretKey::generate().unwrap();
    let mallory = hybrid::HybridSecretKey::generate().unwrap();

    let (ciphertext, sent) = alice.public_key().unwrap().encapsulate().unwrap();

    let wrong = mallory.decapsulate(&ciphertext).unwrap();
    assert_ne!(sent, wrong);
}

#[test]
fn the_combiner_binds_the_whole_transcript() {
    let identity = hybrid::HybridSecretKey::generate().unwrap();
    let public = identity.public_key().unwrap();

    let (ct_a, secret_a) = public.encapsulate().unwrap();
    let (ct_b, secret_b) = public.encapsulate().unwrap();

    let mut spliced = ct_a.to_bytes();
    spliced[hybrid::X25519_LEN..].copy_from_slice(&ct_b.to_bytes()[hybrid::X25519_LEN..]);

    let ct_spliced = hybrid::HybridCiphertext::from_bytes(&spliced).unwrap();
    let derived = identity.decapsulate(&ct_spliced).unwrap();

    assert_ne!(derived, secret_a);
    assert_ne!(derived, secret_b);
}

#[test]
fn hybrid_encodings_round_trip_and_reject_bad_lengths() {
    let identity = hybrid::HybridSecretKey::generate().unwrap();
    let public = identity.public_key().unwrap();
    let (ciphertext, _) = public.encapsulate().unwrap();

    assert_eq!(
        hybrid::HybridPublicKey::from_bytes(&public.to_bytes()).unwrap(),
        public
    );
    assert_eq!(
        hybrid::HybridCiphertext::from_bytes(&ciphertext.to_bytes()).unwrap(),
        ciphertext
    );

    assert!(hybrid::HybridPublicKey::from_bytes(&[0u8; 10]).is_err());
    assert!(hybrid::HybridCiphertext::from_bytes(&[0u8; 10]).is_err());
}

#[test]
fn wrapped_keys_round_trip() {
    let identity = hybrid::HybridSecretKey::generate().unwrap();
    let vault_key = SecretKey::random().unwrap();

    let wrapped = hybrid::wrap_key(
        &identity.public_key().unwrap(),
        &vault_key,
        b"slot:recovery",
    )
    .unwrap();
    let recovered = hybrid::unwrap_key(&identity, &wrapped, b"slot:recovery").unwrap();

    assert_eq!(vault_key, recovered);
}

#[test]
fn a_wrapped_key_cannot_be_moved_to_another_slot() {
    let identity = hybrid::HybridSecretKey::generate().unwrap();
    let vault_key = SecretKey::random().unwrap();

    let wrapped = hybrid::wrap_key(
        &identity.public_key().unwrap(),
        &vault_key,
        b"slot:recovery",
    )
    .unwrap();

    assert_eq!(
        hybrid::unwrap_key(&identity, &wrapped, b"slot:device-2").unwrap_err(),
        CryptoError::Authentication
    );
}

#[test]
fn a_wrapped_key_resists_the_wrong_identity_and_tampering() {
    let alice = hybrid::HybridSecretKey::generate().unwrap();
    let mallory = hybrid::HybridSecretKey::generate().unwrap();
    let vault_key = SecretKey::random().unwrap();

    let wrapped = hybrid::wrap_key(&alice.public_key().unwrap(), &vault_key, b"aad").unwrap();

    assert!(hybrid::unwrap_key(&mallory, &wrapped, b"aad").is_err());

    let mut corrupted = wrapped.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0x01;
    assert!(hybrid::unwrap_key(&alice, &corrupted, b"aad").is_err());

    assert!(hybrid::unwrap_key(&alice, &wrapped[..20], b"aad").is_err());
}

#[test]
fn secrets_never_print_their_contents() {
    let key = SecretKey::from_bytes([0xAB; 32]);
    let rendered = format!("{key:?}");

    assert!(!rendered.contains("171"));
    assert!(!rendered.contains("ab"));
    assert!(rendered.contains("redacted"));
}

#[test]
fn secrets_compare_by_value() {
    assert_eq!(
        SecretBytes::<32>::from_bytes([1; 32]),
        SecretBytes::<32>::from_bytes([1; 32])
    );
    assert_ne!(
        SecretBytes::<32>::from_bytes([1; 32]),
        SecretBytes::<32>::from_bytes([2; 32])
    );
}

#[test]
fn random_secrets_differ() {
    assert_ne!(SecretKey::random().unwrap(), SecretKey::random().unwrap());
}

#[test]
fn slice_conversion_checks_length() {
    assert!(SecretKey::try_from_slice(&[0u8; 32], "key").is_ok());
    assert!(SecretKey::try_from_slice(&[0u8; 31], "key").is_err());
    assert!(SecretKey::try_from_slice(&[0u8; 33], "key").is_err());
}
