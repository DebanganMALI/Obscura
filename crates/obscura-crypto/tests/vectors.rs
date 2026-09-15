#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use obscura_crypto::{
    derive, hybrid, kdf, mac,
    secret::{SecretBytes, SecretKey},
};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[test]
fn argon2id_construction_is_stable() {
    let params = kdf::KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 2,
        p_cost: 1,
    };
    let key = kdf::derive_key(b"correct horse battery staple", &[0x02; 16], params).unwrap();
    assert_eq!(
        hex(key.expose()),
        "3e9925bdec12b76d7547d582553e21251d1466950a634aaf27f153cac63c0512"
    );
}

#[test]
fn hkdf_construction_is_stable() {
    let ikm = SecretKey::from_bytes([0x42; 32]);

    let unsalted = derive::subkey::<32>(&ikm, None, b"obscura/test/a").unwrap();
    assert_eq!(
        hex(unsalted.expose()),
        "ca5c58716045db0c23123527d438c9488adc5a7c4f018550fd74ff23b9ac8930"
    );

    let salted = derive::subkey::<32>(&ikm, Some(&[0x01; 16]), b"obscura/test/a").unwrap();
    assert_eq!(
        hex(salted.expose()),
        "e2a286a2924de1e6a3fbf855558356a96bd75afbc0c4e4305c3d3776adba90bd"
    );
}

#[test]
fn blake3_mac_is_stable() {
    let key = SecretKey::from_bytes([0x07; 32]);
    assert_eq!(
        hex(&mac::tag(&key, b"obscura header")),
        "daf065e005ad7ee0ca18464cff7f38d9d1483deaaa00b1899bed544155ed90cf"
    );
}

#[test]
fn hybrid_encodings_have_the_sizes_fips203_specifies() {
    let identity = hybrid::HybridSecretKey::from_seed(SecretBytes::<32>::from_bytes([0x09; 32]));
    let public = identity.public_key().unwrap();

    assert_eq!(public.to_bytes().len(), hybrid::PUBLIC_KEY_LEN);
    assert_eq!(hybrid::PUBLIC_KEY_LEN, 32 + 1184);

    let (ciphertext, _) = public.encapsulate().unwrap();
    assert_eq!(ciphertext.to_bytes().len(), hybrid::CIPHERTEXT_LEN);
    assert_eq!(hybrid::CIPHERTEXT_LEN, 32 + 1088);
}

#[test]
fn a_seed_always_yields_the_same_identity() {
    let seed = SecretBytes::<32>::from_bytes([0x09; 32]);
    let a = hybrid::HybridSecretKey::from_seed(seed.clone())
        .public_key()
        .unwrap();
    let b = hybrid::HybridSecretKey::from_seed(seed)
        .public_key()
        .unwrap();

    assert_eq!(a.to_bytes(), b.to_bytes());
    assert_eq!(hex(&a.to_bytes()[..16]), "47a3f733908eac96097be8aa340af59c");
}
