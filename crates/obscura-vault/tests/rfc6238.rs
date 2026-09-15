#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unreadable_literal
)]

use obscura_vault::totp::{Totp, TotpAlgorithm};

const SEED1: &[u8] = b"12345678901234567890";
const SEED256: &[u8] = b"12345678901234567890123456789012";
const SEED512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

#[test]
fn rfc6238_appendix_b() {
    let cases: &[(u64, &str, &str, &str)] = &[
        (59, "94287082", "46119246", "90693936"),
        (1111111109, "07081804", "68084774", "25091201"),
        (1111111111, "14050471", "67062674", "99943326"),
        (1234567890, "89005924", "91819424", "93441116"),
        (2000000000, "69279037", "90698825", "38618901"),
        (20000000000, "65353130", "77737706", "47863826"),
    ];
    for &(t, want1, want256, want512) in cases {
        let a = Totp::new(SEED1.to_vec(), TotpAlgorithm::Sha1, 8, 30).unwrap();
        let b = Totp::new(SEED256.to_vec(), TotpAlgorithm::Sha256, 8, 30).unwrap();
        let c = Totp::new(SEED512.to_vec(), TotpAlgorithm::Sha512, 8, 30).unwrap();
        assert_eq!(a.code_at(t).unwrap(), want1, "SHA1 at t={t}");
        assert_eq!(b.code_at(t).unwrap(), want256, "SHA256 at t={t}");
        assert_eq!(c.code_at(t).unwrap(), want512, "SHA512 at t={t}");
    }
}
