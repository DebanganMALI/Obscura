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

#[test]
fn every_accepted_digit_count_produces_a_code_of_that_length() {
    for digits in 6..=10u8 {
        let totp = Totp::new(SEED1.to_vec(), TotpAlgorithm::Sha1, digits, 30).unwrap();
        let code = totp.code_at(59).unwrap();
        assert_eq!(
            code.len(),
            digits as usize,
            "digits={digits} produced {code:?}"
        );
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }
}

#[test]
fn ten_digits_does_not_overflow_the_modulus() {
    let totp = Totp::new(SEED1.to_vec(), TotpAlgorithm::Sha1, 10, 30).unwrap();
    assert_eq!(
        totp.code_at(59).unwrap(),
        "1094287082",
        "10^10 does not fit in u32, and with overflow-checks and panic=abort a release \
         build aborted the whole process on any otpauth URI carrying digits=10"
    );
}

#[test]
fn a_ten_digit_uri_round_trips_instead_of_aborting() {
    let uri = "otpauth://totp/Example:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
               &algorithm=SHA1&digits=10&period=30";
    let totp = Totp::from_uri(uri).unwrap();
    assert_eq!(totp.digits(), 10);
    assert_eq!(totp.code_at(59).unwrap().len(), 10);
}
