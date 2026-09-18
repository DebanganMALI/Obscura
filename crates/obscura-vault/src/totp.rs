use hmac::{EagerHash, Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::VaultError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    fn parse(value: &str) -> Result<Self, VaultError> {
        match value.to_ascii_uppercase().as_str() {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            _ => Err(VaultError::OtpAuthUri("unsupported algorithm")),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Totp {
    secret: Vec<u8>,
    #[zeroize(skip)]
    algorithm: TotpAlgorithm,
    digits: u8,
    period: u64,
    #[zeroize(skip)]
    issuer: Option<String>,
    #[zeroize(skip)]
    account: Option<String>,
}

impl Totp {
    pub fn new(
        secret: Vec<u8>,
        algorithm: TotpAlgorithm,
        digits: u8,
        period: u64,
    ) -> Result<Self, VaultError> {
        if secret.is_empty() {
            return Err(VaultError::TotpConfig("the shared secret is empty"));
        }
        if !(6..=10).contains(&digits) {
            return Err(VaultError::TotpConfig("digits must be between 6 and 10"));
        }
        if period == 0 {
            return Err(VaultError::TotpConfig("period must be at least 1 second"));
        }
        Ok(Self {
            secret,
            algorithm,
            digits,
            period,
            issuer: None,
            account: None,
        })
    }

    pub fn from_base32(
        secret: &str,
        algorithm: TotpAlgorithm,
        digits: u8,
        period: u64,
    ) -> Result<Self, VaultError> {
        Self::new(base32_decode(secret)?, algorithm, digits, period)
    }

    #[must_use]
    pub const fn algorithm(&self) -> TotpAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub const fn digits(&self) -> u8 {
        self.digits
    }

    #[must_use]
    pub const fn period(&self) -> u64 {
        self.period
    }

    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    #[must_use]
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    pub fn code_at(&self, unix_seconds: u64) -> Result<String, VaultError> {
        let counter = unix_seconds / self.period;
        let message = counter.to_be_bytes();

        let digest = match self.algorithm {
            TotpAlgorithm::Sha1 => hmac_bytes::<Sha1>(&self.secret, &message)?,
            TotpAlgorithm::Sha256 => hmac_bytes::<Sha256>(&self.secret, &message)?,
            TotpAlgorithm::Sha512 => hmac_bytes::<Sha512>(&self.secret, &message)?,
        };

        Ok(truncate(&digest, self.digits))
    }

    pub fn current(&self) -> Result<(String, u64), VaultError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| VaultError::Clock)?
            .as_secs();
        let remaining = remaining_in_period(now, self.period);
        Ok((self.code_at(now)?, remaining))
    }

    pub fn from_uri(uri: &str) -> Result<Self, VaultError> {
        let rest = uri
            .strip_prefix("otpauth://totp/")
            .ok_or(VaultError::OtpAuthUri("expected an otpauth://totp/ URI"))?;

        let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
        let label = percent_decode(label);

        let mut secret = None;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut digits = 6u8;
        let mut period = 30u64;
        let mut issuer = None;

        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair
                .split_once('=')
                .ok_or(VaultError::OtpAuthUri("malformed query parameter"))?;
            let value = percent_decode(value);
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(value),
                "algorithm" => algorithm = TotpAlgorithm::parse(&value)?,
                "digits" => {
                    digits = value
                        .parse()
                        .map_err(|_| VaultError::OtpAuthUri("digits is not a number"))?;
                }
                "period" => {
                    period = value
                        .parse()
                        .map_err(|_| VaultError::OtpAuthUri("period is not a number"))?;
                }
                "issuer" => issuer = Some(value),
                _ => {}
            }
        }

        let secret = secret.ok_or(VaultError::OtpAuthUri("no secret parameter"))?;
        let mut totp = Self::from_base32(&secret, algorithm, digits, period)?;

        let (label_issuer, account) = match label.split_once(':') {
            Some((i, a)) => (Some(i.trim().to_owned()), a.trim().to_owned()),
            None => (None, label.trim().to_owned()),
        };
        totp.issuer = issuer.or(label_issuer).filter(|s| !s.is_empty());
        totp.account = Some(account).filter(|s| !s.is_empty());

        Ok(totp)
    }

    #[must_use]
    pub fn to_uri(&self) -> String {
        let account = self.account.as_deref().unwrap_or("account");
        let label = match &self.issuer {
            Some(issuer) => format!("{issuer}:{account}"),
            None => account.to_owned(),
        };

        let mut uri = format!(
            "otpauth://totp/{}?secret={}&algorithm={}&digits={}&period={}",
            percent_encode(&label),
            base32_encode(&self.secret),
            self.algorithm.as_str(),
            self.digits,
            self.period
        );
        if let Some(issuer) = &self.issuer {
            uri.push_str("&issuer=");
            uri.push_str(&percent_encode(issuer));
        }
        uri
    }
}

impl PartialEq for Totp {
    fn eq(&self, other: &Self) -> bool {
        let secret_matches: bool = self.secret.ct_eq(&other.secret).into();
        secret_matches
            && self.algorithm == other.algorithm
            && self.digits == other.digits
            && self.period == other.period
            && self.issuer == other.issuer
            && self.account == other.account
    }
}

impl Eq for Totp {}

impl core::fmt::Debug for Totp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Totp")
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .finish()
    }
}

fn hmac_bytes<D: EagerHash>(key: &[u8], message: &[u8]) -> Result<Vec<u8>, VaultError> {
    let mut mac = <Hmac<D> as KeyInit>::new_from_slice(key)
        .map_err(|_| VaultError::TotpConfig("the shared secret is not a usable HMAC key"))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn truncate(digest: &[u8], digits: u8) -> String {
    let offset = (digest.last().copied().unwrap_or(0) & 0x0f) as usize;
    let [b0, b1, b2, b3] = digest
        .get(offset..offset + 4)
        .and_then(|window| <[u8; 4]>::try_from(window).ok())
        .unwrap_or([0; 4]);

    let binary =
        (u32::from(b0 & 0x7f) << 24) | (u32::from(b1) << 16) | (u32::from(b2) << 8) | u32::from(b3);

    let modulus = 10u64.pow(u32::from(digits));
    format!(
        "{:0width$}",
        u64::from(binary) % modulus,
        width = digits as usize
    )
}

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_decode(input: &str) -> Result<Vec<u8>, VaultError> {
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(input.len() * 5 / 8);

    for ch in input.chars() {
        if ch == '=' || ch.is_whitespace() || ch == '-' {
            continue;
        }
        let upper = ch.to_ascii_uppercase() as u8;
        let value = BASE32_ALPHABET
            .iter()
            .position(|&c| c == upper)
            .and_then(|index| u32::try_from(index).ok())
            .ok_or(VaultError::Base32)?;

        buffer = (buffer << 5) | value;
        bits += 5;

        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).map_err(|_| VaultError::Base32)?);
        }
    }

    if out.is_empty() {
        return Err(VaultError::Base32);
    }
    Ok(out)
}

fn symbol(index: usize) -> u8 {
    BASE32_ALPHABET.get(index).copied().unwrap_or(b'A')
}

fn base32_encode(input: &[u8]) -> String {
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = String::with_capacity(input.len().div_ceil(5) * 8);

    for &byte in input {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            out.push(char::from(symbol(index)));
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(char::from(symbol(index)));
    }
    out
}

fn percent_decode(input: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut bytes = input.bytes().peekable();

    while let Some(byte) = bytes.next() {
        match byte {
            b'%' => {
                let hi = bytes.peek().copied();
                let digits: Option<u8> = hi.and_then(|h| {
                    let mut lookahead = bytes.clone();
                    lookahead.next();
                    let lo = lookahead.peek().copied()?;
                    let pair = [h, lo];
                    let text = core::str::from_utf8(&pair).ok()?;
                    u8::from_str_radix(text, 16).ok()
                });
                if let Some(decoded) = digits {
                    out.push(decoded);
                    bytes.next();
                    bytes.next();
                } else {
                    out.push(b'%');
                }
            }
            b'+' => out.push(b' '),
            other => out.push(other),
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

fn percent_encode(input: &str) -> String {
    use core::fmt::Write as _;

    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

const fn remaining_in_period(now: u64, period: u64) -> u64 {
    period - (now % period)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod vectors {
    use super::*;

    const RFC4648: [(&str, &str); 6] = [
        ("f", "MY"),
        ("fo", "MZXQ"),
        ("foo", "MZXW6"),
        ("foob", "MZXW6YQ"),
        ("fooba", "MZXW6YTB"),
        ("foobar", "MZXW6YTBOI"),
    ];

    #[test]
    fn base32_matches_rfc4648_in_both_directions() {
        for (plain, encoded) in RFC4648 {
            assert_eq!(
                base32_encode(plain.as_bytes()),
                encoded,
                "encoding {plain:?} did not match the RFC vector"
            );
            assert_eq!(
                base32_decode(encoded).unwrap(),
                plain.as_bytes(),
                "decoding {encoded:?} did not match the RFC vector"
            );
        }
    }

    #[test]
    fn an_input_that_fills_the_last_group_gains_no_extra_symbol() {
        assert_eq!(base32_encode(b"").len(), 0);
        assert_eq!(base32_encode(b"fooba").len(), 8);
        assert_eq!(base32_encode(b"foobar").len(), 10);
    }

    #[test]
    fn every_algorithm_the_uri_may_name_is_understood() {
        assert_eq!(TotpAlgorithm::parse("SHA1").unwrap(), TotpAlgorithm::Sha1);
        assert_eq!(
            TotpAlgorithm::parse("SHA256").unwrap(),
            TotpAlgorithm::Sha256
        );
        assert_eq!(
            TotpAlgorithm::parse("SHA512").unwrap(),
            TotpAlgorithm::Sha512
        );
        assert_eq!(
            TotpAlgorithm::parse("sha512").unwrap(),
            TotpAlgorithm::Sha512
        );
        assert!(TotpAlgorithm::parse("MD5").is_err());

        for algorithm in [
            TotpAlgorithm::Sha1,
            TotpAlgorithm::Sha256,
            TotpAlgorithm::Sha512,
        ] {
            assert_eq!(TotpAlgorithm::parse(algorithm.as_str()).unwrap(), algorithm);
        }
    }

    #[test]
    fn a_sha512_uri_survives_the_round_trip() {
        let totp = Totp::from_uri(
            "otpauth://totp/Acme:me?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(totp.algorithm(), TotpAlgorithm::Sha512);
        assert_eq!(totp.digits(), 8);
        assert_eq!(totp.period(), 60);
        assert_eq!(totp.code_at(0).unwrap().len(), 8);
    }

    #[test]
    fn an_issuer_given_only_in_the_query_is_kept() {
        let totp =
            Totp::from_uri("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&issuer=Acme").unwrap();
        assert_eq!(totp.issuer(), Some("Acme"));
        assert_eq!(totp.account(), Some("Example"));
    }

    #[test]
    fn the_seconds_left_count_down_within_the_period() {
        assert_eq!(remaining_in_period(0, 30), 30);
        assert_eq!(remaining_in_period(1, 30), 29);
        assert_eq!(remaining_in_period(29, 30), 1);
        assert_eq!(remaining_in_period(30, 30), 30);
        assert_eq!(remaining_in_period(59, 30), 1);
        assert_eq!(remaining_in_period(7, 60), 53);
    }

    #[test]
    fn the_current_code_has_the_shape_the_entry_asked_for() {
        let totp = Totp::from_base32("JBSWY3DPEHPK3PXP", TotpAlgorithm::Sha1, 6, 30).unwrap();
        let (code, remaining) = totp.current().unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        assert!((1..=30).contains(&remaining));
    }

    #[test]
    fn a_label_is_escaped_only_where_it_has_to_be() {
        assert_eq!(percent_encode("abc123"), "abc123");
        assert_eq!(percent_encode("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(
            percent_encode("Acme Corp:me@example.test"),
            "Acme%20Corp%3Ame%40example.test"
        );
    }

    #[test]
    fn the_debug_form_redacts_the_secret_rather_than_printing_nothing() {
        let totp = Totp::from_base32("JBSWY3DPEHPK3PXP", TotpAlgorithm::Sha1, 6, 30).unwrap();
        let shown = format!("{totp:?}");
        assert!(shown.contains("<redacted>"));
        assert!(shown.contains("Sha1"));
    }
}
