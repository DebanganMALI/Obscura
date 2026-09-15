use obscura_crypto::{hybrid::HybridSecretKey, mac, SecretBytes, SecretKey};
use zeroize::Zeroize as _;

use crate::error::VaultError;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const SEED_LEN: usize = 32;

const DATA_CHARS: usize = 52;

const CHECK_CHARS: usize = 4;

const GROUP: usize = 8;

const CHECKSUM_KEY: SecretKey = SecretBytes::from_bytes(*b"obscura-recovery-checksum-v1.0.0");

#[derive(Clone)]
pub struct RecoveryCode {
    seed: SecretBytes<SEED_LEN>,
}

impl RecoveryCode {
    #[must_use]
    pub const fn from_seed(seed: SecretBytes<SEED_LEN>) -> Self {
        Self { seed }
    }

    pub fn generate() -> Result<Self, VaultError> {
        Ok(Self {
            seed: SecretBytes::random()?,
        })
    }

    #[must_use]
    pub fn identity(&self) -> HybridSecretKey {
        HybridSecretKey::from_seed(self.seed.clone())
    }

    #[must_use]
    pub const fn seed(&self) -> &SecretBytes<SEED_LEN> {
        &self.seed
    }

    #[must_use]
    pub fn to_printable(&self) -> String {
        let mut body = encode(self.seed.expose());
        body.push_str(&checksum(&self.seed));

        let mut out = String::with_capacity(body.len() + body.len() / GROUP);
        for (i, ch) in body.chars().enumerate() {
            if i > 0 && i % GROUP == 0 {
                out.push('-');
            }
            out.push(ch);
        }
        body.zeroize();
        out
    }

    pub fn parse(text: &str) -> Result<Self, VaultError> {
        let mut symbols = Vec::with_capacity(DATA_CHARS + CHECK_CHARS);
        for ch in text.chars() {
            if ch.is_whitespace() || ch == '-' || ch == '_' {
                continue;
            }
            symbols.push(value_of(ch).ok_or(VaultError::RecoveryCodeFormat)?);
        }

        if symbols.len() != DATA_CHARS + CHECK_CHARS {
            return Err(VaultError::RecoveryCodeFormat);
        }

        let (data, check) = symbols.split_at(DATA_CHARS);
        let seed = decode(data)?;
        let code = Self { seed };

        let expected = checksum(&code.seed);
        let actual: String = check.iter().map(|&v| symbol(u16::from(v))).collect();
        if expected != actual {
            return Err(VaultError::RecoveryCodeChecksum);
        }

        Ok(code)
    }
}

impl core::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryCode(<redacted>)")
    }
}

fn symbol(value: u16) -> char {
    ALPHABET
        .get((value & 0x1f) as usize)
        .copied()
        .map_or('0', char::from)
}

fn value_of(ch: char) -> Option<u8> {
    let upper = ch.to_ascii_uppercase();
    match upper {
        'I' | 'L' => Some(1),
        'O' => Some(0),
        _ => ALPHABET
            .iter()
            .position(|&a| a == upper as u8)
            .and_then(|p| u8::try_from(p).ok()),
    }
}

fn encode(bytes: &[u8; SEED_LEN]) -> String {
    let mut out = String::with_capacity(DATA_CHARS);
    let mut acc: u16 = 0;
    let mut bits: u32 = 0;
    let mut next = 0usize;

    while out.len() < DATA_CHARS {
        if bits < 5 {
            let byte = bytes.get(next).copied().unwrap_or(0);
            next += 1;
            acc = (acc << 8) | u16::from(byte);
            bits += 8;
        }
        bits -= 5;
        out.push(symbol(acc >> bits));
    }
    out
}

fn decode(symbols: &[u8]) -> Result<SecretBytes<SEED_LEN>, VaultError> {
    let mut bytes = [0u8; SEED_LEN];
    let mut acc: u16 = 0;
    let mut bits: u32 = 0;
    let mut next = 0usize;

    for &symbol in symbols {
        acc = (acc << 5) | u16::from(symbol);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if let Some(slot) = bytes.get_mut(next) {
                *slot = ((acc >> bits) & 0xff) as u8;
                next += 1;
            }
        }
    }

    if next != SEED_LEN {
        bytes.zeroize();
        return Err(VaultError::RecoveryCodeFormat);
    }

    if bits > 0 && acc & ((1 << bits) - 1) != 0 {
        bytes.zeroize();
        return Err(VaultError::RecoveryCodeFormat);
    }

    let out = SecretBytes::from_bytes(bytes);
    bytes.zeroize();
    Ok(out)
}

fn checksum(seed: &SecretBytes<SEED_LEN>) -> String {
    let tag = mac::tag(&CHECKSUM_KEY, seed.expose());
    let mut out = String::with_capacity(CHECK_CHARS);
    let mut acc: u16 = 0;
    let mut bits: u32 = 0;
    let mut next = 0usize;

    while out.len() < CHECK_CHARS {
        if bits < 5 {
            acc = (acc << 8) | u16::from(tag.get(next).copied().unwrap_or(0));
            next += 1;
            bits += 8;
        }
        bits -= 5;
        out.push(symbol(acc >> bits));
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let code = RecoveryCode::generate().expect("rng");
        let text = code.to_printable();
        let back = RecoveryCode::parse(&text).expect("parse");
        assert_eq!(code.seed().expose(), back.seed().expose());
    }

    #[test]
    fn printable_shape_is_stable() {
        let code = RecoveryCode::from_seed(SecretBytes::from_bytes([0x5a; SEED_LEN]));
        let text = code.to_printable();
        assert_eq!(text.len(), DATA_CHARS + CHECK_CHARS + 6);
        assert_eq!(text.matches('-').count(), 6);
        for group in text.split('-') {
            assert_eq!(group.len(), GROUP);
        }
    }

    #[test]
    fn alphabet_excludes_confusable_characters() {
        for forbidden in ['I', 'L', 'O', 'U'] {
            assert!(!ALPHABET.contains(&(forbidden as u8)), "{forbidden}");
        }
    }

    #[test]
    fn accepts_any_reasonable_transcription() {
        let code = RecoveryCode::generate().expect("rng");
        let text = code.to_printable();

        for variant in [
            text.to_lowercase(),
            text.replace('-', ""),
            text.replace('-', " "),
            format!("  {text}  "),
            text.replace('-', "\n"),
        ] {
            let back = RecoveryCode::parse(&variant).expect("variant should parse");
            assert_eq!(code.seed().expose(), back.seed().expose());
        }
    }

    #[test]
    fn folds_confusable_characters() {
        let code = RecoveryCode::from_seed(SecretBytes::from_bytes([0u8; SEED_LEN]));
        let text = code.to_printable();
        let handwritten = text.replace('0', "O").replace('1', "l");
        let back = RecoveryCode::parse(&handwritten).expect("folds");
        assert_eq!(code.seed().expose(), back.seed().expose());
    }

    #[test]
    fn rejects_a_single_character_typo() {
        let code = RecoveryCode::generate().expect("rng");
        let text = code.to_printable();

        let mut caught = 0;
        for position in 0..text.len() {
            let ch = text.as_bytes()[position];
            if ch == b'-' {
                continue;
            }
            let replacement = if ch == b'0' { b'1' } else { b'0' };
            let mut bytes = text.clone().into_bytes();
            bytes[position] = replacement;
            let mangled = String::from_utf8(bytes).expect("ascii");

            match RecoveryCode::parse(&mangled) {
                Err(VaultError::RecoveryCodeChecksum | VaultError::RecoveryCodeFormat) => {
                    caught += 1;
                }
                Ok(_) => panic!("a one-character typo at {position} was accepted"),
                Err(other) => panic!("unexpected error: {other}"),
            }
        }
        assert_eq!(caught, DATA_CHARS + CHECK_CHARS);
    }

    #[test]
    fn rejects_wrong_length() {
        let code = RecoveryCode::generate().expect("rng");
        let text = code.to_printable();
        assert!(matches!(
            RecoveryCode::parse(&text[..text.len() - 1]),
            Err(VaultError::RecoveryCodeFormat)
        ));
        assert!(matches!(
            RecoveryCode::parse(&format!("{text}A")),
            Err(VaultError::RecoveryCodeFormat)
        ));
    }

    #[test]
    fn rejects_characters_outside_the_alphabet() {
        let code = RecoveryCode::generate().expect("rng");
        let text = code.to_printable().replacen(|c: char| c != '-', "!", 1);
        assert!(matches!(
            RecoveryCode::parse(&text),
            Err(VaultError::RecoveryCodeFormat)
        ));
    }

    #[test]
    fn debug_does_not_leak_the_seed() {
        let code = RecoveryCode::from_seed(SecretBytes::from_bytes([0xab; SEED_LEN]));
        let rendered = format!("{code:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("ab"));
    }

    #[test]
    fn distinct_codes_have_distinct_checksums() {
        let a = RecoveryCode::from_seed(SecretBytes::from_bytes([1u8; SEED_LEN]));
        let b = RecoveryCode::from_seed(SecretBytes::from_bytes([2u8; SEED_LEN]));
        assert_ne!(checksum(a.seed()), checksum(b.seed()));
    }
}
