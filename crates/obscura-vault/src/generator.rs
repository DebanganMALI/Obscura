use zeroize::Zeroizing;

use crate::error::VaultError;

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!#$%&()*+,-./:;<=>?@[]^_{|}~";

const AMBIGUOUS: &[u8] = b"0O1lI|";

const MAX_ATTEMPTS: usize = 4096;

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordPolicy {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
    pub require_each_class: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
            require_each_class: true,
        }
    }
}

impl PasswordPolicy {
    #[must_use]
    pub fn charset(&self) -> Vec<u8> {
        let mut set = Vec::with_capacity(96);
        for (enabled, class) in [
            (self.lowercase, LOWERCASE),
            (self.uppercase, UPPERCASE),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ] {
            if enabled {
                set.extend_from_slice(class);
            }
        }
        if self.exclude_ambiguous {
            set.retain(|c| !AMBIGUOUS.contains(c));
        }
        set
    }

    #[must_use]
    pub fn entropy_bits(&self) -> f64 {
        let size = self.charset().len();
        if size <= 1 || self.length == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        {
            (self.length as f64) * (size as f64).log2()
        }
    }

    pub fn validate(&self) -> Result<(), VaultError> {
        if self.length == 0 {
            return Err(VaultError::Policy("length must be at least 1"));
        }
        if self.length > 1024 {
            return Err(VaultError::Policy("length must be at most 1024"));
        }
        let enabled = usize::from(self.lowercase)
            + usize::from(self.uppercase)
            + usize::from(self.digits)
            + usize::from(self.symbols);
        if enabled == 0 {
            return Err(VaultError::Policy(
                "at least one character class is required",
            ));
        }
        if self.charset().len() < 2 {
            return Err(VaultError::Policy("the character set is too small"));
        }
        if self.require_each_class && self.length < enabled {
            return Err(VaultError::Policy(
                "length is shorter than the number of required classes",
            ));
        }
        Ok(())
    }
}

pub fn generate_password(policy: &PasswordPolicy) -> Result<Zeroizing<String>, VaultError> {
    policy.validate()?;
    let charset = policy.charset();

    let classes: Vec<&[u8]> = [
        (policy.lowercase, LOWERCASE),
        (policy.uppercase, UPPERCASE),
        (policy.digits, DIGITS),
        (policy.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter_map(|(enabled, class)| enabled.then_some(class))
    .collect();

    for _ in 0..MAX_ATTEMPTS {
        let mut out = Zeroizing::new(String::with_capacity(policy.length));
        for _ in 0..policy.length {
            let index = uniform_below(charset.len())?;
            let byte = charset
                .get(index)
                .copied()
                .ok_or(VaultError::Policy("character set changed while generating"))?;
            out.push(char::from(byte));
        }

        if !policy.require_each_class || has_every_class(&out, &classes, policy.exclude_ambiguous) {
            return Ok(out);
        }
    }

    Err(VaultError::Policy(
        "could not satisfy the policy; loosen the class requirements",
    ))
}

fn has_every_class(password: &str, classes: &[&[u8]], exclude_ambiguous: bool) -> bool {
    classes.iter().all(|class| {
        password
            .bytes()
            .any(|byte| class.contains(&byte) && !(exclude_ambiguous && AMBIGUOUS.contains(&byte)))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Separator {
    #[default]
    Hyphen,
    Space,
    Dot,
    None,
}

impl Separator {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Hyphen => "-",
            Self::Space => " ",
            Self::Dot => ".",
            Self::None => "",
        }
    }
}

pub fn generate_passphrase(
    wordlist: &[&str],
    words: usize,
    separator: Separator,
    capitalize: bool,
) -> Result<Zeroizing<String>, VaultError> {
    if wordlist.len() < 2 {
        return Err(VaultError::Policy("the wordlist needs at least two words"));
    }
    if words == 0 || words > 64 {
        return Err(VaultError::Policy("word count must be between 1 and 64"));
    }

    let mut out = Zeroizing::new(String::new());
    for i in 0..words {
        if i > 0 {
            out.push_str(separator.as_str());
        }
        let index = uniform_below(wordlist.len())?;
        let word = wordlist
            .get(index)
            .ok_or(VaultError::Policy("wordlist changed while generating"))?;
        if capitalize {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                out.extend(first.to_uppercase());
                out.push_str(chars.as_str());
            }
        } else {
            out.push_str(word);
        }
    }
    Ok(out)
}

#[must_use]
pub fn passphrase_entropy_bits(wordlist_len: usize, words: usize) -> f64 {
    if wordlist_len <= 1 || words == 0 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)]
    {
        (words as f64) * (wordlist_len as f64).log2()
    }
}

const fn rejection_limit(n: u32) -> u32 {
    (u32::MAX / n) * n
}

const fn reduce(value: u32, n: u32) -> Option<usize> {
    if value < rejection_limit(n) {
        Some((value % n) as usize)
    } else {
        None
    }
}

fn uniform_below(n: usize) -> Result<usize, VaultError> {
    use obscura_crypto::CryptoError;
    use rand_core::{OsRng, TryRngCore};

    let n_u32 = u32::try_from(n).map_err(|_| VaultError::Policy("range is too large"))?;
    if n_u32 == 0 {
        return Err(VaultError::Policy("range is empty"));
    }

    loop {
        let mut bytes = [0u8; 4];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| VaultError::Crypto(CryptoError::Rng))?;
        if let Some(index) = reduce(u32::from_le_bytes(bytes), n_u32) {
            return Ok(index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_classes(length: usize) -> PasswordPolicy {
        PasswordPolicy {
            length,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
            require_each_class: true,
        }
    }

    fn no_classes() -> PasswordPolicy {
        PasswordPolicy {
            length: 20,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
            require_each_class: false,
        }
    }

    #[test]
    fn entropy_is_zero_when_there_is_nothing_to_choose_from() {
        assert!(no_classes().entropy_bits().abs() < f64::EPSILON);
        assert!(all_classes(0).entropy_bits().abs() < f64::EPSILON);
        assert!(passphrase_entropy_bits(0, 5).abs() < f64::EPSILON);
        assert!(passphrase_entropy_bits(1, 5).abs() < f64::EPSILON);
        assert!(passphrase_entropy_bits(5, 0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_policy_with_no_character_classes_is_refused() {
        assert!(matches!(
            no_classes().validate(),
            Err(VaultError::Policy(
                "at least one character class is required"
            ))
        ));
    }

    #[test]
    fn the_length_bounds_are_accepted_at_their_edges_and_not_past_them() {
        assert!(all_classes(1024).validate().is_ok());
        assert!(matches!(
            all_classes(1025).validate(),
            Err(VaultError::Policy("length must be at most 1024"))
        ));
        assert!(matches!(
            all_classes(0).validate(),
            Err(VaultError::Policy("length must be at least 1"))
        ));
    }

    #[test]
    fn a_password_must_be_long_enough_to_hold_one_of_every_required_class() {
        assert!(all_classes(4).validate().is_ok());
        assert!(matches!(
            all_classes(3).validate(),
            Err(VaultError::Policy(
                "length is shorter than the number of required classes"
            ))
        ));
    }

    #[test]
    fn every_class_keeps_at_least_two_members_after_the_ambiguous_filter() {
        for (lowercase, uppercase, digits, symbols) in [
            (true, false, false, false),
            (false, true, false, false),
            (false, false, true, false),
            (false, false, false, true),
        ] {
            for exclude_ambiguous in [false, true] {
                let policy = PasswordPolicy {
                    length: 20,
                    lowercase,
                    uppercase,
                    digits,
                    symbols,
                    exclude_ambiguous,
                    require_each_class: false,
                };
                assert!(policy.charset().len() >= 2);
            }
        }
    }

    #[test]
    fn a_passphrase_needs_two_words_to_choose_from_and_at_most_sixty_four_words() {
        let list = ["alpha", "bravo"];
        assert!(generate_passphrase(&list, 1, Separator::Hyphen, false).is_ok());
        assert!(generate_passphrase(&list, 64, Separator::Hyphen, false).is_ok());
        assert!(matches!(
            generate_passphrase(&list, 65, Separator::Hyphen, false),
            Err(VaultError::Policy("word count must be between 1 and 64"))
        ));
        assert!(matches!(
            generate_passphrase(&list, 0, Separator::Hyphen, false),
            Err(VaultError::Policy("word count must be between 1 and 64"))
        ));
        assert!(matches!(
            generate_passphrase(&["only"], 4, Separator::Hyphen, false),
            Err(VaultError::Policy("the wordlist needs at least two words"))
        ));
    }

    #[test]
    fn the_rejection_limit_is_the_largest_whole_multiple_that_fits() {
        for n in [2u32, 3, 8, 26, 90, 1000, 65_536] {
            let limit = rejection_limit(n);
            assert_eq!(limit % n, 0, "the limit for {n} is not a whole multiple");
            assert!(
                limit > u32::MAX - n,
                "the limit for {n} discards more than one multiple"
            );
        }
    }

    #[test]
    fn a_value_at_or_above_the_limit_is_rejected_rather_than_folded() {
        let n = 26u32;
        let limit = rejection_limit(n);
        assert_eq!(reduce(limit, n), None);
        assert_eq!(reduce(u32::MAX, n), None);
        assert_eq!(reduce(limit - 1, n), Some(25));
        assert_eq!(reduce(0, n), Some(0));
        assert_eq!(reduce(n, n), Some(0));
        assert_eq!(reduce(n - 1, n), Some(25));
    }
}
