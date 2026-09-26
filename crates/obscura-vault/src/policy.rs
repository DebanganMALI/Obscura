use std::collections::HashSet;
use std::sync::LazyLock;

pub const MIN_PASSWORD_CHARS: usize = 15;

const APP_NAME: &str = "obscura";

const COMMON: &str = include_str!("common-passwords.txt");

static COMMON_SORTED: LazyLock<Vec<&'static str>> = LazyLock::new(|| COMMON.lines().collect());

const ROWS: [&str; 9] = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiopasdfghjklzxcvbnm",
    "1234567890qwertyuiopasdfghjklzxcvbnm",
    "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p",
    "qazwsxedcrfvtgbyhnujmikolp",
    "qwertzuiopasdfghjklyxcvbnm",
    "`1234567890-=",
    "~!@#$%^&*()_+",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Weakness {
    TooShort,
    Common,
    Repetitive,
    Sequential,
    AppName,
}

impl Weakness {
    #[must_use]
    pub fn describe(self, label: &str) -> String {
        match self {
            Self::TooShort => {
                format!("the {label} must be at least {MIN_PASSWORD_CHARS} characters")
            }
            Self::Common => format!("the {label} is on a list of commonly used passwords"),
            Self::Repetitive => format!("the {label} repeats itself too much"),
            Self::Sequential => format!("the {label} is a run of neighbouring keys or letters"),
            Self::AppName => format!("the {label} leans on the name of this app"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assessment {
    pub score: u8,
    pub weakness: Option<Weakness>,
}

#[must_use]
pub fn weakness(password: &str) -> Option<Weakness> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Some(Weakness::TooShort);
    }
    let lower = password.to_lowercase();
    if let Some(found) = shape_of(&lower) {
        return Some(found);
    }
    if lower.contains(APP_NAME) {
        let rest = lower.replace(APP_NAME, "");
        if compact(&rest).chars().count() < MIN_PASSWORD_CHARS || shape_of(&rest).is_some() {
            return Some(Weakness::AppName);
        }
    }
    None
}

#[must_use]
pub fn assess(password: &str) -> Assessment {
    if password.is_empty() {
        return Assessment {
            score: 0,
            weakness: None,
        };
    }
    let weakness = weakness(password);
    let score = if weakness.is_some() {
        1
    } else {
        match estimated_bits(password) {
            bits if bits < 80.0 => 2,
            bits if bits < 110.0 => 3,
            _ => 4,
        }
    };
    Assessment { score, weakness }
}

fn shape_of(lower: &str) -> Option<Weakness> {
    let compact = compact(lower);
    if is_common(lower) || is_common(&compact) {
        return Some(Weakness::Common);
    }
    if distinct(lower) < 5 || repeats(lower) || repeats(&compact) {
        return Some(Weakness::Repetitive);
    }
    if along_a_row(lower) || along_a_row(&compact) {
        return Some(Weakness::Sequential);
    }
    None
}

fn is_separator(c: char) -> bool {
    c.is_whitespace() || matches!(c, '-' | '_' | '.' | ',' | '/' | '+')
}

fn compact(lower: &str) -> String {
    lower.chars().filter(|c| !is_separator(*c)).collect()
}

fn is_common(candidate: &str) -> bool {
    !candidate.is_empty() && COMMON_SORTED.binary_search(&candidate).is_ok()
}

fn distinct(text: &str) -> usize {
    text.chars().collect::<HashSet<char>>().len()
}

fn repeats(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let total = chars.len();
    (1..MIN_PASSWORD_CHARS.min(total)).any(|unit| {
        total.is_multiple_of(unit)
            && chars
                .chunks(unit)
                .zip(chars.chunks(unit).skip(1))
                .all(|(a, b)| a == b)
    })
}

fn along_a_row(text: &str) -> bool {
    if text.chars().count() < 4 {
        return false;
    }
    ROWS.iter().any(|row| {
        let forward = row.repeat(3);
        let backward: String = forward.chars().rev().collect();
        forward.contains(text) || backward.contains(text)
    })
}

#[allow(clippy::cast_precision_loss)]
fn estimated_bits(password: &str) -> f64 {
    let mut pool = 0_u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if password
        .chars()
        .any(|c| c.is_ascii() && !c.is_ascii_alphanumeric())
    {
        pool += 33;
    }
    if !password.is_ascii() {
        pool += 100;
    }
    password.chars().count() as f64 * f64::from(pool.max(2)).log2()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_list_is_sorted_lowercase_and_unique() {
        let lines: Vec<&str> = COMMON.lines().collect();
        assert!(lines.len() > 20_000);
        assert!(lines.windows(2).all(|pair| matches!(pair, [a, b] if a < b)));
        assert!(lines.iter().all(|line| *line == line.to_lowercase()));
    }

    #[test]
    fn length_is_counted_in_characters() {
        let bengali: String = ('\u{0995}'..='\u{09A3}').collect();
        assert_eq!(bengali.chars().count(), MIN_PASSWORD_CHARS);
        assert_eq!(weakness(&bengali), None);

        let short: String = bengali.chars().skip(1).collect();
        assert!(short.len() > MIN_PASSWORD_CHARS);
        assert_eq!(weakness(&short), Some(Weakness::TooShort));
    }

    #[test]
    fn common_passwords_are_refused_whatever_the_case_or_spacing() {
        assert_eq!(
            weakness("correcthorsebatterystaple"),
            Some(Weakness::Common)
        );
        assert_eq!(
            weakness("Correct Horse Battery Staple"),
            Some(Weakness::Common)
        );
        assert_eq!(
            weakness("correct-horse-battery-staple"),
            Some(Weakness::Common)
        );
        assert_eq!(weakness("i-l-o-v-e-y-o-u-1"), Some(Weakness::Common));
    }

    #[test]
    fn repetition_is_refused() {
        assert!(distinct("aaaaaaaaaaaaaaa") < 5);
        assert!(repeats("abababababababab"));
        assert!(repeats("sunflower7sunflower7"));
        assert!(!repeats("sunflower7sunflower8"));
        assert_eq!(weakness("marigold4 marigold4"), Some(Weakness::Repetitive));
        assert!(weakness("aaaaaaaaaaaaaaa").is_some());
    }

    #[test]
    fn runs_along_the_keyboard_or_alphabet_are_refused() {
        for run in [
            "abcdefghijklmnop",
            "ponmlkjihgfedcba",
            "1234567890123456",
            "qwertyuiopasdfgh",
            "1qaz2wsx3edc4rfv",
            "!@#$%^&*()",
            "xyzabcdefghijklm",
        ] {
            assert!(along_a_row(run), "{run}");
            assert!(
                run.len() < MIN_PASSWORD_CHARS || weakness(run).is_some(),
                "{run}"
            );
        }
        assert_eq!(weakness("m-n-o-p-q-r-s-t-u"), Some(Weakness::Sequential));
        assert!(!along_a_row("lanternmango"));
    }

    #[test]
    fn the_app_name_does_not_count() {
        assert_eq!(weakness("obscura obscura!"), Some(Weakness::AppName));
        assert_eq!(weakness("obscura12345678"), Some(Weakness::AppName));
        assert_eq!(weakness("obscura lantern mango quiet orbit"), None);
    }

    #[test]
    fn ordinary_passphrases_pass() {
        assert_eq!(weakness("lantern mango quiet orbit tamarind"), None);
        assert_eq!(weakness("Tr0ub4dor&3 walks a llama"), None);
    }

    #[test]
    fn the_score_follows_the_policy() {
        assert_eq!(assess("").score, 0);
        assert_eq!(assess("short").score, 1);
        assert_eq!(assess("correcthorsebatterystaple").score, 1);
        assert!(assess("lantern mango quiet orbit tamarind").score >= 3);
        assert_eq!(assess("lantern mango quiet orbit tamarind").weakness, None);
    }

    #[test]
    fn every_weakness_names_the_password_it_is_about() {
        for weakness in [
            Weakness::TooShort,
            Weakness::Common,
            Weakness::Repetitive,
            Weakness::Sequential,
            Weakness::AppName,
        ] {
            assert!(weakness.describe("new password").contains("new password"));
        }
        assert!(Weakness::TooShort
            .describe("master password")
            .contains(&MIN_PASSWORD_CHARS.to_string()));
    }
}
