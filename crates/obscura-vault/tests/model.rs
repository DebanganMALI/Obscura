#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unreadable_literal
)]

use obscura_vault::{
    generator::{generate_passphrase, generate_password, passphrase_entropy_bits, Separator},
    Entry, EntryKind, PasswordPolicy, SecretString, Totp, TotpAlgorithm,
};

#[test]
fn secret_strings_never_print_their_contents() {
    let secret = SecretString::from("hunter2");
    assert_eq!(format!("{secret:?}"), "SecretString(<redacted>)");
    assert_eq!(format!("{secret}"), "<redacted>");
    assert_eq!(secret.expose(), "hunter2");
}

#[test]
fn secret_strings_compare_by_value() {
    assert_eq!(SecretString::from("a"), SecretString::from("a"));
    assert_ne!(SecretString::from("a"), SecretString::from("b"));
    assert_ne!(SecretString::from("a"), SecretString::from("aa"));
}

#[test]
fn base32_secrets_round_trip_through_a_uri() {
    let totp = Totp::from_base32("JBSWY3DPEHPK3PXP", TotpAlgorithm::Sha1, 6, 30).unwrap();
    let uri = totp.to_uri();
    let parsed = Totp::from_uri(&uri).unwrap();

    assert_eq!(parsed.code_at(0).unwrap(), totp.code_at(0).unwrap());
    assert_eq!(parsed.digits(), 6);
    assert_eq!(parsed.period(), 30);
}

#[test]
fn base32_tolerates_how_issuers_actually_print_secrets() {
    let canonical = Totp::from_base32("JBSWY3DPEHPK3PXP", TotpAlgorithm::Sha1, 6, 30).unwrap();
    for variant in [
        "jbswy3dpehpk3pxp",
        "JBSW Y3DP EHPK 3PXP",
        "JBSWY3DP-EHPK3PXP",
        "JBSWY3DPEHPK3PXP====",
    ] {
        let parsed = Totp::from_base32(variant, TotpAlgorithm::Sha1, 6, 30).unwrap();
        assert_eq!(
            parsed.code_at(1234567890).unwrap(),
            canonical.code_at(1234567890).unwrap(),
            "variant {variant} did not decode to the same secret"
        );
    }
}

#[test]
fn invalid_base32_is_rejected() {
    assert!(Totp::from_base32("!!!!", TotpAlgorithm::Sha1, 6, 30).is_err());
    assert!(Totp::from_base32("", TotpAlgorithm::Sha1, 6, 30).is_err());
    assert!(Totp::from_base32("1", TotpAlgorithm::Sha1, 6, 30).is_err());
}

#[test]
fn otpauth_uris_carry_issuer_and_account() {
    let uri = "otpauth://totp/GitHub:saheb%40example.com\
               ?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60";
    let totp = Totp::from_uri(uri).unwrap();

    assert_eq!(totp.issuer(), Some("GitHub"));
    assert_eq!(totp.account(), Some("saheb@example.com"));
    assert_eq!(totp.algorithm(), TotpAlgorithm::Sha256);
    assert_eq!(totp.digits(), 8);
    assert_eq!(totp.period(), 60);
    assert_eq!(totp.code_at(0).unwrap().len(), 8);
}

#[test]
fn malformed_uris_are_rejected() {
    assert!(Totp::from_uri("https://example.com").is_err());
    assert!(Totp::from_uri("otpauth://totp/Acme?digits=6").is_err());
    assert!(Totp::from_uri("otpauth://hotp/Acme?secret=JBSWY3DPEHPK3PXP").is_err());
}

#[test]
fn totp_rejects_parameters_outside_the_spec() {
    assert!(Totp::new(b"seed".to_vec(), TotpAlgorithm::Sha1, 5, 30).is_err());
    assert!(Totp::new(b"seed".to_vec(), TotpAlgorithm::Sha1, 11, 30).is_err());
    assert!(Totp::new(b"seed".to_vec(), TotpAlgorithm::Sha1, 6, 0).is_err());
    assert!(Totp::new(Vec::new(), TotpAlgorithm::Sha1, 6, 30).is_err());
}

#[test]
fn codes_change_between_periods_and_hold_within_one() {
    let totp = Totp::from_base32("JBSWY3DPEHPK3PXP", TotpAlgorithm::Sha1, 6, 30).unwrap();
    assert_eq!(totp.code_at(0).unwrap(), totp.code_at(29).unwrap());
    assert_ne!(totp.code_at(29).unwrap(), totp.code_at(30).unwrap());
}

#[test]
fn totp_secrets_are_compared_in_constant_time_and_by_value() {
    let a = Totp::from_base32("JBSWY3DPEHPK3PXP", TotpAlgorithm::Sha1, 6, 30).unwrap();
    let b = Totp::from_base32("JBSWY3DPEHPK3PXP", TotpAlgorithm::Sha1, 6, 30).unwrap();
    let c = Totp::from_base32("KRSXG5DJNZTSA33O", TotpAlgorithm::Sha1, 6, 30).unwrap();
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn a_new_login_has_an_id_and_timestamps() {
    let entry = Entry::new_login("GitHub", "saheb");
    assert_eq!(entry.kind, EntryKind::Login);
    assert_eq!(entry.created_at, entry.updated_at);
    assert_eq!(entry.password_age_days(), Some(0));
    assert!(!entry.id.is_nil());
}

#[test]
fn entry_keys_are_bound_to_the_entry_id() {
    let a = Entry::new_login("A", "a");
    let b = Entry::new_login("B", "b");
    assert_ne!(a.key_info(), b.key_info());
    assert!(a.key_info().starts_with(b"obscura/entry/"));
}

#[test]
fn setting_a_password_stamps_its_own_timestamp() {
    let mut entry = Entry::new_login("GitHub", "saheb");
    let created = entry.created_at;

    entry.set_password("correct horse battery staple");

    assert_eq!(entry.password.expose(), "correct horse battery staple");
    assert!(entry.password_changed_at >= created);
    assert_eq!(entry.password_changed_at, entry.updated_at);
}

#[test]
fn editing_another_field_does_not_reset_password_age() {
    let mut entry = Entry::new_login("GitHub", "saheb");
    entry.set_password("secret");
    let password_stamp = entry.password_changed_at;

    entry.title = "GitHub (work)".to_owned();
    entry.touch();

    assert_eq!(entry.password_changed_at, password_stamp);
    assert!(entry.updated_at >= password_stamp);
}

#[test]
fn search_covers_metadata_but_never_the_password() {
    let mut entry = Entry::new_login("GitHub", "saheb@example.com");
    entry.urls.push("https://github.com/login".to_owned());
    entry.tags.push("work".to_owned());
    entry.set_password("zzzsecretzzz");

    assert!(entry.matches("github"));
    assert!(entry.matches("GITHUB"));
    assert!(entry.matches("example.com"));
    assert!(entry.matches("work"));
    assert!(entry.matches(""));

    assert!(!entry.matches("zzzsecretzzz"));
}

#[test]
fn oversized_fields_are_rejected() {
    let mut entry = Entry::new_login("GitHub", "saheb");
    assert!(entry.validate().is_ok());

    entry.title = "x".repeat(obscura_vault::entry::MAX_FIELD_LEN + 1);
    assert!(entry.validate().is_err());
}

#[test]
fn generated_passwords_match_the_requested_length() {
    for length in [1usize, 8, 20, 64, 128] {
        let policy = PasswordPolicy {
            length,
            require_each_class: false,
            ..PasswordPolicy::default()
        };
        assert_eq!(generate_password(&policy).unwrap().chars().count(), length);
    }
}

#[test]
fn required_classes_are_always_present() {
    let policy = PasswordPolicy::default();
    for _ in 0..200 {
        let password = generate_password(&policy).unwrap();
        assert!(password.chars().any(char::is_lowercase), "{}", &*password);
        assert!(password.chars().any(char::is_uppercase), "{}", &*password);
        assert!(
            password.chars().any(|c| c.is_ascii_digit()),
            "{}",
            &*password
        );
        assert!(
            password.chars().any(|c| c.is_ascii_punctuation()),
            "{}",
            &*password
        );
    }
}

#[test]
fn ambiguous_characters_can_be_excluded() {
    let policy = PasswordPolicy {
        length: 64,
        exclude_ambiguous: true,
        ..PasswordPolicy::default()
    };
    for _ in 0..50 {
        let password = generate_password(&policy).unwrap();
        assert!(
            !password.chars().any(|c| "0O1lI|".contains(c)),
            "{}",
            &*password
        );
    }
}

#[test]
fn every_character_in_the_set_is_reachable() {
    let policy = PasswordPolicy {
        length: 64,
        require_each_class: false,
        ..PasswordPolicy::default()
    };
    let charset: Vec<char> = policy.charset().iter().map(|&b| char::from(b)).collect();

    let mut seen = std::collections::HashSet::new();
    for _ in 0..400 {
        seen.extend(generate_password(&policy).unwrap().chars());
    }

    for expected in charset {
        assert!(seen.contains(&expected), "never generated {expected:?}");
    }
}

#[test]
fn successive_passwords_differ() {
    let policy = PasswordPolicy::default();
    let a = generate_password(&policy).unwrap();
    let b = generate_password(&policy).unwrap();
    assert_ne!(*a, *b);
}

#[test]
fn unsatisfiable_policies_are_rejected() {
    let no_classes = PasswordPolicy {
        lowercase: false,
        uppercase: false,
        digits: false,
        symbols: false,
        ..PasswordPolicy::default()
    };
    let zero_length = PasswordPolicy {
        length: 0,
        ..PasswordPolicy::default()
    };
    let too_short_for_classes = PasswordPolicy {
        length: 3,
        require_each_class: true,
        ..PasswordPolicy::default()
    };

    assert!(generate_password(&no_classes).is_err());
    assert!(generate_password(&zero_length).is_err());
    assert!(generate_password(&too_short_for_classes).is_err());
}

#[test]
fn entropy_matches_the_arithmetic() {
    let digits_only = PasswordPolicy {
        length: 10,
        lowercase: false,
        uppercase: false,
        digits: true,
        symbols: false,
        exclude_ambiguous: false,
        require_each_class: false,
    };
    assert!((digits_only.entropy_bits() - 33.219_280_948_873_62).abs() < 1e-9);

    assert!(PasswordPolicy::default().entropy_bits() > 128.0);
}

#[test]
fn passphrases_use_the_supplied_wordlist() {
    let words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"];

    let phrase = generate_passphrase(&words, 4, Separator::Hyphen, false).unwrap();
    assert_eq!(phrase.split('-').count(), 4);
    assert!(phrase.split('-').all(|w| words.contains(&w)));

    let capitalized = generate_passphrase(&words, 3, Separator::Space, true).unwrap();
    assert!(capitalized
        .split(' ')
        .all(|w| w.starts_with(char::is_uppercase)));

    assert!(generate_passphrase(&["only"], 3, Separator::Hyphen, false).is_err());
    assert!(generate_passphrase(&words, 0, Separator::Hyphen, false).is_err());
}

#[test]
fn passphrase_entropy_matches_the_eff_list() {
    let bits = passphrase_entropy_bits(7776, 6);
    assert!((bits - 77.549_1).abs() < 0.01, "got {bits}");
}
