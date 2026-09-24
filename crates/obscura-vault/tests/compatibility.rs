#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use obscura_vault::{Credential, RecoveryCode, Vault};

const VERSION_ONE: &[u8] = include_bytes!("fixtures/version-one.bin");

const PASSWORD: &[u8] = b"correct horse battery staple";

const RECOVERY: &str = "GCGTKCC3-7N838YC8-TSJE6QB0-156EJQP3-A673QH5E-Z6AWK6B7-G3CGZ858";

fn holds_what_was_written(vault: &Vault) {
    assert_eq!(vault.entries().len(), 1);
    let entry = &vault.entries()[0];
    assert_eq!(entry.title, "GitHub");
    assert_eq!(entry.username, "d-mali");
    assert_eq!(entry.password.expose(), "first-secret");
    assert_eq!(entry.urls, ["https://github.com"]);
    assert_eq!(entry.notes.expose(), "recovery email dmali@proton.me");
}

#[test]
fn a_version_one_vault_still_opens_with_its_password() {
    let vault = Vault::from_bytes(VERSION_ONE, &Credential::Password(PASSWORD), None).unwrap();
    holds_what_was_written(&vault);
}

#[test]
fn a_version_one_vault_still_opens_with_its_printed_recovery_code() {
    let identity = RecoveryCode::parse(RECOVERY).unwrap().identity();
    let vault = Vault::from_bytes(VERSION_ONE, &Credential::Identity(&identity), None).unwrap();
    holds_what_was_written(&vault);
}

#[test]
fn a_version_one_vault_refuses_a_wrong_password() {
    assert!(Vault::from_bytes(VERSION_ONE, &Credential::Password(b"wrong horse"), None).is_err());
}
