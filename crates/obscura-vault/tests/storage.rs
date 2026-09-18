#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use obscura_crypto::KdfParams;
use obscura_vault::{
    backup_path,
    entry::Entry,
    format::{self, SlotKind},
    vault::{new_recovery_identity, Credential},
    Vault, VaultError,
};

const FAST: KdfParams = KdfParams {
    m_cost_kib: 64 * 1024,
    t_cost: 2,
    p_cost: 1,
};

const PASSWORD: &[u8] = b"correct horse battery staple";

fn seeded_vault() -> Vault {
    let mut vault = Vault::create(PASSWORD, FAST).unwrap();

    let mut github = Entry::new_login("GitHub", "saheb");
    github.set_password("first-secret");
    github.urls.push("https://github.com".to_owned());
    vault.add(github).unwrap();

    let mut bank = Entry::new_login("Bank", "saheb@example.com");
    bank.set_password("second-secret");
    vault.add(bank).unwrap();

    vault
}

fn scratch_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("obscura-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_vault_round_trips_through_bytes() {
    let mut vault = seeded_vault();
    let bytes = vault.to_bytes().unwrap();

    let reopened = Vault::from_bytes(&bytes, &Credential::Password(PASSWORD), None).unwrap();

    assert_eq!(reopened.len(), 2);
    assert_eq!(reopened.id(), vault.id());

    let github = reopened
        .entries()
        .iter()
        .find(|e| e.title == "GitHub")
        .unwrap();
    assert_eq!(github.password.expose(), "first-secret");
    assert_eq!(github.urls, vec!["https://github.com".to_owned()]);
}

#[test]
fn an_empty_vault_round_trips() {
    let mut vault = Vault::create(PASSWORD, FAST).unwrap();
    let bytes = vault.to_bytes().unwrap();
    let reopened = Vault::from_bytes(&bytes, &Credential::Password(PASSWORD), None).unwrap();
    assert!(reopened.is_empty());
}

#[test]
fn the_wrong_password_is_rejected() {
    let mut vault = seeded_vault();
    let bytes = vault.to_bytes().unwrap();

    assert_eq!(
        Vault::from_bytes(&bytes, &Credential::Password(b"wrong"), None).unwrap_err(),
        VaultError::NoMatchingSlot
    );
}

#[test]
fn editing_the_header_breaks_decryption() {
    let mut vault = seeded_vault();
    let bytes = vault.to_bytes().unwrap();

    for offset in [format::PREFIX_LEN, format::PREFIX_LEN + 5] {
        let mut corrupted = bytes.clone();
        corrupted[offset] ^= 0x01;
        assert!(
            Vault::from_bytes(&corrupted, &Credential::Password(PASSWORD), None).is_err(),
            "a flipped header byte at {offset} went undetected"
        );
    }
}

#[test]
fn editing_the_body_breaks_decryption() {
    let mut vault = seeded_vault();
    let bytes = vault.to_bytes().unwrap();

    let last = bytes.len() - 1;
    for offset in [bytes.len() - 40, last] {
        let mut corrupted = bytes.clone();
        corrupted[offset] ^= 0x01;
        assert!(
            Vault::from_bytes(&corrupted, &Credential::Password(PASSWORD), None).is_err(),
            "a flipped body byte at {offset} went undetected"
        );
    }
}

#[test]
fn a_body_cannot_be_moved_between_vaults() {
    let mut a = seeded_vault();
    let mut b = seeded_vault();

    let bytes_a = a.to_bytes().unwrap();
    let bytes_b = b.to_bytes().unwrap();

    let (_, header_a, body_start_a) = format::decode_header(&bytes_a).unwrap();
    let (_, _, body_start_b) = format::decode_header(&bytes_b).unwrap();

    let mut frankenstein = bytes_a[..body_start_a].to_vec();
    frankenstein.extend_from_slice(&bytes_b[body_start_b..]);
    assert_eq!(header_a.len() + format::PREFIX_LEN, body_start_a);

    assert!(Vault::from_bytes(&frankenstein, &Credential::Password(PASSWORD), None).is_err());
}

#[test]
fn a_file_that_is_not_a_vault_is_rejected() {
    assert_eq!(
        Vault::from_bytes(b"hello world", &Credential::Password(PASSWORD), None).unwrap_err(),
        VaultError::BadMagic
    );
    assert!(Vault::from_bytes(&[], &Credential::Password(PASSWORD), None).is_err());
}

#[test]
fn a_future_format_version_is_refused_rather_than_guessed() {
    let mut vault = seeded_vault();
    let mut bytes = vault.to_bytes().unwrap();
    bytes[8] = 99;

    assert_eq!(
        Vault::from_bytes(&bytes, &Credential::Password(PASSWORD), None).unwrap_err(),
        VaultError::UnsupportedVersion(99)
    );
}

#[test]
fn a_truncated_file_is_rejected() {
    let mut vault = seeded_vault();
    let bytes = vault.to_bytes().unwrap();

    for cut in [10, 14, 20, bytes.len() / 2] {
        assert!(
            Vault::from_bytes(&bytes[..cut], &Credential::Password(PASSWORD), None).is_err(),
            "a file truncated to {cut} bytes was accepted"
        );
    }
}

#[test]
fn saving_advances_the_revision() {
    let mut vault = seeded_vault();
    assert_eq!(vault.revision(), 1);

    vault.to_bytes().unwrap();
    assert_eq!(vault.revision(), 2);

    vault.to_bytes().unwrap();
    assert_eq!(vault.revision(), 3);
}

#[test]
fn an_older_file_is_refused_when_the_caller_knows_better() {
    let mut vault = seeded_vault();
    let old = vault.to_bytes().unwrap();
    vault.to_bytes().unwrap();

    assert_eq!(
        Vault::from_bytes(&old, &Credential::Password(PASSWORD), Some(3)).unwrap_err(),
        VaultError::Rollback {
            found: 2,
            expected: 3,
        }
    );

    assert!(Vault::from_bytes(&old, &Credential::Password(PASSWORD), Some(2)).is_ok());
}

#[test]
fn a_recovery_identity_opens_the_same_vault() {
    let mut vault = seeded_vault();
    let identity = new_recovery_identity().unwrap();
    vault
        .add_identity_slot(SlotKind::Recovery, "Printed recovery code", &identity)
        .unwrap();

    let bytes = vault.to_bytes().unwrap();
    let recovered = Vault::from_bytes(&bytes, &Credential::Identity(&identity), None).unwrap();

    assert_eq!(recovered.len(), 2);
    assert_eq!(recovered.slots().len(), 2);
}

#[test]
fn a_different_identity_cannot_open_a_recovery_slot() {
    let mut vault = seeded_vault();
    let real = new_recovery_identity().unwrap();
    let impostor = new_recovery_identity().unwrap();
    vault
        .add_identity_slot(SlotKind::Recovery, "recovery", &real)
        .unwrap();

    let bytes = vault.to_bytes().unwrap();
    assert_eq!(
        Vault::from_bytes(&bytes, &Credential::Identity(&impostor), None).unwrap_err(),
        VaultError::NoMatchingSlot
    );
}

#[test]
fn the_last_slot_cannot_be_removed() {
    let mut vault = seeded_vault();
    let only = vault.slots()[0].id;

    assert_eq!(vault.remove_slot(only).unwrap_err(), VaultError::LastSlot);
}

#[test]
fn removing_a_slot_revokes_exactly_that_credential() {
    let mut vault = seeded_vault();
    let identity = new_recovery_identity().unwrap();
    let slot = vault
        .add_identity_slot(SlotKind::Recovery, "recovery", &identity)
        .unwrap();

    vault.remove_slot(slot).unwrap();
    let bytes = vault.to_bytes().unwrap();

    assert!(Vault::from_bytes(&bytes, &Credential::Identity(&identity), None).is_err());
    assert!(Vault::from_bytes(&bytes, &Credential::Password(PASSWORD), None).is_ok());
}

#[test]
fn changing_the_password_keeps_the_entries() {
    let mut vault = seeded_vault();
    vault
        .change_password(b"a brand new passphrase", None)
        .unwrap();

    let bytes = vault.to_bytes().unwrap();

    assert!(Vault::from_bytes(&bytes, &Credential::Password(PASSWORD), None).is_err());

    let reopened = Vault::from_bytes(
        &bytes,
        &Credential::Password(b"a brand new passphrase"),
        None,
    )
    .unwrap();
    assert_eq!(reopened.len(), 2);
    assert_eq!(
        reopened
            .entries()
            .iter()
            .find(|e| e.title == "GitHub")
            .unwrap()
            .password
            .expose(),
        "first-secret"
    );
}

#[test]
fn changing_the_password_leaves_other_slots_working() {
    let mut vault = seeded_vault();
    let identity = new_recovery_identity().unwrap();
    vault
        .add_identity_slot(SlotKind::Recovery, "recovery", &identity)
        .unwrap();

    vault.change_password(b"rotated", None).unwrap();
    let bytes = vault.to_bytes().unwrap();

    assert!(Vault::from_bytes(&bytes, &Credential::Identity(&identity), None).is_ok());
    assert!(Vault::from_bytes(&bytes, &Credential::Password(b"rotated"), None).is_ok());
}

#[test]
fn weak_kdf_parameters_are_refused_on_change() {
    let mut vault = seeded_vault();
    let weak = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };
    assert!(vault.change_password(b"whatever", Some(weak)).is_err());
}

#[test]
fn entries_can_be_added_removed_and_searched() {
    let mut vault = seeded_vault();
    let id = vault.entries()[0].id;

    assert_eq!(vault.search("github").len(), 1);
    assert_eq!(vault.search("").len(), 2);
    assert!(vault.get(id).is_some());

    vault.remove(id).unwrap();
    assert_eq!(vault.len(), 1);
    assert!(vault.get(id).is_none());
    assert!(vault.remove(id).is_err());
}

#[test]
fn edits_survive_a_round_trip() {
    let mut vault = seeded_vault();
    let id = vault.entries()[0].id;

    vault.get_mut(id).unwrap().set_password("rotated-secret");
    let bytes = vault.to_bytes().unwrap();

    let reopened = Vault::from_bytes(&bytes, &Credential::Password(PASSWORD), None).unwrap();
    assert_eq!(
        reopened.get(id).unwrap().password.expose(),
        "rotated-secret"
    );
}

#[test]
fn every_entry_gets_its_own_key() {
    let mut vault = Vault::create(PASSWORD, FAST).unwrap();
    let mut a = Entry::new_login("Same", "same");
    a.set_password("identical");
    let mut b = Entry::new_login("Same", "same");
    b.set_password("identical");
    vault.add(a).unwrap();
    vault.add(b).unwrap();

    let bytes = vault.to_bytes().unwrap();
    let (_, _, body_start) = format::decode_header(&bytes).unwrap();
    let body = &bytes[body_start..];

    let midpoint = body.len() / 2;
    assert_ne!(body[..midpoint], body[midpoint..midpoint * 2]);
}

#[test]
fn saving_writes_atomically_and_keeps_a_backup() {
    let dir = scratch_dir();
    let path = dir.join("test.obscura");

    let mut vault = seeded_vault();
    vault.save(&path).unwrap();
    assert!(path.exists());
    assert!(
        !dir.join("test.obscura.tmp").exists(),
        "temp file left behind"
    );

    let first = std::fs::read(&path).unwrap();

    vault.add(Entry::new_login("Third", "third")).unwrap();
    vault.save(&path).unwrap();

    let backup = dir.join("test.obscura.bak");
    assert!(backup.exists(), "no backup written");
    assert_eq!(std::fs::read(&backup).unwrap(), first);

    let reopened = Vault::open(&path, &Credential::Password(PASSWORD), None).unwrap();
    assert_eq!(reopened.len(), 3);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn opening_a_missing_file_reports_io_rather_than_panicking() {
    let path = std::env::temp_dir().join("obscura-does-not-exist.obscura");
    assert!(matches!(
        Vault::open(&path, &Credential::Password(PASSWORD), None),
        Err(VaultError::Io(_))
    ));
}

#[test]
fn a_recovery_code_opens_the_vault() {
    let mut vault = seeded_vault();
    let (_id, code) = vault.add_recovery_slot("printed code").unwrap();
    let bytes = vault.to_bytes().unwrap();

    let reopened =
        Vault::from_bytes(&bytes, &Credential::Identity(&code.identity()), None).unwrap();
    assert_eq!(reopened.len(), vault.len());
}

#[test]
fn a_recovery_code_survives_a_round_trip_through_paper() {
    let mut vault = seeded_vault();
    let (_id, code) = vault.add_recovery_slot("printed code").unwrap();
    let bytes = vault.to_bytes().unwrap();

    let written_down = code.to_printable().to_lowercase().replace('-', " ");
    let typed_back = obscura_vault::RecoveryCode::parse(&written_down).unwrap();

    assert!(Vault::from_bytes(&bytes, &Credential::Identity(&typed_back.identity()), None).is_ok());
}

#[test]
fn the_last_portable_slot_cannot_be_removed() {
    let mut vault = seeded_vault();
    let hardware = new_recovery_identity().unwrap();
    vault
        .add_identity_slot(SlotKind::Hardware, "Windows Hello", &hardware)
        .unwrap();

    let password_slot = vault
        .slots()
        .iter()
        .find(|s| s.kind == SlotKind::Password)
        .unwrap()
        .id;

    assert_eq!(
        vault.remove_slot(password_slot),
        Err(VaultError::LastPortableSlot)
    );
    assert!(Vault::from_bytes(
        &vault.to_bytes().unwrap(),
        &Credential::Password(PASSWORD),
        None
    )
    .is_ok());
}

#[test]
fn the_password_can_be_removed_once_a_recovery_code_exists() {
    let mut vault = seeded_vault();
    let (_id, code) = vault.add_recovery_slot("printed code").unwrap();
    let hardware = new_recovery_identity().unwrap();
    vault
        .add_identity_slot(SlotKind::Hardware, "Windows Hello", &hardware)
        .unwrap();

    let password_slot = vault
        .slots()
        .iter()
        .find(|s| s.kind == SlotKind::Password)
        .unwrap()
        .id;
    vault.remove_slot(password_slot).unwrap();

    let bytes = vault.to_bytes().unwrap();
    assert!(Vault::from_bytes(&bytes, &Credential::Password(PASSWORD), None).is_err());
    assert!(Vault::from_bytes(&bytes, &Credential::Identity(&code.identity()), None).is_ok());
    assert!(Vault::from_bytes(&bytes, &Credential::Identity(&hardware), None).is_ok());
}

#[test]
fn a_hardware_slot_can_always_be_removed() {
    let mut vault = seeded_vault();
    let hardware = new_recovery_identity().unwrap();
    let slot = vault
        .add_identity_slot(SlotKind::Hardware, "Windows Hello", &hardware)
        .unwrap();

    vault.remove_slot(slot).unwrap();
    assert_eq!(vault.portable_slots(), 1);
}

#[test]
fn the_last_recovery_code_cannot_be_removed_either() {
    let mut vault = seeded_vault();
    let (recovery_slot, _code) = vault.add_recovery_slot("printed code").unwrap();
    let hardware = new_recovery_identity().unwrap();
    vault
        .add_identity_slot(SlotKind::Hardware, "Windows Hello", &hardware)
        .unwrap();

    let password_slot = vault
        .slots()
        .iter()
        .find(|s| s.kind == SlotKind::Password)
        .unwrap()
        .id;
    vault.remove_slot(password_slot).unwrap();

    assert_eq!(
        vault.remove_slot(recovery_slot),
        Err(VaultError::LastPortableSlot)
    );
}

#[test]
fn a_vault_down_to_one_slot_reports_the_plainer_error() {
    let mut vault = seeded_vault();
    let (recovery_slot, _code) = vault.add_recovery_slot("printed code").unwrap();

    let password_slot = vault
        .slots()
        .iter()
        .find(|s| s.kind == SlotKind::Password)
        .unwrap()
        .id;
    vault.remove_slot(password_slot).unwrap();

    assert_eq!(vault.remove_slot(recovery_slot), Err(VaultError::LastSlot));
}

#[test]
fn changing_the_password_does_not_disturb_a_recovery_code() {
    let mut vault = seeded_vault();
    let (_id, code) = vault.add_recovery_slot("printed code").unwrap();

    vault
        .change_password(b"an entirely new master password", None)
        .unwrap();
    let bytes = vault.to_bytes().unwrap();

    assert!(Vault::from_bytes(&bytes, &Credential::Identity(&code.identity()), None).is_ok());
    assert!(Vault::from_bytes(&bytes, &Credential::Password(PASSWORD), None).is_err());
}

#[test]
fn a_watermark_tag_is_stable_for_one_vault_and_revision() {
    let vault = seeded_vault();
    let first = vault.watermark_tag(7).unwrap();
    let second = vault.watermark_tag(7).unwrap();
    assert_eq!(first, second);
    assert!(vault.verify_watermark(7, &first).unwrap());
}

#[test]
fn a_watermark_tag_is_bound_to_the_revision() {
    let vault = seeded_vault();
    let seven = vault.watermark_tag(7).unwrap();
    let eight = vault.watermark_tag(8).unwrap();
    assert_ne!(seven, eight);
    assert!(!vault.verify_watermark(8, &seven).unwrap());
}

#[test]
fn a_watermark_tag_is_bound_to_the_vault() {
    let mine = seeded_vault();
    let theirs = seeded_vault();
    let tag = mine.watermark_tag(7).unwrap();
    assert!(
        !theirs.verify_watermark(7, &tag).unwrap(),
        "a watermark lifted from another vault must not verify, or an attacker could \
         transplant a low revision record onto a vault they want to roll back"
    );
}

#[test]
fn changing_the_master_password_keeps_watermarks_verifiable() {
    let mut vault = seeded_vault();
    let tag = vault.watermark_tag(3).unwrap();
    vault
        .change_password(b"a different master password", None)
        .unwrap();
    assert!(
        vault.verify_watermark(3, &tag).unwrap(),
        "the watermark key comes from the vault key, which a password change rewraps \
         rather than replaces - otherwise every password change would look like tampering"
    );
}

#[test]
fn a_reopened_vault_produces_the_same_watermark() {
    let dir = scratch_dir();
    let path = dir.join("vault.obscura");

    let mut vault = seeded_vault();
    vault.save(&path).unwrap();
    let revision = vault.revision();
    let tag = vault.watermark_tag(revision).unwrap();

    let reopened = Vault::open(&path, &Credential::Password(PASSWORD), None).unwrap();
    assert!(
        reopened.verify_watermark(revision, &tag).unwrap(),
        "the watermark must survive a save and reopen or it would fire on every launch"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[cfg(unix)]
#[test]
fn the_vault_and_its_backup_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = scratch_dir();
    let path = dir.join("vault.obscura");
    let mut vault = seeded_vault();
    vault.save(&path).unwrap();
    vault.save(&path).unwrap();

    for name in ["vault.obscura", "vault.obscura.bak"] {
        let target = dir.join(name);
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "{name} is mode {mode:o}, so every other account on this machine can read the ciphertext"
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_backup_helper_names_the_file_save_actually_writes() {
    let dir = scratch_dir();
    let path = dir.join("vault.obscura");
    let mut vault = seeded_vault();
    vault.save(&path).unwrap();
    vault.save(&path).unwrap();

    let backup = backup_path(&path);
    assert_eq!(backup.file_name().unwrap(), "vault.obscura.bak");
    assert!(backup.exists());

    assert!(
        !path.with_extension("bak").exists(),
        "with_extension(\"bak\") replaces the last extension and yields vault.bak, which is \
         not what save writes - relocate used that spelling and so left the real backup, a \
         complete older copy of the vault, sitting at the old location"
    );

    let mut found: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| {
            std::path::Path::new(name)
                .extension()
                .is_some_and(|e| e == "bak")
        })
        .collect();
    found.sort();
    assert_eq!(found, vec!["vault.obscura.bak".to_owned()]);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_credential_can_be_checked_against_the_open_vault_without_touching_the_disk() {
    let mut vault = seeded_vault();
    let (_, code) = vault.add_recovery_slot("Recovery code").unwrap();

    assert!(vault.accepts(&Credential::Password(PASSWORD)).unwrap());
    assert!(vault
        .accepts(&Credential::Identity(&code.identity()))
        .unwrap());

    assert!(!vault.accepts(&Credential::Password(b"wrong")).unwrap());
    assert!(!vault
        .accepts(&Credential::Identity(&new_recovery_identity().unwrap()))
        .unwrap());
}

#[test]
fn a_recovery_code_can_be_confirmed_before_the_slot_is_ever_written() {
    let dir = scratch_dir();
    let path = dir.join("vault.obscura");

    let mut vault = seeded_vault();
    vault.save(&path).unwrap();

    let (slot, code) = vault.add_recovery_slot("Recovery code").unwrap();
    assert!(
        vault
            .accepts(&Credential::Identity(&code.identity()))
            .unwrap(),
        "the code has to be checkable while the slot is still only in memory, or confirming \
         it would require saving it first - and a slot saved before the user confirms it \
         counts as portable even though nobody has written it down"
    );

    let on_disk = Vault::open(&path, &Credential::Password(PASSWORD), None).unwrap();
    assert!(
        !on_disk
            .accepts(&Credential::Identity(&code.identity()))
            .unwrap(),
        "nothing was saved, so the file must not carry the unconfirmed slot"
    );
    assert_eq!(on_disk.slots().len(), 1);

    vault.remove_slot(slot).unwrap();
    assert_eq!(vault.slots().len(), 1);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_header_asking_for_unbounded_work_is_refused_before_any_is_done() {
    let mut vault = seeded_vault();
    let bytes = vault.to_bytes().unwrap();

    let (mut header, _, _) = format::decode_header(&bytes).unwrap();
    header.kdf.t_cost = u32::MAX;

    let header_bytes = format::encode_header(&header).unwrap();
    let prefix = format::encode_prefix(header_bytes.len()).unwrap();
    let mut hostile = prefix;
    hostile.extend_from_slice(&header_bytes);
    hostile.extend_from_slice(&bytes[format::PREFIX_LEN..]);

    let outcome = Vault::from_bytes(&hostile, &Credential::Password(PASSWORD), None);

    assert!(
        matches!(outcome, Err(VaultError::Crypto(_))),
        "every Argon2 parameter is read out of the file, so the parameters have to be \
         bounded before they are used - reaching the KDF at all would mean grinding \
         through however many passes the file asked for"
    );
}

#[test]
fn a_mangled_prefix_is_always_an_error_and_never_a_panic() {
    let mut vault = seeded_vault();
    let bytes = vault.to_bytes().unwrap();

    for index in 0..format::PREFIX_LEN {
        for bit in 0..8u8 {
            let mut corrupted = bytes.clone();
            corrupted[index] ^= 1 << bit;
            assert!(
                Vault::from_bytes(&corrupted, &Credential::Password(PASSWORD), None).is_err(),
                "flipping bit {bit} of prefix byte {index} was accepted"
            );
        }
    }
}

#[test]
fn every_truncation_of_a_vault_is_refused() {
    let mut vault = seeded_vault();
    let bytes = vault.to_bytes().unwrap();

    for len in 0..bytes.len().min(512) {
        assert!(
            Vault::from_bytes(&bytes[..len], &Credential::Password(PASSWORD), None).is_err(),
            "a vault truncated to {len} bytes was accepted"
        );
    }
}

#[test]
fn a_header_length_that_overruns_the_file_is_refused() {
    let mut vault = seeded_vault();
    let bytes = vault.to_bytes().unwrap();

    for claimed in [
        u32::MAX,
        format::MAX_HEADER_LEN,
        format::MAX_HEADER_LEN - 1,
        0,
    ] {
        let mut corrupted = bytes.clone();
        corrupted[10..14].copy_from_slice(&claimed.to_le_bytes());
        assert!(
            Vault::from_bytes(&corrupted, &Credential::Password(PASSWORD), None).is_err(),
            "a header claiming to be {claimed} bytes long was accepted"
        );
    }
}

#[test]
fn a_password_can_be_set_again_after_it_has_been_removed() {
    let mut vault = seeded_vault();
    let (_, code) = vault.add_recovery_slot("Recovery code").unwrap();

    let password_slot = vault
        .slots()
        .iter()
        .find(|slot| slot.kind == SlotKind::Password)
        .unwrap()
        .id;
    vault.remove_slot(password_slot).unwrap();
    assert!(!vault.has_password());
    assert!(!vault.accepts(&Credential::Password(PASSWORD)).unwrap());

    assert_eq!(
        vault
            .change_password(b"a brand new password", None)
            .unwrap_err(),
        VaultError::NoMatchingSlot,
        "there is nothing to change - the vault has no password slot to rewrap"
    );

    vault.add_password(b"a brand new password", None).unwrap();

    assert!(vault.has_password());
    assert!(vault
        .accepts(&Credential::Password(b"a brand new password"))
        .unwrap());
    assert!(
        vault
            .accepts(&Credential::Identity(&code.identity()))
            .unwrap(),
        "setting a password must not disturb the recovery code that was the only way in"
    );

    assert_eq!(
        vault.add_password(b"a third password", None).unwrap_err(),
        VaultError::PasswordSlotExists,
        "one salt lives in the header, so a second password slot could never be opened"
    );
}

#[test]
fn removing_an_entry_that_is_not_there_says_so() {
    let mut vault = seeded_vault();
    assert_eq!(
        vault.remove(uuid::Uuid::new_v4()).unwrap_err(),
        VaultError::NoSuchEntry,
        "reporting a missing entry as a missing unlock slot sends the reader to the wrong \
         part of the vault entirely"
    );
}

#[test]
fn a_header_edit_that_still_parses_is_caught_by_the_body_tag() {
    let mut vault = seeded_vault();
    let bytes = vault.to_bytes().unwrap();
    let (header, header_bytes, body_start) = format::decode_header(&bytes).unwrap();

    let mut edited = header.clone();
    edited.revision ^= 1;
    let edited_bytes = format::encode_header(&edited).unwrap();
    assert_eq!(
        edited_bytes.len(),
        header_bytes.len(),
        "the edit changed the encoded length, so this test no longer isolates the tag"
    );

    let mut file = format::encode_prefix(edited_bytes.len()).unwrap();
    file.extend_from_slice(&edited_bytes);
    file.extend_from_slice(&bytes[body_start..]);

    assert!(
        Vault::from_bytes(&file, &Credential::Password(PASSWORD), None).is_err(),
        "a header edit that parsed cleanly was accepted"
    );
}

#[test]
fn a_vault_that_holds_entries_says_so_and_never_shows_its_key() {
    let vault = seeded_vault();
    assert!(!vault.is_empty());

    let shown = format!("{vault:?}");
    assert!(shown.contains("Vault"));
    assert!(shown.contains("<redacted>"));
}
