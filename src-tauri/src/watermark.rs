use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use obscura_crypto::mac::TAG_LEN;
use obscura_vault::Vault;
use serde::{Deserialize, Serialize};
use tauri::Manager;

const LEGACY: &str = "watermarks.json";

const RECORDS: &str = "watermarks";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    revision: u64,
    tag: String,
}

type Book = BTreeMap<String, Record>;

pub enum Verdict {
    Fresh,
    Current,
    Tampered,
    Rollback { found: u64, expected: u64 },
    Unreadable(String),
}

fn config_dir<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("cannot locate the application config directory: {e}"))?;
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir)
}

fn record_path(dir: &Path, vault: &Vault) -> PathBuf {
    dir.join(RECORDS).join(format!("{}.json", vault.id()))
}

fn aside_path(dir: &Path, vault: &Vault) -> PathBuf {
    dir.join(RECORDS)
        .join(format!("{}.damaged.json", vault.id()))
}

fn temp_path(dir: &Path, vault: &Vault) -> PathBuf {
    dir.join(RECORDS).join(format!("{}.json.tmp", vault.id()))
}

fn read_text(path: &Path) -> Result<Option<String>, String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

fn read_record(path: &Path) -> Result<Option<Record>, String> {
    let Some(text) = read_text(path)? else {
        return Ok(None);
    };
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|e| format!("{} is not readable: {e}", path.display()))
}

fn read_legacy(dir: &Path, vault: &Vault) -> Result<Option<Record>, String> {
    let path = dir.join(LEGACY);
    let Some(text) = read_text(&path)? else {
        return Ok(None);
    };
    let book: Book = serde_json::from_str(&text)
        .map_err(|e| format!("{} is not readable: {e}", path.display()))?;
    Ok(book.get(&vault.id().to_string()).cloned())
}

fn write_record(dir: &Path, vault: &Vault, record: &Record) -> Result<(), String> {
    let folder = dir.join(RECORDS);
    fs::create_dir_all(&folder).map_err(|e| format!("cannot create {}: {e}", folder.display()))?;
    let text = serde_json::to_string_pretty(record)
        .map_err(|e| format!("cannot encode the rollback record: {e}"))?;
    let temp = temp_path(dir, vault);
    {
        let mut file = fs::File::create(&temp)
            .map_err(|e| format!("cannot create {}: {e}", temp.display()))?;
        file.write_all(text.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", temp.display()))?;
        file.sync_all()
            .map_err(|e| format!("cannot flush {}: {e}", temp.display()))?;
    }
    let target = record_path(dir, vault);
    fs::rename(&temp, &target).map_err(|e| {
        let _ = fs::remove_file(&temp);
        format!("cannot replace {}: {e}", target.display())
    })
}

fn to_hex(bytes: &[u8; TAG_LEN]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(TAG_LEN * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn from_hex(text: &str) -> Option<[u8; TAG_LEN]> {
    if text.len() != TAG_LEN * 2 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; TAG_LEN];
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    for (slot, pair) in out.iter_mut().zip(pairs) {
        let digits = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(digits, 16).ok()?;
    }
    Some(out)
}

fn entry_for(vault: &Vault) -> Result<Record, String> {
    let revision = vault.revision();
    let tag = vault
        .watermark_tag(revision)
        .map_err(|e| format!("cannot seal the rollback record: {e}"))?;
    Ok(Record {
        revision,
        tag: to_hex(&tag),
    })
}

pub fn check<R: tauri::Runtime>(app: &tauri::AppHandle<R>, vault: &Vault) -> Verdict {
    match config_dir(app) {
        Ok(dir) => check_in(&dir, vault),
        Err(reason) => Verdict::Unreadable(reason),
    }
}

pub fn check_in(dir: &Path, vault: &Vault) -> Verdict {
    let found = match read_record(&record_path(dir, vault)) {
        Ok(Some(record)) => Ok(Some(record)),
        Ok(None) => read_legacy(dir, vault),
        Err(reason) => Err(reason),
    };
    match found {
        Ok(Some(record)) => judge(vault, &record),
        Ok(None) => Verdict::Fresh,
        Err(reason) => Verdict::Unreadable(reason),
    }
}

fn judge(vault: &Vault, record: &Record) -> Verdict {
    let Some(tag) = from_hex(&record.tag) else {
        return Verdict::Tampered;
    };
    if !vault
        .verify_watermark(record.revision, &tag)
        .unwrap_or(false)
    {
        return Verdict::Tampered;
    }
    if vault.revision() < record.revision {
        return Verdict::Rollback {
            found: vault.revision(),
            expected: record.revision,
        };
    }
    Verdict::Current
}

pub fn record<R: tauri::Runtime>(app: &tauri::AppHandle<R>, vault: &Vault) -> Result<(), String> {
    record_in(&config_dir(app)?, vault)
}

pub fn record_in(dir: &Path, vault: &Vault) -> Result<(), String> {
    write_record(dir, vault, &entry_for(vault)?)
}

pub fn reset_to<R: tauri::Runtime>(app: &tauri::AppHandle<R>, vault: &Vault) -> Result<(), String> {
    reset_to_in(&config_dir(app)?, vault)
}

pub fn reset_to_in(dir: &Path, vault: &Vault) -> Result<(), String> {
    let existing = record_path(dir, vault);
    if existing.exists() {
        fs::rename(&existing, aside_path(dir, vault))
            .map_err(|e| format!("cannot set {} aside: {e}", existing.display()))?;
    }
    record_in(dir, vault)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("obscura-watermark-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    const FAST: obscura_crypto::KdfParams = obscura_crypto::KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 2,
        p_cost: 1,
    };

    const PASSWORD: &[u8] = b"correct horse battery staple";

    fn a_vault() -> Vault {
        Vault::create(PASSWORD, FAST).unwrap()
    }

    fn write_legacy(dir: &Path, vaults: &[&Vault]) {
        let mut book = Book::new();
        for vault in vaults {
            book.insert(vault.id().to_string(), entry_for(vault).unwrap());
        }
        fs::write(dir.join(LEGACY), serde_json::to_string(&book).unwrap()).unwrap();
    }

    #[test]
    fn hex_round_trips() {
        let tag = [0xa5u8; TAG_LEN];
        let text = to_hex(&tag);
        assert_eq!(text.len(), TAG_LEN * 2);
        assert_eq!(from_hex(&text).unwrap(), tag);
    }

    #[test]
    fn malformed_hex_is_rejected_rather_than_guessed() {
        assert!(from_hex("").is_none());
        assert!(from_hex("zz").is_none());
        assert!(from_hex(&"ab".repeat(TAG_LEN - 1)).is_none());
        assert!(from_hex(&"ab".repeat(TAG_LEN + 1)).is_none());
        assert!(from_hex(&format!("{}gg", "ab".repeat(TAG_LEN - 1))).is_none());
    }

    #[test]
    fn a_record_that_was_never_written_is_absent() {
        let dir = scratch();
        let vault = a_vault();
        assert!(read_record(&record_path(&dir, &vault)).unwrap().is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_record_that_does_not_parse_is_an_error_rather_than_an_absent_one() {
        let dir = scratch();
        let vault = a_vault();
        fs::create_dir_all(dir.join(RECORDS)).unwrap();
        fs::write(record_path(&dir, &vault), "{ not json").unwrap();
        assert!(
            read_record(&record_path(&dir, &vault)).is_err(),
            "a record that fails to parse must not read as no record at all - that would make \
             the vault look fresh and silently retire its rollback protection"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn recording_leaves_no_temporary_behind_and_a_torn_one_is_ignored() {
        let dir = scratch();
        let vault = a_vault();
        record_in(&dir, &vault).unwrap();
        assert!(!temp_path(&dir, &vault).exists());

        fs::write(temp_path(&dir, &vault), "{ half-written").unwrap();
        assert!(matches!(check_in(&dir, &vault), Verdict::Current));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_vault_never_seen_before_is_fresh_and_recording_it_makes_it_current() {
        let dir = scratch();
        let vault = a_vault();

        assert!(matches!(check_in(&dir, &vault), Verdict::Fresh));
        record_in(&dir, &vault).unwrap();
        assert!(matches!(check_in(&dir, &vault), Verdict::Current));

        let stranger = a_vault();
        assert!(
            matches!(check_in(&dir, &stranger), Verdict::Fresh),
            "one vault record must never answer for another, or opening a second vault would \
             be judged against the first"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_vault_restored_from_an_older_copy_is_caught() {
        let dir = scratch();
        let mut vault = a_vault();

        let older = vault.to_bytes().unwrap();
        let _newer = vault.to_bytes().unwrap();
        record_in(&dir, &vault).unwrap();

        let restored =
            Vault::from_bytes(&older, &obscura_vault::Credential::Password(PASSWORD), None)
                .unwrap();

        match check_in(&dir, &restored) {
            Verdict::Rollback { found, expected } => {
                assert_eq!(found, restored.revision());
                assert_eq!(expected, vault.revision());
            }
            _ => panic!(
                "an older copy of the vault put back in place is the attack this whole file \
                 exists to catch"
            ),
        }

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_record_that_does_not_verify_is_tampering_however_it_was_spoiled() {
        let dir = scratch();
        let vault = a_vault();
        record_in(&dir, &vault).unwrap();

        for spoiled in ["00".repeat(TAG_LEN), "not hexadecimal".to_owned()] {
            let mut record = read_record(&record_path(&dir, &vault)).unwrap().unwrap();
            record.tag = spoiled.clone();
            write_record(&dir, &vault, &record).unwrap();

            assert!(
                matches!(check_in(&dir, &vault), Verdict::Tampered),
                "a record that does not verify must never read as current: {spoiled}"
            );
        }

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resetting_one_vault_leaves_every_other_vault_protected() {
        let dir = scratch();
        let vault = a_vault();
        let stranger = a_vault();

        record_in(&dir, &stranger).unwrap();
        record_in(&dir, &vault).unwrap();
        fs::write(record_path(&dir, &vault), b"{ this is not json").unwrap();
        assert!(matches!(check_in(&dir, &vault), Verdict::Unreadable(_)));
        assert!(matches!(check_in(&dir, &stranger), Verdict::Current));

        reset_to_in(&dir, &vault).unwrap();

        assert!(
            aside_path(&dir, &vault).exists(),
            "the unreadable record is set aside rather than deleted, because it is the only \
             evidence of whatever spoiled it"
        );
        assert!(matches!(check_in(&dir, &vault), Verdict::Current));
        assert!(
            matches!(check_in(&dir, &stranger), Verdict::Current),
            "resetting one vault must never make another look new"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_record_in_the_old_shared_book_still_protects_its_vault() {
        let dir = scratch();
        let mut vault = a_vault();

        let older = vault.to_bytes().unwrap();
        let _newer = vault.to_bytes().unwrap();
        write_legacy(&dir, &[&vault]);
        assert!(matches!(check_in(&dir, &vault), Verdict::Current));

        let restored =
            Vault::from_bytes(&older, &obscura_vault::Credential::Password(PASSWORD), None)
                .unwrap();
        assert!(matches!(
            check_in(&dir, &restored),
            Verdict::Rollback { .. }
        ));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_vault_record_of_its_own_takes_precedence_over_the_old_book() {
        let dir = scratch();
        let mut vault = a_vault();

        write_legacy(&dir, &[&vault]);
        let _newer = vault.to_bytes().unwrap();
        record_in(&dir, &vault).unwrap();
        fs::write(dir.join(LEGACY), "{ not json").unwrap();

        assert!(matches!(check_in(&dir, &vault), Verdict::Current));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_damaged_old_book_asks_about_each_vault_and_resetting_one_leaves_the_rest_asking() {
        let dir = scratch();
        let vault = a_vault();
        let stranger = a_vault();

        fs::write(dir.join(LEGACY), "{ not json").unwrap();
        assert!(matches!(check_in(&dir, &vault), Verdict::Unreadable(_)));
        assert!(matches!(check_in(&dir, &stranger), Verdict::Unreadable(_)));

        reset_to_in(&dir, &vault).unwrap();

        assert!(matches!(check_in(&dir, &vault), Verdict::Current));
        assert!(
            matches!(check_in(&dir, &stranger), Verdict::Unreadable(_)),
            "a vault that may have had a record in the damaged book must still be asked about, \
             never quietly treated as new"
        );
        assert!(dir.join(LEGACY).exists());

        fs::remove_dir_all(&dir).unwrap();
    }
}
