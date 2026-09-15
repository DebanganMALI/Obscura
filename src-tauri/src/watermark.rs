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

const FILE: &str = "watermarks.json";

const TEMP: &str = "watermarks.json.tmp";

const DAMAGED: &str = "watermarks.damaged.json";

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

fn config_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("cannot locate the application config directory: {e}"))?;
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir)
}

fn read_book(path: &Path) -> Result<Book, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Book::new()),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    serde_json::from_str(&text).map_err(|e| format!("{} is not readable: {e}", path.display()))
}

fn write_book(dir: &Path, book: &Book) -> Result<(), String> {
    let text =
        serde_json::to_string_pretty(book).map_err(|e| format!("cannot encode {FILE}: {e}"))?;
    let temp = dir.join(TEMP);
    {
        let mut file = fs::File::create(&temp)
            .map_err(|e| format!("cannot create {}: {e}", temp.display()))?;
        file.write_all(text.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", temp.display()))?;
        file.sync_all()
            .map_err(|e| format!("cannot flush {}: {e}", temp.display()))?;
    }
    let target = dir.join(FILE);
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
    let bytes = text.as_bytes();
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
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

pub fn check(app: &tauri::AppHandle, vault: &Vault) -> Verdict {
    let book = match config_dir(app).and_then(|dir| read_book(&dir.join(FILE))) {
        Ok(book) => book,
        Err(reason) => return Verdict::Unreadable(reason),
    };
    let Some(record) = book.get(&vault.id().to_string()) else {
        return Verdict::Fresh;
    };
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

pub fn record(app: &tauri::AppHandle, vault: &Vault) -> Result<(), String> {
    let dir = config_dir(app)?;
    let mut book = read_book(&dir.join(FILE))?;
    book.insert(vault.id().to_string(), entry_for(vault)?);
    write_book(&dir, &book)
}

pub fn reset_to(app: &tauri::AppHandle, vault: &Vault) -> Result<(), String> {
    let dir = config_dir(app)?;
    let existing = dir.join(FILE);
    if existing.exists() {
        fs::rename(&existing, dir.join(DAMAGED))
            .map_err(|e| format!("cannot set {} aside: {e}", existing.display()))?;
    }
    let mut book = Book::new();
    book.insert(vault.id().to_string(), entry_for(vault)?);
    write_book(&dir, &book)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("obscura-watermark-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn book_of(id: &str, revision: u64) -> Book {
        let mut book = Book::new();
        book.insert(
            id.to_owned(),
            Record {
                revision,
                tag: to_hex(&[0x11u8; TAG_LEN]),
            },
        );
        book
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
    fn a_book_that_was_never_written_is_empty() {
        let dir = scratch();
        assert!(read_book(&dir.join(FILE)).unwrap().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_book_that_does_not_parse_is_an_error_rather_than_an_empty_one() {
        let dir = scratch();
        fs::write(dir.join(FILE), "{ not json").unwrap();
        assert!(
            read_book(&dir.join(FILE)).is_err(),
            "a book that fails to parse must not read as no records at all - that would make \
             every vault look fresh and silently retire rollback protection for all of them"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_book_survives_a_round_trip_and_leaves_no_temporary_behind() {
        let dir = scratch();
        write_book(&dir, &book_of("a", 7)).unwrap();

        let back = read_book(&dir.join(FILE)).unwrap();
        assert_eq!(back.get("a").unwrap().revision, 7);
        assert!(!dir.join(TEMP).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_second_write_replaces_the_first_whole() {
        let dir = scratch();
        write_book(&dir, &book_of("a", 7)).unwrap();

        let mut next = read_book(&dir.join(FILE)).unwrap();
        next.insert(
            "b".to_owned(),
            Record {
                revision: 2,
                tag: to_hex(&[0x22u8; TAG_LEN]),
            },
        );
        write_book(&dir, &next).unwrap();

        let back = read_book(&dir.join(FILE)).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back.get("a").unwrap().revision, 7);
        assert_eq!(back.get("b").unwrap().revision, 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_torn_temporary_file_is_not_mistaken_for_the_book() {
        let dir = scratch();
        write_book(&dir, &book_of("a", 7)).unwrap();
        fs::write(dir.join(TEMP), "{ half-written").unwrap();

        let back = read_book(&dir.join(FILE)).unwrap();
        assert_eq!(back.get("a").unwrap().revision, 7);
        fs::remove_dir_all(&dir).unwrap();
    }
}
