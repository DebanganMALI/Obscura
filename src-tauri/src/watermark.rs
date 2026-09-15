use std::{collections::BTreeMap, fs, path::PathBuf};

use obscura_crypto::mac::TAG_LEN;
use obscura_vault::Vault;
use serde::{Deserialize, Serialize};
use tauri::Manager;

const FILE: &str = "watermarks.json";

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
}

fn book_file(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("cannot locate the application config directory: {e}"))?;
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir.join(FILE))
}

fn read(app: &tauri::AppHandle) -> Book {
    let Ok(path) = book_file(app) else {
        return Book::new();
    };
    let Ok(text) = fs::read_to_string(path) else {
        return Book::new();
    };
    serde_json::from_str(&text).unwrap_or_default()
}

fn write(app: &tauri::AppHandle, book: &Book) -> Result<(), String> {
    let text =
        serde_json::to_string_pretty(book).map_err(|e| format!("cannot encode {FILE}: {e}"))?;
    let path = book_file(app)?;
    fs::write(&path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))
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

pub fn check(app: &tauri::AppHandle, vault: &Vault) -> Verdict {
    let book = read(app);
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
    let revision = vault.revision();
    let tag = vault
        .watermark_tag(revision)
        .map_err(|e| format!("cannot seal the rollback record: {e}"))?;
    let mut book = read(app);
    book.insert(
        vault.id().to_string(),
        Record {
            revision,
            tag: to_hex(&tag),
        },
    );
    write(app, &book)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
}
