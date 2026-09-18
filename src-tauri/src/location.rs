use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use tauri::Manager;

const POINTER_FILE: &str = "location.json";

const SYNC_MARKERS: [&str; 14] = [
    "onedrive",
    "dropbox",
    "google drive",
    "googledrive",
    "my drive",
    "icloud",
    "nextcloud",
    "owncloud",
    "pcloud",
    "megasync",
    "syncthing",
    "seafile",
    "yandexdisk",
    "creative cloud files",
];

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    vault_path: Option<String>,
    #[serde(default)]
    auto_lock_secs: Option<u64>,
}

fn pointer_file<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("cannot locate the application config directory: {e}"))?;
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir.join(POINTER_FILE))
}

fn load_from(file: &Path) -> Stored {
    fs::read_to_string(file)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn save_to(file: &Path, stored: &Stored) -> Result<(), String> {
    let text = serde_json::to_string_pretty(stored)
        .map_err(|e| format!("cannot encode the settings file: {e}"))?;
    fs::write(file, text).map_err(|e| format!("cannot write {}: {e}", file.display()))
}

#[must_use]
pub fn remembered<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Option<PathBuf> {
    pointer_file(app).ok().and_then(|file| remembered_in(&file))
}

#[must_use]
pub fn remembered_in(file: &Path) -> Option<PathBuf> {
    load_from(file)
        .vault_path
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from)
}

pub fn remember<R: tauri::Runtime>(app: &tauri::AppHandle<R>, path: &Path) -> Result<(), String> {
    remember_in(&pointer_file(app)?, path)
}

pub fn remember_in(file: &Path, path: &Path) -> Result<(), String> {
    let mut stored = load_from(file);
    stored.vault_path = Some(path.display().to_string());
    save_to(file, &stored)
}

pub fn forget<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Result<(), String> {
    forget_in(&pointer_file(app)?)
}

pub fn forget_in(file: &Path) -> Result<(), String> {
    let mut stored = load_from(file);
    stored.vault_path = None;
    save_to(file, &stored)
}

#[must_use]
pub fn remembered_auto_lock<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Option<u64> {
    pointer_file(app)
        .ok()
        .and_then(|file| remembered_auto_lock_in(&file))
}

#[must_use]
pub fn remembered_auto_lock_in(file: &Path) -> Option<u64> {
    load_from(file).auto_lock_secs
}

pub fn remember_auto_lock<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    seconds: u64,
) -> Result<(), String> {
    remember_auto_lock_in(&pointer_file(app)?, seconds)
}

pub fn remember_auto_lock_in(file: &Path, seconds: u64) -> Result<(), String> {
    let mut stored = load_from(file);
    stored.auto_lock_secs = Some(seconds);
    save_to(file, &stored)
}

#[must_use]
pub fn looks_synced(path: &Path) -> bool {
    path.components().any(|component| {
        let name = component.as_os_str().to_string_lossy().to_lowercase();
        SYNC_MARKERS
            .iter()
            .any(|marker| name.starts_with(marker) || name.ends_with(marker))
    })
}

#[must_use]
pub fn parent_writable(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    if !parent.is_dir() {
        return false;
    }
    let probe = parent.join(format!(".obscura-write-test-{}", uuid::Uuid::new_v4()));
    match fs::File::create(&probe) {
        Ok(handle) => {
            drop(handle);
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

#[must_use]
pub fn file_writable(path: &Path) -> bool {
    fs::OpenOptions::new().append(true).open(path).is_ok()
}

#[must_use]
pub fn is_vault_file(path: &Path) -> bool {
    fs::read(path).is_ok_and(|bytes| {
        obscura_vault::format::decode_header(&bytes).is_ok_and(|(_, _, body_start)| {
            bytes.len() >= body_start.saturating_add(obscura_crypto::aead::OVERHEAD)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_business_cloud_folder_is_recognised_as_a_syncing_one() {
        for folder in [
            "OneDrive - Contoso",
            "OneDrive - Personal",
            "OneDrive",
            "Dropbox (Personal)",
            "Dropbox",
            "iCloud Drive",
            "Google Drive",
            "My Drive",
            "Nextcloud",
            "pCloud Drive",
        ] {
            let path = Path::new("/home/saheb").join(folder).join("vault.obscura");
            assert!(
                looks_synced(&path),
                "{folder} is a syncing folder, and a sync client restoring an older copy of a \
                 vault silently undoes every password change made since"
            );
        }
    }

    #[test]
    fn an_ordinary_folder_is_left_alone() {
        for folder in ["Documents", "Vaults", "boxes", "Downloads", "work notes"] {
            let path = Path::new("/home/saheb").join(folder).join("vault.obscura");
            assert!(
                !looks_synced(&path),
                "{folder} was wrongly called a sync folder"
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod verification {
    use super::*;
    use obscura_crypto::KdfParams;
    use obscura_vault::Vault;

    const FAST: KdfParams = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 2,
        p_cost: 1,
    };

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("obscura-location-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn a_real_vault_is_recognised_and_ordinary_files_are_not() {
        let mut vault = Vault::create(b"correct horse battery staple", FAST).unwrap();
        let bytes = vault.to_bytes().unwrap();

        let good = scratch("good.obscura");
        fs::write(&good, &bytes).unwrap();
        assert!(is_vault_file(&good));

        let text = scratch("notes.txt");
        fs::write(&text, b"this is not a vault").unwrap();
        assert!(!is_vault_file(&text));

        let empty = scratch("empty.obscura");
        fs::write(&empty, b"").unwrap();
        assert!(!is_vault_file(&empty));

        assert!(!is_vault_file(&scratch("absent.obscura")));
        assert!(!is_vault_file(good.parent().unwrap()));

        let _ = fs::remove_file(&good);
        let _ = fs::remove_file(&text);
        let _ = fs::remove_file(&empty);
    }

    #[test]
    fn a_file_carrying_only_a_header_is_not_accepted_as_a_vault() {
        let mut vault = Vault::create(b"correct horse battery staple", FAST).unwrap();
        let bytes = vault.to_bytes().unwrap();
        let (_, _, body_start) = obscura_vault::format::decode_header(&bytes).unwrap();

        let headless = scratch("headless.obscura");
        fs::write(&headless, &bytes[..body_start]).unwrap();

        assert!(
            !is_vault_file(&headless),
            "relocate_vault removes the original vault once this says the new file is sound, so a \
             file carrying no encrypted body must never pass"
        );

        let stub = scratch("stub.obscura");
        let mut partial = bytes[..body_start].to_vec();
        partial.extend_from_slice(&[0u8; 8]);
        fs::write(&stub, &partial).unwrap();
        assert!(
            !is_vault_file(&stub),
            "a body too short to hold a sealed message is a torn write, not a vault"
        );

        let _ = fs::remove_file(&stub);
        let _ = fs::remove_file(&headless);
    }

    #[test]
    fn a_writable_folder_is_reported_and_the_probe_leaves_nothing_behind() {
        let file = scratch("probe.obscura");
        let dir = file.parent().unwrap().to_path_buf();

        assert!(parent_writable(&file));
        assert!(!parent_writable(&dir.join("absent").join("probe.obscura")));

        let left: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".obscura-write-test-")
            })
            .collect();
        assert!(
            left.is_empty(),
            "the writability probe left {} file(s) behind in the user's folder",
            left.len()
        );
    }

    #[test]
    fn a_sync_folder_is_recognised_at_either_end_of_its_name() {
        assert!(looks_synced(Path::new(
            "/home/saheb/Work OneDrive/vault.obscura"
        )));
        assert!(looks_synced(Path::new(
            "/home/saheb/OneDrive Work/vault.obscura"
        )));
        assert!(!looks_synced(Path::new(
            "/home/saheb/one drive over/vault.obscura"
        )));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod remembering {
    use super::*;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("obscura-location-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn forgetting_the_vault_leaves_the_other_settings_alone() {
        let dir = scratch();
        let file = dir.join("settings.json");

        assert!(remembered_in(&file).is_none());
        assert!(remembered_auto_lock_in(&file).is_none());

        remember_auto_lock_in(&file, 900).unwrap();
        remember_in(&file, Path::new("D:/vaults/personal.obscura")).unwrap();

        assert_eq!(
            remembered_in(&file).unwrap(),
            PathBuf::from("D:/vaults/personal.obscura")
        );
        assert_eq!(remembered_auto_lock_in(&file), Some(900));

        forget_in(&file).unwrap();

        assert!(remembered_in(&file).is_none());
        assert_eq!(
            remembered_auto_lock_in(&file),
            Some(900),
            "forgetting where the vault lives must not discard the auto-lock the user set - \
             both live in one file, which is why every write reads it first"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_settings_file_that_will_not_parse_is_empty_rather_than_fatal() {
        let dir = scratch();
        let file = dir.join("settings.json");
        fs::write(&file, b"{ this is not json").unwrap();

        assert!(remembered_in(&file).is_none());
        assert!(remembered_auto_lock_in(&file).is_none());

        remember_in(&file, Path::new("D:/vaults/personal.obscura")).unwrap();
        assert_eq!(
            remembered_in(&file).unwrap(),
            PathBuf::from("D:/vaults/personal.obscura"),
            "a spoiled settings file must never stop Obscura opening - it holds a convenience, \
             not the vault"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_blank_path_is_not_a_remembered_location() {
        let dir = scratch();
        let file = dir.join("settings.json");

        remember_in(&file, Path::new("   ")).unwrap();
        assert!(
            remembered_in(&file).is_none(),
            "whitespace resolves to the working directory, so the gate would offer to unlock a \
             vault that is not there"
        );

        fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::permissions_set_readonly_false)]
mod writability {
    use super::*;

    #[test]
    fn a_read_only_file_is_not_writable_though_its_folder_still_is() {
        let dir = std::env::temp_dir().join(format!("obscura-readonly-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("vault.obscura");
        fs::write(&file, b"anything").unwrap();

        assert!(file_writable(&file));

        let mut locked = fs::metadata(&file).unwrap().permissions();
        locked.set_readonly(true);
        fs::set_permissions(&file, locked).unwrap();

        assert!(
            !file_writable(&file),
            "a read-only vault has to be reported before the user types a password, not \
             discovered at save time once they have done work"
        );
        assert!(
            parent_writable(&file),
            "the folder is still writable, which is exactly why the file has to be \
             checked separately rather than inferred from its parent"
        );

        let mut freed = fs::metadata(&file).unwrap().permissions();
        freed.set_readonly(false);
        fs::set_permissions(&file, freed).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }
}
