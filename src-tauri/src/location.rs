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

fn pointer_file(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("cannot locate the application config directory: {e}"))?;
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir.join(POINTER_FILE))
}

fn load(app: &tauri::AppHandle) -> Stored {
    pointer_file(app)
        .ok()
        .and_then(|file| fs::read_to_string(file).ok())
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn save(app: &tauri::AppHandle, stored: &Stored) -> Result<(), String> {
    let text = serde_json::to_string_pretty(stored)
        .map_err(|e| format!("cannot encode the settings file: {e}"))?;
    let file = pointer_file(app)?;
    fs::write(&file, text).map_err(|e| format!("cannot write {}: {e}", file.display()))
}

#[must_use]
pub fn remembered(app: &tauri::AppHandle) -> Option<PathBuf> {
    load(app)
        .vault_path
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from)
}

pub fn remember(app: &tauri::AppHandle, path: &Path) -> Result<(), String> {
    let mut stored = load(app);
    stored.vault_path = Some(path.display().to_string());
    save(app, &stored)
}

pub fn forget(app: &tauri::AppHandle) -> Result<(), String> {
    let mut stored = load(app);
    stored.vault_path = None;
    save(app, &stored)
}

#[must_use]
pub fn remembered_auto_lock(app: &tauri::AppHandle) -> Option<u64> {
    load(app).auto_lock_secs
}

pub fn remember_auto_lock(app: &tauri::AppHandle, seconds: u64) -> Result<(), String> {
    let mut stored = load(app);
    stored.auto_lock_secs = Some(seconds);
    save(app, &stored)
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
