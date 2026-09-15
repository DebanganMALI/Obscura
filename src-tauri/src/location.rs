use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use tauri::Manager;

const POINTER_FILE: &str = "location.json";

const SYNC_MARKERS: [&str; 8] = [
    "onedrive",
    "dropbox",
    "google drive",
    "googledrive",
    "icloud",
    "icloud drive",
    "nextcloud",
    "pcloud",
];

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Pointer {
    vault_path: Option<String>,
}

fn pointer_file(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("cannot locate the application config directory: {e}"))?;
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir.join(POINTER_FILE))
}

#[must_use]
pub fn remembered(app: &tauri::AppHandle) -> Option<PathBuf> {
    let file = pointer_file(app).ok()?;
    let text = fs::read_to_string(file).ok()?;
    let pointer: Pointer = serde_json::from_str(&text).ok()?;
    pointer
        .vault_path
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from)
}

pub fn remember(app: &tauri::AppHandle, path: &Path) -> Result<(), String> {
    let pointer = Pointer {
        vault_path: Some(path.display().to_string()),
    };
    let text = serde_json::to_string_pretty(&pointer)
        .map_err(|e| format!("cannot encode the location file: {e}"))?;
    let file = pointer_file(app)?;
    fs::write(&file, text).map_err(|e| format!("cannot write {}: {e}", file.display()))
}

pub fn forget(app: &tauri::AppHandle) -> Result<(), String> {
    let file = pointer_file(app)?;
    match fs::remove_file(&file) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot remove {}: {e}", file.display())),
    }
}

#[must_use]
pub fn looks_synced(path: &Path) -> bool {
    path.components().any(|component| {
        let name = component.as_os_str().to_string_lossy().to_lowercase();
        SYNC_MARKERS.contains(&name.as_str())
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
    fs::read(path).is_ok_and(|bytes| obscura_vault::format::decode_header(&bytes).is_ok())
}
