#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::unnecessary_wraps)]

use std::{path::PathBuf, time::Duration};

use obscura_crypto::{kdf, KdfParams};
use obscura_vault::{
    generator::{self, PasswordPolicy},
    Credential, Entry, SecretString, Totp, Vault,
};
use tauri::{Manager, State};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    clipboard,
    dto::{
        CustomFieldView, EntryDetail, EntryInput, EntrySummary, GeneratedPassword, SlotView,
        TotpCode, VaultInfo,
    },
    state::{AppState, Session},
};

fn default_vault_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("cannot locate the application data directory: {e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir.join("obscura.obscura"))
}

fn resolve(app: &tauri::AppHandle, path: Option<String>) -> Result<PathBuf, String> {
    if let Some(chosen) = path.filter(|p| !p.trim().is_empty()) {
        Ok(PathBuf::from(chosen))
    } else {
        default_vault_path(app)
    }
}

fn info(session: &Session, auto_lock_secs: u64) -> VaultInfo {
    VaultInfo {
        id: session.vault.id(),
        revision: session.vault.revision(),
        entry_count: session.vault.len(),
        slots: session
            .vault
            .slots()
            .iter()
            .map(|slot| SlotView {
                id: slot.id,
                kind: format!("{:?}", slot.kind).to_lowercase(),
                label: slot.label.clone(),
            })
            .collect(),
        path: session.path.display().to_string(),
        auto_lock_secs,
    }
}

#[tauri::command]
pub fn vault_exists(app: tauri::AppHandle, path: Option<String>) -> Result<bool, String> {
    Ok(resolve(&app, path)?.exists())
}

#[tauri::command]
pub fn default_path(app: tauri::AppHandle) -> Result<String, String> {
    Ok(default_vault_path(&app)?.display().to_string())
}

#[tauri::command]
pub fn calibrate(target_ms: u32) -> Result<serde_json::Value, String> {
    let params = kdf::calibrate(target_ms.clamp(200, 3000));
    Ok(serde_json::json!({
        "mCostKib": params.m_cost_kib,
        "tCost": params.t_cost,
        "pCost": params.p_cost,
    }))
}

#[tauri::command]
pub fn create_vault(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    path: Option<String>,
    password: String,
    calibrate_ms: Option<u32>,
) -> Result<VaultInfo, String> {
    let password = Zeroizing::new(password);
    let target = resolve(&app, path)?;

    if target.exists() {
        return Err("a vault already exists at that location".to_owned());
    }

    let params =
        calibrate_ms.map_or_else(KdfParams::default, |ms| kdf::calibrate(ms.clamp(200, 3000)));

    let mut vault = Vault::create(password.as_bytes(), params).map_err(|e| e.to_string())?;
    vault.save(&target).map_err(|e| e.to_string())?;

    let revision = vault.revision();
    let session = Session {
        vault,
        path: target,
        last_activity: std::time::Instant::now(),
        min_revision: revision,
    };
    let summary = info(&session, state.auto_lock().as_secs());
    state.set(session);
    Ok(summary)
}

#[tauri::command]
pub fn unlock(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    path: Option<String>,
    password: String,
) -> Result<VaultInfo, String> {
    let password = Zeroizing::new(password);
    let target = resolve(&app, path)?;

    let vault = Vault::open(&target, &Credential::Password(password.as_bytes()), None)
        .map_err(|_| "could not unlock the vault with that password".to_owned())?;

    let revision = vault.revision();
    let session = Session {
        vault,
        path: target,
        last_activity: std::time::Instant::now(),
        min_revision: revision,
    };
    let summary = info(&session, state.auto_lock().as_secs());
    state.set(session);
    Ok(summary)
}

#[tauri::command]
pub fn lock(state: State<'_, AppState>) -> bool {
    state.lock()
}

#[tauri::command]
pub fn is_locked(state: State<'_, AppState>) -> bool {
    !state.is_unlocked()
}

#[tauri::command]
pub fn touch(state: State<'_, AppState>) {
    state.touch();
}

#[tauri::command]
pub fn vault_info(state: State<'_, AppState>) -> Result<VaultInfo, String> {
    let secs = state.auto_lock().as_secs();
    state.with_session(|session| Ok(info(session, secs)))
}

#[tauri::command]
pub fn set_auto_lock(state: State<'_, AppState>, seconds: u64) -> u64 {
    state.set_auto_lock(Duration::from_secs(seconds));
    state.auto_lock().as_secs()
}

#[tauri::command]
pub fn list_entries(
    state: State<'_, AppState>,
    query: Option<String>,
) -> Result<Vec<EntrySummary>, String> {
    let needle = query.unwrap_or_default();
    state.with_session(|session| {
        let mut found: Vec<EntrySummary> = session
            .vault
            .search(&needle)
            .into_iter()
            .map(EntrySummary::from)
            .collect();
        found.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
                .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
        });
        Ok(found)
    })
}

#[tauri::command]
pub fn get_entry(state: State<'_, AppState>, id: Uuid) -> Result<EntryDetail, String> {
    state.with_session(|session| {
        let entry = session.vault.get(id).ok_or("no such entry")?;
        Ok(EntryDetail {
            summary: EntrySummary::from(entry),
            urls: entry.urls.clone(),
            notes: entry.notes.expose().to_owned(),
            custom_fields: entry
                .custom_fields
                .iter()
                .map(|field| CustomFieldView {
                    name: field.name.clone(),
                    value: (!field.hidden).then(|| field.value.expose().to_owned()),
                    hidden: field.hidden,
                })
                .collect(),
            password_len: entry.password.len(),
        })
    })
}

#[tauri::command]
pub fn reveal_password(state: State<'_, AppState>, id: Uuid) -> Result<String, String> {
    state.with_session(|session| {
        let entry = session.vault.get(id).ok_or("no such entry")?;
        Ok(entry.password.expose().to_owned())
    })
}

#[tauri::command]
pub fn copy_password(
    state: State<'_, AppState>,
    id: Uuid,
    clear_after: Option<u64>,
) -> Result<(), String> {
    let value = state.with_session(|session| {
        let entry = session.vault.get(id).ok_or("no such entry")?;
        Ok(Zeroizing::new(entry.password.expose().to_owned()))
    })?;
    clipboard::copy_with_timeout(value, clear_after.unwrap_or(30))
}

#[tauri::command]
pub fn copy_text(text: String, clear_after: Option<u64>) -> Result<(), String> {
    clipboard::copy_with_timeout(Zeroizing::new(text), clear_after.unwrap_or(30))
}

#[tauri::command]
pub fn save_entry(state: State<'_, AppState>, input: EntryInput) -> Result<Uuid, String> {
    let id = state.with_session(|session| {
        let id = if let Some(existing) = input.id {
            let entry = session.vault.get_mut(existing).ok_or("no such entry")?;
            apply(entry, &input)?;
            existing
        } else {
            let mut entry = Entry::new_login(input.title.clone(), input.username.clone());
            apply(&mut entry, &input)?;
            session.vault.add(entry).map_err(|e| e.to_string())?
        };
        let path = session.path.clone();
        session.vault.save(&path).map_err(|e| e.to_string())?;
        session.min_revision = session.vault.revision();
        Ok(id)
    })?;
    Ok(id)
}

fn apply(entry: &mut Entry, input: &EntryInput) -> Result<(), String> {
    entry.kind = input.kind;
    entry.title.clone_from(&input.title);
    entry.username.clone_from(&input.username);
    entry.urls.clone_from(&input.urls);
    entry.notes = SecretString::from(input.notes.as_str());
    entry.tags.clone_from(&input.tags);
    entry.favorite = input.favorite;

    if let Some(uri) = input.totp_uri.as_ref().filter(|u| !u.trim().is_empty()) {
        entry.totp = Some(Totp::from_uri(uri.trim()).map_err(|e| e.to_string())?);
    }

    if let Some(password) = input.password.as_ref() {
        entry.set_password(password.as_str());
    } else {
        entry.touch();
    }

    entry.validate().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn delete_entry(state: State<'_, AppState>, id: Uuid) -> Result<(), String> {
    state.with_session(|session| {
        session.vault.remove(id).map_err(|e| e.to_string())?;
        let path = session.path.clone();
        session.vault.save(&path).map_err(|e| e.to_string())?;
        session.min_revision = session.vault.revision();
        Ok(())
    })
}

#[tauri::command]
pub fn totp_code(state: State<'_, AppState>, id: Uuid) -> Result<TotpCode, String> {
    state.with_session(|session| {
        let entry = session.vault.get(id).ok_or("no such entry")?;
        let totp = entry.totp.as_ref().ok_or("this entry has no TOTP")?;
        let (code, remaining) = totp.current().map_err(|e| e.to_string())?;
        Ok(TotpCode {
            code,
            remaining,
            period: totp.period(),
        })
    })
}

#[tauri::command]
#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
pub fn generate(
    length: usize,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
    exclude_ambiguous: bool,
    require_each_class: bool,
) -> Result<GeneratedPassword, String> {
    let policy = PasswordPolicy {
        length,
        lowercase,
        uppercase,
        digits,
        symbols,
        exclude_ambiguous,
        require_each_class,
    };
    let password = generator::generate_password(&policy).map_err(|e| e.to_string())?;
    Ok(GeneratedPassword {
        password: password.to_string(),
        entropy_bits: policy.entropy_bits(),
    })
}

#[tauri::command]
pub fn change_master_password(
    state: State<'_, AppState>,
    current: String,
    new: String,
) -> Result<(), String> {
    let current = Zeroizing::new(current);
    let new = Zeroizing::new(new);

    if new.len() < 8 {
        return Err("the new password must be at least 8 characters".to_owned());
    }

    state.with_session(|session| {
        Vault::open(
            &session.path,
            &Credential::Password(current.as_bytes()),
            None,
        )
        .map_err(|_| "the current password is not correct".to_owned())?;

        session
            .vault
            .change_password(new.as_bytes(), None)
            .map_err(|e| e.to_string())?;
        let path = session.path.clone();
        session.vault.save(&path).map_err(|e| e.to_string())?;
        session.min_revision = session.vault.revision();
        Ok(())
    })
}
