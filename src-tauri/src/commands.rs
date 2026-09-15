#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::unnecessary_wraps)]

use std::{path::PathBuf, time::Duration};

use obscura_crypto::{kdf, KdfParams};
use obscura_vault::{
    format::SlotKind,
    generator::{self, PasswordPolicy},
    Credential, Entry, RecoveryCode, SecretString, Totp, Vault,
};
use tauri::{Manager, State};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    clipboard,
    dto::{
        CustomFieldView, EntryDetail, EntryInput, EntrySummary, GeneratedPassword,
        IssuedRecoveryCode, LocationProbe, RelocateResult, SlotView, TotpCode, UnlockError,
        VaultInfo,
    },
    location,
    state::{AppState, Session},
    watermark,
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
        return Ok(PathBuf::from(chosen.trim()));
    }
    if let Some(remembered) = location::remembered(app) {
        return Ok(remembered);
    }
    default_vault_path(app)
}

fn apply_remember(app: &tauri::AppHandle, path: &std::path::Path, remember: Option<bool>) {
    if remember.unwrap_or(true) {
        let _ = location::remember(app, path);
    } else {
        let _ = location::forget(app);
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
                created_at: slot
                    .created_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                portable: matches!(slot.kind, SlotKind::Password | SlotKind::Recovery),
            })
            .collect(),
        path: session.path.display().to_string(),
        auto_lock_secs,
    }
}

fn persist(
    app: &tauri::AppHandle,
    session: &mut Session,
    path: &std::path::Path,
) -> Result<(), String> {
    session.vault.save(path).map_err(|e| e.to_string())?;
    session.min_revision = session.vault.revision();
    watermark::record(app, &session.vault)
}

fn admit(
    app: &tauri::AppHandle,
    vault: &Vault,
    accept_revision: Option<u64>,
) -> Result<(), UnlockError> {
    match watermark::check(app, vault) {
        watermark::Verdict::Fresh | watermark::Verdict::Current => {}
        watermark::Verdict::Tampered => {
            if accept_revision != Some(vault.revision()) {
                return Err(UnlockError::damaged(vault.revision()));
            }
        }
        watermark::Verdict::Rollback { found, expected } => {
            if accept_revision != Some(found) {
                return Err(UnlockError::rollback(found, expected));
            }
        }
        watermark::Verdict::Unreadable(detail) => {
            if accept_revision != Some(vault.revision()) {
                return Err(UnlockError::unreadable(vault.revision(), detail));
            }
            return watermark::reset_to(app, vault).map_err(UnlockError::message);
        }
    }
    watermark::record(app, vault).map_err(UnlockError::message)
}

#[tauri::command]
pub fn vault_exists(app: tauri::AppHandle, path: Option<String>) -> Result<bool, String> {
    Ok(resolve(&app, path)?.exists())
}

#[tauri::command]
pub fn default_path(app: tauri::AppHandle) -> Result<String, String> {
    Ok(default_vault_path(&app)?.display().to_string())
}

#[tauri::command(async)]
pub fn calibrate(target_ms: u32) -> Result<serde_json::Value, String> {
    let params = kdf::calibrate(target_ms.clamp(200, 3000));
    Ok(serde_json::json!({
        "mCostKib": params.m_cost_kib,
        "tCost": params.t_cost,
        "pCost": params.p_cost,
    }))
}

#[tauri::command(async)]
pub fn create_vault(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    path: Option<String>,
    password: String,
    calibrate_ms: Option<u32>,
    remember: Option<bool>,
) -> Result<VaultInfo, String> {
    let password = Zeroizing::new(password);
    let target = resolve(&app, path)?;

    if target.exists() {
        return Err("a vault already exists at that location".to_owned());
    }
    match target.parent() {
        Some(parent) if parent.is_dir() => {}
        Some(parent) => {
            return Err(format!(
                "the folder {} does not exist - if the vault lives on an encrypted volume or a removable disk, mount it first",
                parent.display()
            ))
        }
        None => return Err("that is not a valid file path".to_owned()),
    }

    let params =
        calibrate_ms.map_or_else(KdfParams::default, |ms| kdf::calibrate(ms.clamp(200, 3000)));

    let mut vault = Vault::create(password.as_bytes(), params).map_err(|e| e.to_string())?;
    vault.save(&target).map_err(|e| e.to_string())?;
    watermark::record(&app, &vault)?;
    apply_remember(&app, &target, remember);

    let session = Session::new(vault, target);
    let summary = info(&session, state.auto_lock().as_secs());
    state.set(session);
    Ok(summary)
}

#[tauri::command(async)]
pub fn unlock(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    path: Option<String>,
    password: String,
    remember: Option<bool>,
    accept_revision: Option<u64>,
) -> Result<VaultInfo, UnlockError> {
    let password = Zeroizing::new(password);
    let target = resolve(&app, path).map_err(UnlockError::message)?;

    if !target.exists() {
        let hint = match target.parent() {
            Some(parent) if !parent.is_dir() => format!(
                " - the folder {} is not there either, so the disk or encrypted volume may not be mounted",
                parent.display()
            ),
            _ => String::new(),
        };
        return Err(UnlockError::message(format!(
            "no vault found at {}{hint}",
            target.display()
        )));
    }

    let vault = Vault::open(&target, &Credential::Password(password.as_bytes()), None)
        .map_err(|_| UnlockError::message("could not unlock the vault with that password"))?;
    admit(&app, &vault, accept_revision)?;
    apply_remember(&app, &target, remember);

    let session = Session::new(vault, target);
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
pub fn save_entry(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    input: EntryInput,
) -> Result<Uuid, String> {
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
        persist(&app, session, &path)?;
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

    match input.totp_uri.as_deref().map(str::trim) {
        Some("") => entry.totp = None,
        Some(uri) => entry.totp = Some(Totp::from_uri(uri).map_err(|e| e.to_string())?),
        None => {}
    }

    if let Some(password) = input.password.as_ref() {
        entry.set_password(password.as_str());
    } else {
        entry.touch();
    }

    entry.validate().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn delete_entry(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
) -> Result<(), String> {
    state.with_session(|session| {
        session.vault.remove(id).map_err(|e| e.to_string())?;
        let path = session.path.clone();
        persist(&app, session, &path)?;
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

#[tauri::command(async)]
pub fn change_master_password(
    app: tauri::AppHandle,
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
        persist(&app, session, &path)?;
        Ok(())
    })
}

#[tauri::command]
pub fn probe_location(
    app: tauri::AppHandle,
    path: Option<String>,
) -> Result<LocationProbe, String> {
    let explicit = path.as_ref().is_some_and(|p| !p.trim().is_empty());
    let target = resolve(&app, path)?;
    let default = default_vault_path(&app)?;
    let remembered = !explicit && location::remembered(&app).is_some();

    let exists = target.is_file();
    let parent_exists = target.parent().is_some_and(std::path::Path::is_dir);
    let writable = if exists {
        true
    } else {
        location::parent_writable(&target)
    };
    let is_vault = exists && location::is_vault_file(&target);

    let warning = if exists && !is_vault {
        Some("There is a file here, but it is not an Obscura vault.".to_owned())
    } else if !parent_exists {
        Some(
            "That folder is not available. If the vault lives on an encrypted volume or a removable disk, mount it first."
                .to_owned(),
        )
    } else if !writable {
        Some("Obscura cannot write to that folder.".to_owned())
    } else if location::looks_synced(&target) {
        Some(
            "That folder looks like a syncing cloud drive. Sync clients can restore an older copy of a file, which for a vault means silently undoing password changes."
                .to_owned(),
        )
    } else {
        None
    };

    Ok(LocationProbe {
        path: target.display().to_string(),
        parent: target
            .parent()
            .map_or_else(String::new, |p| p.display().to_string()),
        exists,
        is_vault,
        parent_exists,
        writable,
        remembered,
        is_default: target == default,
        warning,
    })
}

#[tauri::command]
pub fn remembered_location(app: tauri::AppHandle) -> Result<Option<String>, String> {
    Ok(location::remembered(&app).map(|p| p.display().to_string()))
}

#[tauri::command]
pub fn forget_location(app: tauri::AppHandle) -> Result<(), String> {
    location::forget(&app)
}

#[tauri::command(async)]
pub fn pick_new_location(app: tauri::AppHandle) -> Result<Option<String>, String> {
    let start = default_vault_path(&app)?;
    let chosen = app
        .dialog()
        .file()
        .set_title("Where should Obscura keep your vault?")
        .add_filter("Obscura vault", &["obscura"])
        .set_file_name("obscura.obscura")
        .set_directory(start.parent().unwrap_or(&start))
        .blocking_save_file();
    Ok(chosen
        .and_then(|file| file.into_path().ok())
        .map(|p| p.display().to_string()))
}

#[tauri::command(async)]
pub fn pick_existing_vault(app: tauri::AppHandle) -> Result<Option<String>, String> {
    let start = resolve(&app, None)?;
    let chosen = app
        .dialog()
        .file()
        .set_title("Locate your Obscura vault")
        .add_filter("Obscura vault", &["obscura"])
        .set_directory(start.parent().unwrap_or(&start))
        .blocking_pick_file();
    Ok(chosen
        .and_then(|file| file.into_path().ok())
        .map(|p| p.display().to_string()))
}

#[tauri::command(async)]
pub fn relocate_vault(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    destination: String,
    remember: Option<bool>,
) -> Result<RelocateResult, String> {
    let target = PathBuf::from(destination.trim());
    if target.as_os_str().is_empty() {
        return Err("choose a destination first".to_owned());
    }
    if target.exists() {
        return Err("something already exists at that location".to_owned());
    }
    match target.parent() {
        Some(parent) if parent.is_dir() => {}
        Some(parent) => {
            return Err(format!(
                "the folder {} does not exist - mount the disk or volume first",
                parent.display()
            ))
        }
        None => return Err("that is not a valid file path".to_owned()),
    }

    let secs = state.auto_lock().as_secs();
    let (result, previous) = state.with_session(|session| {
        let previous = session.path.clone();
        session.vault.save(&target).map_err(|e| e.to_string())?;

        if !location::is_vault_file(&target) {
            let _ = std::fs::remove_file(&target);
            return Err("the vault did not write correctly to that location".to_owned());
        }

        session.path.clone_from(&target);
        session.min_revision = session.vault.revision();
        watermark::record(&app, &session.vault)?;
        Ok((info(session, secs), previous))
    })?;

    let previous_removed = std::fs::remove_file(&previous).is_ok();
    let _ = std::fs::remove_file(obscura_vault::backup_path(&previous));

    apply_remember(&app, &target, remember);

    Ok(RelocateResult {
        info: result,
        previous: previous.display().to_string(),
        previous_removed,
    })
}

#[tauri::command]
pub fn create_recovery_code(
    state: State<'_, AppState>,
    label: String,
) -> Result<IssuedRecoveryCode, String> {
    let label = if label.trim().is_empty() {
        "Recovery code".to_owned()
    } else {
        label.trim().to_owned()
    };

    state.with_session(|session| {
        let (slot, code) = session
            .vault
            .add_recovery_slot(label)
            .map_err(|e| e.to_string())?;
        Ok(IssuedRecoveryCode {
            slot,
            code: code.to_printable(),
        })
    })
}

#[tauri::command(async)]
pub fn confirm_recovery_code(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    code: String,
) -> Result<VaultInfo, String> {
    let parsed = RecoveryCode::parse(code.trim()).map_err(|e| e.to_string())?;
    let identity = parsed.identity();
    let secs = state.auto_lock().as_secs();

    state.with_session(|session| {
        if !session
            .vault
            .accepts(&Credential::Identity(&identity))
            .map_err(|e| e.to_string())?
        {
            return Err("that code does not open this vault".to_owned());
        }
        let path = session.path.clone();
        persist(&app, session, &path)?;
        Ok(info(session, secs))
    })
}

#[tauri::command]
pub fn discard_recovery_code(state: State<'_, AppState>, id: Uuid) -> Result<VaultInfo, String> {
    let secs = state.auto_lock().as_secs();
    state.with_session(|session| {
        session.vault.remove_slot(id).map_err(|e| e.to_string())?;
        Ok(info(session, secs))
    })
}

#[tauri::command(async)]
pub fn unlock_with_recovery(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    path: Option<String>,
    code: String,
    remember: Option<bool>,
    accept_revision: Option<u64>,
) -> Result<VaultInfo, UnlockError> {
    let parsed =
        RecoveryCode::parse(code.trim()).map_err(|e| UnlockError::message(e.to_string()))?;
    let target = resolve(&app, path).map_err(UnlockError::message)?;

    if !target.exists() {
        return Err(UnlockError::message(format!(
            "no vault found at {}",
            target.display()
        )));
    }

    let vault = Vault::open(&target, &Credential::Identity(&parsed.identity()), None)
        .map_err(|_| UnlockError::message("that recovery code does not open this vault"))?;
    admit(&app, &vault, accept_revision)?;
    apply_remember(&app, &target, remember);

    let session = Session::new(vault, target);
    let summary = info(&session, state.auto_lock().as_secs());
    state.set(session);
    Ok(summary)
}

#[tauri::command]
pub fn remove_slot(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
) -> Result<VaultInfo, String> {
    let secs = state.auto_lock().as_secs();
    state.with_session(|session| {
        session.vault.remove_slot(id).map_err(|e| e.to_string())?;
        let path = session.path.clone();
        persist(&app, session, &path)?;
        Ok(info(session, secs))
    })
}

#[tauri::command]
pub fn hello_selftest() -> Result<String, String> {
    use obscura_platform::hello;

    const PROBE_ID: &str = "selftest-0000-0000-0000-000000000000";

    let available = hello::is_available().map_err(|e| e.to_string())?;
    if !available {
        return Ok("Not available: this machine has no usable Windows Hello provider.".to_owned());
    }

    let enrolled = hello::enroll(PROBE_ID).map_err(|e| format!("Enrol failed: {e}"))?;
    let reproduced = hello::unlock(PROBE_ID).map_err(|e| {
        let _ = hello::forget(PROBE_ID);
        format!("Unlock failed: {e}")
    })?;

    let matches = reproduced.expose() == enrolled.expose();
    let _ = hello::forget(PROBE_ID);

    if matches {
        Ok(
            "Windows Hello works: the signature is reproducible and the derived key matched."
                .to_owned(),
        )
    } else {
        Err("The derived key changed between enrolment and unlock, so hardware unlock cannot work on this machine.".to_owned())
    }
}

#[tauri::command]
pub fn hello_isolation_setup() -> Result<String, String> {
    use obscura_platform::hello;

    const ISOLATION_ID: &str = "isolation-0000-0000-0000-000000000000";

    if !hello::is_available().map_err(|e| e.to_string())? {
        return Ok("Not available: this machine has no usable Windows Hello provider.".to_owned());
    }

    hello::enroll(ISOLATION_ID).map_err(|e| format!("Enrol failed: {e}"))?;

    let name = hello::credential_name(ISOLATION_ID);
    let print = hello::public_fingerprint(ISOLATION_ID)
        .map_err(|e| format!("The credential was created but could not be read back: {e}"))?;

    Ok(format!(
        "Test credential left in place.\n\nName: {name}\nPublic key: {print}\n\nNow run the scope probe from a terminal. If it prints the same fingerprint, a Hello credential is not private to the app that made it."
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const URI: &str = "otpauth://totp/GitHub:saheb?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";

    fn input() -> EntryInput {
        EntryInput {
            id: None,
            kind: obscura_vault::EntryKind::Login,
            title: "GitHub".to_owned(),
            username: "saheb".to_owned(),
            password: None,
            urls: Vec::new(),
            notes: String::new(),
            tags: Vec::new(),
            favorite: false,
            totp_uri: None,
        }
    }

    #[test]
    fn every_address_the_editor_sent_is_kept() {
        let mut entry = Entry::new_login("GitHub", "saheb");
        let mut sent = input();
        sent.urls = vec![
            "https://github.com".to_owned(),
            "https://gist.github.com".to_owned(),
            "https://github.dev".to_owned(),
        ];

        apply(&mut entry, &sent).unwrap();

        assert_eq!(
            entry.urls, sent.urls,
            "the editor used to send only the first address, so saving an entry silently \
             dropped every other one it had"
        );
    }

    #[test]
    fn the_kind_is_whatever_the_editor_sent() {
        let mut entry = Entry::new_login("Passport", "");
        let mut sent = input();
        sent.kind = obscura_vault::EntryKind::Identity;

        apply(&mut entry, &sent).unwrap();

        assert_eq!(entry.kind, obscura_vault::EntryKind::Identity);
    }

    #[test]
    fn a_two_factor_code_can_be_added_kept_and_removed() {
        let mut entry = Entry::new_login("GitHub", "saheb");

        let mut adding = input();
        adding.totp_uri = Some(URI.to_owned());
        apply(&mut entry, &adding).unwrap();
        assert!(entry.totp.is_some());

        apply(&mut entry, &input()).unwrap();
        assert!(
            entry.totp.is_some(),
            "no field means the editor did not touch the code"
        );

        let mut removing = input();
        removing.totp_uri = Some("   ".to_owned());
        apply(&mut entry, &removing).unwrap();
        assert!(
            entry.totp.is_none(),
            "an empty field is the only way to take a code off an entry, and before this \
             there was none - once added, a code could never be removed"
        );
    }
}
