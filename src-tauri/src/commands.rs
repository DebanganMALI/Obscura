#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::unnecessary_wraps)]

use std::{path::PathBuf, time::Duration};

use obscura_crypto::{hybrid::HybridSecretKey, kdf, KdfParams};
use obscura_platform::hello;
use obscura_vault::{
    csv_import,
    format::SlotKind,
    generator::{self, PasswordPolicy},
    portable, Credential, CustomField, Entry, RecoveryCode, SecretString, Totp, Vault,
};
use tauri::{Manager, State};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    clipboard,
    dto::{
        CustomFieldView, EntryDetail, EntryInput, EntrySummary, ExportResult, GeneratedPassword,
        ImportResult, IssuedRecoveryCode, LocationProbe, PasswordCheck, RelocateResult, SlotView,
        TotpCode, UnlockError, VaultInfo,
    },
    location,
    state::{AppState, Session},
    watermark,
};

fn kind_name(kind: SlotKind) -> &'static str {
    match kind {
        SlotKind::Password => "password",
        SlotKind::Recovery => "recovery",
        SlotKind::Passkey => "passkey",
        SlotKind::Hardware => "hardware",
        _ => "other",
    }
}

fn unlock_failure(error: &obscura_vault::VaultError) -> UnlockError {
    use obscura_vault::VaultError as E;
    match error {
        E::NoMatchingSlot => UnlockError::message("that password does not open this vault"),
        E::BadMagic => UnlockError::message("that file is not an Obscura vault"),
        E::UnsupportedVersion(v) => UnlockError::message(format!(
            "that vault was written in format version {v}, which this build of Obscura cannot read"
        )),
        E::Corrupt(what) => UnlockError::message(format!("the vault file is damaged: {what}")),
        E::Io(detail) => UnlockError::message(detail.clone()),
        other => UnlockError::message(other.to_string()),
    }
}

fn hello_failure(error: &obscura_platform::PlatformError) -> UnlockError {
    use obscura_platform::PlatformError as E;
    match error {
        E::CredentialMissing => UnlockError::message(
            "no Windows Hello credential is set up for this vault on this PC - unlock with your master password, then add one in Settings",
        ),
        E::Cancelled => UnlockError::message("Windows Hello was dismissed"),
        E::DeviceLocked => UnlockError::message(
            "the security device is locked - sign in to Windows again, then try once more",
        ),
        E::NotConfigured | E::Unsupported => {
            UnlockError::message("Windows Hello is not available on this machine")
        }
        other => UnlockError::message(other.to_string()),
    }
}
fn default_vault_path<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("cannot locate the application data directory: {e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir.join("obscura.obscura"))
}

fn resolve<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    path: Option<String>,
) -> Result<PathBuf, String> {
    if let Some(chosen) = path.filter(|p| !p.trim().is_empty()) {
        return Ok(PathBuf::from(chosen.trim()));
    }
    if let Some(remembered) = location::remembered(app) {
        return Ok(remembered);
    }
    default_vault_path(app)
}

fn apply_remember<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    path: &std::path::Path,
    remember: Option<bool>,
) {
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
                kind: kind_name(slot.kind).to_owned(),
                label: slot.label.clone(),
                created_at: slot
                    .created_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                portable: matches!(
                    slot.kind,
                    SlotKind::Password | SlotKind::Recovery | SlotKind::Passkey
                ),
            })
            .collect(),
        path: session.path.display().to_string(),
        auto_lock_secs,
        has_password: session.vault.has_password(),
        unlocked_by_recovery: session.unlocked_by_recovery,
    }
}

fn persist<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    session: &mut Session,
    path: &std::path::Path,
) -> Result<(), String> {
    session.vault.save(path).map_err(|e| e.to_string())?;
    session.min_revision = session.vault.revision();
    watermark::record(app, &session.vault)
}

enum Admission {
    Proceed,
    Reset,
    Refuse(UnlockError),
}

fn admission(
    verdict: watermark::Verdict,
    revision: u64,
    accept_revision: Option<u64>,
) -> Admission {
    match verdict {
        watermark::Verdict::Fresh | watermark::Verdict::Current => Admission::Proceed,
        watermark::Verdict::Tampered => {
            if accept_revision == Some(revision) {
                Admission::Proceed
            } else {
                Admission::Refuse(UnlockError::damaged(revision))
            }
        }
        watermark::Verdict::Rollback { found, expected } => {
            if accept_revision == Some(found) {
                Admission::Proceed
            } else {
                Admission::Refuse(UnlockError::rollback(found, expected))
            }
        }
        watermark::Verdict::Unreadable(detail) => {
            if accept_revision == Some(revision) {
                Admission::Reset
            } else {
                Admission::Refuse(UnlockError::unreadable(revision, detail))
            }
        }
    }
}

fn admit<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    vault: &Vault,
    accept_revision: Option<u64>,
) -> Result<(), UnlockError> {
    match admission(
        watermark::check(app, vault),
        vault.revision(),
        accept_revision,
    ) {
        Admission::Refuse(error) => Err(error),
        Admission::Reset => watermark::reset_to(app, vault).map_err(UnlockError::message),
        Admission::Proceed => watermark::record(app, vault).map_err(UnlockError::message),
    }
}

#[tauri::command]
pub fn vault_exists<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    path: Option<String>,
) -> Result<bool, String> {
    Ok(resolve(&app, path)?.exists())
}

#[tauri::command]
pub fn default_path<R: tauri::Runtime>(app: tauri::AppHandle<R>) -> Result<String, String> {
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

fn check_new_vault_location(target: &std::path::Path) -> Result<(), String> {
    if target.exists() {
        return Err("a vault already exists at that location".to_owned());
    }
    match target.parent() {
        Some(parent) if parent.is_dir() => Ok(()),
        Some(parent) => Err(format!(
            "the folder {} does not exist - if the vault lives on an encrypted volume or a removable disk, mount it first",
            parent.display()
        )),
        None => Err("that is not a valid file path".to_owned()),
    }
}

#[tauri::command(async)]
pub fn create_vault<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
    path: Option<String>,
    password: String,
    calibrate_ms: Option<u32>,
    remember: Option<bool>,
) -> Result<VaultInfo, String> {
    let password = Zeroizing::new(password);
    let target = resolve(&app, path)?;

    check_new_password(password.as_str(), "master password")?;
    check_new_vault_location(&target)?;

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
pub fn unlock<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
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
        .map_err(|e| unlock_failure(&e))?;
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
pub fn set_auto_lock<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
    seconds: u64,
) -> u64 {
    state.set_auto_lock(Duration::from_secs(seconds));
    let applied = state.auto_lock().as_secs();
    let _ = location::remember_auto_lock(&app, applied);
    applied
}

fn summaries(session: &Session, needle: &str) -> Vec<EntrySummary> {
    let mut found: Vec<EntrySummary> = session
        .vault
        .search(needle)
        .into_iter()
        .map(EntrySummary::from)
        .collect();
    found.sort_by(|a, b| {
        b.favorite
            .cmp(&a.favorite)
            .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
    });
    found
}

#[tauri::command]
pub fn list_entries(
    state: State<'_, AppState>,
    query: Option<String>,
) -> Result<Vec<EntrySummary>, String> {
    let needle = query.unwrap_or_default();
    state.with_session(|session| Ok(summaries(session, &needle)))
}

fn detail(session: &Session, id: Uuid) -> Result<EntryDetail, String> {
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
}

#[tauri::command]
pub fn get_entry(state: State<'_, AppState>, id: Uuid) -> Result<EntryDetail, String> {
    state.with_session(|session| detail(session, id))
}

fn field_value(session: &Session, id: Uuid, name: &str) -> Result<String, String> {
    let entry = session.vault.get(id).ok_or("no such entry")?;
    entry
        .custom_fields
        .iter()
        .find(|field| field.name == name)
        .map(|field| field.value.expose().to_owned())
        .ok_or_else(|| "no such field".to_owned())
}

#[tauri::command]
pub fn reveal_field(state: State<'_, AppState>, id: Uuid, name: String) -> Result<String, String> {
    state.with_session(|session| field_value(session, id, &name))
}

fn password_value(session: &Session, id: Uuid) -> Result<String, String> {
    let entry = session.vault.get(id).ok_or("no such entry")?;
    Ok(entry.password.expose().to_owned())
}

#[tauri::command]
pub fn reveal_password(state: State<'_, AppState>, id: Uuid) -> Result<String, String> {
    state.with_session(|session| password_value(session, id))
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

fn store(session: &mut Session, input: &EntryInput) -> Result<Uuid, String> {
    if let Some(existing) = input.id {
        let mut edited = session.vault.get(existing).ok_or("no such entry")?.clone();
        apply(&mut edited, input)?;
        *session.vault.get_mut(existing).ok_or("no such entry")? = edited;
        Ok(existing)
    } else {
        let mut entry = Entry::new_login(input.title.clone(), input.username.clone());
        apply(&mut entry, input)?;
        session.vault.add(entry).map_err(|e| e.to_string())
    }
}

#[tauri::command]
pub fn save_entry<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
    input: EntryInput,
) -> Result<Uuid, String> {
    state.with_session(|session| {
        let id = store(session, &input)?;
        let path = session.path.clone();
        persist(&app, session, &path)?;
        Ok(id)
    })
}

fn rebuild_fields(entry: &mut Entry, input: &EntryInput) -> Vec<CustomField> {
    let previous = std::mem::take(&mut entry.custom_fields);
    let mut fields = Vec::with_capacity(input.custom_fields.len());

    for sent in &input.custom_fields {
        let name = sent.name.trim();
        if name.is_empty() {
            continue;
        }
        let value = match sent.value.as_deref() {
            Some(text) => SecretString::from(text),
            None => previous
                .iter()
                .find(|old| old.name == name)
                .map_or_else(SecretString::default, |old| old.value.clone()),
        };
        fields.push(CustomField {
            name: name.to_owned(),
            value,
            hidden: sent.hidden,
        });
    }
    fields
}

fn apply(entry: &mut Entry, input: &EntryInput) -> Result<(), String> {
    entry.kind = input.kind;
    entry.title.clone_from(&input.title);
    entry.username.clone_from(&input.username);
    entry.urls.clone_from(&input.urls);
    entry.notes = SecretString::from(input.notes.as_str());
    entry.tags.clone_from(&input.tags);
    entry.favorite = input.favorite;
    entry.custom_fields = rebuild_fields(entry, input);

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
pub fn delete_entry<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
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

fn totp_for(session: &Session, id: Uuid) -> Result<TotpCode, String> {
    let entry = session.vault.get(id).ok_or("no such entry")?;
    let totp = entry.totp.as_ref().ok_or("this entry has no TOTP")?;
    let (code, remaining) = totp.current().map_err(|e| e.to_string())?;
    Ok(TotpCode {
        code,
        remaining,
        period: totp.period(),
    })
}

#[tauri::command]
pub fn totp_code(state: State<'_, AppState>, id: Uuid) -> Result<TotpCode, String> {
    state.with_session(|session| totp_for(session, id))
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
pub fn set_master_password<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
    password: String,
) -> Result<VaultInfo, String> {
    let password = Zeroizing::new(password);
    check_new_password(password.as_str(), "master password")?;
    let secs = state.auto_lock().as_secs();

    state.with_session(|session| {
        session
            .vault
            .add_password(password.as_bytes(), None)
            .map_err(|e| e.to_string())?;
        let path = session.path.clone();
        persist(&app, session, &path)?;
        Ok(info(session, secs))
    })
}

#[tauri::command(async)]
pub fn change_master_password<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
    current: String,
    new: String,
) -> Result<(), String> {
    let current = Zeroizing::new(current);
    let new = Zeroizing::new(new);

    check_new_password(new.as_str(), "new password")?;

    state.with_session(|session| {
        if !session
            .vault
            .accepts(&Credential::Password(current.as_bytes()))
            .map_err(|e| e.to_string())?
        {
            return Err("the current password is not correct".to_owned());
        }

        session
            .vault
            .change_password(new.as_bytes(), None)
            .map_err(|e| e.to_string())?;
        let path = session.path.clone();
        persist(&app, session, &path)?;
        Ok(())
    })
}

#[tauri::command(async)]
pub fn reset_master_password<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
    new: String,
) -> Result<VaultInfo, String> {
    let new = Zeroizing::new(new);
    let secs = state.auto_lock().as_secs();

    state.with_session(|session| {
        reset_password(session, new.as_str())?;
        let path = session.path.clone();
        persist(&app, session, &path)?;
        Ok(info(session, secs))
    })
}

fn reset_password(session: &mut Session, password: &str) -> Result<(), String> {
    if !session.unlocked_by_recovery {
        return Err(
            "a forgotten master password can only be reset after unlocking with your recovery code"
                .to_owned(),
        );
    }
    check_new_password(password, "new password")?;
    if session.vault.has_password() {
        session
            .vault
            .change_password(password.as_bytes(), None)
            .map_err(|e| e.to_string())
    } else {
        session
            .vault
            .add_password(password.as_bytes(), None)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

fn remove_unlock_method(
    session: &mut Session,
    id: Uuid,
    expected: Option<SlotKind>,
) -> Result<(), String> {
    let Some(kind) = session
        .vault
        .slots()
        .iter()
        .find(|slot| slot.id == id)
        .map(|slot| slot.kind)
    else {
        return Err("that unlock method is not on this vault".to_owned());
    };
    if kind == SlotKind::Password {
        return Err("the master password can be changed but never removed".to_owned());
    }
    if expected.is_some_and(|wanted| wanted != kind) {
        return Err("that unlock method cannot be removed from here".to_owned());
    }
    session.vault.remove_slot(id).map_err(|e| e.to_string())
}

#[tauri::command]
#[must_use]
pub fn assess_password(password: String) -> PasswordCheck {
    let password = Zeroizing::new(password);
    let assessment = obscura_vault::policy::assess(password.as_str());
    PasswordCheck {
        score: assessment.score,
        problem: assessment
            .weakness
            .map(|weakness| weakness.describe("password")),
    }
}

fn check_new_password(password: &str, label: &str) -> Result<(), String> {
    match obscura_vault::policy::weakness(password) {
        Some(weakness) => Err(weakness.describe(label)),
        None => Ok(()),
    }
}

fn check_destination(target: &std::path::Path) -> Result<(), String> {
    if target.as_os_str().is_empty() {
        return Err("choose a destination first".to_owned());
    }
    if target.exists() {
        return Err("something already exists at that location".to_owned());
    }
    match target.parent() {
        Some(parent) if parent.is_dir() => Ok(()),
        Some(parent) => Err(format!(
            "the folder {} does not exist - mount the disk or volume first",
            parent.display()
        )),
        None => Err("that is not a valid file path".to_owned()),
    }
}

enum TargetState {
    Missing,
    Vault,
    Foreign,
}

impl TargetState {
    const fn of(exists: bool, is_vault: bool) -> Self {
        if !exists {
            Self::Missing
        } else if is_vault {
            Self::Vault
        } else {
            Self::Foreign
        }
    }
}

fn warning_for(
    state: TargetState,
    parent_exists: bool,
    writable: bool,
    synced: bool,
) -> Option<String> {
    if matches!(state, TargetState::Foreign) {
        Some("There is a file here, but it is not an Obscura vault.".to_owned())
    } else if !parent_exists {
        Some(
            "That folder is not available. If the vault lives on an encrypted volume or a removable disk, mount it first."
                .to_owned(),
        )
    } else if !writable {
        Some(match state {
            TargetState::Vault => {
                "That vault is read-only, so Obscura can open it but cannot save changes."
                    .to_owned()
            }
            TargetState::Missing | TargetState::Foreign => {
                "Obscura cannot write to that folder.".to_owned()
            }
        })
    } else if synced {
        Some(
            "That folder looks like a syncing cloud drive. Sync clients can restore an older copy of a file, which for a vault means silently undoing password changes."
                .to_owned(),
        )
    } else {
        None
    }
}

#[tauri::command]
pub fn probe_location<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    path: Option<String>,
) -> Result<LocationProbe, String> {
    let explicit = path.as_ref().is_some_and(|p| !p.trim().is_empty());
    let target = resolve(&app, path)?;
    let default = default_vault_path(&app)?;
    let remembered = !explicit && location::remembered(&app).is_some();

    let exists = target.is_file();
    let parent_exists = target.parent().is_some_and(std::path::Path::is_dir);
    let writable =
        location::parent_writable(&target) && (!exists || location::file_writable(&target));
    let is_vault = exists && location::is_vault_file(&target);

    let warning = warning_for(
        TargetState::of(exists, is_vault),
        parent_exists,
        writable,
        location::looks_synced(&target),
    );

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
pub fn remembered_location<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
) -> Result<Option<String>, String> {
    Ok(location::remembered(&app).map(|p| p.display().to_string()))
}

#[tauri::command]
pub fn forget_location<R: tauri::Runtime>(app: tauri::AppHandle<R>) -> Result<(), String> {
    location::forget(&app)
}

#[tauri::command(async)]
pub fn pick_new_location<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
) -> Result<Option<String>, String> {
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
pub fn pick_existing_vault<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
) -> Result<Option<String>, String> {
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
pub fn export_entries<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
) -> Result<Option<ExportResult>, String> {
    let today = time::OffsetDateTime::now_utc().date();
    let Some(target) = app
        .dialog()
        .file()
        .set_title("Where should the plain-text export go?")
        .add_filter("Obscura export", &["json"])
        .set_file_name(format!("obscura-export-{today}.json"))
        .blocking_save_file()
        .and_then(|file| file.into_path().ok())
    else {
        return Ok(None);
    };

    let doc = state.with_session(|session| Ok(session.vault.export()))?;
    portable::write(&target, &doc).map_err(|e| e.to_string())?;

    Ok(Some(ExportResult {
        path: target.display().to_string(),
        entries: doc.entries.len(),
    }))
}

#[tauri::command(async)]
pub fn import_entries<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
) -> Result<Option<ImportResult>, String> {
    let Some(chosen) = app
        .dialog()
        .file()
        .set_title("Which file should Obscura read?")
        .add_filter("Export or CSV", &["json", "csv"])
        .blocking_pick_file()
        .and_then(|file| file.into_path().ok())
    else {
        return Ok(None);
    };

    let bytes = Zeroizing::new(
        std::fs::read(&chosen).map_err(|e| format!("cannot read {}: {e}", chosen.display()))?,
    );
    let (label, entries, notes) = read_import(&bytes)?;
    let secs = state.auto_lock().as_secs();

    state.with_session(|session| {
        let report = session
            .vault
            .import_all(entries)
            .map_err(|e| e.to_string())?;
        let path = session.path.clone();
        persist(&app, session, &path)?;
        Ok(Some(ImportResult {
            path: chosen.display().to_string(),
            source: label,
            added: report.added,
            renumbered: report.renumbered,
            skipped: notes.skipped_blank + notes.skipped_invalid,
            totp_dropped: notes.totp_dropped,
            info: info(session, secs),
        }))
    })
}

fn read_import(bytes: &[u8]) -> Result<(String, Vec<Entry>, csv_import::CsvNotes), String> {
    match portable::decode(bytes) {
        Ok(doc) => Ok((
            "an Obscura export".to_owned(),
            doc.entries,
            csv_import::CsvNotes::default(),
        )),
        Err(json_reason) => match csv_import::parse(bytes) {
            Ok((source, entries, notes)) => Ok((format!("a {} export", source.label()), entries, notes)),
            Err(csv_reason) => Err(format!(
                "Obscura could not read that file. As an Obscura export: {json_reason}. As a CSV: {csv_reason}."
            )),
        },
    }
}

#[tauri::command(async)]
pub fn relocate_vault<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
    destination: String,
    remember: Option<bool>,
) -> Result<RelocateResult, String> {
    let target = PathBuf::from(destination.trim());
    check_destination(&target)?;

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
pub fn confirm_recovery_code<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
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
        remove_unlock_method(session, id, Some(SlotKind::Recovery))?;
        Ok(info(session, secs))
    })
}

#[tauri::command(async)]
pub fn unlock_with_recovery<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
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

    let mut session = Session::new(vault, target);
    session.unlocked_by_recovery = true;
    let summary = info(&session, state.auto_lock().as_secs());
    state.set(session);
    Ok(summary)
}

#[tauri::command]
pub fn remove_slot<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
    id: Uuid,
) -> Result<VaultInfo, String> {
    let secs = state.auto_lock().as_secs();
    state.with_session(|session| {
        remove_unlock_method(session, id, None)?;
        let path = session.path.clone();
        persist(&app, session, &path)?;
        Ok(info(session, secs))
    })
}

#[tauri::command]
pub fn hello_available() -> Result<bool, String> {
    hello::is_available().map_err(|e| e.to_string())
}

#[tauri::command(async)]
pub fn hello_enroll<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
    label: String,
) -> Result<VaultInfo, String> {
    let secs = state.auto_lock().as_secs();
    let label = if label.trim().is_empty() {
        "Windows Hello".to_owned()
    } else {
        label.trim().to_owned()
    };

    state.with_session(|session| {
        let vault_id = session.vault.id().to_string();
        let seed = hello::enroll(&vault_id).map_err(|e| e.to_string())?;
        session
            .vault
            .add_identity_slot(SlotKind::Hardware, label, &HybridSecretKey::from_seed(seed))
            .map_err(|e| e.to_string())?;
        let path = session.path.clone();
        persist(&app, session, &path)?;
        Ok(info(session, secs))
    })
}

#[tauri::command(async)]
pub fn hello_forget<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
    id: Uuid,
) -> Result<VaultInfo, String> {
    let secs = state.auto_lock().as_secs();
    state.with_session(|session| {
        let vault_id = session.vault.id().to_string();
        remove_unlock_method(session, id, Some(SlotKind::Hardware))?;
        hello::forget(&vault_id).map_err(|e| e.to_string())?;
        let path = session.path.clone();
        persist(&app, session, &path)?;
        Ok(info(session, secs))
    })
}

#[tauri::command(async)]
pub fn unlock_with_hello<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
    path: Option<String>,
    remember: Option<bool>,
    accept_revision: Option<u64>,
) -> Result<VaultInfo, UnlockError> {
    let target = resolve(&app, path).map_err(UnlockError::message)?;
    if !target.exists() {
        return Err(UnlockError::message(format!(
            "no vault found at {}",
            target.display()
        )));
    }

    let bytes = std::fs::read(&target)
        .map_err(|e| UnlockError::message(format!("cannot read {}: {e}", target.display())))?;
    let (header, _, _) =
        obscura_vault::format::decode_header(&bytes).map_err(|e| unlock_failure(&e))?;

    let seed = hello::unlock(&header.vault_id.to_string()).map_err(|e| hello_failure(&e))?;

    let vault = Vault::from_bytes(
        &bytes,
        &Credential::Identity(&HybridSecretKey::from_seed(seed)),
        None,
    )
    .map_err(|e| unlock_failure(&e))?;

    admit(&app, &vault, accept_revision)?;
    apply_remember(&app, &target, remember);

    let session = Session::new(vault, target);
    let summary = info(&session, state.auto_lock().as_secs());
    state.set(session);
    Ok(summary)
}

#[cfg(target_os = "windows")]
fn passkey_window<R: tauri::Runtime>(window: &tauri::WebviewWindow<R>) -> Result<isize, String> {
    window
        .hwnd()
        .map(|handle| handle.0 as isize)
        .map_err(|e| format!("cannot find the application window: {e}"))
}

#[cfg(not(target_os = "windows"))]
fn passkey_window<R: tauri::Runtime>(_window: &tauri::WebviewWindow<R>) -> Result<isize, String> {
    Err("passkeys need Windows in this build of Obscura".to_owned())
}

fn passkey_failure(error: &obscura_webauthn::WebAuthnError) -> UnlockError {
    use obscura_webauthn::WebAuthnError as E;
    match error {
        E::ApiTooOld(version) => UnlockError::message(format!(
            "this copy of Windows speaks WebAuthn version {version}, and a passkey needs version \
             {}, which arrived in Windows 10 version 2004",
            obscura_webauthn::PRF_API_VERSION
        )),
        E::NoPrfSecret | E::PrfSecretLength(_) => UnlockError::message(
            "that authenticator cannot derive a vault key, so it cannot open this vault",
        ),
        E::Unsupported => UnlockError::message("this build of Obscura has no passkey support"),
        other => UnlockError::message(other.to_string()),
    }
}

#[tauri::command]
pub fn passkey_available() -> bool {
    obscura_webauthn::is_available()
}

#[tauri::command(async)]
pub fn passkey_enroll<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    window: tauri::WebviewWindow<R>,
    state: State<'_, AppState>,
    label: String,
) -> Result<VaultInfo, String> {
    let secs = state.auto_lock().as_secs();
    let handle = passkey_window(&window)?;
    let label = label.trim().to_owned();

    state.with_session(|session| {
        let vault_id = session.vault.id().to_string();
        let enrolled = obscura_webauthn::enroll(
            handle,
            obscura_webauthn::RP_ID,
            "Obscura",
            &vault_id,
            vault_id.as_bytes(),
        )
        .map_err(|e| e.to_string())?;

        if !enrolled.prf_enabled {
            return Err(
                "that authenticator cannot derive a vault key, so it cannot open this vault"
                    .to_owned(),
            );
        }

        let salt = obscura_webauthn::salt_for(&vault_id).map_err(|e| e.to_string())?;
        let seed = obscura_webauthn::prf_secret(handle, obscura_webauthn::RP_ID, &salt)
            .map_err(|e| e.to_string())?;

        session
            .vault
            .add_identity_slot(
                SlotKind::Passkey,
                if label.is_empty() {
                    obscura_webauthn::label_for(enrolled.transport).to_owned()
                } else {
                    label
                },
                &HybridSecretKey::from_seed(seed),
            )
            .map_err(|e| e.to_string())?;
        let path = session.path.clone();
        persist(&app, session, &path)?;
        Ok(info(session, secs))
    })
}

#[tauri::command(async)]
pub fn unlock_with_passkey<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    window: tauri::WebviewWindow<R>,
    state: State<'_, AppState>,
    path: Option<String>,
    remember: Option<bool>,
    accept_revision: Option<u64>,
) -> Result<VaultInfo, UnlockError> {
    let handle = passkey_window(&window).map_err(UnlockError::message)?;
    let target = resolve(&app, path).map_err(UnlockError::message)?;
    if !target.exists() {
        return Err(UnlockError::message(format!(
            "no vault found at {}",
            target.display()
        )));
    }

    let bytes = std::fs::read(&target)
        .map_err(|e| UnlockError::message(format!("cannot read {}: {e}", target.display())))?;
    let (header, _, _) =
        obscura_vault::format::decode_header(&bytes).map_err(|e| unlock_failure(&e))?;

    let salt = obscura_webauthn::salt_for(&header.vault_id.to_string())
        .map_err(|e| passkey_failure(&e))?;
    let seed = obscura_webauthn::prf_secret(handle, obscura_webauthn::RP_ID, &salt)
        .map_err(|e| passkey_failure(&e))?;

    let vault = Vault::from_bytes(
        &bytes,
        &Credential::Identity(&HybridSecretKey::from_seed(seed)),
        None,
    )
    .map_err(|e| unlock_failure(&e))?;

    admit(&app, &vault, accept_revision)?;
    apply_remember(&app, &target, remember);

    let session = Session::new(vault, target);
    let summary = info(&session, state.auto_lock().as_secs());
    state.set(session);
    Ok(summary)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
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
            custom_fields: Vec::new(),
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
    fn a_hidden_field_keeps_its_value_when_the_editor_could_not_see_it() {
        use crate::dto::CustomFieldInput;

        let mut entry = Entry::new_login("Bank", "saheb");
        let mut adding = input();
        adding.custom_fields = vec![
            CustomFieldInput {
                name: "PIN".to_owned(),
                value: Some("4821".to_owned()),
                hidden: true,
            },
            CustomFieldInput {
                name: "Branch".to_owned(),
                value: Some("Habra".to_owned()),
                hidden: false,
            },
        ];
        apply(&mut entry, &adding).unwrap();
        assert_eq!(entry.custom_fields.len(), 2);

        let mut editing = input();
        editing.custom_fields = vec![
            CustomFieldInput {
                name: "PIN".to_owned(),
                value: None,
                hidden: true,
            },
            CustomFieldInput {
                name: "Branch".to_owned(),
                value: Some("Kolkata".to_owned()),
                hidden: false,
            },
        ];
        apply(&mut entry, &editing).unwrap();

        assert_eq!(
            entry.custom_fields[0].value.expose(),
            "4821",
            "the editor never receives a hidden value, so sending nothing back has to mean \
             keep it - anything else silently empties the field on the next unrelated edit"
        );
        assert_eq!(entry.custom_fields[1].value.expose(), "Kolkata");

        let mut removing = input();
        removing.custom_fields = vec![CustomFieldInput {
            name: "Branch".to_owned(),
            value: Some("Kolkata".to_owned()),
            hidden: false,
        }];
        apply(&mut entry, &removing).unwrap();
        assert_eq!(entry.custom_fields.len(), 1);
        assert_eq!(entry.custom_fields[0].name, "Branch");
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod session_reads {
    use super::*;
    use obscura_vault::CustomField;

    const FAST: KdfParams = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 2,
        p_cost: 1,
    };

    fn a_session() -> (Session, Uuid) {
        let mut vault = Vault::create(b"correct horse battery staple", FAST).unwrap();

        let mut entry = Entry::new_login("GitHub", "saheb");
        entry.set_password("correct-horse-battery-staple");
        entry.notes = SecretString::from("a private note");
        entry.custom_fields = vec![
            CustomField {
                name: "shown".to_owned(),
                value: SecretString::from("a visible value"),
                hidden: false,
            },
            CustomField {
                name: "hidden".to_owned(),
                value: SecretString::from("a hidden value"),
                hidden: true,
            },
        ];
        let id = vault.add(entry).unwrap();

        let mut favourite = Entry::new_login("aardvark", "someone");
        favourite.favorite = true;
        vault.add(favourite).unwrap();

        (Session::new(vault, PathBuf::from("vault.obscura")), id)
    }

    #[test]
    fn the_entry_view_withholds_a_hidden_field_but_keeps_its_name() {
        let (session, id) = a_session();
        let view = detail(&session, id).unwrap();

        let shown = view
            .custom_fields
            .iter()
            .find(|f| f.name == "shown")
            .unwrap();
        assert_eq!(shown.value.as_deref(), Some("a visible value"));
        assert!(!shown.hidden);

        let hidden = view
            .custom_fields
            .iter()
            .find(|f| f.name == "hidden")
            .unwrap();
        assert!(hidden.hidden);
        assert!(
            hidden.value.is_none(),
            "a hidden field's value must reach the interface only through reveal_field"
        );
    }

    #[test]
    fn the_entry_view_sends_a_length_and_never_the_password() {
        let (session, id) = a_session();
        let view = detail(&session, id).unwrap();

        assert_eq!(view.password_len, "correct-horse-battery-staple".len());

        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("correct-horse-battery-staple"));
        assert!(!json.contains("a hidden value"));
    }

    #[test]
    fn revealing_answers_for_one_named_field_and_refuses_the_rest() {
        let (session, id) = a_session();

        assert_eq!(
            field_value(&session, id, "hidden").unwrap(),
            "a hidden value"
        );
        assert_eq!(
            field_value(&session, id, "shown").unwrap(),
            "a visible value"
        );
        assert!(field_value(&session, id, "absent").is_err());
        assert!(field_value(&session, Uuid::nil(), "hidden").is_err());
    }

    #[test]
    fn a_password_is_revealed_only_for_an_entry_that_exists() {
        let (session, id) = a_session();

        assert_eq!(
            password_value(&session, id).unwrap(),
            "correct-horse-battery-staple"
        );
        assert!(password_value(&session, Uuid::nil()).is_err());
    }

    #[test]
    fn the_list_puts_favourites_first_and_then_sorts_by_title() {
        let (session, _) = a_session();
        let all = summaries(&session, "");

        assert_eq!(all.len(), 2);
        assert_eq!(all[0].title, "aardvark");
        assert_eq!(all[1].title, "GitHub");

        assert_eq!(summaries(&session, "github").len(), 1);
        assert_eq!(summaries(&session, "nothing here at all").len(), 0);
    }

    #[test]
    fn a_generated_password_matches_the_policy_it_was_asked_for() {
        let made = generate(24, true, true, true, false, false, true).unwrap();
        assert_eq!(made.password.chars().count(), 24);
        assert!(made.entropy_bits > 0.0);
        assert!(generate(0, true, true, true, true, false, true).is_err());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod plain_parts {
    use super::*;

    #[test]
    fn a_file_that_is_neither_an_export_nor_a_csv_names_both_attempts() {
        let error = read_import(b"this is not a vault and not a table").unwrap_err();
        assert!(error.contains("As an Obscura export"), "{error}");
        assert!(error.contains("As a CSV"), "{error}");
        assert!(read_import(b"").is_err());
    }

    #[test]
    fn a_csv_is_read_once_the_export_reader_has_refused_it() {
        let (label, entries, notes) =
            read_import(b"name,login_username,login_password\nGitHub,saheb,hunter2\n").unwrap();

        assert!(
            label.to_lowercase().contains("bitwarden"),
            "the import report would name the wrong source: {label}"
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "GitHub");
        assert_eq!(notes.skipped_blank + notes.skipped_invalid, 0);
    }

    #[test]
    fn a_file_here_that_is_not_a_vault_outranks_every_other_warning() {
        let warning = warning_for(TargetState::Foreign, false, false, true).unwrap();
        assert!(warning.contains("not an Obscura vault"), "{warning}");
    }

    #[test]
    fn a_missing_folder_is_reported_before_an_unwritable_one() {
        assert!(warning_for(TargetState::Missing, false, false, false)
            .unwrap()
            .contains("not available"));
        assert!(warning_for(TargetState::Missing, true, false, false)
            .unwrap()
            .contains("cannot write"));
    }

    #[test]
    fn a_syncing_folder_is_flagged_even_when_nothing_else_is_wrong() {
        let warning = warning_for(TargetState::Vault, true, true, true).unwrap();
        assert!(warning.contains("cloud drive"), "{warning}");
        assert!(warning_for(TargetState::Vault, true, true, false).is_none());
        assert!(warning_for(TargetState::Missing, true, true, false).is_none());
    }

    #[test]
    fn a_relocation_target_must_be_named_free_and_inside_a_folder_that_exists() {
        assert!(check_destination(std::path::Path::new("")).is_err());

        let dir = std::env::temp_dir().join(format!("obscura-relocate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let free = dir.join("moved.obscura");
        assert!(check_destination(&free).is_ok());

        std::fs::write(&free, b"not a vault").unwrap();
        assert!(
            check_destination(&free).is_err(),
            "relocating must never write over a file that is already there"
        );

        assert!(check_destination(&dir.join("absent").join("moved.obscura"))
            .unwrap_err()
            .contains("does not exist"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_new_master_password_is_measured_and_the_message_says_which_one() {
        let short = "a".repeat(obscura_vault::MIN_PASSWORD_CHARS - 1);
        let long = "lantern mango quiet orbit";

        let error = check_new_password(&short, "master password").unwrap_err();
        assert!(error.contains("master password"), "{error}");
        assert!(
            error.contains(&obscura_vault::MIN_PASSWORD_CHARS.to_string()),
            "{error}"
        );

        assert!(check_new_password(&short, "new password")
            .unwrap_err()
            .contains("new password"));
        assert!(check_new_password(long, "master password").is_ok());
    }

    #[test]
    fn a_common_master_password_is_refused_and_the_message_says_which_one() {
        let error = check_new_password("Correct Horse Battery Staple", "new password").unwrap_err();
        assert!(error.contains("new password"), "{error}");
        assert!(error.contains("common"), "{error}");
    }

    #[test]
    fn the_meter_reports_the_same_verdict_as_the_check() {
        let weak = assess_password("correcthorsebatterystaple".to_owned());
        assert_eq!(weak.score, 1);
        assert!(weak.problem.unwrap().contains("common"));

        let fine = assess_password("lantern mango quiet orbit tamarind".to_owned());
        assert!(fine.score >= 3);
        assert!(fine.problem.is_none());

        assert_eq!(assess_password(String::new()).score, 0);
    }

    #[test]
    fn a_new_master_password_is_counted_in_characters_not_bytes() {
        let short = "\u{0986}".repeat(obscura_vault::MIN_PASSWORD_CHARS - 1);
        let enough: String = ('\u{0995}'..='\u{09A3}').collect();

        assert!(short.len() > obscura_vault::MIN_PASSWORD_CHARS);
        assert!(check_new_password(&short, "master password").is_err());
        assert!(check_new_password(&enough, "master password").is_ok());
    }

    #[test]
    fn a_file_that_is_not_a_vault_is_told_apart_from_no_file_at_all() {
        assert!(matches!(
            TargetState::of(false, false),
            TargetState::Missing
        ));
        assert!(matches!(TargetState::of(true, true), TargetState::Vault));
        assert!(matches!(TargetState::of(true, false), TargetState::Foreign));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod unlock_and_info {
    use super::*;
    use obscura_vault::VaultError as E;

    const FAST: KdfParams = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 2,
        p_cost: 1,
    };

    const PASSWORD: &[u8] = b"correct horse battery staple";

    fn shown(error: &UnlockError) -> String {
        serde_json::to_string(error).unwrap()
    }

    fn a_session() -> Session {
        let mut vault = Vault::create(PASSWORD, FAST).unwrap();
        vault.add(Entry::new_login("GitHub", "saheb")).unwrap();
        Session::new(vault, PathBuf::from("vault.obscura"))
    }

    #[test]
    fn a_wrong_password_is_never_reported_as_a_damaged_file() {
        let told = shown(&unlock_failure(&E::NoMatchingSlot));
        assert!(
            told.contains("that password does not open this vault"),
            "{told}"
        );
        assert!(!told.contains("damaged"), "{told}");
        assert!(!told.contains("not an Obscura vault"), "{told}");
    }

    #[test]
    fn a_damaged_file_is_never_reported_as_a_wrong_password() {
        let told = shown(&unlock_failure(&E::Corrupt("the header is truncated")));
        assert!(told.contains("damaged"), "{told}");
        assert!(told.contains("the header is truncated"), "{told}");
        assert!(!told.contains("password"), "{told}");
    }

    #[test]
    fn every_other_arm_says_something_of_its_own() {
        assert!(shown(&unlock_failure(&E::BadMagic)).contains("not an Obscura vault"));
        assert!(shown(&unlock_failure(&E::UnsupportedVersion(7))).contains('7'));
        assert!(
            shown(&unlock_failure(&E::Io("permission denied".to_owned())))
                .contains("permission denied")
        );

        let fallback = E::RecoveryCodeFormat;
        let told = shown(&unlock_failure(&fallback));
        assert!(told.contains(&fallback.to_string()), "{told}");
    }

    #[test]
    fn the_summary_describes_the_vault_the_session_holds() {
        let session = a_session();
        let summary = info(&session, 300);

        assert_eq!(summary.entry_count, 1);
        assert_eq!(summary.auto_lock_secs, 300);
        assert_eq!(summary.path, "vault.obscura");
        assert!(summary.has_password);
        assert_eq!(summary.revision, session.vault.revision());

        assert_eq!(summary.slots.len(), 1);
        assert_eq!(summary.slots[0].kind, "password");
        assert!(summary.slots[0].portable);
        assert!(
            summary.slots[0].created_at.contains('T'),
            "a slot's creation time reaches the interface as RFC 3339: {}",
            summary.slots[0].created_at
        );
    }

    #[test]
    fn the_summary_never_carries_the_master_password() {
        let session = a_session();
        let json = serde_json::to_string(&info(&session, 300)).unwrap();
        assert!(!json.contains("correct horse battery staple"), "{json}");
    }

    #[test]
    fn an_obscura_export_is_read_as_one_rather_than_falling_through_to_the_csv_reader() {
        let session = a_session();
        let doc = session.vault.export();
        let bytes = portable::encode(&doc).unwrap();

        let (label, entries, notes) = read_import(bytes.as_slice()).unwrap();

        assert!(
            label.contains("Obscura"),
            "a user's own backup must be named as one: {label}"
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "GitHub");
        assert_eq!(notes.skipped_blank + notes.skipped_invalid, 0);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod admission_rules {
    use super::*;
    use watermark::Verdict;

    const REVISION: u64 = 12;

    fn refusal(admission: Admission) -> String {
        match admission {
            Admission::Refuse(error) => serde_json::to_string(&error).unwrap(),
            Admission::Proceed => panic!("this was let through and should not have been"),
            Admission::Reset => panic!("this reset the watermark and should not have"),
        }
    }

    #[test]
    fn a_vault_whose_watermark_agrees_opens_without_a_question() {
        assert!(matches!(
            admission(Verdict::Fresh, REVISION, None),
            Admission::Proceed
        ));
        assert!(matches!(
            admission(Verdict::Current, REVISION, None),
            Admission::Proceed
        ));
        assert!(matches!(
            admission(Verdict::Current, REVISION, Some(999)),
            Admission::Proceed
        ));
    }

    #[test]
    fn a_rolled_back_vault_is_refused_until_the_revision_on_disk_is_confirmed() {
        let told = refusal(admission(
            Verdict::Rollback {
                found: 9,
                expected: REVISION,
            },
            9,
            None,
        ));
        assert!(told.contains('9'), "{told}");
        assert!(told.contains("12"), "{told}");

        assert!(
            matches!(
                admission(
                    Verdict::Rollback {
                        found: 9,
                        expected: REVISION
                    },
                    9,
                    Some(9)
                ),
                Admission::Proceed
            ),
            "confirming the revision found on disk is what lets a rollback through"
        );

        assert!(
            !matches!(
                admission(
                    Verdict::Rollback {
                        found: 9,
                        expected: REVISION
                    },
                    9,
                    Some(REVISION)
                ),
                Admission::Proceed
            ),
            "the expected revision is not the one the interface was shown, so confirming it \
             must not open a rolled-back vault"
        );
    }

    #[test]
    fn a_tampered_watermark_is_refused_until_this_revision_is_confirmed() {
        let told = refusal(admission(Verdict::Tampered, REVISION, None));
        assert!(told.contains("12"), "{told}");

        assert!(matches!(
            admission(Verdict::Tampered, REVISION, Some(REVISION)),
            Admission::Proceed
        ));
        assert!(!matches!(
            admission(Verdict::Tampered, REVISION, Some(11)),
            Admission::Proceed
        ));
    }

    #[test]
    fn an_unreadable_watermark_is_rewritten_only_once_the_user_has_agreed() {
        let told = refusal(admission(
            Verdict::Unreadable("the book is not valid json".to_owned()),
            REVISION,
            None,
        ));
        assert!(told.contains("the book is not valid json"), "{told}");

        assert!(
            matches!(
                admission(
                    Verdict::Unreadable("the book is not valid json".to_owned()),
                    REVISION,
                    Some(REVISION)
                ),
                Admission::Reset
            ),
            "an unreadable book is replaced rather than appended to, and only on agreement"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod new_vault_location {
    use super::*;

    #[test]
    fn a_new_vault_needs_a_free_name_inside_a_folder_that_is_there() {
        let dir = std::env::temp_dir().join(format!("obscura-create-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let free = dir.join("obscura.obscura");
        assert!(check_new_vault_location(&free).is_ok());

        std::fs::write(&free, b"anything").unwrap();
        assert!(
            check_new_vault_location(&free)
                .unwrap_err()
                .contains("already exists"),
            "creating a vault must never write over a file that is already there"
        );

        assert!(
            check_new_vault_location(&dir.join("absent").join("obscura.obscura"))
                .unwrap_err()
                .contains("does not exist")
        );

        assert!(check_new_vault_location(std::path::Path::new(""))
            .unwrap_err()
            .contains("not a valid file path"));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod storing {
    use super::*;

    const FAST: KdfParams = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 2,
        p_cost: 1,
    };

    fn a_session() -> (Session, Uuid) {
        let mut vault = Vault::create(b"correct horse battery staple", FAST).unwrap();
        let id = vault.add(Entry::new_login("GitHub", "saheb")).unwrap();
        (Session::new(vault, PathBuf::from("vault.obscura")), id)
    }

    fn sent(id: Option<Uuid>) -> EntryInput {
        EntryInput {
            id,
            kind: obscura_vault::EntryKind::Login,
            title: "GitHub".to_owned(),
            username: "saheb".to_owned(),
            password: None,
            urls: Vec::new(),
            notes: String::new(),
            tags: Vec::new(),
            favorite: false,
            totp_uri: None,
            custom_fields: Vec::new(),
        }
    }

    #[test]
    fn an_entry_without_an_id_is_added_and_one_with_an_id_is_edited_in_place() {
        let (mut session, id) = a_session();

        let mut edit = sent(Some(id));
        edit.title = "GitHub (work)".to_owned();
        assert_eq!(store(&mut session, &edit).unwrap(), id);
        assert_eq!(session.vault.len(), 1);
        assert_eq!(session.vault.get(id).unwrap().title, "GitHub (work)");

        let fresh = store(&mut session, &sent(None)).unwrap();
        assert_ne!(fresh, id);
        assert_eq!(session.vault.len(), 2);
    }

    #[test]
    fn an_unknown_id_is_refused_rather_than_quietly_creating_an_entry() {
        let (mut session, _) = a_session();

        assert!(store(&mut session, &sent(Some(Uuid::nil()))).is_err());
        assert_eq!(
            session.vault.len(),
            1,
            "an id the vault does not hold must never be taken as a request to create one"
        );
    }

    #[test]
    fn a_rejected_edit_leaves_the_entry_it_touched_unchanged() {
        let (mut session, id) = a_session();

        let mut bad = sent(Some(id));
        bad.title = "GitHub (work)".to_owned();
        bad.totp_uri = Some("this is not an otpauth uri".to_owned());

        assert!(store(&mut session, &bad).is_err());
        assert_eq!(
            session.vault.get(id).unwrap().title,
            "GitHub",
            "a save that failed must leave nothing behind - the next successful save of any \
             other entry writes the whole vault, and would carry these values to disk"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod hello_errors {
    use super::*;
    use obscura_platform::PlatformError as E;

    fn shown(error: &UnlockError) -> String {
        serde_json::to_string(error).unwrap()
    }

    #[test]
    fn a_missing_credential_points_at_settings_rather_than_implying_loss() {
        let told = shown(&hello_failure(&E::CredentialMissing));
        assert!(told.contains("Settings"), "{told}");
        assert!(
            !told.contains("no longer"),
            "a first enrolment has not been lost, so the message must not say it has: {told}"
        );
    }

    #[test]
    fn a_dismissed_prompt_does_not_read_as_a_failure() {
        let told = shown(&hello_failure(&E::Cancelled));
        assert!(told.contains("dismissed"), "{told}");
    }

    #[test]
    fn a_locked_device_names_the_remedy() {
        let told = shown(&hello_failure(&E::DeviceLocked));
        assert!(told.contains("locked"), "{told}");
        assert!(told.contains("sign in"), "{told}");
    }

    #[test]
    fn anything_unrecognised_still_repeats_what_windows_said() {
        let raw = E::Platform(0x8009_0027);
        assert!(shown(&hello_failure(&raw)).contains(&raw.to_string()));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod passkey_errors {
    use super::*;
    use obscura_webauthn::WebAuthnError as E;

    fn shown(error: &E) -> String {
        serde_json::to_string(&passkey_failure(error)).unwrap()
    }

    #[test]
    fn a_windows_too_old_for_prf_names_the_version_it_needs() {
        let told = shown(&E::ApiTooOld(1));
        assert!(told.contains('1'), "{told}");
        assert!(
            told.contains(&obscura_webauthn::PRF_API_VERSION.to_string()),
            "{told}"
        );
    }

    #[test]
    fn an_authenticator_without_prf_is_never_reported_as_a_wrong_credential() {
        for error in [E::NoPrfSecret, E::PrfSecretLength(16)] {
            let told = shown(&error);
            assert!(told.contains("cannot derive a vault key"), "{told}");
            assert!(!told.contains("does not open this vault"), "{told}");
        }
    }

    #[test]
    fn anything_else_still_repeats_what_the_platform_said() {
        let error = E::Platform(0x8009_0027);
        assert!(shown(&error).contains(&error.to_string()));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod unlock_methods {
    use super::*;
    use obscura_crypto::KdfParams;

    const FAST: KdfParams = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 2,
        p_cost: 1,
    };

    const OLD: &[u8] = b"correct horse battery staple";
    const NEW: &str = "lantern mango quiet orbit tamarind";

    fn a_session() -> (Session, Uuid, Uuid) {
        let mut vault = Vault::create(OLD, FAST).unwrap();
        let (recovery, _) = vault.add_recovery_slot("Printed code").unwrap();
        let password = vault
            .slots()
            .iter()
            .find(|slot| slot.kind == SlotKind::Password)
            .unwrap()
            .id;
        (
            Session::new(vault, PathBuf::from("vault.obscura")),
            password,
            recovery,
        )
    }

    fn opens_with(session: &Session, password: &[u8]) -> bool {
        session
            .vault
            .accepts(&Credential::Password(password))
            .unwrap()
    }

    #[test]
    fn the_master_password_is_never_removed_whatever_asks() {
        let (mut session, password, _) = a_session();

        for expected in [None, Some(SlotKind::Recovery), Some(SlotKind::Hardware)] {
            let error = remove_unlock_method(&mut session, password, expected).unwrap_err();
            assert!(error.contains("never removed"), "{error}");
        }
        assert!(session.vault.has_password());
        assert!(opens_with(&session, OLD));
    }

    #[test]
    fn other_unlock_methods_still_come_off() {
        let (mut session, _, recovery) = a_session();
        remove_unlock_method(&mut session, recovery, None).unwrap();
        assert_eq!(session.vault.slots().len(), 1);
    }

    #[test]
    fn a_removal_is_refused_when_it_names_a_different_kind() {
        let (mut session, _, recovery) = a_session();
        assert!(remove_unlock_method(&mut session, recovery, Some(SlotKind::Hardware)).is_err());
        assert!(remove_unlock_method(&mut session, Uuid::new_v4(), None).is_err());
        assert_eq!(session.vault.slots().len(), 2);
    }

    #[test]
    fn a_session_opened_any_other_way_cannot_reset_the_password() {
        let (mut session, _, _) = a_session();
        let error = reset_password(&mut session, NEW).unwrap_err();
        assert!(error.contains("recovery code"), "{error}");
        assert!(opens_with(&session, OLD));
    }

    #[test]
    fn a_session_opened_with_the_recovery_code_can_reset_the_password() {
        let (mut session, _, _) = a_session();
        session.unlocked_by_recovery = true;

        reset_password(&mut session, NEW).unwrap();

        assert!(opens_with(&session, NEW.as_bytes()));
        assert!(!opens_with(&session, OLD));
    }

    #[test]
    fn a_reset_password_still_has_to_meet_the_minimum() {
        let (mut session, _, _) = a_session();
        session.unlocked_by_recovery = true;

        let error = reset_password(&mut session, "too short").unwrap_err();
        assert!(
            error.contains(&obscura_vault::MIN_PASSWORD_CHARS.to_string()),
            "{error}"
        );
        assert!(opens_with(&session, OLD));
    }
}

#[cfg(test)]
mod slot_kinds {
    use super::*;

    #[test]
    fn every_kind_reaches_the_interface_as_a_stable_word() {
        assert_eq!(kind_name(SlotKind::Password), "password");
        assert_eq!(kind_name(SlotKind::Recovery), "recovery");
        assert_eq!(kind_name(SlotKind::Passkey), "passkey");
        assert_eq!(
            kind_name(SlotKind::Hardware),
            "hardware",
            "the interface decides what to call a slot and which command removes it from \
             this word, so it cannot be the derived Debug spelling - a variant named in \
             two words would reach the interface run together and match nothing"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod two_factor {
    use super::*;

    const FAST: KdfParams = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 2,
        p_cost: 1,
    };

    const URI: &str = "otpauth://totp/GitHub:saheb?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";

    fn a_session() -> (Session, Uuid, Uuid) {
        let mut vault = Vault::create(b"correct horse battery staple", FAST).unwrap();

        let mut carrying = Entry::new_login("GitHub", "saheb");
        carrying.totp = Some(Totp::from_uri(URI).unwrap());
        let carrying = vault.add(carrying).unwrap();

        let bare = vault.add(Entry::new_login("Fastmail", "saheb")).unwrap();

        (
            Session::new(vault, PathBuf::from("vault.obscura")),
            carrying,
            bare,
        )
    }

    #[test]
    fn a_code_is_six_digits_and_its_countdown_sits_inside_the_period() {
        let (session, carrying, _) = a_session();
        let answer = totp_for(&session, carrying).unwrap();

        assert_eq!(answer.code.len(), 6);
        assert!(answer.code.chars().all(char::is_numeric), "{}", answer.code);
        assert_eq!(answer.period, 30);
        assert!(
            answer.remaining > 0 && answer.remaining <= 30,
            "a countdown of nothing tells the interface a live code has already expired, and \
             one above the period keeps a stale code on screen: {} of {}",
            answer.remaining,
            answer.period
        );
    }

    #[test]
    fn an_entry_without_a_code_is_told_apart_from_an_entry_that_is_not_there() {
        let (session, _, bare) = a_session();

        let absent = totp_for(&session, bare).unwrap_err();
        assert!(absent.contains("no TOTP"), "{absent}");

        let unknown = totp_for(&session, Uuid::nil()).unwrap_err();
        assert!(unknown.contains("no such entry"), "{unknown}");
    }

    #[test]
    fn the_code_belongs_to_the_entry_that_was_asked_about() {
        let (session, carrying, _) = a_session();
        let direct = session
            .vault
            .get(carrying)
            .unwrap()
            .totp
            .as_ref()
            .unwrap()
            .current()
            .unwrap();

        assert_eq!(totp_for(&session, carrying).unwrap().code, direct.0);
    }
}

#[cfg(all(test, not(target_os = "windows")))]
#[allow(clippy::unwrap_used, clippy::panic)]
mod wiring {
    use super::*;
    use tauri::test::{mock_builder, mock_context, noop_assets};

    const PASSWORD: &str = "lantern mango quiet orbit tamarind";

    struct Fixture {
        app: tauri::App<tauri::test::MockRuntime>,
        config: PathBuf,
        dir: PathBuf,
        vault: PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.config);
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn fixture() -> Fixture {
        let unique = Uuid::new_v4();
        let mut context = mock_context(noop_assets());
        context.config_mut().identifier = format!("obscura-test-{unique}");

        let app = mock_builder()
            .manage(AppState::default())
            .build(context)
            .unwrap();

        let config = app.path().app_config_dir().unwrap();
        let dir = std::env::temp_dir().join(format!("obscura-wiring-{unique}"));
        std::fs::create_dir_all(&dir).unwrap();

        Fixture {
            app,
            config,
            vault: dir.join("vault.obscura"),
            dir,
        }
    }

    impl Fixture {
        fn handle(&self) -> tauri::AppHandle<tauri::test::MockRuntime> {
            self.app.handle().clone()
        }

        fn at(&self) -> Option<String> {
            Some(self.vault.display().to_string())
        }

        fn create(&self) -> VaultInfo {
            create_vault(
                self.handle(),
                self.app.state(),
                self.at(),
                PASSWORD.to_owned(),
                Some(120),
                Some(false),
            )
            .unwrap()
        }

        fn open(&self, accept_revision: Option<u64>) -> Result<VaultInfo, UnlockError> {
            unlock(
                self.handle(),
                self.app.state(),
                self.at(),
                PASSWORD.to_owned(),
                Some(false),
                accept_revision,
            )
        }
    }

    fn an_entry() -> EntryInput {
        EntryInput {
            id: None,
            kind: obscura_vault::EntryKind::Login,
            title: "GitHub".to_owned(),
            username: "saheb".to_owned(),
            password: Some("first-secret".to_owned()),
            urls: Vec::new(),
            notes: String::new(),
            tags: Vec::new(),
            favorite: false,
            totp_uri: None,
            custom_fields: Vec::new(),
        }
    }

    #[test]
    fn a_vault_is_created_where_it_was_asked_to_be_and_opens_again() {
        let f = fixture();
        let made = f.create();

        assert!(f.vault.is_file());
        assert_eq!(made.entry_count, 0);
        assert!(lock(f.app.state()));

        let reopened = f.open(None).unwrap();
        assert_eq!(reopened.id, made.id);
    }

    #[test]
    fn an_entry_saved_through_the_command_is_on_disk_before_the_session_ends() {
        let f = fixture();
        f.create();

        save_entry(f.handle(), f.app.state(), an_entry()).unwrap();
        lock(f.app.state());

        assert_eq!(
            f.open(None).unwrap().entry_count,
            1,
            "save_entry writes the vault itself rather than waiting for anything later, so an \\
             entry must survive a lock with no further action"
        );
    }

    #[test]
    fn a_wrong_password_leaves_the_session_locked() {
        let f = fixture();
        f.create();
        lock(f.app.state());

        let refused = unlock(
            f.handle(),
            f.app.state(),
            f.at(),
            "not the master password".to_owned(),
            Some(false),
            None,
        );

        assert!(refused.is_err());
        assert!(
            vault_info(f.app.state()).is_err(),
            "a refused unlock must not leave a session behind for the next command to use"
        );
    }

    #[test]
    fn relocating_leaves_nothing_at_the_old_place() {
        let f = fixture();
        f.create();
        let moved = f.dir.join("moved.obscura");

        relocate_vault(
            f.handle(),
            f.app.state(),
            moved.display().to_string(),
            Some(false),
        )
        .unwrap();

        assert!(moved.is_file());
        assert!(
            !f.vault.exists(),
            "relocating deletes the original, which is why the written file is verified first"
        );
    }

    #[test]
    fn an_older_copy_put_back_is_refused_until_the_revision_on_disk_is_confirmed() {
        let f = fixture();
        let made = f.create();
        let older = std::fs::read(&f.vault).unwrap();

        save_entry(f.handle(), f.app.state(), an_entry()).unwrap();
        lock(f.app.state());

        std::fs::write(&f.vault, &older).unwrap();

        let refused = f.open(None).unwrap_err();
        let told = serde_json::to_string(&refused).unwrap();
        assert!(told.contains("confirm"), "{told}");

        let admitted = f.open(Some(made.revision)).unwrap();
        assert_eq!(
            admitted.entry_count, 0,
            "confirming the revision found on disk opens that older vault, entries and all"
        );
    }

    #[test]
    fn the_auto_lock_the_user_chose_outlives_the_session() {
        let f = fixture();
        f.create();

        assert_eq!(set_auto_lock(f.handle(), f.app.state(), 900), 900);
        assert_eq!(
            location::remembered_auto_lock(&f.handle()),
            Some(900),
            "the setting reaches the settings file, or it would be forgotten on the next launch"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod read_only {
    use super::*;

    #[test]
    fn a_read_only_vault_says_so_rather_than_blaming_the_folder() {
        let vault = warning_for(TargetState::Vault, true, false, false).unwrap();
        assert!(vault.contains("read-only"), "{vault}");
        assert!(
            !vault.contains("folder"),
            "the folder is writable in this case - saying otherwise sends the user to \
             fix the wrong thing: {vault}"
        );

        let missing = warning_for(TargetState::Missing, true, false, false).unwrap();
        assert!(missing.contains("folder"), "{missing}");
    }
}
