#![forbid(unsafe_code)]

mod clipboard;
mod commands;
mod dto;
mod location;
mod state;
mod watermark;

use std::{thread, time::Duration};

use tauri::{Emitter, Manager};

use crate::state::AppState;

pub const LOCKED_EVENT: &str = "obscura://locked";

#[allow(clippy::expect_used)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::vault_exists,
            commands::default_path,
            commands::probe_location,
            commands::remembered_location,
            commands::forget_location,
            commands::pick_new_location,
            commands::pick_existing_vault,
            commands::relocate_vault,
            commands::export_entries,
            commands::import_entries,
            commands::calibrate,
            commands::create_vault,
            commands::unlock,
            commands::lock,
            commands::is_locked,
            commands::touch,
            commands::vault_info,
            commands::set_auto_lock,
            commands::list_entries,
            commands::get_entry,
            commands::reveal_password,
            commands::copy_password,
            commands::copy_text,
            commands::save_entry,
            commands::delete_entry,
            commands::totp_code,
            commands::generate,
            commands::change_master_password,
            commands::create_recovery_code,
            commands::confirm_recovery_code,
            commands::discard_recovery_code,
            commands::unlock_with_recovery,
            commands::remove_slot,
            commands::hello_selftest,
            commands::hello_isolation_setup,
        ])
        .setup(|app| {
            spawn_auto_lock_clock(app.handle().clone());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Obscura could not start: the platform webview is unavailable");
}

fn spawn_auto_lock_clock(app: tauri::AppHandle) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(1));
        let state = app.state::<AppState>();
        if state.lock_if_idle() {
            let _ = app.emit(LOCKED_EVENT, ());
        }
    });
}
