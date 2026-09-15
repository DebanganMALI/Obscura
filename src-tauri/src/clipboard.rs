use std::{thread, time::Duration};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use arboard::SetExtLinux as _;
#[cfg(target_os = "windows")]
use arboard::SetExtWindows as _;

pub const MAX_CLEAR_DELAY: u64 = 120;

#[cfg(target_os = "windows")]
fn place(clipboard: &mut arboard::Clipboard, value: &str) -> Result<(), arboard::Error> {
    clipboard.set().exclude_from_monitoring().text(value)
}

#[cfg(target_os = "linux")]
fn place(clipboard: &mut arboard::Clipboard, value: &str) -> Result<(), arboard::Error> {
    clipboard.set().exclude_from_history().text(value)
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn place(clipboard: &mut arboard::Clipboard, value: &str) -> Result<(), arboard::Error> {
    clipboard.set_text(value)
}

pub fn copy_with_timeout(value: Zeroizing<String>, clear_after: u64) -> Result<(), String> {
    let mut clipboard =
        arboard::Clipboard::new().map_err(|e| format!("clipboard unavailable: {e}"))?;

    place(&mut clipboard, value.as_str()).map_err(|e| format!("could not copy: {e}"))?;

    let delay = clear_after.clamp(1, MAX_CLEAR_DELAY);
    let expected = value;

    thread::spawn(move || {
        thread::sleep(Duration::from_secs(delay));
        let Ok(mut clipboard) = arboard::Clipboard::new() else {
            return;
        };
        let still_ours = clipboard
            .get_text()
            .is_ok_and(|current| bool::from(current.as_bytes().ct_eq(expected.as_bytes())));
        if still_ours {
            let _ = clipboard.clear();
        }
    });

    Ok(())
}
