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

    let delay = clear_delay(clear_after);
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

#[must_use]
pub fn clear_delay(requested: u64) -> u64 {
    requested.clamp(1, MAX_CLEAR_DELAY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clear_delay_is_kept_inside_its_bounds() {
        assert_eq!(MAX_CLEAR_DELAY, 120);
        assert_eq!(clear_delay(0), 1);
        assert_eq!(clear_delay(1), 1);
        assert_eq!(clear_delay(30), 30);
        assert_eq!(clear_delay(MAX_CLEAR_DELAY), MAX_CLEAR_DELAY);
        assert_eq!(clear_delay(MAX_CLEAR_DELAY + 1), MAX_CLEAR_DELAY);
        assert_eq!(clear_delay(u64::MAX), MAX_CLEAR_DELAY);
    }
}
