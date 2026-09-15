use std::{thread, time::Duration};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const MAX_CLEAR_DELAY: u64 = 120;

pub fn copy_with_timeout(value: Zeroizing<String>, clear_after: u64) -> Result<(), String> {
    let mut clipboard =
        arboard::Clipboard::new().map_err(|e| format!("clipboard unavailable: {e}"))?;

    clipboard
        .set_text(value.as_str())
        .map_err(|e| format!("could not copy: {e}"))?;

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
