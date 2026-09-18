#![no_main]

use libfuzzer_sys::fuzz_target;
use obscura_vault::recovery::RecoveryCode;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = RecoveryCode::parse(text);
    }
});