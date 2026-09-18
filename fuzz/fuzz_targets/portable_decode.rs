#![no_main]

use libfuzzer_sys::fuzz_target;
use obscura_vault::portable;

fuzz_target!(|data: &[u8]| {
    let _ = portable::decode(data);
});