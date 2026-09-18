#![no_main]

use libfuzzer_sys::fuzz_target;
use obscura_vault::format;

fuzz_target!(|data: &[u8]| {
    let _ = format::decode_header(data);
});