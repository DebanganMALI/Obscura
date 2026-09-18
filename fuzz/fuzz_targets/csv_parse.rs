#![no_main]

use libfuzzer_sys::fuzz_target;
use obscura_vault::csv_import;

fuzz_target!(|data: &[u8]| {
    let _ = csv_import::parse(data);
});