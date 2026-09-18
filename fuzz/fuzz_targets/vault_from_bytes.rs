#![no_main]

use libfuzzer_sys::fuzz_target;
use obscura_vault::{Credential, Vault};

fuzz_target!(|data: &[u8]| {
    let _ = Vault::from_bytes(data, &Credential::Password(b"a fuzzing password"), None);
});