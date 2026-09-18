# Audit 3 - what is left

Paused after 4f2eacf, to be resumed after passkeys and biometrics.
Audits 1, 2, 4 and 5 are complete. Everything found so far is fixed and pushed.

Bugs found and fixed: 2. Both had the same shape - a check that runs after the damage is done.
- location::is_vault_file accepted a valid header with no encrypted body, and it is the only
  verification between a bad write and relocate_vault deleting the original vault.
- apply mutated an entry then validated at the end, so a rejected save left the rejected values
  in memory, and Vault::save writes the whole vault.

Read "lines missed", not the percentage: llvm-cov instruments test code, so tests inflate both sides.
commands.rs 719 -> 550, location.rs 70 -> 61, dto.rs 56 -> 0, workspace 1002 -> 931 (79.37%).
Tests 211 -> 244.

## 1. Doable without a Tauri runtime

- Vault::import_all - check for a third bug of the same shape. If entry 7 of 10 fails validation,
  do entries 1-6 stay in the vault? The export side is all-or-nothing; the import side has no
  equivalent test. Do this first.
- totp_code - no test at all. Extracts to &Session like detail and field_value.
- delete_entry - thin wrapper over the tested vault.remove. Comes free with section 2.

## 2. Needs tauri::test (mock_builder / mock_app, dev-dependency, test feature)

One decision unblocks all of this. Without it none of it is testable.

- Thirteen commands end to end: unlock, create_vault, relocate_vault, import_entries,
  export_entries, set_master_password, change_master_password, confirm_recovery_code,
  unlock_with_recovery, remove_slot, probe_location, save_entry, delete_entry.
  Both bugs so far lived in sequences like these, not in the pure functions.
- watermark.rs - 15 of 29 functions untouched, including record, check and reset_to.
  The decision table is tested; reading and writing the book on disk is not.
- location.rs - 16 remaining functions, all config-directory I/O.
- clipboard.rs - 6 of 8 functions. Where exclude_from_monitoring lives.

## 3. Needs Linux or WSL - the largest outstanding risk

restrict_to_owner has never been compiled. The cfg(unix) test in vault.rs asserting the vault
file is 0600 has never been built on any machine. portable's owner-only test passes on Windows,
where there is no 0600, so it proves nothing there. Run on WSL:
  cargo test --workspace
  cargo mutants -p obscura-vault

## 4. Decisions, not tests

- MIN_PASSWORD_LEN is 8, measured in bytes. Two emoji pass. check_new_password is the single
  place to change it. Current behaviour is pinned by test, not endorsed by it.
- probe_location reports writable: true whenever the file exists, without checking the file,
  so a read-only vault reads as usable and fails later at save time.
- obscura-cli is a 144-byte stub at 0%. Build it out or exclude it from release artifacts.
- obscura-platform/src/hello.rs at 28.88%, 19 of 28 functions untouched. WinRT surface, not
  unit-testable without hardware. Directly relevant to the biometrics work.

## Order on resuming

1. import_all  2. totp_code  3. WSL run  4. then decide on tauri::test

## Traps

- Never git add -A. Screenshot PNGs were swept in that way once (4a4a2ef, removed in 6fd78fa,
  still reachable). Named paths or git add -u only.
- Check git status --short before each commit. hybrid.rs sat uncommitted for days and the whole
  fuzz/ directory was untracked until 9dda105.
- PowerShell splices: guard boundaries on line content, not position. A line like "};" closes
  two constructs - replacing it with "}" drops a brace.
- rustfmt will not reindent a line exceeding max_width, so a moved long string keeps its indent.
- cargo-mutants globs with forward slashes: -f "*secret.rs" works, -f "*vault/src/secret.rs" does not.
- Windows mislabels cfg(unix) mutants as MISSED - it patches source that never compiles.
