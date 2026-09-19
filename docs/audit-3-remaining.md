# Audit 3

Complete. Audits 1, 2, 4 and 5 were already complete.

## What it found

Four defects, all the same shape: **a check that runs after the damage is
done.**

1. `location::is_vault_file` accepted a file with a valid header and no
   encrypted body. It is the only verification between a bad write and
   `relocate_vault` deleting the user's original vault. Now requires a body of
   at least `aead::OVERHEAD`.
2. `apply` mutated an entry field by field and validated only at the end, so a
   rejected save left the rejected values in memory - and `Vault::save` writes
   the whole vault, so the next successful save of any entry would have
   committed them. `store` applies to a clone and writes back on success.
3. `import_all` added entries one at a time and returned on the first failure,
   leaving every entry before it in the vault. It now validates and renumbers
   the whole batch into a staging vector and commits it in one infallible step.
4. `probe_location` asserted `writable` whenever the file existed, so a
   read-only vault read as a usable location and the truth arrived at save time.
   It checks the parent and the file now, because `save` writes a temporary file
   beside the target and renames over it.

Two more found while working rather than by the audit:

- `hello::credential_name` produced a name containing a path separator, which
  made `RequestCreateAsync` fail with `NTE_INVALID_PARAMETER` on every machine.
  The test pinned the broken format.
- `removeSlot` armed the first remove button in the list rather than the one
  clicked, so a single click could delete the master password slot with no
  confirmation. Found by using the application; no test would have caught it.

## What it covered

Tests went 211 -> 271.

- `totp_code`, the one command with no test, now has three.
- `watermark`'s `check`, `record` and `reset_to` - the rollback detection - are
  tested against temporary directories.
- `location`'s settings file is tested, including that forgetting the vault
  location leaves the auto-lock alone.
- Thirteen commands run end-to-end on `MockRuntime`, including the rollback
  refusal. Linux only - see `testing.md`.
- `cargo mutants` on Linux: 464 of 465 killable mutants caught. See
  `mutation-testing.md`.

Two things were written down rather than changed, because both are defensible
but neither was recorded anywhere:

- `watermark::reset_to` keeps only the vault being opened, so every other vault
  silently loses its rollback protection. A book that will not parse cannot be
  trusted for any vault, so this is arguable - but it should be a decision.
- `clipboard::copy_with_timeout` writes to the real system clipboard and takes
  no handle, so testing it would clobber whatever the developer had copied. It
  stays untested on purpose. `exclude_from_monitoring` is the security-relevant
  part and it is not reachable without a real clipboard.

## Decisions still open

- `MIN_PASSWORD_LEN` is 8, measured in **bytes**. Two emoji pass. Comparable
  projects sit at 12 or more. `check_new_password` is the single place to change
  it. Current behaviour is pinned by test, not endorsed by it.
- `obscura-cli` is a 144-byte stub at 0%. See `release-blockers.md`.
- `brain.md` has been stale since `77aacf8`.
- The interface has no tests at all. Three static files, no dependencies, and
  the one defect found there was found by clicking. Worth deciding rather than
  drifting into.

## Traps worth re-reading before touching this code

- **Never `git add -A`.** Screenshot PNGs were swept into history that way once
  (`4a4a2ef`, removed in `6fd78fa`, still reachable). Named paths or `git add -u`.
- Check `git status --short` before each commit.
- PowerShell line-splicing edits: guard every boundary on line *content*, and
  count braces rather than lines. A line like `    };` closes two constructs.
- A bare `return` does not reliably stop a pasted block. Wrap the whole thing in
  `& { ... }` so guards actually halt.
- PowerShell has no backslash escape, so a double-quoted commit message cannot
  contain a quote at all. Use single quotes.
- Search anchored from the top of a file finds the first match, which is rarely
  the one you want. Anchor from the enclosing function.
- rustfmt will not reindent a line that exceeds `max_width`, so a moved long
  string literal keeps its old indentation.
- cargo-mutants globs with forward slashes: `-f "*secret.rs"` works,
  `-f "*vault/src/secret.rs"` matches nothing.
- `concurrency.cancel-in-progress` is on, so two pushes in quick succession
  cancel the older run. A cancelled run shows one "failed" test with code
  `0xc000013a`. That is not a real failure.