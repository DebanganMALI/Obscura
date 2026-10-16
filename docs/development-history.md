# Development history

Obscura was built by one person, in the open, from an empty repository on
15 September 2026 to a signed Microsoft Store listing on 16 October 2026. This
file is the narrative of how it got there: what was built in each phase, what
went wrong, how it was found and how it was fixed. The commit history is the
primary record; every claim here can be checked against it.

## At a glance

| Date | Milestone |
| --- | --- |
| 15 Sep 2026 | First commit: workspace, toolchain, CI and supply-chain policy from day one |
| 16 Sep 2026 | Export, import, and CSV import from Bitwarden, Chrome, Edge and Firefox |
| 18 Sep 2026 | Third audit closed four defects; five fuzz harnesses; Windows Hello and phone passkey unlock |
| 19 Sep 2026 | cargo-mutants run: 464 mutants caught, 14 of 15 survivors proven equivalent |
| 21 Sep 2026 | Command line tool and terminal browser |
| 25 Sep 2026 | 0.1.0 and 0.1.1 released with CycloneDX SBOMs and build provenance |
| 15 Oct 2026 | 0.2.0 released: password health, locked memory, threat model, ISO/IEC 27001 Annex A posture |
| 16 Oct 2026 | Obscura Vault live on the Microsoft Store |

Tests over the same period: 211 before the third audit, 271 after it, 345 once
secrets moved into locked memory, and 346 Rust tests plus 40 interface tests at
0.2.0, passing on Linux and Windows.

## Phase 1 - foundations (15-16 September)

The first commit set up the workspace together with CI, cargo-deny and the
supply-chain policy, so nothing was ever written without checks running on it.
The same day brought the cryptography (Argon2id, XChaCha20-Poly1305, HKDF,
BLAKE3 and a hybrid X25519 + ML-KEM-768 construction), vault entries with
RFC 6238 two-factor codes and unbiased password generation, the `.obscura`
container with envelope encryption and atomic writes, the Tauri v2 shell with
locked-down IPC and auto-lock, recovery codes, Windows Hello, a durable
anti-rollback watermark, clipboard history exclusion and owner-only vault files.

What went wrong, and what changed:

- **Auto-lock never fired while the window was open.** Background reads from
  the interface were counted as user activity. They no longer are.
- **Ten-digit two-factor codes overflowed** the modulus. Fixed and pinned.
- **The interface kept secrets on screen after locking.** Every panel is now
  cleared and every modal closed when the vault locks.
- **Slow commands froze the window.** Key derivation and file work moved off the
  window thread.
- **Decrypted buffers outlived their use.** They now wipe themselves.
- **Screenshots were swept into a commit** by a careless `git add`. They were
  removed the same night, and the rule since has been to stage named paths only.

## Phase 2 - import, export and the third audit (16-18 September)

Lossless export and import landed, then CSV import from the four most common
password managers. A vault header could name an Argon2 time cost large enough to
hang the application, so the value read from a header is now bounded.

Most of these three days went into testing. Every boundary in the format was
pinned in both directions: header lengths, sealed-message overhead, field limits,
the recovery checksum, the clipboard clear delay. Logic that needed a running
application only to find a directory was given a twin that takes a path, so it
could be tested against a temporary directory. Five fuzz harnesses were written,
one for every parser that reads untrusted input.

The third audit found four defects with the same shape, a check that runs after
the damage is done, and two more turned up while fixing them:

1. A file with a valid header and no body passed as a vault, and that check was
   the only thing standing between a bad write and the original vault being
   deleted during a move.
2. A rejected edit left its rejected values in memory, where the next successful
   save would have written them.
3. A failing import left every entry before the failure in the vault. Import is
   now all-or-nothing.
4. A read-only vault looked writable until the user tried to save.
5. Every Windows Hello credential name contained a path separator, so enrolment
   failed on every machine. The test had pinned the broken format.
6. The remove button armed the first slot in the list rather than the one
   clicked, so one click could remove the master password with no confirmation.
   Found by using the application; no test would have caught it.

A random source that kept failing could also hang the password generator. The
rejection sampler is now bounded and returns an error instead.

`docs/audit-3-remaining.md` records each of these in full.

## Phase 3 - unlocking without a password (18-19 September)

Windows Hello enrolment and unlock were wired through the command layer and the
interface. Phone passkeys followed, through the Windows WebAuthn PRF extension
with a salt derived per vault, so one passkey answers for one vault only.

The relying party id was first set to `obscura.app`. That domain turned out to
be held by a reseller, and a passkey bound to a domain nobody on the project
controls would have been abandoned the day it changed, so before the first
release it was settled on `debanganmali.github.io`, a registrable domain on the
Public Suffix List. `docs/release-blockers.md` and `docs/passkeys.md` explain the
decision.

Thirteen commands were driven end to end on Tauri's mock runtime, including the
rollback refusal. `cargo mutants` was set up to run on demand; the run of
19 September caught 464 mutants, and of the 15 that survived, 14 are proven
equivalent in `docs/mutation-testing.md`.

## Phase 4 - packaging and the command line (18-21 September)

The application was packaged as a signed MSIX with the identity the Microsoft
Store assigned, and installers for Windows and Linux were built in CI. A privacy
policy was written. The `obscura` command line tool arrived with a terminal
browser and the scripted commands `list`, `get` and `totp`, under three rules:
the master password is never an argument, secrets go to standard output and
everything else to standard error, and a query that matches more than one entry
is an error, never a guess.

## Phase 5 - 0.1.0 and 0.1.1 (24-25 September)

The master password floor was raised to 15 characters, counted as characters
rather than bytes, after it turned out two emoji passed the old 8-byte rule.
Every release gained a CycloneDX SBOM attested against the installers, gitleaks
began scanning the full history on every pull request, and a version-one vault
fixture was added so no later change can silently break old vaults.

0.1.0 was tagged on 25 September. 0.1.1 followed the same day to name the
publisher, homepage, copyright and licence in the installers.

## Phase 6 - toward 0.2.0 (26 September-15 October)

- The master password can no longer be removed; a recovery code resets a
  forgotten one.
- Common, repetitive and sequential passwords are refused, following
  NIST SP 800-63B-4, and the strength meter asks the same Rust code that makes
  the decision.
- Each vault got its own rollback record, so resetting one never weakens
  another.
- The interface logic moved into a module tested with Node's built-in runner,
  still with no npm dependencies.
- **The application tests could not run on Windows.** The test binary aborted
  before `main` with `0xc0000139`, because only the application, not the test
  harness, carried the manifest asking for Common Controls 6. The manifest is
  now embedded by the linker into every artifact. `docs/testing.md` has the
  details.
- New vaults are created in `Documents\Obscura`, so uninstalling, Store version
  included, never removes one.
- The password health view lists reused, weak and year-old passwords, worked
  out in Rust.
- The vault key and every stored secret are kept in locked memory and out of
  crash dumps, verified on Kali Linux through `VmLck` and the core-dump limit.
- A threat model and a walk through all 93 controls of ISO/IEC 27001:2022
  Annex A were written, and documents that had fallen behind the code were
  corrected.

0.2.0 was released on 15 October. Two problems surfaced the same day:

- **The Windows Hello and passkey prompts opened behind the Obscura window**,
  reachable only from the taskbar. The prompt is now brought to the front while
  Obscura is in the foreground.
- **Partner Center rejected the Store package.** The step that stamps the
  version into the MSIX manifest also overwrote the minimum Windows version. It
  now changes only the package version.

## Phase 7 - Microsoft Store (16 October)

The package passed certification and Obscura Vault went live on the Microsoft
Store, signed by Microsoft, under the publisher name Debangan Mali.

## What the history shows

Two lessons recur. Every defect found so far was in a sequence of steps rather
than in a single function, and every one became reachable by a test once that
sequence was a function taking values instead of a handle. And the most
dangerous bugs were checks that ran after the damage was done; the fix each time
was to validate a copy and commit in one step that cannot fail.

## Where the evidence is

- The commit history, from the first commit on 15 September 2026
- The pull requests on GitHub
- `docs/audit-3-remaining.md`, `docs/testing.md`, `docs/mutation-testing.md`
- `docs/threat-model.md`, `docs/security-posture.md`, `docs/release-blockers.md`
- The releases, each with SHA-256 checksums, SBOMs and build provenance that
  `gh attestation verify` checks
