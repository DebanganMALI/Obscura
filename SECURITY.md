# Security Policy

## Supported versions

Obscura is before 1.0. Only the latest release receives security fixes; an
older release is fixed by upgrading, not by a backport.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Anything older | No |

## Reporting a vulnerability

Report security issues **privately** through GitHub Security Advisories: the
"Report a vulnerability" button on the Security tab of this repository. Please
do not open a public issue, discussion or pull request for a vulnerability.

A useful report says:

- which version or commit you tested, and on which operating system
- what an attacker needs to start with - a copy of the vault file, a local
  account, a running unlocked application
- what they get at the end, and the steps in between
- a proof of concept, if you have one

Obscura is maintained by one person alongside other work, so there is no staffed
response window to promise. Reports are acknowledged as soon as they are seen,
and you will get an honest estimate rather than a deadline.

Disclosure is coordinated. The default is 90 days from the report, or the day a
fixed release is published if that comes first; either side can ask for more
time when a fix genuinely needs it. You will be credited in the advisory unless
you ask not to be.

## Scope

**In scope**

- The vault format and everything that parses it: the header, the body, key
  slots, the portable export format and CSV import
- The cryptographic implementation and the way keys are derived, wrapped and
  wiped
- Every unlock method: master password, Windows Hello, phone passkeys and
  recovery codes
- Rollback detection
- The Tauri IPC surface and the content security policy of the interface
- The command line tool, including any way a secret could reach the process
  list, shell history, a log or the wrong output stream
- Clipboard handling
- The release pipeline: the workflows, checksums, build provenance and the SBOM

**Out of scope**

- Attacks that need an already compromised operating system account, or
  malware running as the user
- Physical access to a machine while the vault is unlocked
- Guessing a master password that meets the minimum below
- Deleting or corrupting a vault file you already have write access to
- Missing hardening with no demonstrated way to exploit it
- Anything the README or this file lists as not built

## Cryptography

| Purpose | Primitive |
| --- | --- |
| Password key derivation | Argon2id, calibrated to the machine at vault creation |
| Content encryption | XChaCha20-Poly1305, one key per entry |
| Key derivation | HKDF-SHA512 |
| Key wrapping for recovery codes, Windows Hello and passkeys | Hybrid X25519 + ML-KEM-768 |
| Windows Hello | HKDF-SHA512 over a signature from a Windows Hello key |
| Phone passkeys | WebAuthn PRF, salted from the vault id |
| Rollback watermark | Keyed BLAKE3 MAC |
| Recovery code checksum | Keyed BLAKE3 hash |

Every unlock method unwraps the same 32-byte vault key; none of them encrypts an
entry directly. A recovery code is not a weaker door, it opens the same lock.

The header carries no MAC of its own. It is bound to the body instead: the
length prefix and the header bytes are the associated data for the body's AEAD,
so any edit to the header makes the body fail to decrypt.

Vault contents at rest are protected by symmetric primitives, which are already
quantum-resistant at these key sizes. The post-quantum hybrid is applied where
it matters - asymmetric key wrapping, which means every unlock method other than
the master password: recovery codes, Windows Hello and phone passkeys.

[docs/architecture.md](docs/architecture.md) has the byte layout and the full
key hierarchy.

## Master password policy

Following NIST SP 800-63B-4, because a stolen vault file is protected by the
master password and Argon2id and nothing else:

- At least 15 characters, counted as Unicode characters rather than bytes
- Not on a list of about 29,000 commonly used passwords, compared without
  regard to case, spaces or hyphens; the list is built from the SecLists
  collections and ships inside the application, so the check never goes online
- Not built from one short piece repeated, a handful of distinct characters, a
  run along the alphabet or the keyboard, or the name of the application
- No composition rules - no required digits, symbols or mixed case
- No maximum below what a person would reasonably type
- No forced periodic change

These rules apply when a password is chosen - creating a vault, setting a
master password, changing it or resetting it with a recovery code. The strength
meter in the interface asks the same Rust code, so it cannot disagree with the
check that decides. A vault made before these rules still opens with its
existing password.

A password is put into Unicode NFKC normal form before it reaches Argon2id, as
SP 800-63B-4 recommends, so the same password typed on another keyboard or
operating system, where an accented letter may arrive as two code points rather
than one, still opens the vault. A vault whose password was set before 0.2.1
still opens with exactly the characters it was set with; changing the password
once stores it in normal form.

## Secrets in memory

While a vault is open, the vault key and every password, note, custom field and
two-factor secret are held in memory pages locked with `VirtualLock` on Windows
or `mlock` on Linux, so the operating system does not write them to the page
file or swap. Pages are counted, so a page shared by two secrets stays locked
until both are gone, and each secret is zeroized before its page is released.

At start-up both programs also keep secrets out of crash reports: on Windows,
Windows Error Reporting is told to leave the heap out of its dumps, and the
working set is raised so there is room to lock; on Linux, core dumps are
switched off and the process is marked non-dumpable, which also stops other
processes running as you from attaching to it.

Locking is best effort. If the operating system refuses, Obscura keeps
working and the secret is still zeroized when it is dropped. All of this lives
in `obscura-memlock`, the only crate besides the WebAuthn bindings that
contains `unsafe` code.

## Verifying a release

Every release includes a `SHA256SUMS` file, a CycloneDX SBOM, and signed build
provenance for each file, recorded in a public transparency log.

```sh
gh attestation verify Obscura_0.2.0_x64-setup.exe --repo DebanganMALI/Obscura
gh attestation verify Obscura_0.2.0_x64-setup.exe --repo DebanganMALI/Obscura \
  --predicate-type https://cyclonedx.org/bom
```

The first proves which commit and workflow run built the installer. The second
proves which SBOM describes it. The command line tool's archive is verified the
same way and has its own SBOM, `obscura-cli_<tag>.cdx.json`.

## Supply chain

- The application makes no network requests and contains no HTTP client
- The interface is four static files with no npm dependencies, under a
  `default-src 'none'` content security policy
- `cargo deny` checks advisories, licences, duplicate crates and sources on
  every pull request; each ignored advisory is listed in `deny.toml` with the
  reason it does not reach runtime code
- Dependabot watches the Cargo lockfile and the GitHub Actions in use
- Every GitHub Action is pinned to a full commit hash, with its version beside
  it, so a tag moved upstream cannot change what a build runs
- `main` accepts changes only through pull requests that pass formatting,
  Clippy, the Rust and interface test suites on Windows and Linux,
  `cargo deny` and gitleaks

## Threat model and posture

[docs/threat-model.md](docs/threat-model.md) lists the assets, trust
boundaries and attackers, every threat with the code that answers it, and the
risk that remains. [docs/security-posture.md](docs/security-posture.md) maps the
project against ISO/IEC 27001:2022 Annex A; Obscura is not certified and does
not claim to be.

## Known limitations

- Obscura has not been independently audited.
- The interface's logic is tested, but the way it drives the page is checked
  only by hand.
- Memory locking covers secrets that live as long as the vault is open. A
  password is briefly in ordinary memory while it is typed, decrypted or
  copied, and the interface's web view holds what it displays. Hibernation
  writes all memory to disk, locked pages included. An administrator can still
  read Obscura's memory directly, and so on Windows can any process running as
  you.
- The rollback watermark is a local file in the application config directory.
  An attacker who can delete it gets a vault that looks new to Obscura.
- The common-password list is a fixed snapshot. It is not a check against a
  breach corpus such as Have I Been Pwned, which would need a network request.
- Browsing the vault with `obscura` keeps the vault key in memory until you
  quit or it locks on idle. It is not an agent: there is no socket, no daemon
  and nothing cached on disk.
