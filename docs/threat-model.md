# Threat model

What Obscura protects, from whom, where the boundaries are, and what is left
over once every defence below has done its job. It describes version 0.2.1 and
is revisited with every release that changes the file format, adds a way to
unlock, or adds a boundary.

The method is plain: list the assets, draw the trust boundaries, name the
attackers, then walk each boundary with STRIDE - spoofing, tampering,
repudiation, information disclosure, denial of service and elevation of
privilege. Every threat names the code or the process that answers it and the
risk that remains. A residual risk is written down here rather than left for a
reader to find.

[architecture.md](architecture.md) has the file format and the key hierarchy
this document refers to. [SECURITY.md](../SECURITY.md) has the reporting process
and the short list of known limitations.

## What is protected

| Asset | Why it matters |
| --- | --- |
| Entry secrets - passwords, notes, custom fields, two-factor secrets | The reason the program exists |
| Entry metadata - titles, usernames, addresses, tags | Says which accounts you have and where |
| The vault key | Opens everything; every unlock method unwraps it |
| Unlock credentials - master password, recovery code, Windows Hello key, phone passkey | Each one is a way to the vault key |
| The integrity and freshness of the vault file | A vault that is silently edited or rolled back is wrong without anyone noticing |
| The integrity of the program | A modified Obscura can read everything the real one can |
| Access to your own vault | Losing every way in loses everything; there is no server with a copy |

## Trust boundaries

```
                     +---------------------------------------------+
                     |  Obscura process                            |
                     |                                             |
   vault file  --B1--+-> obscura-vault -> obscura-crypto           |
   export, CSV --B1--+        |                                    |
                     |        |  locked pages (obscura-memlock)    |
                     |   src-tauri commands                        |
                     |        |                                    |
                     |       B2  Tauri IPC                         |
                     |        |                                    |
                     |   web view: ui/, default-src 'none'         |
                     +---+-----------------+----------------+------+
                         |                 |                |
                        B3                B4               B6
                         |                 |                |
              operating system:   Windows Hello,     terminal: argv,
              memory, swap,       WebAuthn and a     stdin, stdout,
              crash dumps,        phone passkey      stderr, pipes
              clipboard

   source -> GitHub Actions -> release files -> your machine      B5
```

| | Boundary | What crosses it | Trusted side |
| --- | --- | --- | --- |
| B1 | Files Obscura reads | Vault files, exports, CSV files | None. Every file is treated as hostile until it authenticates |
| B2 | Rust and the web view | Commands in, summaries and single revealed values out | Rust. The web view gets only what it is about to show |
| B3 | The process and the operating system | Memory pages, crash reports, the clipboard | The operating system account, which is assumed sound |
| B4 | Platform authenticators | A signature from Windows Hello, a PRF output from a passkey | The authenticator, for the secret it alone holds |
| B5 | The supply chain | Crates, GitHub Actions, the build, the downloaded installer | The source in this repository and the workflow that built it |
| B6 | The terminal | The master password in, secrets out | The user at the keyboard |

## Who the attacker is

| | Attacker | Starts with | In scope |
| --- | --- | --- | --- |
| A1 | Thief of the vault file | A copy of the file: a stolen disk, a leaked sync folder, an old backup | Yes - the main case |
| A2 | Someone who can replace the file | Write access to wherever the vault lives, such as a shared or synced folder | Yes |
| A3 | Author of a hostile file | A crafted vault, export or CSV that the user is persuaded to open | Yes |
| A4 | Someone on the network | Your network traffic | Yes, and there is nothing to attack: Obscura sends nothing |
| A5 | Hostile content in the window | Script running in the web view | Yes. The interface loads only its own files, so this needs a bug first |
| A6 | Someone at an unattended screen | A few minutes at an unlocked computer while Obscura is open | Partly - masking and auto-lock |
| A7 | A supply chain attacker | A compromised crate, action or download mirror | Yes |
| A8 | A harvest-now attacker | Today's vault file, and a quantum computer later | Yes, for key wrapping |
| A9 | Malware running as you, or as an administrator | Your account or the machine | No. It can read the screen, the keyboard and the process |
| A10 | Someone holding the unlocked machine | Physical control while the vault is open | No |

Out of scope does not mean ignored. Locked memory and non-dumpable processes
make A9's job harder on Linux, but no promise is made against it.

## Threats and answers

### Spoofing

| | Threat | Answer | What remains |
| --- | --- | --- | --- |
| S1 | A1 guesses the master password offline | Argon2id with at least 64 MiB and two passes, calibrated to the machine at creation. A master password must be 15 characters, not on a list of about 29,000 common passwords, and not a pattern (`policy.rs`) | A password that passes the rules can still be weak in a way they cannot see. Nothing but the password and Argon2id stands between A1 and the vault |
| S2 | A1 forges or swaps a key slot | Each slot's wrapped key is sealed with associated data naming the vault id and the slot id, and the whole header is the body's associated data. A failed unlock says only `NoMatchingSlot`, never which slot came close | None known |
| S3 | A phishing site requests the passkey | The relying party id is fixed at `debanganmali.github.io`, and the PRF salt is derived from the vault id, so a passkey answers for one vault only (`obscura-webauthn`) | The relying party id is tied to the GitHub account name. Renaming the account would abandon every passkey |
| S4 | A1 replays a Windows Hello slot on another machine | The Hello key never leaves the device that created it; the slot opens only where Windows can sign with that key | A Hello slot is as strong as the Windows sign-in that guards it |
| S5 | A fake Obscura installer | Every release file carries a SHA-256 checksum, signed build provenance and an SBOM attestation in a public transparency log. The Store package is signed by Microsoft | Direct downloads are not code signed, so SmartScreen warns and a user who skips verification is trusting the download |

### Tampering

| | Threat | Answer | What remains |
| --- | --- | --- | --- |
| T1 | A2 edits the header - a lower Argon2id cost, another salt, a removed slot | The prefix and header bytes are the body's associated data, so any edit makes the body fail to open. Stored Argon2id costs are checked against bounds before any work is done | None known |
| T2 | A2 moves an entry from one vault to another | Each entry is sealed under its own key with associated data naming the vault and the entry | None known |
| T3 | A2 puts an older copy of the vault back | A keyed BLAKE3 watermark over the vault id and revision is kept outside the file and checked at every unlock; anything but `Current` or `Fresh` stops and asks | The watermark is a local file. An attacker who can delete it gets a vault that looks new on that machine |
| T4 | A3 crafts a file to crash or exhaust Obscura | Header length capped at 1 MiB, Argon2id memory at 2 GiB and passes at 16. Five fuzz targets cover the header, whole vaults, exports, CSV and recovery codes; every truncation of a vault is tested to fail cleanly | A vault at the upper bounds still costs real memory and time to try, by design |
| T5 | A crash or full disk mid-save corrupts the vault | Every entry is validated before anything is written; the vault is written to a temporary file and renamed over the original, and the previous version is kept as `.bak` | None known |
| T6 | A3's import leaves the vault half-changed | An import is validated and renumbered as a batch and committed in one step; a failure leaves the vault untouched. Field sizes are bounded | None known |
| T7 | A7 ships a malicious dependency or action | `Cargo.lock` is committed; `cargo deny` checks advisories, licences and sources on every pull request and refuses unknown registries and git sources; every GitHub Action is pinned to a full commit hash; Dependabot reports updates, which are folded into reviewed commits | The release build installs `tauri-cli` from crates.io at build time |

### Repudiation

Obscura has one user per vault and no server, so there is nobody to deny an
action to. It keeps no activity log on purpose: a log of what was opened when is
itself sensitive. The vault's revision number and timestamps are the only
history, and they are described under what a stolen file reveals in
[architecture.md](architecture.md).

### Information disclosure

| | Threat | Answer | What remains |
| --- | --- | --- | --- |
| I1 | A1 reads the vault file | The body and every entry are sealed with XChaCha20-Poly1305. The number and size of entries is hidden by the outer layer | The plaintext header shows the vault id, timestamps, revision, Argon2id cost and the kind and label of every unlock method |
| I2 | Secrets reach swap, the page file or a crash dump | The vault key and every stored secret live in pages locked with `VirtualLock` or `mlock`; Windows Error Reporting leaves the heap out; Linux core dumps are off and the process is non-dumpable (`obscura-memlock`) | Hibernation writes all memory to disk. A secret is in ordinary memory briefly while typed, decrypted or copied |
| I3 | A copied secret stays on the clipboard | Copies clear themselves after a delay of at most two minutes, only if the clipboard still holds the same value, and are excluded from Windows clipboard history and cloud sync and from Linux clipboard managers | Any program running as you can read the clipboard while the value is there |
| I4 | A5 reads secrets through the interface | The web view gets an entry's password length, never the password, until one field is revealed; hidden fields are withheld; the content security policy is `default-src 'none'` and the window has no file, shell, network or clipboard permission. A test fails if the policy is loosened or a command is called that is not registered | What the window is showing lives in the web view's memory, which is not locked |
| I5 | The CLI leaks a secret | The master password is never an argument, so it never reaches the process list or shell history. Secrets go to stdout and everything else to stderr. An ambiguous query is an error, never a guess | Whatever the user pipes stdout into receives the secret |
| I6 | Obscura sends data somewhere | There is no HTTP client in the program, and the interface cannot open a connection | A malicious dependency could add one; T7 is the defence |
| I7 | An export is read by someone else | Export is behind a confirmation that says the file is plain text; on Linux the file is created readable only by its owner | An export is plain JSON by design, for moving to another manager. On Windows it takes the folder's permissions |
| I8 | A6 reads the screen | Passwords are masked until revealed; the vault locks after an idle period, timed against a monotonic and a wall clock so a machine that slept still locks | What is revealed on screen is visible for as long as it is revealed |
| I9 | A timing difference reveals a secret | Secrets, tags and two-factor secrets are compared in constant time (`subtle`) | The underlying primitives are trusted to be constant time as their crates document |

### Denial of service

| | Threat | Answer | What remains |
| --- | --- | --- | --- |
| D1 | The user forgets the master password | A recovery code unwraps the same key and can reset the password; the last portable unlock method cannot be removed, and the master password can be changed but never removed | With no recovery code, passkey or Hello slot, a forgotten password ends the vault. That is the price of having no server |
| D2 | Uninstalling deletes the vault | New vaults go to `Documents\Obscura`, outside anything an uninstaller or the Store's data cleanup removes | A vault kept in the application data folder by choice is the user's to move |
| D3 | A hostile header asks for unbounded work | Argon2id bounds are checked before derivation starts (T4) | None known |
| D4 | The passkey relying party changes | `RP_ID` is fixed and recorded in [release-blockers.md](release-blockers.md) as final | See S3 |
| D5 | A vault is lost with the disk | Out of Obscura's reach. The `.bak` file is on the same disk | Backups are the user's to keep; the README asks for a second copy of anything that matters |

### Elevation of privilege

| | Threat | Answer | What remains |
| --- | --- | --- | --- |
| E1 | A5 turns script in the window into access to the vault | The window's capability set is the smallest Tauri allows; every command checks its own input and acts on the session in Rust; prototypes are frozen and the asset protocol is off; no remote content is ever loaded | A bug in a command's validation is a bug in Obscura |
| E2 | A3 corrupts memory through a parser | Rust, with `unsafe` forbidden in every crate except `obscura-memlock` and the WebAuthn bindings, fuzzing on every parser, and overflow checks kept on in release builds | `unsafe` remains in those two crates and in dependencies |
| E3 | Code is loaded at run time | Nothing loads code: no plugins, no scripts from disk, no updater | None known |

## Assumptions

- The operating system, the account Obscura runs as and the hardware are not
  compromised.
- The operating system's random number generator is sound.
- The RustCrypto implementations of Argon2id, XChaCha20-Poly1305, HKDF-SHA512,
  X25519 and ML-KEM-768, and the BLAKE3 crate, are correct.
- WebView2 on Windows and WebKitGTK on Linux enforce the content security
  policy.
- The user keeps their recovery code somewhere at least as safe as the vault.

## Residual risk

The risks that remain after everything above, and what is being done about
each.

| Risk | Decision |
| --- | --- |
| A master password that meets the rules but is still guessable | Accepted. The rules follow NIST SP 800-63B-4; the strength meter shows how strong a password is beyond the minimum |
| The rollback watermark can be deleted | Accepted for now. A stronger anchor would need somewhere the attacker cannot write, which a local application does not have |
| Not independently audited | Open. Stated at the top of the README |
| Actions pinned by tag, not commit hash | Closed in 0.2.1. Every action is pinned to a full commit hash |
| Single maintainer | Accepted. Every change still goes through a pull request and the same checks |
| The plain-text export | Accepted. It is labelled as plain text where it is made |
| Hibernation and what the web view displays | Accepted. Outside what an application can control |
| Master passwords are not Unicode-normalised | Closed in 0.2.1. Passwords are put into NFKC form; a vault whose password was set earlier still opens with exactly the characters it was set with |
