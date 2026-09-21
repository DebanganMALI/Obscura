# Obscura

A post-quantum-hardened, open-source password manager for Windows and Linux.
No account, no telemetry, no network access.

> **Status: first public release.** Obscura has not been independently audited
> and the interface has no automated test coverage. Keep a second copy of
> anything you cannot afford to lose.

## Installing

Installers are attached to each [release](https://github.com/DebanganMALI/Obscura/releases).

| Platform | File |
| --- | --- |
| Windows | `Obscura_0.1.0_x64-setup.exe` |
| Windows, MSI | `Obscura_0.1.0_x64_en-US.msi` |
| Debian, Ubuntu | `Obscura_0.1.0_amd64.deb` |
| Fedora, RHEL | `Obscura-0.1.0-1.x86_64.rpm` |
| Any Linux | `Obscura_0.1.0_amd64.AppImage` |

### Windows will warn you

The installers are not code signed, so SmartScreen shows "Windows protected
your PC" the first time you run one. Choose **More info**, then **Run anyway**.

That warning is not a formality being skipped. A certificate that removes it
costs 150 to 300 US dollars a year and requires a hardware token, extended
validation certificates stopped bypassing SmartScreen in 2024, and Microsoft's
free signing service is not offered to individuals outside the USA and Canada.
So instead of buying the absence of a warning, Obscura publishes something you
can check for yourself.

## Verifying what you downloaded

Two checks, and the second is the one that matters.

**The checksum** tells you the file arrived intact. Every release includes a
`SHA256SUMS` file.

```powershell
Get-FileHash .\Obscura_0.1.0_x64-setup.exe -Algorithm SHA256
```

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

**The build provenance** tells you where the file came from. Every installer
carries a signed attestation, recorded in a public transparency log, naming the
commit and the workflow run that produced it.

```sh
gh attestation verify Obscura_0.1.0_x64-setup.exe --repo DebanganMALI/Obscura
```

A checksum only proves the file matches a list published beside it, so anyone
who could replace the installer could replace the list. An attestation cannot be
forged without push access to this repository, and the log is append-only and
public. If you verify one thing, verify this.

## What is built

- **Argon2id**, calibrated at vault creation against your actual hardware
- **XChaCha20-Poly1305** with per-entry keys derived via HKDF-SHA512
- **Envelope encryption** - changing your master password rewraps the 32-byte
  vault key rather than re-keying every entry
- **Hybrid X25519 + ML-KEM-768** key wrapping, so a recorded vault is not opened
  later by a quantum computer that breaks the classical half
- Unlock with a master password, **Windows Hello**, a **phone or tablet
  passkey**, or a printed recovery code. Passkey unlock uses the WebAuthn PRF
  extension, so the key never leaves the authenticator - see
  [docs/passkeys.md](docs/passkeys.md)
- TOTP codes, a password generator, CSV import, and encrypted export
- **Rollback detection** - a keyed BLAKE3 watermark per vault, checked at every
  unlock, so a restored older copy is noticed rather than silently accepted
- Auto-lock on idle, timed against both a monotonic and a wall clock, so a
  machine that slept through the timeout still locks
- Clipboard copies that clear themselves and opt out of Windows clipboard
  history and Linux clipboard managers
- Secrets held in zeroizing memory and wiped when they go out of scope
- A command line tool, `obscura`

## What is not built

On the roadmap. None of it exists today, so do not plan around it:

- A browser extension and its native messaging host
- Second-device enrollment and entry sharing
- Sync of any kind, and mobile applications
- `mlock` / `VirtualLock` on pages holding secrets. Secrets are zeroized, but
  nothing prevents them reaching swap or a crash dump first.

## The command line

`obscura` reads a vault without the desktop application. It is the way to
script a vault on Linux.

```sh
export OBSCURA_VAULT=~/.local/share/obscura/vault.obscura

obscura list              # titles and usernames, never a password
obscura list git          # only matching entries
obscura get github        # the password, to stdout
obscura totp github       # the current code, to stdout
```

Three rules are built in:

- **The master password is never an argument.** It is read from the terminal
  without echo, or from stdin when stdin is not a terminal, so it never reaches
  the process list or your shell history. `pass show master | obscura get
  github` works.
- **There is no background agent and no unlock cache.** Every command prompts
  and forgets. A long-lived process holding a vault key over a socket would be a
  larger attack surface than everything else here put together.
- **An ambiguous query is an error, never a guess.** If `get git` matches two
  entries it lists them and exits non-zero. It will not pick one for you.

Secrets go to stdout and everything else to stderr, so `obscura totp github |
wl-copy` copies six digits and nothing else.

## Building from source

```sh
cargo build --workspace
cargo nextest run --workspace
```

The desktop application needs the Tauri CLI:

```sh
cargo install tauri-cli --version "^2" --locked
cargo tauri build
```

The interface is three static files under `ui/` with no npm dependencies and a
`default-src 'none'` content security policy.

## Security

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

How the project is tested, including what the test suite does not cover, is in
[docs/testing.md](docs/testing.md) and
[docs/mutation-testing.md](docs/mutation-testing.md).

Obscura collects nothing and makes no network requests. See
[docs/privacy-policy.md](docs/privacy-policy.md).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
