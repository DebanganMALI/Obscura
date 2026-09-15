# Obscura

A post-quantum-hardened, open-source password manager for Windows and Linux.

> **Status: pre-alpha.** Do not store real credentials in Obscura yet.
> The vault format is not stable and has not been audited.

## What is built

- **Argon2id**, calibrated at vault creation against your actual hardware
- **XChaCha20-Poly1305** with per-entry keys derived via HKDF-SHA512
- **Envelope encryption** - changing your master password rewraps the 32-byte
  vault key rather than re-keying every entry
- **Hybrid X25519 + ML-KEM-768** key wrapping, used today for printed recovery codes
- Secrets held in zeroizing memory and wiped when they go out of scope
- Rollback detection - a keyed BLAKE3 watermark per vault, checked at every unlock
- Auto-lock on idle, timed against both a monotonic clock and the wall clock, so a
  machine that slept through the timeout still locks
- Clipboard copies that clear themselves and opt out of Windows clipboard history
  and Linux clipboard managers
- Unlock with a master password or a printed recovery code

## What is not built

These are on the roadmap. None of it exists in the code today, so do not plan
around it:

- Unlock with Windows Hello, a TPM, or a FIDO2 security key. The vault format
  reserves a hardware slot kind, but nothing in the application creates one.
- Cross-device passkeys
- Second-device enrollment and entry sharing
- A browser extension and its native messaging host
- `mlock` / `VirtualLock` on pages holding secrets. Secrets are zeroized, but
  nothing prevents them reaching swap or a crash dump first.

## Building

    cargo build --workspace
    cargo nextest run --workspace

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
