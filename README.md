# Obscura

A post-quantum-hardened, open-source password manager for Windows and Linux.

> **Status: pre-alpha.** Do not store real credentials in Obscura yet.
> The vault format is not stable and has not been audited.

## Design

- **Argon2id**, calibrated at vault creation against your actual hardware
- **XChaCha20-Poly1305** with per-entry keys derived via HKDF-SHA512
- **Envelope encryption** - changing your master password rewraps 32 bytes, not the vault
- **Hybrid X25519 + ML-KEM-768** for recovery keys, device enrollment, and sharing
- Secrets held in locked, zeroizing memory
- Unlock via master password, Windows Hello / TPM, or a FIDO2 key

## Building

    cargo build --workspace
    cargo nextest run --workspace

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).