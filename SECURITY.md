# Security Policy

## Reporting a Vulnerability

Report security issues **privately** via GitHub Security Advisories
(the "Report a vulnerability" button on the Security tab).
Please do not open a public issue.

Obscura is maintained by one person alongside other work, so there is no
staffed response window to promise. Reports are acknowledged as soon as they
are seen, and you will get an honest estimate rather than a deadline.

## Scope

**In scope:** the vault format, the cryptographic implementation, and the
Tauri IPC surface.

**Out of scope:** attacks requiring an already-compromised OS account, physical
access to an unlocked vault, user-chosen weak master passwords, and anything
the README lists as not built.

## Cryptography

| Purpose                | Primitive                    |
|------------------------|------------------------------|
| Password KDF           | Argon2id, runtime-calibrated |
| Content encryption     | XChaCha20-Poly1305           |
| Key derivation         | HKDF-SHA512                  |
| Recovery code wrapping | Hybrid X25519 + ML-KEM-768   |
| Rollback watermark     | BLAKE3 keyed MAC             |
| Recovery code checksum | BLAKE3 keyed hash            |

The header carries no MAC of its own. It is bound to the body instead: the
length prefix and the header bytes are the associated data for the body's AEAD,
so any edit to the header makes the body fail to decrypt.

Vault contents at rest are protected by symmetric primitives, which are already
quantum-resistant at these key sizes. The post-quantum hybrid is applied where
it actually matters - asymmetric key wrapping, which today means printed
recovery codes.

## Known limitations

- Secrets are zeroized when dropped, but their pages are not locked. A secret
  can reach swap or a crash dump before it is wiped.
- The rollback watermark is a local file in the application config directory.
  An attacker who can delete it gets a vault that looks new to Obscura.
- Hardware-backed unlock of any kind - Windows Hello, TPM, FIDO2 - is not
  implemented.
