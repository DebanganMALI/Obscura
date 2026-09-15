# Security Policy

## Reporting a Vulnerability

Report security issues **privately** via GitHub Security Advisories
(the "Report a vulnerability" button on the Security tab).
Please do not open a public issue.

Acknowledgement within 72 hours; fix targeted within 90 days.

## Scope

**In scope:** the vault format, cryptographic implementation, the Tauri IPC
surface, the native messaging host, and the browser extension.

**Out of scope:** attacks requiring an already-compromised OS account,
physical access to an unlocked vault, and user-chosen weak master passwords.

## Cryptography

| Purpose                      | Primitive                    |
|------------------------------|------------------------------|
| Password KDF                 | Argon2id, runtime-calibrated |
| Content encryption           | XChaCha20-Poly1305           |
| Key derivation               | HKDF-SHA512                  |
| Header integrity             | BLAKE3 keyed MAC             |
| Recovery & device enrollment | Hybrid X25519 + ML-KEM-768   |

Vault contents at rest are protected by symmetric primitives, which are already
quantum-resistant at these key sizes. The post-quantum hybrid is applied where it
actually matters: asymmetric key wrapping for recovery keys, second-device
enrollment, and entry sharing.