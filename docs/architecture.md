# Architecture

How Obscura is put together, what the vault file actually contains, and which
key protects what.

## The shape of the program

Five library crates and two front ends. The cryptography does not know what a
vault is, the vault does not know what an operating system is, and neither knows
there is a user interface.

```
                    obscura-crypto
          Argon2id - XChaCha20-Poly1305 - HKDF-SHA512
           keyed BLAKE3 - hybrid X25519 + ML-KEM-768
                            |
                            v
                     obscura-vault
        file format - entries - key slots - TOTP - recovery
          password generator - CSV import - portable export
                            |
            +---------------+---------------+
            |                               |
            v                               v
       src-tauri                       obscura-cli
   Tauri commands, session          list / get / totp
   watermark, clipboard,            no agent, no cache
   vault location
            |
            |  obscura-platform  Windows Hello, file permissions
            |  obscura-webauthn  WebAuthn PRF for phone passkeys
            v
          ui/
   three static files, no npm, default-src 'none'
```

`obscura-platform` and `obscura-webauthn` are only reached from the desktop
application. Both compile to stubs on platforms that do not have the underlying
API, so the workspace builds everywhere.

## The vault file

One file. No directory, no sidecar, no database.

```
offset  size  contents
------  ----  ---------------------------------------------
     0     8  magic, "OBSCURA\0"
     8     2  format version, u16 little endian, currently 1
    10     4  header length, u32 little endian, max 1 MiB
    14     n  header, CBOR, PLAINTEXT
  14+n     -  body, XChaCha20-Poly1305 sealed
```

The header is deliberately not encrypted, because **the header is the body's
additional authenticated data**. Any edit to it - a changed salt, a removed key
slot, a rewritten revision number - makes the body fail to decrypt rather than
decrypt into something else. That also means the vault id is readable before
anything is unlocked, which is what lets a passkey derive its PRF salt without
first knowing the password.

### Header

```
VaultHeader
  vault_id    uuid
  kdf         { m_cost_kib, t_cost, p_cost }   Argon2id cost, per vault
  salt        16 bytes
  revision    u64, incremented on every save
  created_at  rfc3339
  updated_at  rfc3339
  slots       [ KeySlot ]

KeySlot
  id          uuid
  kind        password | recovery | passkey | hardware
  label       string
  wrapped_key the 32-byte vault key, sealed to this slot
  public_key  optional, present for recovery slots
  created_at  rfc3339
```

Every slot holds the **same** vault key, wrapped differently. That is what makes
adding a passkey or changing the master password cheap: one 32-byte value is
rewrapped, and not a single entry is touched.

### Body

```
body   = seal( vault_key, aad = prefix || header_bytes,
               CBOR([ SealedEntry ]) )

SealedEntry { id, blob }
blob   = seal( entry_key, aad = "obscura/entry/v1/" || vault_id || entry_id,
               CBOR(Entry) )
```

Two layers, and the inner one is not redundant. The outer layer hides how many
entries exist and how large each one is. The inner layer means a single entry
cannot be lifted out of one vault and pasted into another, because its tag is
bound to the vault it belongs to.

## Which key protects what

```
master password ──Argon2id(salt, kdf)──> slot key ─┐
                                                   │
recovery code ──decode──> hybrid secret key ───────┼──unwraps──> VAULT KEY
                          X25519 + ML-KEM-768      │             32 bytes
                                                   │
passkey ──WebAuthn PRF(salt = HKDF(vault_id))──────┘
                                                                     │
                                          ┌──────────────────────────┤
                                          │                          │
                          HKDF-SHA512     │                          │  HKDF-SHA512
                   info "obscura/entry/"  │                          │  info "obscura/
                          + entry_id      │                          │  anti-rollback/v1"
                                          v                          v
                                     entry key                  watermark key
                                   one per entry                      │
                                                                      v
                                                        keyed BLAKE3 over
                                                        vault_id || revision
```

Three things follow from that diagram:

- **The vault key never changes.** Changing the master password rewraps it.
  Losing a passkey means deleting one slot. Neither re-encrypts your entries.
- **Every unlock path is equal.** A recovery code is not a weaker back door; it
  unwraps exactly the same key the password does.
- **The watermark key is derived, not stored.** The anti-rollback tag is kept
  outside the vault file, so an attacker who copies an old vault back cannot
  also forge a matching tag without the vault key.

### Anti-rollback

The vault file cannot defend itself against being replaced with an older copy of
itself - every byte of it is authentic. So the application keeps a keyed BLAKE3
tag over `vault_id || revision` outside the file, and checks it at every unlock.

| Verdict | Meaning |
| --- | --- |
| `Fresh` | No watermark yet. First unlock on this machine. |
| `Current` | Revision matches the tag. |
| `Rollback` | The file is older than the tag. Someone restored a backup. |
| `Tampered` | The revision matches but the tag does not verify. |
| `Unreadable` | The watermark store is damaged or missing. |

Everything except `Current` and `Fresh` stops the unlock and asks the user,
naming the revision, rather than silently accepting or silently refusing.

## Unlocking, step by step

1. Read the file, check the magic and the version.
2. Decode the plaintext header. If a minimum revision was demanded and the
   header is below it, stop with `Rollback` - before any cryptography runs.
3. Validate the stored Argon2id cost. Refuse implausible parameters rather than
   spending an hour of CPU on a hostile file.
4. Derive the key-encryption key from the credential, and try to unwrap each
   slot of the matching kind. No match means `NoMatchingSlot` - the vault never
   reveals which slot was close.
5. Open the body with the vault key, using the prefix and header bytes as AAD.
6. Derive a key per entry and open each one.
7. Check the watermark, and let the application decide whether to admit.

## Saving, step by step

1. Validate every entry **before** anything is written. A vault is never
   partially valid on disk.
2. Increment the revision and set `updated_at`.
3. Seal each entry, then seal the table.
4. Write to `vault.obscura.tmp`, restrict it to the owner on Unix, then rename
   over the real file. A crash mid-write leaves the previous vault intact.
5. Record the new watermark.

## The file tree

```
crates/
  obscura-crypto/        no I/O, no clock, no filesystem
    aead.rs              XChaCha20-Poly1305 seal and open
    kdf.rs               Argon2id, and calibration against real hardware
    derive.rs            HKDF-SHA512 subkeys
    hybrid.rs            X25519 + ML-KEM-768 encapsulation
    mac.rs               keyed BLAKE3
    secret.rs            SecretBytes, zeroized on drop

  obscura-vault/         the format and the data model
    format.rs            byte layout, header, key slots, AAD construction
    vault.rs             open, save, slots, watermark tags
    entry.rs             Entry, EntryKind, custom fields, validation
    totp.rs              RFC 6238, otpauth:// parsing
    recovery.rs          printed recovery codes and their checksum
    generator.rs         password and passphrase generation
    csv_import.rs        importing from other managers
    portable.rs          encrypted export and import

  obscura-platform/      hello.rs      Windows Hello, file permissions
  obscura-webauthn/      imp.rs        Windows WebAuthn PRF
                         stub.rs       everything else
  obscura-cli/           args.rs main.rs prompt.rs

src-tauri/
  commands.rs            every command the interface can call
  state.rs               the unlocked session and the auto-lock clock
  watermark.rs           the anti-rollback store
  location.rs            where the vault lives, and whether it is writable
  clipboard.rs           copies that clear themselves
  dto.rs                 what crosses into the interface - never a raw Entry

ui/                      index.html  styles.css  app.js
docs/                    this file, passkeys, testing, mutation testing
packaging/windows/       MSIX manifest and build script
```

## What a stolen vault file reveals

Being honest about this is more useful than claiming nothing leaks. Without any
credential, the plaintext header tells an attacker:

- that the file is an Obscura vault, and its format version
- the vault id, its creation and last-modified timestamps, and its revision
- the Argon2id cost parameters and the salt
- **how many ways in there are, of what kind, with what labels** - so "3 slots:
  password, passkey 'Pixel 8', recovery" is visible

What it does not reveal: how many entries exist, how large any of them is, or
anything at all about their contents.

The revision number and timestamps also mean a vault file is a record of how
often you use it. If that matters to you, the file is exactly as private as the
disk it sits on.

## Deliberate absences

- **No `mlock` / `VirtualLock`.** Secrets are zeroized, but nothing stops a page
  reaching swap or a crash dump first.
- **No network code of any kind.** Not a disabled feature - the application has
  no HTTP client, and the interface's content security policy is
  `default-src 'none'`.
- **No agent, no unlock cache, no IPC socket.** The CLI prompts and forgets.
- **No plugin surface.** Nothing loads code at runtime.
