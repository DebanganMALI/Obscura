# Passkeys

A passkey opens the vault. It is never used for anything inside the vault:
entries are protected by the vault key, and a passkey is one of the ways to
obtain that key, alongside a master password, a recovery code and Windows
Hello.

## How it works

The authenticator holds a resident credential. Asking it for an assertion with
the CTAP2 hmac-secret extension and a 32-byte salt returns 32 bytes that are
stable for that credential and that salt, derived inside the authenticator and
never exportable.

Those 32 bytes seed a hybrid X25519 + ML-KEM-768 identity, and that identity
opens a Passkey slot in the vault header, exactly as a recovery code does. The
unlock path needed no change: it tries every slot that is not a password slot
as an identity slot.

The salt is `subkey_from_ikm(vault_id, "obscura/passkey/salt/v1")`. Deriving it
from the vault id means one phone credential enrolled against two vaults yields
a different key for each, so opening one never yields the key to the other. The
vault id is readable before unlocking because the header is plaintext CBOR: it
is the body's associated data, so it cannot be tampered with undetected.

## Why enrolment asks for the phone twice

`WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS` is at version 7 in Windows and
carries `bEnablePrf`, which turns the extension on, and nothing else about PRF.
The salt fields live on the get-assertion options struct. There is no way to
ask Windows for a PRF secret while creating the credential, so enrolment is
necessarily two operations: create the credential, then read the secret. Each
one raises its own dialog.

This is a property of the Windows API, not of Obscura. It is not worth
revisiting unless a future version of the struct grows a PRF evaluation field.

## Why removing a slot does not remove the credential

Removing a passkey slot revokes the credential's access to the vault, which is
what matters: the slot is the only thing that turns those 32 bytes into the
vault key. The credential itself lives in the phone's keystore and only the
phone's owner can delete it there, so the interface says so rather than
implying the passkey is gone.

There is no `passkey_forget` command for this reason. Hello has one because the
TPM credential is on the same machine and can be deleted; a passkey slot goes
through `remove_slot` like any other.

## Platforms

Windows only. Linux has no equivalent OS-level hybrid transport, so
`obscura-webauthn` compiles there against a stub that answers `Unsupported`,
and the interface hides both passkey buttons when the platform reports no PRF
support.

The relying party id is `debanganmali.github.io`. It is free, controlled, and a
registrable domain in its own right because `github.io` is on the Public Suffix
List. See `release-blockers.md` for why a bought domain was not worth it.