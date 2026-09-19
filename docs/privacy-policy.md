# Privacy policy

Last updated: 19 September 2026

Obscura does not collect anything.

That is the whole policy. The rest of this document explains what that means
concretely, so you can check the claim rather than take it.

## No account, no network

Obscura has no sign-up, no sign-in and no server. It makes no outbound network
connections of any kind - not for updates, not for telemetry, not for crash
reports, not for analytics. There is no service behind it that could receive
your data, because there is no service.

The application's content security policy is `default-src 'none'`, which
forbids the interface from loading or contacting anything outside the
application itself.

## What is stored, and where

Everything Obscura keeps lives on your own computer.

**Your vault** is a single encrypted file at a location you choose. Entry
titles, usernames, passwords, notes, custom fields and two-factor secrets are
inside it, encrypted. Obscura never writes them anywhere else.

**A settings file** in your user configuration directory remembers where your
vault is and how long before it locks itself. It contains no secrets.

**A rollback record** in the same directory holds one number and one
authentication tag per vault, so Obscura can notice if an older copy of your
vault is put back in place. It contains no secrets and no entry data.

Uninstalling removes the application. Your vault file is yours and stays where
you put it.

## How your data is protected

Your master password is stretched with Argon2id, calibrated to your machine.
The vault is encrypted with XChaCha20-Poly1305. Each entry is encrypted with
its own key, derived from the vault key and bound to that entry's identity, so
a block of ciphertext cannot be moved between entries or between vaults.

Vault keys are wrapped with a hybrid of X25519 and ML-KEM-768, so a recording
of your vault made today is not decrypted by a future quantum computer breaking
X25519 alone.

None of this protects a vault whose master password is guessed. Choose one you
have not used elsewhere.

## Windows Hello and passkeys

If you set up Windows Hello, the credential is created and held by your
computer's secure hardware. Obscura receives a derived value and never sees
your fingerprint, face or PIN.

If you add a phone passkey, the credential is created and held by your phone.
Obscura receives a derived value and never sees your phone's biometrics.
Removing a passkey in Obscura revokes its access to the vault; the credential
itself stays on the phone until you delete it there.

Neither route sends anything over the internet from Obscura. The passkey
exchange happens between Windows and your phone.

## The clipboard

Copying a password puts it on your system clipboard, which is shared with every
application on your computer. Obscura clears it after a timeout you control and
asks Windows not to include it in clipboard history or cloud sync, but a
clipboard manager already running can still capture it. This is a property of
the clipboard, not of Obscura.

## Importing and exporting

Obscura can read exports from other password managers and can write its own
export. **An export is plain text and is not encrypted.** Obscura writes it
where you ask and does nothing else with it. Delete it when you are done.

## Children

Obscura is not directed at children and collects nothing from anyone.

## Changes

Any change to this policy will be a commit in this repository, with its own
date and its own diff. There is no version of this document you cannot read the
history of.

## Contact

Open an issue at https://github.com/DebanganMALI/Obscura/issues