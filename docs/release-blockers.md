# Release blockers

Things that must be settled before the first public build. Each one is cheap
now and expensive after a stranger has installed Obscura.

## 1. Register obscura.app

`RP_ID` in `crates/obscura-webauthn/src/lib.rs` is `obscura.app`. The domain is
not registered yet.

A passkey is bound to its relying party. Changing `RP_ID` does not migrate
credentials, it abandons them: every passkey enrolled against the old value
stops opening the vault. A user whose passkey slot was their last portable
credential is then locked out of their own data, and no support action recovers
it. So the value has to be final before the first release, not after.

Windows never checks that the domain resolves, so nothing breaks while it is
unregistered. Two things make registering it worth doing anyway: a browser does
check, so an unregistered name forecloses any web companion; and whoever owns
the domain can assert the relying party, so leaving it to a stranger is a
standing risk.

If the name turns out to be taken, decide the replacement before release rather
than shipping and renaming.

## 2. Prove the Windows bundlers

Only `cargo tauri build --no-bundle` has ever run. The MSI and NSIS bundlers are
unexercised, and the MSIX path goes through Microsoft's `winapp` CLI, which is
in public preview.

## 3. Build the Linux artifacts once

`deb`, `rpm` and AppImage have never been built. Linux CI compiles and tests the
workspace, so the code is known to work there; the packaging is not.

## 4. Sign the binaries

Package identity is `Name` plus `Publisher`, and `Publisher` must match the
signing certificate subject. `packaging/windows/build.ps1` currently falls back
to a generated self-signed certificate, which is fine for local testing and not
for distribution.

## 5. Decide on obscura-cli

A 144-byte stub at 0% coverage. Either build it out or exclude it from the
release artifacts, because shipping an executable that does nothing is worse
than shipping neither.