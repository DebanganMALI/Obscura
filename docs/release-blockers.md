# Release blockers

Things that must be settled before the first public build. Each one is cheap
now and expensive after a stranger has installed Obscura.

## 1. Relying party id - settled

`RP_ID` in `crates/obscura-webauthn/src/lib.rs` is `debanganmali.github.io`.

A passkey is bound to its relying party. Changing `RP_ID` does not migrate
credentials, it abandons them: every passkey enrolled against the old value
stops opening the vault, and a user whose passkey was their last portable
credential is locked out with no recovery. So the value had to be final before
the first release.

`obscura.app` was the first choice and is held by a reseller asking around
17,000 rupees. `obscura.com` and `obscura.in` are taken too. For an open-source
project that is not a sensible trade.

`debanganmali.github.io` is free and genuinely controlled. It is a valid
relying party id rather than a workaround: `github.io` is on the Public Suffix
List, so `debanganmali.github.io` is a registrable domain in its own right,
exactly as `obscura.app` would have been.

Two consequences worth knowing. A relying party id is a domain with no path, so
this identity covers the whole GitHub Pages space of that account rather than
Obscura alone. And it is tied to the account name - renaming or deleting
`DebanganMALI` would abandon every passkey enrolled against it.

Buying a domain later remains possible. It would cost every existing user a
re-enrolment, which is a release note while the user base is small and a
migration problem once it is not.

## 2. Prove the Windows bundlers - done

`cargo tauri build` produces an MSI and an NSIS installer, verified locally and
on a clean CI runner. `packaging/windows/build.ps1` produces a signed MSIX with
the identity the Store assigned.

## 3. Build the Linux artifacts - done

`deb`, `rpm` and AppImage all build on ubuntu in the Bundle workflow.

## 4. Signing - decided

Nothing is code signed for direct download, and nothing will be. Azure Artifact
Signing is limited to the USA and Canada for individuals. EV certificates
stopped bypassing SmartScreen in 2024. An OV certificate costs 150 to 300
dollars a year and needs a hardware token.

Instead: SHA-256 checksums and GitHub build provenance attestation, which tie
each installer to the commit and workflow run that produced it. That is a claim
a user can verify, rather than a reassuring absence of a warning.

Windows will show a SmartScreen warning on download. The README has to say so
plainly rather than let people discover it.

The Microsoft Store is the route to a signed binary, because Microsoft signs
Store packages. `Obscura Vault` is reserved, product `9PB5FVD26LPM`.

## 5. obscura-cli - settled

Built out rather than removed. `obscura list`, `obscura get <query>` and
`obscura totp <query>` - the only way to script the vault on Linux.

Three rules are baked in. The master password is never an argument: it is read
from the terminal without echo, or from stdin when stdin is not a terminal, so
it never reaches the process list or the shell history. There is no background
agent and no unlock cache - every command prompts and forgets, rather than a
long lived process holding a vault key over a socket. And a query matching more
than one entry is an error that lists the candidates, never a guess: printing
the wrong password silently is the worst thing this tool could do.

Secrets go to stdout and everything else to stderr, so `obscura totp github |
wl-copy` copies six digits and nothing else.

## Store submission, outstanding

Not release blockers - the GitHub release does not wait on these.

- Screenshots, at least one at 1366x768 or larger
- The age rating questionnaire
- Submission deadline of roughly 19 December 2026, three months from the name
  reservation