# Security posture

How the way Obscura is built and released lines up against the controls in
Annex A of ISO/IEC 27001:2022.

## What this is, and what it is not

ISO/IEC 27001 certifies an organisation's information security management
system. Obscura is an application written and maintained by one person; it has
no such system, it is not certified, and nothing here claims conformity.

What Annex A does offer is a well-known checklist. Walking all 93 controls shows
which ones a single offline application meets, which it meets only in part, and
which have nothing to act on - and saying why in each case is more useful than
claiming everything or nothing. In the tables below:

- **Met** - the control's purpose is served, and the evidence is named
- **Partly** - something is done, and what is missing is named too
- **Open** - it applies and is not yet done
- **Not applicable** - there is no organisation, premises, staff or service for
  it to act on

Control titles are given in short form. The evidence column points at files in
this repository, so each line can be checked rather than taken on trust. The
[threat model](threat-model.md) is the companion to this document: it starts
from attackers rather than controls.

## Summary

| Theme | Controls | Met | Partly | Open | Not applicable |
| --- | --- | --- | --- | --- | --- |
| 5 Organisational | 37 | 23 | 4 | 1 | 9 |
| 6 People | 8 | 1 | 0 | 0 | 7 |
| 7 Physical | 14 | 4 | 0 | 0 | 10 |
| 8 Technological | 34 | 21 | 4 | 0 | 9 |
| **Total** | **93** | **49** | **8** | **1** | **35** |

## 5 Organisational controls

| Control | Status | Evidence |
| --- | --- | --- |
| 5.1 Policies for information security | Met | [SECURITY.md](../SECURITY.md) sets supported versions, scope, reporting and disclosure; this document and the threat model set out the rest |
| 5.2 Roles and responsibilities | Met | One maintainer holds every role, and SECURITY.md says so rather than implying a team |
| 5.3 Segregation of duties | Partly | One person cannot be separated from themselves. Instead, `main` accepts changes only through pull requests that pass every required check, so no change skips review by the pipeline |
| 5.4 Management responsibilities | Not applicable | No organisation and no staff to direct |
| 5.5 Contact with authorities | Not applicable | No service is operated and no user data is held, so there is nothing to report to a regulator |
| 5.6 Contact with special interest groups | Met | The RustSec advisory database through `cargo deny`, and the GitHub Advisory Database through Dependabot |
| 5.7 Threat intelligence | Met | Advisories are checked on every pull request; the password policy follows NIST SP 800-63B-4 and key wrapping uses ML-KEM-768 from FIPS 203 |
| 5.8 Security in project management | Met | Security work is on the roadmap in the README, and each audit is written up with what it found, as in [audit-3-remaining.md](audit-3-remaining.md) |
| 5.9 Inventory of information and assets | Met | Every release carries CycloneDX SBOMs for the application and the command line tool; the threat model lists the information assets |
| 5.10 Acceptable use | Not applicable | No shared assets or users to govern |
| 5.11 Return of assets | Not applicable | No staff or equipment |
| 5.12 Classification of information | Met | The code classifies what it holds: secrets are `SecretString`, `SecretBytes` or `LockedBytes`, locked and wiped; metadata is wiped on drop; the header is public by design and documented as such in [architecture.md](architecture.md) |
| 5.13 Labelling of information | Met | Secret types redact themselves in debug output and logs, and the export is labelled plain text where it is made |
| 5.14 Information transfer | Met | No network transfer exists. The clipboard clears itself and opts out of history; the CLI writes secrets only to stdout |
| 5.15 Access control | Met | A vault opens only through one of its key slots; the window holds the smallest Tauri capability set; on Linux the vault and exports are created readable only by their owner |
| 5.16 Identity management | Met | Each unlock method is a labelled slot that can be listed and removed; the master password slot can be changed but never removed |
| 5.17 Authentication information | Met | The master password policy; recovery codes carry a checksum and fold characters that are easy to misread; no credential is stored, only what it unwraps |
| 5.18 Access rights | Met | Adding or removing an unlock method needs an unlocked vault; resetting the master password needs a session opened by recovery code; the last portable method cannot be removed |
| 5.19 Security in supplier relationships | Met | Crates are the suppliers. `cargo deny` checks their advisories, licences and sources on every pull request |
| 5.20 Security in supplier agreements | Not applicable | Open-source licences are the only agreements, and they are checked under 5.32 |
| 5.21 ICT supply chain | Partly | `Cargo.lock` committed; unknown registries and git sources refused; SBOMs and provenance attested. GitHub Actions are pinned by version tag rather than commit hash |
| 5.22 Monitoring supplier services | Met | Dependabot watches the lockfile and the actions weekly; its updates are folded into reviewed commits rather than merged directly |
| 5.23 Use of cloud services | Partly | GitHub hosts the source, the builds and the releases, and the Microsoft Store will distribute the signed package. The application uses no cloud service, and warns when a vault is placed in a syncing folder |
| 5.24 Incident management planning | Met | SECURITY.md: private reporting through GitHub Security Advisories |
| 5.25 Assessing security events | Met | Reports are triaged against the scope in SECURITY.md; Dependabot alerts that do not reach shipped code are dismissed with the reason recorded |
| 5.26 Response to incidents | Met | Coordinated disclosure, 90 days by default, fixed in the latest release, reporter credited |
| 5.27 Learning from incidents | Met | Audit write-ups record each defect, its root cause and the test that now pins it |
| 5.28 Collection of evidence | Not applicable | No service and no logs to preserve. Build provenance in the public transparency log is the evidence a release can offer |
| 5.29 Security during disruption | Not applicable | Nothing runs as a service. The application works offline by design |
| 5.30 ICT readiness for continuity | Not applicable | As 5.29. A user's own continuity rests on recovery codes and backups, covered under 8.13 |
| 5.31 Legal and contractual requirements | Partly | Licences are checked on every pull request. No legal review of cryptography export rules has been made |
| 5.32 Intellectual property rights | Met | GPL-3.0-or-later; every dependency's licence is checked against an allow list; the bundled password list keeps its own licence beside it |
| 5.33 Protection of records | Not applicable | No records are kept. Git history and release attestations are public and append-only |
| 5.34 Privacy and protection of PII | Met | Nothing is collected. [privacy-policy.md](privacy-policy.md) says what is stored, and it is all on the user's own machine |
| 5.35 Independent review | Open | Obscura has not been independently audited, and the README says so at the top |
| 5.36 Compliance with policies and standards | Met | The pipeline enforces the rules: formatting, Clippy at pedantic with warnings as errors, `cargo deny`, gitleaks, and the tests on Windows and Linux |
| 5.37 Documented operating procedures | Met | [testing.md](testing.md), the release workflow, the packaging script, and the verification steps in SECURITY.md |

## 6 People controls

| Control | Status | Evidence |
| --- | --- | --- |
| 6.1 Screening | Not applicable | No staff |
| 6.2 Terms of employment | Not applicable | No staff |
| 6.3 Awareness and training | Not applicable | No staff |
| 6.4 Disciplinary process | Not applicable | No staff |
| 6.5 Responsibilities after a change of employment | Not applicable | No staff |
| 6.6 Confidentiality agreements | Not applicable | The source is public; nothing confidential is shared |
| 6.7 Remote working | Not applicable | No staff |
| 6.8 Reporting security events | Met | Anyone can report privately through GitHub Security Advisories, as SECURITY.md describes |

## 7 Physical controls

The project has no premises. Four controls still apply, to the machine the
vault lives on, and Obscura answers them in software.

| Control | Status | Evidence |
| --- | --- | --- |
| 7.1 to 7.6 Perimeters, entry, offices, monitoring, environmental threats, secure areas | Not applicable | No premises |
| 7.7 Clear desk and clear screen | Met | Secrets are masked until revealed; the vault locks on idle, even across sleep |
| 7.8 Equipment siting and protection | Not applicable | No equipment |
| 7.9 Security of assets off-premises | Met | A laptop carried anywhere holds only the encrypted vault while Obscura is locked |
| 7.10 Storage media | Met | The vault is encrypted at rest, so a lost disk or a stray backup reveals only the header described in architecture.md |
| 7.11 to 7.13 Utilities, cabling, equipment maintenance | Not applicable | No equipment |
| 7.14 Secure disposal or re-use of equipment | Met | A disposed disk holds only ciphertext. Secrets are zeroized in memory when dropped |

Rows 7.1 to 7.6 and 7.11 to 7.13 group nine controls with the same answer; the
summary counts each control once.

## 8 Technological controls

| Control | Status | Evidence |
| --- | --- | --- |
| 8.1 User endpoint devices | Met | The point of the program: encryption at rest, auto-lock, locked memory, no secrets in crash dumps |
| 8.2 Privileged access rights | Met | The application needs no administrator rights. Workflows run with read-only permissions, and only the release job is granted write access, to publish and attest |
| 8.3 Information access restriction | Met | What crosses into the window is a summary that never carries a password; one field is revealed at a time, on request |
| 8.4 Access to source code | Met | The source is public to read; writes reach `main` only through pull requests with required checks; gitleaks scans the history for secrets |
| 8.5 Secure authentication | Met | Argon2id calibrated per machine; four unlock methods, each unwrapping the same vault key; Windows Hello and phone passkeys through platform APIs; a failed unlock reveals nothing about which slot came close |
| 8.6 Capacity management | Met | Argon2id is calibrated to the hardware, stored costs are bounded, and entry fields and headers have size limits |
| 8.7 Protection against malware | Partly | The application loads no code and no remote content. Direct downloads are verifiable but not code signed; the Store package, once published, is signed by Microsoft |
| 8.8 Management of technical vulnerabilities | Met | `cargo deny` advisories on every pull request, Dependabot alerts, each ignored advisory listed in `deny.toml` with its reason, and fixes shipped in the latest release |
| 8.9 Configuration management | Met | Lockfile, toolchain, lints, `deny.toml`, the Tauri capability file and the content security policy are all in the repository, and a test fails if the policy is loosened |
| 8.10 Information deletion | Met | Secrets are zeroized on drop; copied values clear themselves; removing an unlock method revokes it, and removing Windows Hello also deletes its key from Windows |
| 8.11 Data masking | Met | Passwords are masked, and only their length is shown; lists never include a password; secret types print as redacted |
| 8.12 Data leakage prevention | Met | No network code; clipboard exclusions; a content security policy that forbids connections; locked pages for secrets |
| 8.13 Information backup | Partly | Each save keeps the previous vault as `.bak`, and an export moves entries to any manager. Off-machine backup is left to the user, and the README asks for it |
| 8.14 Redundancy of processing facilities | Not applicable | No facilities. Several unlock methods give redundancy of access instead |
| 8.15 Logging | Not applicable | Deliberately no logs and no telemetry; a log of what was opened when would itself be sensitive |
| 8.16 Monitoring activities | Not applicable | Nothing runs as a service. The repository is monitored by Dependabot and gitleaks |
| 8.17 Clock synchronisation | Met | Auto-lock is timed against both a monotonic and a wall clock; two-factor codes follow the system clock, as RFC 6238 expects |
| 8.18 Privileged utility programs | Not applicable | None used or needed |
| 8.19 Installation of software | Partly | Releases are checksummed, attested and SBOM-attested; there is no auto-updater to subvert. The direct installers are not code signed |
| 8.20 Networks security | Not applicable | No network code |
| 8.21 Security of network services | Not applicable | No network services |
| 8.22 Segregation of networks | Not applicable | No network |
| 8.23 Web filtering | Met | The window loads only the four files shipped with it; the content security policy denies everything else |
| 8.24 Use of cryptography | Met | Argon2id, XChaCha20-Poly1305, HKDF-SHA512 with domain separation, keyed BLAKE3 and hybrid X25519 + ML-KEM-768; one vault key wrapped per slot; keys from the operating system's random number generator |
| 8.25 Secure development life cycle | Met | Threat model, pull requests, continuous integration on two operating systems, audits written up, fuzzing and mutation testing |
| 8.26 Application security requirements | Met | Set out in SECURITY.md, the master password policy and the threat model |
| 8.27 Secure architecture and engineering | Met | Layers that do not know about each other, the header as the body's associated data, envelope encryption, and `unsafe` confined to two small crates |
| 8.28 Secure coding | Met | Rust; `unsafe` forbidden in five crates; Clippy at pedantic with `unwrap_used` and `mem_forget` denied; overflow checks and abort-on-panic in release builds; constant-time comparison of secrets |
| 8.29 Security testing in development | Met | Property tests, RFC 6238 vectors and FIPS 203 size checks, five fuzz targets, mutation testing, interface tests that guard the content security policy, and the whole suite on Windows and Linux |
| 8.30 Outsourced development | Not applicable | No development is outsourced |
| 8.31 Separation of environments | Partly | Tests run against temporary directories and never touch a real configuration; releases are built only by the workflow, from a tag. Development and release share one GitHub account |
| 8.32 Change management | Met | Every change is a pull request with required checks, merged by rebase so history stays linear; releases are tagged, and each release file is tied to its commit by provenance |
| 8.33 Test information | Met | Tests use generated vaults and synthetic entries; the one stored fixture is a vault made for the purpose |
| 8.34 Protection during audit testing | Not applicable | No live systems to protect |

## What is open

Gathered from the tables above, in the order they will be addressed.

1. **Pin GitHub Actions by commit hash** (5.21). Dependabot already understands
   pinned hashes and will keep them current.
2. **An independent review** (5.35). Most likely of the file format and the
   unlock paths first, since that is where a mistake costs the most.
3. **Code signing for direct downloads** (8.7, 8.19). Waits on a signing route
   open to an individual developer in India; until then the Store is the
   signed route.
4. **Off-machine backup** (8.13). A reminder in the application, without any
   network code.
