use std::{fs, io::Write as _, path::Path};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{entry::Entry, error::VaultError, vault::restrict_to_owner, Vault};

pub const FORMAT: &str = "obscura.export.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Portable {
    pub format: String,
    #[serde(with = "time::serde::rfc3339")]
    pub exported_at: OffsetDateTime,
    pub vault_id: Uuid,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ImportReport {
    pub added: usize,
    pub renumbered: usize,
}

pub fn encode(doc: &Portable) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let bytes = serde_json::to_vec_pretty(doc)
        .map_err(|_| VaultError::Corrupt("the export could not be encoded"))?;
    Ok(Zeroizing::new(bytes))
}

pub fn decode(bytes: &[u8]) -> Result<Portable, VaultError> {
    let doc: Portable = serde_json::from_slice(bytes)
        .map_err(|_| VaultError::NotAnExport("it is not valid JSON"))?;
    if doc.format != FORMAT {
        return Err(VaultError::NotAnExport("the format marker does not match"));
    }
    for entry in &doc.entries {
        entry.validate()?;
    }
    Ok(doc)
}

pub fn write(path: &Path, doc: &Portable) -> Result<(), VaultError> {
    let bytes = encode(doc)?;

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| VaultError::Io(format!("cannot create {}: {e}", path.display())))?;
    file.write_all(&bytes)
        .map_err(|e| VaultError::Io(format!("cannot write {}: {e}", path.display())))?;
    file.sync_all()
        .map_err(|e| VaultError::Io(format!("cannot flush {}: {e}", path.display())))?;
    drop(file);

    restrict_to_owner(path)
}

pub fn read(path: &Path) -> Result<Portable, VaultError> {
    let bytes = Zeroizing::new(
        fs::read(path)
            .map_err(|e| VaultError::Io(format!("cannot read {}: {e}", path.display())))?,
    );
    decode(&bytes)
}

impl Vault {
    #[must_use]
    pub fn export(&self) -> Portable {
        Portable {
            format: FORMAT.to_owned(),
            exported_at: OffsetDateTime::now_utc(),
            vault_id: self.id(),
            entries: self.entries().to_vec(),
        }
    }

    pub fn import(&mut self, doc: Portable) -> Result<ImportReport, VaultError> {
        let mut report = ImportReport::default();

        for mut entry in doc.entries {
            entry.validate()?;
            if self.get(entry.id).is_some() {
                entry.id = Uuid::new_v4();
                report.renumbered += 1;
            }
            self.add(entry)?;
            report.added += 1;
        }

        Ok(report)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{entry::EntryKind, secret::SecretString, totp::Totp, CustomField};
    use obscura_crypto::KdfParams;

    const FAST: KdfParams = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 2,
        p_cost: 1,
    };

    const URI: &str = "otpauth://totp/GitHub:saheb?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";

    fn loaded() -> Vault {
        let mut vault = Vault::create(b"correct horse battery staple", FAST).unwrap();

        let mut github = Entry::new_login("GitHub", "saheb");
        github.set_password("first-secret");
        github.urls = vec![
            "https://github.com".to_owned(),
            "https://gist.github.com".to_owned(),
        ];
        github.tags = vec!["work".to_owned(), "code".to_owned()];
        github.totp = Some(Totp::from_uri(URI).unwrap());
        github.notes = SecretString::from("recovery codes are in the safe");
        github.favorite = true;
        github.custom_fields = vec![CustomField {
            name: "PIN".to_owned(),
            value: SecretString::from("4821"),
            hidden: true,
        }];
        vault.add(github).unwrap();

        let mut passport = Entry::new_login("Passport", "");
        passport.kind = EntryKind::Identity;
        passport.notes = SecretString::from("expires 2031");
        vault.add(passport).unwrap();

        vault
    }

    fn scratch() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("obscura-export-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn an_export_keeps_every_field_the_vault_holds() {
        let source = loaded();
        let doc = source.export();

        let mut empty = Vault::create(b"another password entirely", FAST).unwrap();
        let report = empty.import(doc).unwrap();

        assert_eq!(report.added, 2);
        assert_eq!(report.renumbered, 0);
        assert_eq!(
            empty.entries(),
            source.entries(),
            "an export that loses a field is a trapdoor - it has to carry ids, timestamps, \
             tags, custom fields and the TOTP secret, or restoring from it quietly costs you data"
        );
    }

    #[test]
    fn a_document_survives_the_round_trip_through_bytes() {
        let source = loaded();
        let bytes = encode(&source.export()).unwrap();
        let doc = decode(&bytes).unwrap();

        let mut empty = Vault::create(b"another password entirely", FAST).unwrap();
        empty.import(doc).unwrap();
        assert_eq!(empty.entries(), source.entries());
    }

    #[test]
    fn a_file_survives_the_round_trip_and_is_owner_only() {
        let dir = scratch();
        let path = dir.join("backup.json");

        let source = loaded();
        write(&path, &source.export()).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "a plaintext export is every password in the clear - it must not be readable \
                 by other accounts on the machine"
            );
        }

        let mut empty = Vault::create(b"another password entirely", FAST).unwrap();
        empty.import(read(&path).unwrap()).unwrap();
        assert_eq!(empty.entries(), source.entries());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn importing_into_the_same_vault_never_overwrites_an_entry() {
        let mut vault = loaded();
        let doc = vault.export();

        let report = vault.import(doc).unwrap();

        assert_eq!(report.added, 2);
        assert_eq!(
            report.renumbered, 2,
            "every id already existed, so each one has to be renumbered rather than replacing \
             the entry that holds it"
        );
        assert_eq!(vault.len(), 4);
    }

    #[test]
    fn a_file_that_is_not_an_export_is_refused() {
        assert!(decode(b"").is_err());
        assert!(decode(b"{}").is_err());
        assert!(decode(b"not json at all").is_err());

        let wrong = br#"{"format":"something.else","exportedAt":"2026-01-01T00:00:00Z","vaultId":"8f1c0000-0000-0000-0000-000000000001","entries":[]}"#;
        assert_eq!(
            decode(wrong).unwrap_err(),
            VaultError::NotAnExport("the format marker does not match")
        );
    }

    #[test]
    fn an_export_carrying_an_oversized_entry_is_refused_whole() {
        let mut huge = Entry::new_login("Huge", "");
        huge.title = "x".repeat(crate::entry::MAX_FIELD_LEN + 1);

        let doc = Portable {
            format: FORMAT.to_owned(),
            exported_at: OffsetDateTime::now_utc(),
            vault_id: Uuid::new_v4(),
            entries: vec![Entry::new_login("Fine", "someone"), huge],
        };
        let bytes = encode(&doc).unwrap();

        assert!(
            decode(&bytes).is_err(),
            "a malformed export must be refused before any of it reaches the vault"
        );

        let mut vault = Vault::create(b"another password entirely", FAST).unwrap();
        assert!(vault.import(doc).is_err());
    }
}
