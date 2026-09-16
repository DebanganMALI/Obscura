use std::collections::BTreeMap;

use crate::{
    entry::{Entry, EntryKind},
    error::VaultError,
    secret::SecretString,
    totp::{Totp, TotpAlgorithm},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Bitwarden,
    Chrome,
    Firefox,
}

impl Source {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Bitwarden => "Bitwarden",
            Self::Chrome => "Chrome or Edge",
            Self::Firefox => "Firefox",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CsvNotes {
    pub skipped_blank: usize,
    pub skipped_invalid: usize,
    pub totp_dropped: usize,
}

type Columns = BTreeMap<String, usize>;

fn columns(headers: &csv::StringRecord) -> Columns {
    headers
        .iter()
        .enumerate()
        .map(|(at, name)| (name.trim().to_lowercase(), at))
        .collect()
}

fn detect(found: &Columns) -> Option<Source> {
    let has = |name: &str| found.contains_key(name);

    if has("login_password") || has("login_username") {
        return Some(Source::Bitwarden);
    }
    if has("password") && has("url") && has("name") {
        return Some(Source::Chrome);
    }
    if has("password") && has("url") && has("username") {
        return Some(Source::Firefox);
    }
    None
}

fn field(row: &csv::StringRecord, found: &Columns, name: &str) -> String {
    found
        .get(name)
        .and_then(|at| row.get(*at))
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn totp_from(value: &str, notes: &mut CsvNotes) -> Option<Totp> {
    if value.is_empty() {
        return None;
    }
    let parsed = if value.starts_with("otpauth://") {
        Totp::from_uri(value)
    } else {
        Totp::from_base32(&value.replace(' ', ""), TotpAlgorithm::Sha1, 6, 30)
    };
    if let Ok(totp) = parsed {
        return Some(totp);
    }
    notes.totp_dropped += 1;
    None
}

fn addresses(value: &str) -> Vec<String> {
    value
        .split(['\n', ','])
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn bitwarden(row: &csv::StringRecord, found: &Columns, notes: &mut CsvNotes) -> Entry {
    let mut entry = Entry::new_login(
        field(row, found, "name"),
        field(row, found, "login_username"),
    );
    entry.kind = match field(row, found, "type").as_str() {
        "note" | "securenote" => EntryKind::Note,
        "card" => EntryKind::Card,
        "identity" => EntryKind::Identity,
        _ => EntryKind::Login,
    };
    entry.password = SecretString::from(field(row, found, "login_password").as_str());
    entry.urls = addresses(&field(row, found, "login_uri"));
    entry.notes = SecretString::from(field(row, found, "notes").as_str());
    entry.favorite = field(row, found, "favorite") == "1";
    entry.totp = totp_from(&field(row, found, "login_totp"), notes);

    let folder = field(row, found, "folder");
    if !folder.is_empty() {
        entry.tags.push(folder);
    }
    entry
}

fn chrome(row: &csv::StringRecord, found: &Columns) -> Entry {
    let mut entry = Entry::new_login(field(row, found, "name"), field(row, found, "username"));
    entry.password = SecretString::from(field(row, found, "password").as_str());
    entry.urls = addresses(&field(row, found, "url"));
    entry.notes = SecretString::from(field(row, found, "note").as_str());
    entry
}

fn firefox(row: &csv::StringRecord, found: &Columns) -> Entry {
    let address = field(row, found, "url");
    let title = address
        .rsplit("://")
        .next()
        .unwrap_or(&address)
        .trim_end_matches('/')
        .to_owned();

    let mut entry = Entry::new_login(title, field(row, found, "username"));
    entry.password = SecretString::from(field(row, found, "password").as_str());
    entry.urls = addresses(&address);
    entry
}

pub fn parse(bytes: &[u8]) -> Result<(Source, Vec<Entry>, CsvNotes), VaultError> {
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_reader(bytes);

    let headers = reader
        .headers()
        .map_err(|_| VaultError::NotAnExport("the first line is not a readable CSV header"))?
        .clone();
    let found = columns(&headers);

    let source = detect(&found).ok_or(VaultError::NotAnExport(
        "the columns do not match a Bitwarden, Chrome, Edge or Firefox export",
    ))?;

    let mut notes = CsvNotes::default();
    let mut entries = Vec::new();

    for row in reader.records() {
        let Ok(row) = row else {
            notes.skipped_invalid += 1;
            continue;
        };

        let entry = match source {
            Source::Bitwarden => bitwarden(&row, &found, &mut notes),
            Source::Chrome => chrome(&row, &found),
            Source::Firefox => firefox(&row, &found),
        };

        if entry.title.is_empty() && entry.password.is_empty() && entry.urls.is_empty() {
            notes.skipped_blank += 1;
            continue;
        }
        if entry.validate().is_err() {
            notes.skipped_invalid += 1;
            continue;
        }
        entries.push(entry);
    }

    Ok((source, entries, notes))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const BITWARDEN: &str = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
        Work,1,login,GitHub,\"line one\nline two\",,0,\"https://github.com,https://gist.github.com\",saheb,\"p,a\"\"ss\",JBSWY3DPEHPK3PXP\n\
        ,0,note,Passport,expires 2031,,0,,,,\n";

    const CHROME: &str = "name,url,username,password,note\n\
        github.com,https://github.com/login,saheb,hunter2,some note\n";

    const FIREFOX: &str =
        "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\"\n\
        \"https://example.org/\",\"saheb\",\"hunter2\",,,\"{abc}\"\n";

    #[test]
    fn a_bitwarden_export_keeps_what_bitwarden_stores() {
        let (source, entries, notes) = parse(BITWARDEN.as_bytes()).unwrap();

        assert_eq!(source, Source::Bitwarden);
        assert_eq!(entries.len(), 2);
        assert_eq!(notes, CsvNotes::default());

        let github = &entries[0];
        assert_eq!(github.title, "GitHub");
        assert_eq!(github.username, "saheb");
        assert_eq!(
            github.password.expose(),
            "p,a\"ss",
            "a password holding a comma and a quote is exactly what a hand-rolled reader \
             truncates, and the user would never know which character went missing"
        );
        assert_eq!(github.notes.expose(), "line one\nline two");
        assert_eq!(github.urls.len(), 2);
        assert_eq!(github.tags, vec!["Work".to_owned()]);
        assert!(github.favorite);
        assert!(github.totp.is_some());

        assert_eq!(entries[1].kind, EntryKind::Note);
        assert!(!entries[1].favorite);
    }

    #[test]
    fn a_chrome_export_is_recognised_by_its_columns() {
        let (source, entries, _) = parse(CHROME.as_bytes()).unwrap();
        assert_eq!(source, Source::Chrome);
        assert_eq!(entries[0].title, "github.com");
        assert_eq!(entries[0].password.expose(), "hunter2");
        assert_eq!(entries[0].notes.expose(), "some note");
    }

    #[test]
    fn a_firefox_export_gets_a_title_from_its_address() {
        let (source, entries, _) = parse(FIREFOX.as_bytes()).unwrap();
        assert_eq!(source, Source::Firefox);
        assert_eq!(entries[0].title, "example.org");
        assert_eq!(entries[0].urls, vec!["https://example.org/".to_owned()]);
    }

    #[test]
    fn a_file_with_unfamiliar_columns_is_refused_rather_than_guessed_at() {
        assert!(parse(b"alpha,beta,gamma\n1,2,3\n").is_err());
        assert!(parse(b"").is_err());
    }

    #[test]
    fn a_row_that_carries_nothing_is_counted_rather_than_imported() {
        let text = format!("{CHROME},,,,\n");
        let (_, entries, notes) = parse(text.as_bytes()).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(notes.skipped_blank, 1);
    }

    #[test]
    fn a_two_factor_secret_that_does_not_parse_is_reported_not_swallowed() {
        let text = BITWARDEN.replace("JBSWY3DPEHPK3PXP", "not-base32-at-all!!");
        let (_, entries, notes) = parse(text.as_bytes()).unwrap();

        assert_eq!(entries.len(), 2, "the entry itself still comes across");
        assert!(entries[0].totp.is_none());
        assert_eq!(
            notes.totp_dropped, 1,
            "dropping a code silently would let someone believe their two-factor seeds \
             made it over when they did not"
        );
    }
}
