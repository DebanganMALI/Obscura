#![forbid(unsafe_code)]

mod args;
mod prompt;

use std::env;
use std::iter;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use obscura_vault::{Credential, Entry, Vault};

use args::{Command, USAGE};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("obscura: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let parsed = args::parse(env::args().skip(1))
        .map_err(|message| anyhow!("{message}\ntry obscura --help"))?;

    match parsed.command {
        Command::Help => {
            print!("{USAGE}");
            Ok(())
        }
        Command::Version => {
            println!("obscura {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::List { query } => {
            list(&open(parsed.vault)?, query.as_deref());
            Ok(())
        }
        Command::Get { query } => get(&open(parsed.vault)?, &query),
        Command::Totp { query } => totp(&open(parsed.vault)?, &query),
    }
}

fn locate(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    match env::var_os("OBSCURA_VAULT") {
        Some(value) if !value.is_empty() => Ok(PathBuf::from(value)),
        _ => Err(anyhow!(
            "no vault given: pass --vault <PATH> or set OBSCURA_VAULT"
        )),
    }
}

fn open(explicit: Option<PathBuf>) -> Result<Vault> {
    let path = locate(explicit)?;
    if !path.is_file() {
        return Err(anyhow!("{} is not a file", path.display()));
    }
    let password = prompt::master_password().context("reading the master password")?;
    Vault::open(&path, &Credential::Password(password.as_bytes()), None)
        .with_context(|| format!("opening {}", path.display()))
}

fn describe(entry: &Entry) -> String {
    if entry.username.is_empty() {
        entry.title.clone()
    } else {
        format!("{} ({})", entry.title, entry.username)
    }
}

fn matching<'a>(vault: &'a Vault, query: &str) -> Result<&'a Entry> {
    let mut found = vault.search(query).into_iter();
    let Some(first) = found.next() else {
        return Err(anyhow!("nothing in the vault matches {query}"));
    };
    let others: Vec<&Entry> = found.collect();
    if others.is_empty() {
        return Ok(first);
    }

    let mut message = format!("{query} matches {} entries:", others.len() + 1);
    for entry in iter::once(first).chain(others) {
        message.push_str("\n    ");
        message.push_str(&describe(entry));
    }
    message.push_str("\nnarrow the search until it matches one");
    Err(anyhow!("{message}"))
}

fn list(vault: &Vault, query: Option<&str>) {
    let entries: Vec<&Entry> = match query {
        Some(text) => vault.search(text),
        None => vault.entries().iter().collect(),
    };

    if entries.is_empty() {
        eprintln!("no entries");
        return;
    }

    let width = entries
        .iter()
        .map(|entry| entry.title.chars().count())
        .max()
        .unwrap_or(0);

    for entry in entries {
        let line = format!("{:width$}  {}", entry.title, entry.username);
        println!("{}", line.trim_end());
    }
}

fn get(vault: &Vault, query: &str) -> Result<()> {
    let entry = matching(vault, query)?;
    println!("{}", entry.password.expose());
    Ok(())
}

fn totp(vault: &Vault, query: &str) -> Result<()> {
    let entry = matching(vault, query)?;
    let Some(totp) = entry.totp.as_ref() else {
        return Err(anyhow!("{} has no one time code", entry.title));
    };
    let (code, remaining) = totp.current()?;
    println!("{code}");
    eprintln!("{remaining}s remaining");
    Ok(())
}
