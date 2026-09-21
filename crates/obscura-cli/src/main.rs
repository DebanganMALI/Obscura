#![forbid(unsafe_code)]

mod args;
mod banner;
mod prompt;
mod tui;

use std::env;
use std::iter;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use obscura_vault::{Credential, Entry, Vault};

use args::{Command, USAGE};

const IDLE: Duration = Duration::from_secs(300);

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
            banner::show();
            print!("{USAGE}");
            Ok(())
        }
        Command::Version => {
            banner::show();
            println!("obscura {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Browse => {
            let vault = open(parsed.vault)?;
            browse(&vault)
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

    banner::show();
    banner::vault(&path);

    let password = prompt::master_password().context("reading the master password")?;
    let vault = Vault::open(&path, &Credential::Password(password.as_bytes()), None)
        .with_context(|| format!("opening {}", path.display()))?;

    banner::opened(vault.entries().len());
    Ok(vault)
}

pub(crate) fn ordered<'v>(vault: &'v Vault, query: Option<&str>) -> Vec<&'v Entry> {
    let mut found: Vec<&Entry> = match query {
        Some(text) if !text.is_empty() => vault.search(text),
        _ => vault.entries().iter().collect(),
    };
    found.sort_by(|a, b| {
        b.favorite
            .cmp(&a.favorite)
            .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
    });
    found
}

fn browse(vault: &Vault) -> Result<()> {
    match tui::run(vault, IDLE)? {
        tui::Outcome::Quit => banner::note(" closed."),
        tui::Outcome::Locked => banner::warn(" locked after five minutes idle."),
    }
    Ok(())
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
    let entries = ordered(vault, query);

    if entries.is_empty() {
        banner::note(" nothing matches.");
        return;
    }

    let width = entries
        .iter()
        .map(|entry| entry.title.chars().count())
        .max()
        .unwrap_or(0);

    for entry in entries {
        if banner::out_coloured() {
            banner::out_paint(banner::BONE, &format!("  {:width$}", entry.title));
            banner::out_paint(banner::DIM, &format!("  {}", entry.username));
            println!();
        } else {
            let line = format!("{:width$}  {}", entry.title, entry.username);
            println!("{}", line.trim_end());
        }
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
    banner::note(&format!(" {remaining}s remaining"));
    Ok(())
}
