use std::path::PathBuf;

pub const USAGE: &str = "obscura - command line access to an Obscura vault

USAGE
    obscura [OPTIONS] <COMMAND>

COMMANDS
    list [QUERY]      list matching entries by title and username
    get <QUERY>       print the password of the one matching entry
    totp <QUERY>      print the current one time code of the one matching entry

OPTIONS
    --vault <PATH>    the vault file to open, otherwise OBSCURA_VAULT
    -h, --help        print this message
    -V, --version     print the version

The master password is never taken as an argument. It is read from the
terminal without echo, or from standard input when standard input is not a
terminal, so it never reaches the process list or the shell history.

A query that matches more than one entry is an error, never a guess.
";

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    List { query: Option<String> },
    Get { query: String },
    Totp { query: String },
    Help,
    Version,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Parsed {
    pub command: Command,
    pub vault: Option<PathBuf>,
}

pub fn parse<I>(argv: I) -> Result<Parsed, String>
where
    I: IntoIterator<Item = String>,
{
    let mut vault: Option<PathBuf> = None;
    let mut words: Vec<String> = Vec::new();
    let mut argv = argv.into_iter();

    while let Some(arg) = argv.next() {
        if arg == "--vault" {
            let Some(path) = argv.next() else {
                return Err("--vault needs a path".to_owned());
            };
            vault = Some(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--vault=") {
            vault = Some(PathBuf::from(path));
        } else if arg == "-h" || arg == "--help" {
            return Ok(Parsed {
                command: Command::Help,
                vault,
            });
        } else if arg == "-V" || arg == "--version" {
            return Ok(Parsed {
                command: Command::Version,
                vault,
            });
        } else if arg.starts_with('-') && arg != "-" {
            return Err(format!("unknown option {arg}"));
        } else {
            words.push(arg);
        }
    }

    let mut words = words.into_iter();
    let Some(name) = words.next() else {
        return Ok(Parsed {
            command: Command::Help,
            vault,
        });
    };

    let command = match name.as_str() {
        "list" => Command::List {
            query: words.next(),
        },
        "get" => Command::Get {
            query: wanted(words.next(), "get")?,
        },
        "totp" => Command::Totp {
            query: wanted(words.next(), "totp")?,
        },
        "help" => Command::Help,
        "version" => Command::Version,
        other => return Err(format!("unknown command {other}")),
    };

    if let Some(extra) = words.next() {
        return Err(format!("unexpected argument {extra}"));
    }

    Ok(Parsed { command, vault })
}

fn wanted(value: Option<String>, command: &str) -> Result<String, String> {
    value.ok_or_else(|| format!("{command} needs something to search for"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(argv: &[&str]) -> Result<Parsed, String> {
        parse(argv.iter().map(|word| (*word).to_owned()))
    }

    #[test]
    fn a_bare_invocation_asks_for_help() {
        assert_eq!(
            parsed(&[]),
            Ok(Parsed {
                command: Command::Help,
                vault: None
            })
        );
    }

    #[test]
    fn get_needs_something_to_search_for() {
        assert_eq!(
            parsed(&["get"]),
            Err("get needs something to search for".to_owned())
        );
    }

    #[test]
    fn list_does_not_need_anything_to_search_for() {
        assert_eq!(
            parsed(&["list"]),
            Ok(Parsed {
                command: Command::List { query: None },
                vault: None
            })
        );
    }

    #[test]
    fn the_vault_can_be_given_as_one_word_or_two() {
        let two = parsed(&["--vault", "D:\\v.obscura", "list"]);
        let one = parsed(&["--vault=D:\\v.obscura", "list"]);
        assert_eq!(two, one);
        assert_eq!(
            two,
            Ok(Parsed {
                command: Command::List { query: None },
                vault: Some(PathBuf::from("D:\\v.obscura")),
            })
        );
    }

    #[test]
    fn an_option_that_is_not_ours_is_refused() {
        assert_eq!(
            parsed(&["--colour", "list"]),
            Err("unknown option --colour".to_owned())
        );
    }

    #[test]
    fn a_second_search_term_is_refused_rather_than_ignored() {
        assert_eq!(
            parsed(&["get", "github", "gitlab"]),
            Err("unexpected argument gitlab".to_owned())
        );
    }

    #[test]
    fn a_dash_on_its_own_is_a_search_term_not_an_option() {
        assert_eq!(
            parsed(&["get", "-"]),
            Ok(Parsed {
                command: Command::Get {
                    query: "-".to_owned()
                },
                vault: None,
            })
        );
    }

    #[test]
    fn help_wins_even_when_a_command_follows_it() {
        assert_eq!(
            parsed(&["--help", "get", "github"]),
            Ok(Parsed {
                command: Command::Help,
                vault: None
            })
        );
    }
}
