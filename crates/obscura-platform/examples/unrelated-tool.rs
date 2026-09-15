#![allow(clippy::print_stdout, clippy::print_stderr)]

use obscura_platform::{hello, PlatformError};

fn main() {
    let mut args = std::env::args().skip(1);
    let mut name = String::new();
    let mut delete = false;

    for arg in args.by_ref() {
        if arg == "--delete" {
            delete = true;
        } else if name.is_empty() {
            name = arg;
        }
    }

    if name.is_empty() {
        eprintln!("usage: unrelated-tool <credential-name> [--delete]");
        eprintln!();
        eprintln!("The credential name is the one Obscura printed, for example:");
        eprintln!("  Obscura/isolation-0000-0000-0000-000000000000");
        std::process::exit(2);
    }

    println!("A program that is not Obscura\n");
    println!("process:     {}", program_name());
    println!("credential:  {name}");
    println!();

    match hello::public_fingerprint_by_name(&name) {
        Ok(print) => {
            println!("open:        SUCCEEDED");
            println!("public key:  {print}");
            println!();
            println!("This process opened a credential it did not create, and read its");
            println!("public key, without a single prompt. If that fingerprint matches the");
            println!("one Obscura showed, the credential is scoped to the Windows account");
            println!("and not to the application - so a hardware slot must not be able to");
            println!("open the vault on its own.");
        }
        Err(PlatformError::CredentialMissing) => {
            println!("open:        NotFound");
            println!();
            println!("This process cannot see Obscura's credential at all. That is the");
            println!("good answer: Hello credentials are scoped per application, and a");
            println!("hardware slot is as private as it needs to be.");
            println!();
            println!("Worth confirming the name is exactly the one Obscura printed - a");
            println!("typo produces this same result.");
        }
        Err(PlatformError::Unsupported) => {
            println!("open:        unsupported - this build has no Windows Hello backend.");
            println!();
            println!("Run this on Windows.");
        }
        Err(e) => {
            println!("open:        FAILED - {e}");
            println!();
            println!("Neither answer. Please send this line along with the fingerprint");
            println!("Obscura printed.");
        }
    }

    if delete {
        println!();
        match hello::forget_by_name(&name) {
            Ok(()) => println!("delete:      requested (no error reported)"),
            Err(e) => println!("delete:      FAILED - {e}"),
        }
        match hello::public_fingerprint_by_name(&name) {
            Err(PlatformError::CredentialMissing) => {
                println!("verify:      gone - an unrelated process deleted it.");
            }
            Ok(_) => println!("verify:      still there - the delete did not take effect."),
            Err(e) => println!("verify:      inconclusive - {e}"),
        }
    }
}

fn program_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "unknown".to_owned())
}
