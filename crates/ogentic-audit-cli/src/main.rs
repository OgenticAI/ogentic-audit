//! `ogentic-audit` — CLI for inspecting and verifying audit logs.
//!
//! Subcommand layout matches `docs/spec/v0.1.md` §CLI. Exit codes are
//! disciplined so CI scripts can branch on outcome.
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0 | Verified / success |
//! | 1 | Verification failed (altered, missing, added, untrusted signer) |
//! | 2 | I/O error (missing log, permissions, no segments) |
//! | 3 | Argument / input error |
//! | 4 | Not verified: no key supplied, or nothing signed (signed mode) |
//! | 64 | Usage error (sysexits.h `EX_USAGE`) from the argument parser |
//!
//! [OGE-435]: https://linear.app/ogenticai/issue/OGE-435
//! [OGE-436]: https://linear.app/ogenticai/issue/OGE-436

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

mod checkpoint_file;
mod cli;
mod commands;
mod exit;
mod keysource;
mod output;
mod pdf;
mod signedargs;

use std::process::ExitCode;

use clap::Parser as _;

use crate::cli::{Cli, Command};
use crate::exit::ExitCodeKind;

fn main() -> ExitCode {
    // Parser errors are usage errors (64), not I/O errors (clap's own
    // default, 2). Help and version print and exit 0.
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return match e.kind() {
                clap::error::ErrorKind::DisplayHelp
                | clap::error::ErrorKind::DisplayVersion
                | clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
                    ExitCode::SUCCESS
                },
                _ => ExitCodeKind::Usage.into(),
            };
        },
    };
    let result = match cli.command {
        Command::Verify(args) => commands::verify::run(&cli.global, args),
        Command::VerifyRelease(args) => commands::verify_release::run(&cli.global, args),
        Command::Witness(args) => commands::witness::run(&cli.global, args),
        Command::Key(cmd) => commands::key::run(&cli.global, cmd),
        Command::Keygen(args) => commands::key::generate(&cli.global, args),
        Command::ExportPublicKey(args) => commands::key::export(args),
        Command::Show(args) => commands::show::run(&cli.global, args),
        Command::Head(args) => commands::head::run(&cli.global, args),
        Command::Checkpoint(args) => commands::checkpoint::run(&cli.global, args),
        Command::Export(args) => commands::export::run(&cli.global, args),
        Command::Version => {
            commands::version::run();
            Ok(ExitCodeKind::Success)
        },
    };

    match result {
        Ok(kind) => kind.into(),
        Err(err) => {
            eprintln!("error: {err:#}");
            err.exit_code().into()
        },
    }
}
