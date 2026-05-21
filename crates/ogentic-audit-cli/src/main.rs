//! `ogentic-audit` — CLI for inspecting and verifying audit logs.
//!
//! Subcommand layout matches `docs/spec/v0.1.md` §CLI. Exit codes are
//! disciplined so CI scripts can branch on outcome.
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0 | Success |
//! | 1 | Verification failed (chain break / tamper) |
//! | 2 | I/O error (missing log, permissions) |
//! | 3 | Argument / config error |
//! | 64 | Reserved (sysexits.h `EX_USAGE`) |
//!
//! [OGE-435]: https://linear.app/ogenticai/issue/OGE-435
//! [OGE-436]: https://linear.app/ogenticai/issue/OGE-436

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

mod cli;
mod commands;
mod exit;
mod keysource;
mod output;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::exit::ExitCodeKind;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Verify(args) => commands::verify::run(&cli.global, args),
        Command::Show(args) => commands::show::run(&cli.global, args),
        Command::Head(args) => commands::head::run(&cli.global, args),
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
