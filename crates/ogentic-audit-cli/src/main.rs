use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "ogentic-audit",
    version,
    about = "Verify, inspect, and export tamper-evident audit logs"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the on-disk format version this binary implements.
    Version,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => {
            println!(
                "ogentic-audit {}  format v{:#06x}",
                ogentic_audit_core::VERSION,
                ogentic_audit_core::FORMAT_VERSION
            );
        },
    }
    Ok(())
}
