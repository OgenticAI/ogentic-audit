//! Clap-derive structure for the `ogentic-audit` CLI.

use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

/// Top-level CLI parser.
#[derive(Debug, Parser)]
#[command(
    name = "ogentic-audit",
    version,
    about = "Verify, inspect, and export tamper-evident audit logs",
    long_about = "\
Verify, inspect, and export tamper-evident audit logs produced by \
the ogentic-audit library.

Daily-driver subcommands:

  ogentic-audit verify <log_dir>          # exit 0 verified, 1 violation
  ogentic-audit head   <log_dir>          # print chain head hash + summary
  ogentic-audit show   <log_dir>          # pretty-print records

Exit codes:
  0  success
  1  verification failed (chain break / tamper)
  2  I/O error (missing log, permission denied)
  3  argument / config error
 64  reserved (sysexits.h EX_USAGE — emitted by clap on bad invocation)
",
    after_long_help = "\
Examples:

  # Verify a vault's audit log under the default key source
  ogentic-audit verify ~/.local/share/sotto/audit/

  # Pretty-print the last 100 records of a log as JSON
  ogentic-audit show ./logs --from 0 --to 100 --format json

  # Show the chain head fingerprint for the human audit story
  ogentic-audit head ./logs
"
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,
    #[command(subcommand)]
    pub command: Command,
}

/// Global flags that apply to every subcommand.
#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// Where to load the signing key from.
    #[arg(
        long,
        value_enum,
        global = true,
        default_value_t = KeySource::Env,
        help = "How to load the signing key (keychain | file | env)",
    )]
    pub key_source: KeySource,

    /// Macros service name when `--key-source=keychain`. Ignored otherwise.
    #[arg(long, global = true, default_value = "ogentic-audit")]
    pub keychain_service: String,

    /// Account name when `--key-source=keychain`. Ignored otherwise.
    #[arg(long, global = true, default_value = "default")]
    pub keychain_account: String,

    /// Path to a 32-byte raw key file (hex or binary; 64 hex chars
    /// without whitespace counts as hex). Required with
    /// `--key-source=file`.
    #[arg(long, global = true)]
    pub key_file: Option<PathBuf>,

    /// Environment variable holding the 64-char hex key. Used with
    /// `--key-source=env`; defaults to `OGENTIC_AUDIT_KEY_HEX`.
    #[arg(long, global = true, default_value = "OGENTIC_AUDIT_KEY_HEX")]
    pub key_env: String,

    /// Suppress non-essential output. Errors still go to stderr.
    #[arg(short = 'q', long, global = true, action = ArgAction::SetTrue)]
    pub quiet: bool,
}

/// How to load the signing key.
#[derive(Debug, Copy, Clone, ValueEnum, PartialEq, Eq)]
pub enum KeySource {
    /// macOS Keychain via the `ogentic-audit-keychain` crate.
    Keychain,
    /// Raw key bytes from a file.
    File,
    /// Hex-encoded key from an environment variable.
    Env,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Verify the chain integrity of an audit log.
    ///
    /// Exits 0 on Verified, 1 on any violation. Prints a structured
    /// report to stdout (text by default, JSON with `--format json`).
    #[command(after_long_help = "\
Examples:

  ogentic-audit verify ./logs                           # text report
  ogentic-audit verify ./logs --format json             # machine-readable
  ogentic-audit verify ./logs --forensic                # do not stop at first violation
")]
    Verify(VerifyArgs),

    /// Pretty-print records from an audit log.
    #[command(after_long_help = "\
Examples:

  ogentic-audit show ./logs                           # all records, text
  ogentic-audit show ./logs --from 0 --to 100         # first 100 records
  ogentic-audit show ./logs --format json             # JSON stream
")]
    Show(ShowArgs),

    /// Print the chain head fingerprint + record/segment summary.
    Head(HeadArgs),

    /// Export the log as a court-ready PDF (tracked in OGE-438).
    Export(ExportArgs),

    /// Print the binary version + on-disk format version.
    Version,
}

/// Output format selector shared between `verify` and `show`.
#[derive(Debug, Copy, Clone, ValueEnum, Default, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable plain text (no color when stdout is not a TTY).
    #[default]
    Text,
    /// Machine-readable JSON.
    Json,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Directory containing the `audit-NNNN.cbor` segment files.
    pub log_dir: PathBuf,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
    /// Continue scanning past the first violation and report every
    /// failure (R3's `VerifyOptions::forensic_mode`).
    #[arg(long, action = ArgAction::SetTrue)]
    pub forensic: bool,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    /// Directory containing the `audit-NNNN.cbor` segment files.
    pub log_dir: PathBuf,
    /// Inclusive lower bound on `record_id` within the segment. If
    /// unset, starts at record 0 of segment 0.
    #[arg(long)]
    pub from: Option<u64>,
    /// Exclusive upper bound on `record_id` within the segment. If
    /// unset, runs to EOF.
    #[arg(long)]
    pub to: Option<u64>,
    /// Actor filter (substring match).
    #[arg(long)]
    pub actor: Option<String>,
    /// Event filter (glob; supports `*` and `?`).
    #[arg(long = "event-glob")]
    pub event_glob: Option<String>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct HeadArgs {
    /// Directory containing the `audit-NNNN.cbor` segment files.
    pub log_dir: PathBuf,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Directory containing the `audit-NNNN.cbor` segment files.
    pub log_dir: PathBuf,
    /// Output PDF path.
    #[arg(long)]
    pub pdf: PathBuf,
    /// Override the "Generated" timestamp on the cover (RFC 3339
    /// string). Default is `1970-01-01T00:00:00Z` for bit-
    /// reproducibility; pass the actual generation time for real
    /// court submissions.
    #[arg(long)]
    pub source_date: Option<String>,
    /// Custodian name on the cover. Defaults to the value of
    /// `HOSTNAME` / `COMPUTERNAME`, or `(unknown host)`.
    #[arg(long)]
    pub custodian: Option<String>,
    /// Include every record in the sample-events section instead of
    /// just head 50 + tail 50.
    #[arg(long, action = ArgAction::SetTrue)]
    pub full: bool,
}
