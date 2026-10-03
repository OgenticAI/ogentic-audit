//! Clap-derive structure for the `ogentic-audit` CLI.

use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

/// Top-level CLI parser.
#[derive(Debug, Parser)]
#[command(
    name = "ogentic-audit",
    version,
    about = "Verify, inspect, and export tamper-evident audit logs and signed releases",
    long_about = "\
Verify, inspect, and export tamper-evident audit logs produced by \
the ogentic-audit library, and verify signed releases.

Two log formats:

  0x0002  signed (Ed25519). Anyone can verify with the signer's PUBLIC key,
          and nobody who verifies can forge. Pass the key you obtained from
          the signer with --public-key, --key-fingerprint or --trust.
  0x0001  HMAC-SHA256. Verifying needs the shared secret key, and whoever
          holds it could also have written the log. Pass the key explicitly
          with --key-source or --key-file.

The verifier reads the log's format before it loads any key, and never
uses a key you did not name on the command line.

Daily-driver subcommands:

  ogentic-audit verify <log_dir> --key-fingerprint <fp>   # signed log
  ogentic-audit verify-release <dir> --key-fingerprint <fp>
  ogentic-audit head   <log_dir>          # print chain head + summary
  ogentic-audit show   <log_dir>          # pretty-print records

Exit codes:
  0  verified
  1  verification failed: something was altered, removed, added, or is not
     signed by a trusted key
  2  I/O error (missing log, permission denied, no segment files)
  3  argument or input error (a malformed key, fingerprint, trust file,
     statement or checkpoint; a key of the wrong kind for this log)
  4  not verified: no key was supplied, or nothing was signed (signed
     logs and releases only). Not a failure of the log, not a success
 64  usage error (unknown flag, missing argument)
",
    after_long_help = "\
Examples:

  # A signed log, checked against the fingerprint the signer published
  ogentic-audit verify ./logs --key-fingerprint 6db5-e9b8-a1ba-ce1c-dd9a-7c6a-db9e-9396-acc5-0734-65d9-fe8e-3a0e-f6d9-c60d-6d4f

  # A signed release folder
  ogentic-audit verify-release ./release --public-key signer.pub

  # An HMAC log, with its key given explicitly
  ogentic-audit verify ./logs --key-source env
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
    /// Where to load an HMAC key (format 0x0001 logs only). There is no
    /// default: an HMAC key is used only when named here or with
    /// --key-file.
    #[arg(
        long,
        value_enum,
        global = true,
        help = "How to load an HMAC key for a format 0x0001 log (keychain | file | env). Never implied."
    )]
    pub key_source: Option<KeySource>,

    /// Service name when `--key-source=keychain`. Ignored otherwise.
    #[arg(long, global = true, default_value = "ogentic-audit")]
    pub keychain_service: String,

    /// Account name when `--key-source=keychain`. Ignored otherwise.
    #[arg(long, global = true, default_value = "default")]
    pub keychain_account: String,

    /// Path to a 32-byte raw HMAC key file (hex or binary). Implies
    /// `--key-source=file`.
    #[arg(long, global = true)]
    pub key_file: Option<PathBuf>,

    /// Environment variable holding the 64-char hex HMAC key, used with
    /// `--key-source=env`.
    #[arg(long, global = true, default_value = "OGENTIC_AUDIT_KEY_HEX")]
    pub key_env: String,

    /// Suppress non-essential output. Errors still go to stderr.
    #[arg(short = 'q', long, global = true, action = ArgAction::SetTrue)]
    pub quiet: bool,

    /// Use ASCII status marks instead of ✓ ✗ !.
    #[arg(
        long,
        global = true,
        action = ArgAction::SetTrue,
        help = "Print [OK] [FAILED] [!] instead of the ✓ ✗ ! marks (automatic on consoles that are not UTF-8)"
    )]
    pub ascii: bool,
}

impl GlobalArgs {
    /// Whether the caller named an HMAC key on the command line.
    #[must_use]
    pub fn hmac_key_given(&self) -> bool {
        self.key_source.is_some() || self.key_file.is_some()
    }
}

/// How to load an HMAC key.
#[derive(Debug, Copy, Clone, ValueEnum, PartialEq, Eq)]
pub enum KeySource {
    /// OS keychain via the `ogentic-audit-keychain` crate.
    Keychain,
    /// Raw key bytes from a file.
    File,
    /// Hex-encoded key from an environment variable.
    Env,
}

/// Pins and statements: what the verifier trusts. Obtain keys and
/// fingerprints from the signer, never from the artefact.
#[derive(Debug, Args, Default, Clone)]
pub struct TrustArgs {
    /// The signer's public key: a file, or the key itself (OpenSSH line,
    /// PEM, or 64 hex digits).
    #[arg(long, value_name = "FILE|KEY")]
    pub public_key: Option<String>,
    /// The signer's key fingerprint (64 hex digits in any grouping, or
    /// SHA256:…). Repeatable. Compared in full, by machine.
    #[arg(long, value_name = "FINGERPRINT")]
    pub key_fingerprint: Vec<String>,
    /// A trust file in OpenSSH allowed_signers format:
    /// `<principal> [namespaces="…"] ssh-ed25519 <base64>`.
    #[arg(long, value_name = "FILE")]
    pub trust: Option<PathBuf>,
    /// A directory of key statements (transitions, revocations).
    /// Repeatable.
    #[arg(long, value_name = "DIR")]
    pub statements: Vec<PathBuf>,
    /// A revocation statement published by the signer. Repeatable.
    #[arg(long, value_name = "FILE")]
    pub revocations: Vec<PathBuf>,
}

impl TrustArgs {
    /// Whether any signed-mode trust input was given.
    #[must_use]
    pub fn any(&self) -> bool {
        self.public_key.is_some()
            || !self.key_fingerprint.is_empty()
            || self.trust.is_some()
            || !self.statements.is_empty()
            || !self.revocations.is_empty()
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Verify an audit log (signed 0x0002 or HMAC 0x0001).
    ///
    /// Exits 0 verified, 1 violation, 2 I/O, 3 argument, 4 not verified
    /// (no key supplied, or nothing signed).
    #[command(after_long_help = "\
Examples:

  ogentic-audit verify ./logs --key-fingerprint <fp>    # signed log
  ogentic-audit verify ./logs --public-key signer.pub   # signed log
  ogentic-audit verify ./logs --trust allowed_signers   # signed log
  ogentic-audit verify ./logs --key-source env          # HMAC log
  ogentic-audit verify ./logs ... --format json         # machine-readable
  ogentic-audit verify ./logs ... --forensic            # every violation
  ogentic-audit verify ./logs ... --segment 0           # report on segment 0 only
  ogentic-audit verify ./logs ... --checkpoint cp.json  # also prove it extends a known head

A signed log verified without a key is at best \"Not verified\" (exit 4):
the records match their signatures, but anyone could have made them.

Without --checkpoint, verification shows the chain is consistent with
itself up to its last record. A checkpoint held by someone else is what
makes a rewrite or a cut visible.
")]
    Verify(VerifyArgs),

    /// Verify a signed release folder: the attestation's signature, every
    /// file, and every audit log in it.
    #[command(
        name = "verify-release",
        after_long_help = "\
Examples:

  ogentic-audit verify-release ./release --key-fingerprint <fp>
  ogentic-audit verify-release ./release --public-key signer.pub --format json

Every problem is listed, grouped as Altered, Missing, and Not covered by
the signature. Files the attestation does not list fail the check unless
--allow-unattested is given.
"
    )]
    VerifyRelease(VerifyReleaseArgs),

    /// Pretty-print records from an audit log (either format).
    #[command(after_long_help = "\
Examples:

  ogentic-audit show ./logs                           # all records, text
  ogentic-audit show ./logs --from 0 --to 100         # first 100 records
  ogentic-audit show ./logs --format json             # JSON stream
")]
    Show(ShowArgs),

    /// Print the chain head + record/segment summary (either format).
    Head(HeadArgs),

    /// Emit a checkpoint pinning the current chain head, for an
    /// external observer to store and later verify against.
    #[command(
        args_conflicts_with_subcommands = true,
        after_long_help = "\
Examples:

  ogentic-audit checkpoint ./logs --out cp.json                   # signed log, unsigned observation
  ogentic-audit checkpoint ./logs --out cp.json --sign keychain:svc:acct  # by the log's signer
  ogentic-audit checkpoint ./logs --out cp.json --key-source env  # HMAC log (v1 checkpoint)
  ogentic-audit checkpoint compare a.json b.json                  # prove equivocation

A checkpoint is the head observed now. Give it to a party that does not
control the log, and `verify --checkpoint` can later prove the log still
contains that history. A copy kept beside the log proves nothing.

The chain is verified before a checkpoint is emitted.
"
    )]
    Checkpoint(CheckpointArgs),

    /// Co-sign a checkpoint as a witness, with your own key and clock.
    Witness(WitnessArgs),

    /// Signing keys: generate, export the public key, fingerprint, and
    /// key statements (transition, accept, revoke, KRL).
    #[command(subcommand)]
    Key(KeyCommand),

    /// Same as `key generate`.
    Keygen(KeyGenerateArgs),

    /// Same as `key export`.
    #[command(name = "export-public-key")]
    ExportPublicKey(KeyExportArgs),

    /// Export the log as a court-ready PDF.
    Export(ExportArgs),

    /// Print the binary version + on-disk format versions.
    Version,
}

/// Output format selector.
#[derive(Debug, Copy, Clone, ValueEnum, Default, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable plain text.
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
    /// Emit a single-line verdict. Mutually exclusive with `--format json`.
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "format")]
    pub summary: bool,
    /// Continue scanning past the first violation and report every one.
    #[arg(long, action = ArgAction::SetTrue)]
    pub forensic: bool,
    /// Report only on segment N (0–65535). Every segment is still
    /// checked; this never improves the verdict. Exits 2 if the segment
    /// does not exist.
    #[arg(long)]
    pub segment: Option<u64>,
    /// A checkpoint file (and its `.sig`, if present beside it). Signed
    /// logs accept several; HMAC logs one.
    #[arg(long)]
    pub checkpoint: Vec<PathBuf>,
    /// A witness co-signature (and its `.sig`) for a supplied checkpoint.
    /// Repeatable.
    #[arg(long)]
    pub witness: Vec<PathBuf>,
    /// The log you mean: its 32-hex-digit log_id.
    #[arg(long, value_name = "LOG_ID")]
    pub expect_log_id: Option<String>,
    #[command(flatten)]
    pub trust: TrustArgs,
}

#[derive(Debug, Args)]
pub struct VerifyReleaseArgs {
    /// The release folder.
    pub release_dir: PathBuf,
    #[command(flatten)]
    pub trust: TrustArgs,
    /// A witness co-signature (and its `.sig`). Repeatable.
    #[arg(long)]
    pub witness: Vec<PathBuf>,
    /// The release you mean.
    #[arg(long, value_name = "ID")]
    pub expect_release_id: Option<String>,
    /// Report files the attestation does not list as warnings instead of
    /// failures.
    #[arg(long, action = ArgAction::SetTrue)]
    pub allow_unattested: bool,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct CheckpointArgs {
    #[command(subcommand)]
    pub sub: Option<CheckpointSub>,
    /// Directory containing the `audit-NNNN.cbor` segment files.
    pub log_dir: Option<PathBuf>,
    /// Write the checkpoint here instead of stdout (required with --sign;
    /// the signature goes to `<out>.sig`).
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Override `observed_at` (RFC 3339). For reproducible tests.
    #[arg(long)]
    pub observed_at: Option<String>,
    /// Signed logs: sign the checkpoint with the log's key
    /// (`keychain:<service>:<account>`, `file:<seed file>`, `env:<VAR>`).
    #[arg(long, value_name = "SIGNER")]
    pub sign: Option<String>,
    #[command(flatten)]
    pub trust: TrustArgs,
}

#[derive(Debug, Subcommand)]
pub enum CheckpointSub {
    /// Compare two signed checkpoints: two different heads at one
    /// position of one log, signed by one key, prove equivocation.
    Compare {
        /// First checkpoint (its `.sig` beside it).
        a: PathBuf,
        /// Second checkpoint (its `.sig` beside it).
        b: PathBuf,
    },
}

#[derive(Debug, Args)]
pub struct WitnessArgs {
    /// The checkpoint file to co-sign.
    pub checkpoint: PathBuf,
    /// The witness's signing key.
    #[arg(long, value_name = "SIGNER")]
    pub sign: String,
    /// Output file (its signature goes to `<out>.sig`).
    #[arg(long)]
    pub out: PathBuf,
    /// Override `observed_at` (RFC 3339 with milliseconds).
    #[arg(long)]
    pub observed_at: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Generate a signing key (never overwrites an existing one).
    Generate(KeyGenerateArgs),
    /// Export a public key (never a private key).
    Export(KeyExportArgs),
    /// Print a key's fingerprint in every form.
    Fingerprint(KeyFingerprintArgs),
    /// Sign a key transition (rotation) with the old key; with --new,
    /// also accept it with the new key.
    Transition(KeyTransitionArgs),
    /// Accept a transition as its new key.
    Accept(KeyAcceptArgs),
    /// Sign a revocation.
    Revoke(KeyRevokeArgs),
    /// Write an OpenSSH key revocation list (for `ssh-keygen -Y verify -r`).
    Krl(KeyKrlArgs),
}

#[derive(Debug, Args)]
pub struct KeyGenerateArgs {
    /// Where to keep it: `keychain:<service>:<account>` (recommended) or
    /// `file:<path>` (a hex seed file, mode 0600, for tests and CI).
    #[arg(long, value_name = "SIGNER")]
    pub signer: String,
}

/// Public-key export format.
#[derive(Debug, Copy, Clone, ValueEnum, Default, PartialEq, Eq)]
pub enum KeyFormat {
    /// `ssh-ed25519 AAAA… comment`.
    #[default]
    Openssh,
    /// PEM SubjectPublicKeyInfo.
    Pem,
    /// 64 hex digits.
    Hex,
}

#[derive(Debug, Args)]
pub struct KeyExportArgs {
    /// The signing key whose public half to export.
    #[arg(long, value_name = "SIGNER")]
    pub signer: String,
    /// Format.
    #[arg(long, value_enum, default_value_t = KeyFormat::Openssh)]
    pub format: KeyFormat,
    /// Comment for the OpenSSH form.
    #[arg(long, default_value = "ogentic-audit")]
    pub comment: String,
    /// Write here instead of stdout.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct KeyFingerprintArgs {
    /// A public key: file or text (OpenSSH, PEM, hex).
    #[arg(value_name = "FILE|KEY", required_unless_present = "signer")]
    pub key: Option<String>,
    /// Or a signing key's public half.
    #[arg(long, value_name = "SIGNER", conflicts_with = "key")]
    pub signer: Option<String>,
}

#[derive(Debug, Args)]
pub struct KeyTransitionArgs {
    /// The key being retired.
    #[arg(long, value_name = "SIGNER")]
    pub old: String,
    /// The successor's signing key (also signs the acceptance).
    #[arg(
        long,
        value_name = "SIGNER",
        required_unless_present = "new_public_key"
    )]
    pub new: Option<String>,
    /// Or only the successor's public key (it accepts later with `key accept`).
    #[arg(long, value_name = "FILE|KEY", conflicts_with = "new")]
    pub new_public_key: Option<String>,
    /// A log the old key signed (its last record is a final head). Repeatable.
    #[arg(long, value_name = "LOG_DIR")]
    pub final_head: Vec<PathBuf>,
    /// SHA-256 of a release attestation the old key signed. Repeatable.
    #[arg(long, value_name = "SHA256")]
    pub final_release: Vec<String>,
    /// Free-text reason.
    #[arg(long)]
    pub reason: Option<String>,
    /// Override `issued_at` (RFC 3339 with milliseconds).
    #[arg(long)]
    pub issued_at: Option<String>,
    /// Output directory.
    #[arg(long)]
    pub out: PathBuf,
    /// File name stem (`<name>.json`, `.json.sig`, `.json.accept.sig`).
    #[arg(long, default_value = "transition")]
    pub name: String,
}

#[derive(Debug, Args)]
pub struct KeyAcceptArgs {
    /// The transition statement (`<name>.json`).
    pub transition: PathBuf,
    /// The new key.
    #[arg(long, value_name = "SIGNER")]
    pub new: String,
}

#[derive(Debug, Args)]
pub struct KeyRevokeArgs {
    /// The revoking key (the key itself, or a directly pinned key of the
    /// same principal with key-revocation in its scope).
    #[arg(long, value_name = "SIGNER")]
    pub signer: String,
    /// Fingerprint of the key being revoked.
    #[arg(long, value_name = "FINGERPRINT")]
    pub revoked: String,
    /// A log whose records up to its last record stay trusted. Repeatable.
    #[arg(long, value_name = "LOG_DIR")]
    pub trusted_head: Vec<PathBuf>,
    /// SHA-256 of an attestation that stays trusted. Repeatable.
    #[arg(long, value_name = "SHA256")]
    pub trusted_release: Vec<String>,
    /// A successor key that stays trusted. Repeatable.
    #[arg(long, value_name = "FINGERPRINT")]
    pub trusted_successor: Vec<String>,
    /// Free-text reason.
    #[arg(long)]
    pub reason: Option<String>,
    /// Override `issued_at`.
    #[arg(long)]
    pub issued_at: Option<String>,
    /// Output directory.
    #[arg(long)]
    pub out: PathBuf,
    /// File name stem.
    #[arg(long, default_value = "revocation")]
    pub name: String,
}

#[derive(Debug, Args)]
pub struct KeyKrlArgs {
    /// Revocation statements whose revoked keys to list.
    pub revocations: Vec<PathBuf>,
    /// Fingerprints to list. Repeatable.
    #[arg(long, value_name = "FINGERPRINT")]
    pub revoked: Vec<String>,
    /// Output file.
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    /// Directory containing the `audit-NNNN.cbor` segment files.
    pub log_dir: PathBuf,
    /// Inclusive lower bound on `record_id` within the segment.
    #[arg(long)]
    pub from: Option<u64>,
    /// Exclusive upper bound on `record_id` within the segment.
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
    /// Override the "Generated" timestamp on the cover (RFC 3339).
    /// Default is `1970-01-01T00:00:00Z` for bit-reproducibility.
    #[arg(long)]
    pub source_date: Option<String>,
    /// Custodian name on the cover.
    #[arg(long)]
    pub custodian: Option<String>,
    /// Include every record in the sample-events section.
    #[arg(long, action = ArgAction::SetTrue)]
    pub full: bool,
    /// Signed logs: the signer's key, fingerprint, or trust file.
    #[command(flatten)]
    pub trust: TrustArgs,
}
