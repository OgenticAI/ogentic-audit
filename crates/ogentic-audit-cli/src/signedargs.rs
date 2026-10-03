//! Shared plumbing for signed-mode subcommands: building a trust context
//! from flags, resolving `--signer` specs, and console details.

use std::path::Path;

use anyhow::anyhow;
use ogentic_audit_core::signed::{InMemorySigner, PublicKey, Scope, Signer, TrustContext};
use zeroize::Zeroizing;

use crate::cli::{GlobalArgs, TrustArgs};
use crate::keysource::AppError;

/// Build the trust context from `--public-key`, `--key-fingerprint`,
/// `--trust`, `--statements`, `--revocations`. Every problem is an
/// argument error (exit 3).
pub fn trust_context(args: &TrustArgs) -> Result<TrustContext, AppError> {
    let arg = |e: String| AppError::argument(anyhow!(e));
    let mut t = TrustContext::new();
    if let Some(pk) = &args.public_key {
        let key = read_public_key(pk)?;
        t.pin_key(key, None, Scope::DEFAULT)
            .map_err(|e| arg(format!("--public-key: {e}")))?;
    }
    for fp in &args.key_fingerprint {
        t.pin(fp, None, Scope::DEFAULT)
            .map_err(|e| arg(format!("--key-fingerprint {fp:?}: {e}")))?;
    }
    if let Some(path) = &args.trust {
        let meta =
            std::fs::metadata(path).map_err(|e| arg(format!("--trust {}: {e}", path.display())))?;
        if meta.len() > 1024 * 1024 {
            return Err(arg(format!(
                "--trust {}: larger than 1 MiB",
                path.display()
            )));
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| arg(format!("--trust {}: {e}", path.display())))?;
        t.add_allowed_signers(&text)
            .map_err(|e| arg(format!("--trust {}: {e}", path.display())))?;
    }
    for dir in &args.statements {
        t.add_statements(dir, true)
            .map_err(|e| arg(format!("--statements: {e}")))?;
    }
    for f in &args.revocations {
        t.add_revocation(f)
            .map_err(|e| arg(format!("--revocations: {e}")))?;
    }
    Ok(t)
}

/// A public key from a file path, or from the text itself.
pub fn read_public_key(spec: &str) -> Result<PublicKey, AppError> {
    let p = Path::new(spec);
    let text = if p.is_file() {
        std::fs::read_to_string(p)
            .map_err(|e| AppError::argument(anyhow!("{}: {e}", p.display())))?
    } else {
        spec.to_string()
    };
    PublicKey::parse(&text).map_err(|e| AppError::argument(anyhow!("public key: {e}")))
}

/// Where a signing key lives, from a `--signer`/`--sign` spec.
#[derive(Debug)]
pub enum SignerSpec {
    /// OS keychain item.
    Keychain {
        /// Service.
        service: String,
        /// Account.
        account: String,
    },
    /// A file holding 64 hex digits (the 32-byte seed), mode 0600.
    File(std::path::PathBuf),
    /// An environment variable holding 64 hex digits.
    Env(String),
}

/// Parse `keychain:<service>:<account>`, `file:<path>`, or `env:<VAR>`.
pub fn parse_signer(spec: &str) -> Result<SignerSpec, AppError> {
    let bad = || {
        AppError::argument(anyhow!(
            "signer {spec:?}: expected keychain:<service>:<account>, file:<path> or env:<VAR>"
        ))
    };
    if let Some(rest) = spec.strip_prefix("keychain:") {
        let (service, account) = rest.split_once(':').ok_or_else(bad)?;
        if service.is_empty() || account.is_empty() {
            return Err(bad());
        }
        return Ok(SignerSpec::Keychain {
            service: service.into(),
            account: account.into(),
        });
    }
    if let Some(p) = spec.strip_prefix("file:") {
        return Ok(SignerSpec::File(p.into()));
    }
    if let Some(v) = spec.strip_prefix("env:") {
        return Ok(SignerSpec::Env(v.into()));
    }
    Err(bad())
}

fn seed_from_hex(text: &str, what: &str) -> Result<InMemorySigner, AppError> {
    let text = Zeroizing::new(text.trim().to_string());
    let seed: Zeroizing<[u8; 32]> =
        Zeroizing::new(ogentic_audit_core::signed::unhex(&text).ok_or_else(|| {
            AppError::argument(anyhow!("{what}: expected 64 hex digits (an Ed25519 seed)"))
        })?);
    Ok(InMemorySigner::from_seed(*seed))
}

/// Load an existing signing key.
pub fn load_signer(spec: &str) -> Result<Box<dyn Signer>, AppError> {
    match parse_signer(spec)? {
        SignerSpec::Keychain { service, account } => {
            let s = ogentic_audit_keychain::KeychainSigner::load(&service, &account)
                .map_err(|e| AppError::io(anyhow!("{e}")))?;
            Ok(Box::new(s))
        },
        SignerSpec::File(p) => {
            crate::keysource::check_key_file_permissions(&p)?;
            let text = Zeroizing::new(
                std::fs::read_to_string(&p)
                    .map_err(|e| AppError::io(anyhow!("{}: {e}", p.display())))?,
            );
            Ok(Box::new(seed_from_hex(&text, &p.display().to_string())?))
        },
        SignerSpec::Env(v) => {
            let text = Zeroizing::new(
                std::env::var(&v)
                    .map_err(|_| AppError::argument(anyhow!("env var {v} not set")))?,
            );
            Ok(Box::new(seed_from_hex(&text, &v)?))
        },
    }
}

/// Generate a key at `spec`. Never overwrites.
pub fn generate_signer(spec: &str) -> Result<Box<dyn Signer>, AppError> {
    match parse_signer(spec)? {
        SignerSpec::Keychain { service, account } => {
            let s = ogentic_audit_keychain::KeychainSigner::create(&service, &account).map_err(
                |e| match e {
                    ogentic_audit_keychain::SignerError::AlreadyExists { .. } => {
                        AppError::argument(anyhow!("{e}"))
                    },
                    other => AppError::io(anyhow!("{other}")),
                },
            )?;
            Ok(Box::new(s))
        },
        SignerSpec::File(p) => {
            let s = InMemorySigner::generate();
            write_new_secret_file(&p, &ogentic_audit_core::signed::hex(s.seed()))?;
            Ok(Box::new(s))
        },
        SignerSpec::Env(_) => Err(AppError::argument(anyhow!(
            "cannot generate into an environment variable; use keychain: or file:"
        ))),
    }
}

fn write_new_secret_file(p: &Path, hex_seed: &str) -> Result<(), AppError> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(p).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            AppError::argument(anyhow!(
                "{} already exists; a key is never overwritten",
                p.display()
            ))
        } else {
            AppError::io(anyhow!("{}: {e}", p.display()))
        }
    })?;
    let line = Zeroizing::new(format!("{hex_seed}\n"));
    f.write_all(line.as_bytes())
        .map_err(|e| AppError::io(anyhow!("{}: {e}", p.display())))
}

/// Whether to print ASCII marks: `--ascii`, or a Windows console that is
/// not Windows Terminal (legacy consoles are not UTF-8).
#[must_use]
pub fn ascii(global: &GlobalArgs) -> bool {
    global.ascii
        || std::env::var_os("OGENTIC_AUDIT_ASCII").is_some()
        || (cfg!(windows) && std::env::var_os("WT_SESSION").is_none())
}

/// Print a JSON value (from core) pretty, with a trailing newline.
pub fn print_json(v: &ogentic_audit_core::signed::json::Value) {
    println!("{}", v.to_pretty());
}
