//! `ogentic-audit key …` — signing keys and key statements (spec v0.2
//! §9, §13.2). Public keys only ever leave; a private key is never
//! exported, and never loaded into ssh-agent.

use std::path::Path;

use anyhow::anyhow;
use ogentic_audit_core::signed::statements::{self, CutPoints, Head};
use ogentic_audit_core::signed::{
    now_rfc3339, parse_rfc3339_millis, unhex, Fingerprint, PublicKey, SignedVerifier, TrustContext,
};
use ogentic_audit_core::Verdict;

use crate::cli::{
    GlobalArgs, KeyAcceptArgs, KeyCommand, KeyExportArgs, KeyFingerprintArgs, KeyFormat,
    KeyGenerateArgs, KeyKrlArgs, KeyRevokeArgs, KeyTransitionArgs,
};
use crate::exit::ExitCodeKind;
use crate::keysource::AppError;
use crate::signedargs;

pub fn run(global: &GlobalArgs, cmd: KeyCommand) -> Result<ExitCodeKind, AppError> {
    match cmd {
        KeyCommand::Generate(a) => generate(global, a),
        KeyCommand::Export(a) => export(a),
        KeyCommand::Fingerprint(a) => fingerprint(a),
        KeyCommand::Transition(a) => transition(global, a),
        KeyCommand::Accept(a) => accept(global, a),
        KeyCommand::Revoke(a) => revoke(global, a),
        KeyCommand::Krl(a) => krl(global, a),
    }
}

fn print_fingerprints(fp: &Fingerprint) {
    println!("Fingerprint (read it aloud, print it, publish it):");
    println!("  {}", fp.to_grouped_hex());
    println!("For command lines:");
    println!("  {}", fp.to_dashed_hex());
    println!("As ssh-keygen -l prints it:");
    println!("  {}", fp.to_openssh());
}

pub fn generate(global: &GlobalArgs, a: KeyGenerateArgs) -> Result<ExitCodeKind, AppError> {
    let s = signedargs::generate_signer(&a.signer)?;
    println!("{}", s.public_key().to_openssh("ogentic-audit"));
    if !global.quiet {
        print_fingerprints(&s.public_key().fingerprint());
        eprintln!(
            "Publish the fingerprint through a channel third parties can check independently \
             of anything you hand them (a website, a letter, a filing)."
        );
    }
    Ok(ExitCodeKind::Success)
}

pub fn export(a: KeyExportArgs) -> Result<ExitCodeKind, AppError> {
    let s = signedargs::load_signer(&a.signer)?;
    let pk = s.public_key();
    let text = match a.format {
        KeyFormat::Openssh => format!("{}\n", pk.to_openssh(&a.comment)),
        KeyFormat::Pem => pk.to_pem(),
        KeyFormat::Hex => format!("{}\n", pk.to_hex()),
    };
    match &a.out {
        Some(p) => {
            std::fs::write(p, text).map_err(|e| AppError::io(anyhow!("{}: {e}", p.display())))?
        },
        None => print!("{text}"),
    }
    Ok(ExitCodeKind::Success)
}

fn fingerprint(a: KeyFingerprintArgs) -> Result<ExitCodeKind, AppError> {
    let pk: PublicKey = match (&a.key, &a.signer) {
        (_, Some(spec)) => *signedargs::load_signer(spec)?.public_key(),
        (Some(k), None) => signedargs::read_public_key(k)?,
        (None, None) => return Err(AppError::argument(anyhow!("give a key or --signer"))),
    };
    if !pk.is_strong() {
        return Err(AppError::argument(anyhow!(
            "this is a key under which anyone can make signatures; it must never be trusted"
        )));
    }
    print_fingerprints(&pk.fingerprint());
    Ok(ExitCodeKind::Success)
}

fn issued_at(o: &Option<String>) -> Result<String, AppError> {
    let t = o.clone().unwrap_or_else(now_rfc3339);
    if parse_rfc3339_millis(&t).is_none() {
        return Err(AppError::argument(anyhow!(
            "--issued-at must be RFC 3339 UTC with milliseconds"
        )));
    }
    Ok(t)
}

/// The head (last record) of a signed log, which must not show any
/// violation.
fn log_head(dir: &Path) -> Result<Head, AppError> {
    let r = SignedVerifier::new(TrustContext::new())
        .verify(dir)
        .map_err(crate::commands::verify::signed_error)?;
    if r.verdict == Verdict::Violation {
        return Err(AppError::argument(anyhow!(
            "{} does not verify ({}); its head cannot be vouched for",
            dir.display(),
            r.compact_verdict()
        )));
    }
    match (r.log.head, r.log.final_record_hash, r.log.log_id) {
        (Some((segment, record_id)), Some(record_hash), Some(log_id)) => Ok(Head {
            log_id,
            segment,
            record_id,
            record_count: r.log.records_inspected,
            record_hash,
        }),
        _ => Err(AppError::argument(anyhow!(
            "{} has no records",
            dir.display()
        ))),
    }
}

fn sha_list(v: &[String], flag: &str) -> Result<Vec<[u8; 32]>, AppError> {
    v.iter()
        .map(|h| {
            unhex::<32>(h.trim())
                .ok_or_else(|| AppError::argument(anyhow!("{flag} {h:?}: expected 64 hex digits")))
        })
        .collect()
}

fn transition(global: &GlobalArgs, a: KeyTransitionArgs) -> Result<ExitCodeKind, AppError> {
    let old = signedargs::load_signer(&a.old)?;
    let heads = a
        .final_head
        .iter()
        .map(|d| log_head(d))
        .collect::<Result<Vec<_>, _>>()?;
    let releases = sha_list(&a.final_release, "--final-release")?;
    let at = issued_at(&a.issued_at)?;
    let st = match (&a.new, &a.new_public_key) {
        (Some(spec), _) => {
            let new = signedargs::load_signer(spec)?;
            statements::transition(
                old.as_ref(),
                new.as_ref(),
                &heads,
                &releases,
                &at,
                a.reason.as_deref(),
            )
            .map_err(|e| AppError::io(anyhow!("signing: {e}")))?
        },
        (None, Some(pk)) => {
            let new = signedargs::read_public_key(pk)?;
            if !new.is_strong() {
                return Err(AppError::argument(anyhow!("the new key is a weak key")));
            }
            let json = statements::transition_json(
                old.public_key(),
                &new,
                &heads,
                &releases,
                &at,
                a.reason.as_deref(),
            );
            let sig = ogentic_audit_core::signed::signer::sign_detached(
                old.as_ref(),
                ogentic_audit_core::signed::NS_TRANSITION,
                &json,
            )
            .map_err(|e| AppError::io(anyhow!("signing: {e}")))?;
            statements::SignedStatement {
                json,
                sig,
                accept_sig: None,
            }
        },
        (None, None) => return Err(AppError::argument(anyhow!("--new or --new-public-key"))),
    };
    st.write(&a.out, &a.name)
        .map_err(|e| AppError::io(anyhow!("{}: {e}", a.out.display())))?;
    if !global.quiet {
        eprintln!(
            "transition written to {}/{}.json{}",
            a.out.display(),
            a.name,
            if st.accept_sig.is_some() {
                " (signed and accepted)"
            } else {
                " (signed; the new key must still run `key accept`)"
            }
        );
        eprintln!("Ship it with every later release and publish it next to the fingerprint; then destroy the old private key.");
    }
    Ok(ExitCodeKind::Success)
}

fn accept(global: &GlobalArgs, a: KeyAcceptArgs) -> Result<ExitCodeKind, AppError> {
    let json = std::fs::read(&a.transition)
        .map_err(|e| AppError::argument(anyhow!("{}: {e}", a.transition.display())))?;
    let doc = ogentic_audit_core::signed::json::parse_canonical(&json, 3)
        .map_err(|e| AppError::argument(anyhow!("{}: {e}", a.transition.display())))?;
    let new = signedargs::load_signer(&a.new)?;
    let named = doc.get("new_key_id").and_then(|v| v.as_str()).unwrap_or("");
    if named != new.public_key().fingerprint().to_hex() {
        return Err(AppError::argument(anyhow!(
            "this transition names a different new key; refusing to accept it"
        )));
    }
    let sig = statements::accept(new.as_ref(), &json)
        .map_err(|e| AppError::io(anyhow!("signing: {e}")))?;
    let mut p = a.transition.as_os_str().to_os_string();
    p.push(".accept.sig");
    std::fs::write(&p, sig).map_err(|e| AppError::io(anyhow!("writing acceptance: {e}")))?;
    if !global.quiet {
        eprintln!("acceptance written next to {}", a.transition.display());
    }
    Ok(ExitCodeKind::Success)
}

fn revoke(global: &GlobalArgs, a: KeyRevokeArgs) -> Result<ExitCodeKind, AppError> {
    let signer = signedargs::load_signer(&a.signer)?;
    let revoked = Fingerprint::parse(&a.revoked)
        .map_err(|e| AppError::argument(anyhow!("--revoked: {e}")))?;
    let cut = CutPoints {
        trusted_heads: a
            .trusted_head
            .iter()
            .map(|d| log_head(d))
            .collect::<Result<Vec<_>, _>>()?,
        trusted_releases: sha_list(&a.trusted_release, "--trusted-release")?,
        trusted_successors: a
            .trusted_successor
            .iter()
            .map(|f| {
                Fingerprint::parse(f)
                    .map_err(|e| AppError::argument(anyhow!("--trusted-successor: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    let self_revocation = signer.public_key().fingerprint() == revoked;
    let st = statements::revocation(
        signer.as_ref(),
        &revoked,
        &cut,
        &issued_at(&a.issued_at)?,
        a.reason.as_deref(),
    )
    .map_err(|e| AppError::io(anyhow!("signing: {e}")))?;
    st.write(&a.out, &a.name)
        .map_err(|e| AppError::io(anyhow!("{}: {e}", a.out.display())))?;
    if !global.quiet {
        eprintln!("revocation written to {}/{}.json", a.out.display(), a.name);
        if self_revocation {
            eprintln!("This is a self-revocation: its cut points are ignored, so nothing the key signed verifies until an authority revocation says what survives.");
        }
        eprintln!("Publish it through the same channel as the fingerprint, with a key revocation list (`key krl`).");
    }
    Ok(ExitCodeKind::Success)
}

fn krl(global: &GlobalArgs, a: KeyKrlArgs) -> Result<ExitCodeKind, AppError> {
    let mut fps = Vec::new();
    for f in &a.revoked {
        fps.push(Fingerprint::parse(f).map_err(|e| AppError::argument(anyhow!("--revoked: {e}")))?);
    }
    for p in &a.revocations {
        let bytes =
            std::fs::read(p).map_err(|e| AppError::argument(anyhow!("{}: {e}", p.display())))?;
        let doc = ogentic_audit_core::signed::json::parse_canonical(&bytes, 3)
            .map_err(|e| AppError::argument(anyhow!("{}: {e}", p.display())))?;
        let id = doc
            .get("revoked_key_id")
            .and_then(|v| v.as_str())
            .and_then(unhex::<32>)
            .ok_or_else(|| AppError::argument(anyhow!("{}: not a revocation", p.display())))?;
        fps.push(Fingerprint(id));
    }
    if fps.is_empty() {
        return Err(AppError::argument(anyhow!("nothing to revoke")));
    }
    #[allow(clippy::disallowed_methods)] // KRL generation date, not audit time.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    std::fs::write(&a.out, statements::krl(&fps, "ogentic-audit", now))
        .map_err(|e| AppError::io(anyhow!("{}: {e}", a.out.display())))?;
    if !global.quiet {
        eprintln!(
            "KRL with {} key(s) written to {}. Stock tools then reject every signature by these keys.",
            fps.len(),
            a.out.display()
        );
    }
    Ok(ExitCodeKind::Success)
}
