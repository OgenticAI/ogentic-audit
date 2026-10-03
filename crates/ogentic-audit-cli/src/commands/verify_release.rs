//! `ogentic-audit verify-release <dir>` — check a signed release folder
//! (spec v0.2 §11.4): the attestation's signature, every file, and every
//! audit log in it. Every problem is listed, not only the first.

use anyhow::anyhow;
use ogentic_audit_core::signed::{verify_release, ReleaseError, ReleaseOptions};
use ogentic_audit_core::Verdict;

use crate::cli::{GlobalArgs, OutputFormat, VerifyReleaseArgs};
use crate::exit::ExitCodeKind;
use crate::keysource::AppError;
use crate::signedargs;

pub fn run(global: &GlobalArgs, args: VerifyReleaseArgs) -> Result<ExitCodeKind, AppError> {
    if global.hmac_key_given() {
        return Err(AppError::argument(anyhow!(
            "a release is checked with the signer's public key or fingerprint, not an HMAC key"
        )));
    }
    let trust = signedargs::trust_context(&args.trust)?;
    let mut opts = ReleaseOptions::new().allow_unattested(args.allow_unattested);
    if let Some(id) = &args.expect_release_id {
        opts = opts.expect_release_id(id.clone());
    }
    opts.witnesses = args.witness.clone();
    let report = verify_release(&args.release_dir, &trust, &opts).map_err(|e| match e {
        ReleaseError::Io(m) => AppError::io(anyhow!("{m}")),
        other => AppError::argument(anyhow!("{other}")),
    })?;
    match args.format {
        OutputFormat::Json => signedargs::print_json(&report.to_json()),
        OutputFormat::Text => print!(
            "{}",
            report.render_human(signedargs::ascii(global), "ogentic-audit")
        ),
    }
    Ok(match report.verdict {
        Verdict::Verified => ExitCodeKind::Success,
        Verdict::SelfConsistent => ExitCodeKind::NotVerified,
        _ => ExitCodeKind::VerificationFailed,
    })
}
