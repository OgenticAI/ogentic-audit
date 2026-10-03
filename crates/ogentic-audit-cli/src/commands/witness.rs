//! `ogentic-audit witness <checkpoint> --sign <key> --out <file>` — a
//! witness co-signature (spec v0.2 §10.2): the witness attests that it
//! observed the checkpoint, at its own time, with its own key.

use anyhow::anyhow;
use ogentic_audit_core::signed::{checkpoint, now_rfc3339, parse_rfc3339_millis, CheckpointV2};

use crate::cli::{GlobalArgs, WitnessArgs};
use crate::exit::ExitCodeKind;
use crate::keysource::AppError;
use crate::signedargs;

pub fn run(global: &GlobalArgs, args: WitnessArgs) -> Result<ExitCodeKind, AppError> {
    let bytes = std::fs::read(&args.checkpoint)
        .map_err(|e| AppError::argument(anyhow!("{}: {e}", args.checkpoint.display())))?;
    CheckpointV2::parse(&bytes)
        .map_err(|e| AppError::argument(anyhow!("{}: {e}", args.checkpoint.display())))?;
    let observed_at = args.observed_at.clone().unwrap_or_else(now_rfc3339);
    if parse_rfc3339_millis(&observed_at).is_none() {
        return Err(AppError::argument(anyhow!(
            "--observed-at must be RFC 3339 UTC with milliseconds"
        )));
    }
    let signer = signedargs::load_signer(&args.sign)?;
    let (doc, sig) = checkpoint::cosign(&bytes, signer.as_ref(), &observed_at)
        .map_err(|e| AppError::io(anyhow!("signing: {e}")))?;
    std::fs::write(&args.out, &doc)
        .map_err(|e| AppError::io(anyhow!("{}: {e}", args.out.display())))?;
    let mut sp = args.out.as_os_str().to_os_string();
    sp.push(".sig");
    std::fs::write(&sp, sig).map_err(|e| AppError::io(anyhow!("writing signature: {e}")))?;
    if !global.quiet {
        eprintln!(
            "witness co-signature written to {} by {}",
            args.out.display(),
            signer.public_key().fingerprint().to_grouped_hex()
        );
    }
    Ok(ExitCodeKind::Success)
}
