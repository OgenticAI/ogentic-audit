//! `ogentic-audit export <log_dir> --pdf <out>` — court-ready PDF.
//!
//! Stub until [C3 / OGE-438] lands. Exits successfully with a
//! "not yet implemented" message — per the OGE-435 AC.
//!
//! [C3 / OGE-438]: https://linear.app/ogenticai/issue/OGE-438

use crate::cli::{ExportArgs, GlobalArgs};
use crate::exit::ExitCodeKind;
use crate::keysource::AppError;

pub fn run(_global: &GlobalArgs, args: ExportArgs) -> Result<ExitCodeKind, AppError> {
    eprintln!(
        "ogentic-audit export {} --pdf {}: not yet implemented (tracked in OGE-438)",
        args.log_dir.display(),
        args.pdf.display(),
    );
    Ok(ExitCodeKind::Success)
}
