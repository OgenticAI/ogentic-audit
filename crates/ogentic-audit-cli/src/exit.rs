//! Disciplined exit codes per OGE-435.
//!
//! Documented in the binary's `--help` and the README. CI scripts and
//! third-party automation rely on these being stable.

use std::process::ExitCode;

/// Successful or non-success exit kinds. Outer code maps these to
/// `std::process::ExitCode` at `main` return.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ExitCodeKind {
    /// 0 — operation succeeded.
    Success,
    /// 1 — verification failed (chain break / tamper detected).
    VerificationFailed,
    /// 2 — I/O error (missing log, permission denied).
    IoError,
    /// 3 — argument / config error from user.
    ArgumentError,
    /// 64 — sysexits.h `EX_USAGE`. Reserved for clap-detected misuse;
    /// clap exits with this on its own when it detects bad invocation.
    Usage,
}

impl From<ExitCodeKind> for ExitCode {
    fn from(kind: ExitCodeKind) -> Self {
        match kind {
            ExitCodeKind::Success => ExitCode::SUCCESS,
            ExitCodeKind::VerificationFailed => ExitCode::from(1),
            ExitCodeKind::IoError => ExitCode::from(2),
            ExitCodeKind::ArgumentError => ExitCode::from(3),
            ExitCodeKind::Usage => ExitCode::from(64),
        }
    }
}
