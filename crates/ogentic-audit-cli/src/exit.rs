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
    /// 4 — not verified: a signed log or release checked without a key,
    /// or with nothing signed. Neither a failure of the log nor a success.
    NotVerified,
    /// 64 — sysexits.h `EX_USAGE`: the parser rejected the invocation.
    Usage,
}

impl From<ExitCodeKind> for ExitCode {
    fn from(kind: ExitCodeKind) -> Self {
        match kind {
            ExitCodeKind::Success => ExitCode::SUCCESS,
            ExitCodeKind::VerificationFailed => ExitCode::from(1),
            ExitCodeKind::IoError => ExitCode::from(2),
            ExitCodeKind::ArgumentError => ExitCode::from(3),
            ExitCodeKind::NotVerified => ExitCode::from(4),
            ExitCodeKind::Usage => ExitCode::from(64),
        }
    }
}
