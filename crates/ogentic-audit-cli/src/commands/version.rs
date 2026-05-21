//! `ogentic-audit version` — print binary + on-disk format version.

pub fn run() {
    println!(
        "ogentic-audit {}  format v{:#06x}",
        ogentic_audit_core::VERSION,
        ogentic_audit_core::FORMAT_VERSION
    );
}
