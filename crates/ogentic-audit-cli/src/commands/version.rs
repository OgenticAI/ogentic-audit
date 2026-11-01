//! `ogentic-audit version` — print binary + on-disk format versions.

pub fn run() {
    println!(
        "ogentic-audit {}  format v{:#06x} (HMAC) and v{:#06x} (signed)",
        ogentic_audit_core::VERSION,
        ogentic_audit_core::FORMAT_VERSION,
        ogentic_audit_core::signed::FORMAT_VERSION_SIGNED
    );
}
