//! Signed mode: format `0x0002` (spec [v0.2], [ADR-0004]).
//!
//! Every record carries a strictly verified Ed25519 signature (an SSHSIG
//! over the record's envelope); records are linked by a public,
//! domain-separated SHA-256 hash; verification needs only the signer's
//! **public** key, pinned from outside the artefact. Nobody who can verify
//! a signed log can forge one.
//!
//! Format `0x0001` (HMAC-SHA256, [`crate::Writer`] / [`crate::Verifier`])
//! is unchanged and remains supported.
//!
//! | Module | What it holds |
//! |---|---|
//! | [`keys`] | [`PublicKey`], [`Fingerprint`], [`SigAlg`] |
//! | [`ed25519`] | strict verification, spec §3.5, rule by rule |
//! | [`sshsig`] | OpenSSH SSHSIG signed data, blobs and armor |
//! | [`signer`] | the [`Signer`] trait and [`InMemorySigner`] |
//! | [`format`] | segment header, envelope, body, record framing |
//! | [`writer`] | [`SignedWriter`] |
//! | [`trust`] | [`TrustContext`]: pins, scopes, transitions, revocations |
//! | [`statements`] | building key transitions, revocations, KRLs |
//! | [`checkpoint`] | checkpoint v2 and witness co-signatures |
//! | [`verify`] | [`SignedVerifier`] and [`log_format`] |
//! | [`report`] | report types, JSON and human output |
//! | [`release`] | release attestations: [`AttestationBuilder`], [`verify_release`] |
//!
//! [v0.2]: https://github.com/OgenticAI/ogentic-audit/blob/main/docs/spec/v0.2.md
//! [ADR-0004]: https://github.com/OgenticAI/ogentic-audit/blob/main/docs/adr/0004-signed-chain-and-offline-verification.md

use sha2::{Digest, Sha256};

pub mod checkpoint;
pub mod ed25519;
pub mod format;
pub mod json;
pub mod keys;
pub mod names;
pub mod release;
pub mod report;
pub mod signer;
pub mod sshsig;
pub mod statements;
pub mod trust;
pub mod verify;
pub mod writer;

pub use checkpoint::{CheckpointV2, WitnessCosignature};
pub use keys::{Fingerprint, KeyParseError, PublicKey, SigAlg};
pub use release::{
    verify_release, AttestationBuilder, AttestationDigest, FileSpec, LogSpec, Part, ReleaseError,
    ReleaseFinding, ReleaseItem, ReleaseOptions, ReleaseReport,
};
pub use report::{
    Finding, Location, NotVerifiedReason, SignedVerifyReport, SignerInfo, SignerReason, Warning,
};
pub use signer::{InMemorySigner, SignError, Signature, Signer};
pub use statements::{CutPoints, Head, SignedStatement};
pub use trust::{Scope, TrustContext, TrustError};
pub use verify::{
    log_format, visit_records, RecordView, SignedVerifier, SignedVerifyError, SignedVerifyOptions,
    SuppliedCheckpoint,
};
pub use writer::SignedWriter;

/// The format version of a signed log (segment header `version`).
pub const FORMAT_VERSION_SIGNED: u16 = 0x0002;

/// SSHSIG namespace for log records.
pub const NS_RECORD: &str = "ogentic-audit/v0.2/record";
/// SSHSIG namespace for checkpoints.
pub const NS_CHECKPOINT: &str = "ogentic-audit/v0.2/checkpoint";
/// SSHSIG namespace for witness co-signatures.
pub const NS_WITNESS: &str = "ogentic-audit/v0.2/witness";
/// SSHSIG namespace for release attestations.
pub const NS_RELEASE: &str = "ogentic-audit/v0.2/release";
/// SSHSIG namespace for key transitions (signed by the old key).
pub const NS_TRANSITION: &str = "ogentic-audit/v0.2/key-transition";
/// SSHSIG namespace for the new key's acceptance of a transition.
pub const NS_TRANSITION_ACCEPT: &str = "ogentic-audit/v0.2/key-transition-accept";
/// SSHSIG namespace for key revocations.
pub const NS_REVOCATION: &str = "ogentic-audit/v0.2/key-revocation";

/// Every namespace of spec §3.3, in table order.
pub const ALL_NAMESPACES: [&str; 7] = [
    NS_RECORD,
    NS_CHECKPOINT,
    NS_WITNESS,
    NS_RELEASE,
    NS_TRANSITION,
    NS_TRANSITION_ACCEPT,
    NS_REVOCATION,
];

/// Hash tag for segment headers (`chain_start`).
pub const TAG_HEADER: &str = "ogentic-audit/v0.2/header";
/// Hash tag for record envelopes (`record_hash`).
pub const TAG_RECORD: &str = "ogentic-audit/v0.2/record";
/// Hash tag for record bodies (`body_hash`).
pub const TAG_BODY: &str = "ogentic-audit/v0.2/body";
/// Hash tag for commitments to content that may be withheld.
pub const TAG_COMMIT: &str = "ogentic-audit/v0.2/commit";

/// `TH(tag, data) = SHA-256(tag ‖ 0x00 ‖ data)` (spec §3.4).
#[must_use]
pub fn th(tag: &str, data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag.as_bytes());
    h.update([0u8]);
    h.update(data);
    h.finalize().into()
}

/// A commitment to `content` that may later be withheld (spec §6.3):
/// `TH("ogentic-audit/v0.2/commit", nonce ‖ content)`. Use a fresh
/// [`random_nonce`] per item and keep the nonce out of any release.
#[must_use]
pub fn commitment(nonce: &[u8; 32], content: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TAG_COMMIT.as_bytes());
    h.update([0u8]);
    h.update(nonce);
    h.update(content);
    h.finalize().into()
}

/// 32 bytes from the OS CSPRNG.
///
/// # Panics
///
/// Panics if the operating system's random source fails, which leaves
/// no safe way to continue.
#[must_use]
pub fn random_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    getrandom::getrandom(&mut n).expect("OS random source failed");
    n
}

/// SHA-256 of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Parse exactly `N` bytes of hex (either case).
#[must_use]
pub fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// Parse exactly `N` bytes of **lowercase** hex, as canonical documents
/// carry it.
#[must_use]
pub fn unhex_lower<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    unhex(s)
}

/// The current time as RFC 3339 UTC with millisecond precision
/// (`2026-10-03T12:00:00.000Z`), the timestamp shape used everywhere in
/// this format.
#[must_use]
pub fn now_rfc3339() -> String {
    // Used for `created_at` / `observed_at` on attestations and
    // checkpoints, never for audit-record time anchoring.
    #[allow(clippy::disallowed_methods)]
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    rfc3339_from_millis(d.as_millis() as i64)
}

/// Format milliseconds since the Unix epoch as RFC 3339 UTC, ms precision.
#[must_use]
pub fn rfc3339_from_millis(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    // civil_from_days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3_600_000,
        (rem / 60_000) % 60,
        (rem / 1000) % 60,
        rem % 1000
    )
}

/// Parse the RFC 3339 ms-precision shape into milliseconds since the
/// epoch. `None` if the string does not have exactly that shape.
#[must_use]
pub fn parse_rfc3339_millis(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 24
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'.'
        || b[23] != b'Z'
    {
        return None;
    }
    let num = |from: usize, len: usize| -> Option<i64> {
        let part = &s[from..from + len];
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let (year, month, day) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    let (hour, minute, second, ms) = (num(11, 2)?, num(14, 2)?, num(17, 2)?, num(20, 3)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400_000 + hour * 3_600_000 + minute * 60_000 + second * 1000 + ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_round_trip() {
        for s in [
            "1970-01-01T00:00:00.000Z",
            "2026-10-03T12:00:00.123Z",
            "2000-02-29T23:59:59.999Z",
            "2100-12-31T00:00:00.001Z",
        ] {
            let ms = parse_rfc3339_millis(s).unwrap();
            assert_eq!(rfc3339_from_millis(ms), s);
        }
        assert!(parse_rfc3339_millis("2026-10-03T12:00:00Z").is_none());
    }

    #[test]
    fn th_is_domain_separated() {
        assert_ne!(th(TAG_RECORD, b"x"), th(TAG_BODY, b"x"));
        assert_eq!(
            th(TAG_COMMIT, &[[7u8; 32].as_slice(), b"page"].concat()),
            commitment(&[7u8; 32], b"page")
        );
    }

    #[test]
    fn hex_helpers() {
        assert_eq!(unhex::<2>("aBcd"), Some([0xab, 0xcd]));
        assert_eq!(unhex_lower::<2>("aBcd"), None);
        assert_eq!(unhex::<2>("abc"), None);
        assert_eq!(hex(&[0, 255]), "00ff");
    }
}
