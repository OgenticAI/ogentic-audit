//! Envelope-encrypted local-HMAC mode for KMS-backed keys.
//!
//! ## Design
//!
//! In envelope mode the KMS key acts as a **Key Encryption Key (KEK)**.
//! On the first [`crate::KmsKey::sign`] call the provider is asked to
//! [`crate::KmsProvider::envelope_unwrap`] a raw 32-byte HMAC key (the
//! **Data Encryption Key / DEK**) by calling e.g. `GenerateDataKey` or
//! `Decrypt` on the underlying KMS service.  The DEK is then held in a
//! [`zeroize::Zeroizing`] buffer for the lifetime of the `KmsKey`.
//!
//! All subsequent `sign` calls use [`local_hmac`] — a plain `HMAC-SHA256`
//! computation with the cached DEK — incurring no KMS round-trip.
//!
//! ## Security properties
//!
//! - The DEK is zeroed in memory on `KmsKey` drop (best-effort; the
//!   Rust memory model does not guarantee that the compiler cannot elide
//!   writes, but `zeroize` uses a `volatile_set_memory` barrier to
//!   maximise the chance of success).
//! - `HMAC-SHA256` computed locally with the same key bytes is
//!   byte-for-byte identical to the output of AWS KMS `GenerateMac`
//!   (`HMAC_SHA_256`) with the same key, so the `Verifier` (R3) is
//!   agnostic to which mode produced the MAC.
//!
//! See: <https://linear.app/ogenticai/issue/OGE-603>

use hmac::{Hmac, Mac};
use ogentic_audit_core::{HmacBytes, HMAC_LEN};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 of `msg` using `key`.
///
/// `key` must be exactly [`HMAC_LEN`] (32) bytes.
///
/// The output is byte-for-byte identical to what AWS KMS `GenerateMac`
/// (`HMAC_SHA_256`) would return for the same key and message, provided
/// the same raw key bytes back the KMS HMAC key.
pub(crate) fn local_hmac(key: &[u8; HMAC_LEN], msg: &[u8]) -> HmacBytes {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key size; HMAC_LEN is 32");
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; HMAC_LEN];
    arr.copy_from_slice(&out);
    HmacBytes::from(arr)
}
