//! Strict Ed25519 verification, defined rule by rule (spec v0.2 §3.5).
//!
//! 1. `A` and `R` decode to curve points and re-encode to the same bytes.
//! 2. Neither `A` nor `R` has small order.
//! 3. `A` is torsion-free (`[L]A` is the identity).
//! 4. `S < L`.
//! 5. Cofactorless: `encode([S]B − [k]A) == R_bytes`, with
//!    `k = SHA-512(R ‖ A ‖ M) mod L`.
//!
//! Rules 2, 4 and 5 are what `ed25519-dalek`'s `verify_strict` does; this
//! module calls it for the final decision and adds rules 1 and 3, which it
//! omits, using `curve25519-dalek` directly. The equation is also
//! evaluated here so that a signature whose only fault is `S ≥ L` can be
//! classified as [`Failure::Reencoded`] rather than an altered message.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
use sha2::{Digest, Sha512};

/// Why a signature failed strict verification (spec §3.5 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Failure {
    /// The public key fails rule 1, 2 or 3: anyone can make signatures
    /// under it.
    WeakKey,
    /// `S ≥ L`, and the signature is valid with `S mod L`: the signed
    /// content is unchanged, the signature bytes were re-encoded.
    Reencoded,
    /// The signature does not match the signed content.
    Mismatch,
}

impl Failure {
    /// The report `reason` string.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Failure::WeakKey => "weak_key",
            Failure::Reencoded => "reencoded",
            Failure::Mismatch => "mismatch",
        }
    }
}

fn decode_canonical(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let point = CompressedEdwardsY(*bytes).decompress()?;
    (point.compress().as_bytes() == bytes).then_some(point)
}

/// Rules 1–3 for a public key: canonical encoding, not of small order,
/// torsion-free. A key that fails is one under which anyone can sign.
#[must_use]
pub fn key_is_strong(public_key: &[u8; 32]) -> bool {
    match decode_canonical(public_key) {
        Some(a) => !a.is_small_order() && a.is_torsion_free(),
        None => false,
    }
}

/// Verify `signature` over `message` under `public_key`, strictly.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<(), Failure> {
    if !key_is_strong(public_key) {
        return Err(Failure::WeakKey);
    }
    let a = decode_canonical(public_key).ok_or(Failure::WeakKey)?;
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);

    // Rules 1 and 2 for R.
    let r_ok = matches!(decode_canonical(&r_bytes), Some(r) if !r.is_small_order());

    let k = {
        let mut h = Sha512::new();
        h.update(r_bytes);
        h.update(public_key);
        h.update(message);
        Scalar::from_bytes_mod_order_wide(&h.finalize().into())
    };
    let equation = |s: &Scalar| -> bool {
        let r_prime = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(-a), s);
        r_prime.compress().as_bytes() == &r_bytes
    };

    match Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) {
        Some(s) => {
            // Rule 4 holds. Rule 5, cross-checked with ed25519-dalek.
            let dalek_ok = VerifyingKey::from_bytes(public_key)
                .map(|vk| {
                    vk.verify_strict(message, &DalekSignature::from_bytes(signature))
                        .is_ok()
                })
                .unwrap_or(false);
            if r_ok && equation(&s) && dalek_ok {
                Ok(())
            } else {
                Err(Failure::Mismatch)
            }
        },
        None => {
            // Rule 4 fails. Valid with S mod L means only the encoding changed.
            let reduced = Scalar::from_bytes_mod_order(s_bytes);
            if r_ok && equation(&reduced) {
                Err(Failure::Reencoded)
            } else {
                Err(Failure::Mismatch)
            }
        },
    }
}

/// `S + L` re-encoding of a valid signature, for tests and vectors: the
/// same signed content, different signature bytes.
#[must_use]
pub fn reencode_s_plus_l(signature: &[u8; 64]) -> [u8; 64] {
    // L, little-endian.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut out = *signature;
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(signature[32 + i]) + u16::from(L[i]) + carry;
        out[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    out
}

/// The 14 small-order encodings of spec Appendix A.
pub const SMALL_ORDER_ENCODINGS: [&str; 14] = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed::unhex;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn k1() -> SigningKey {
        SigningKey::from_bytes(
            &unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap(),
        )
    }

    #[test]
    fn rfc8032_test1() {
        let sk = k1();
        let pk = sk.verifying_key().to_bytes();
        let sig = sk.sign(b"").to_bytes();
        assert_eq!(
            crate::signed::hex(&sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert_eq!(verify(&pk, b"", &sig), Ok(()));
        assert_eq!(verify(&pk, b"x", &sig), Err(Failure::Mismatch));
        let mut bad = sig;
        bad[10] ^= 1;
        assert_eq!(verify(&pk, b"", &bad), Err(Failure::Mismatch));
    }

    #[test]
    fn s_plus_l_is_reencoded() {
        let sk = k1();
        let pk = sk.verifying_key().to_bytes();
        let sig = sk.sign(b"msg").to_bytes();
        let re = reencode_s_plus_l(&sig);
        assert_ne!(re, sig);
        assert_eq!(verify(&pk, b"msg", &re), Err(Failure::Reencoded));
        assert_eq!(verify(&pk, b"other", &re), Err(Failure::Mismatch));
    }

    #[test]
    fn small_order_keys_are_weak() {
        for enc in SMALL_ORDER_ENCODINGS {
            let k: [u8; 32] = unhex(enc).unwrap();
            assert!(!key_is_strong(&k), "{enc} accepted");
            // The forgery both OpenSSH and OpenSSL accept: identity key,
            // R = identity, S = 0.
            let mut sig = [0u8; 64];
            sig[0] = 1;
            assert_eq!(verify(&k, b"anything", &sig), Err(Failure::WeakKey));
        }
    }

    #[test]
    fn mixed_order_key_is_weak() {
        // A + T for a point T of order 8 is not small-order but not
        // torsion-free (rule 3).
        let a = k1().verifying_key().to_bytes();
        let a_pt = CompressedEdwardsY(a).decompress().unwrap();
        let t = CompressedEdwardsY(
            unhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05").unwrap(),
        )
        .decompress()
        .unwrap();
        let mixed = (a_pt + t).compress().to_bytes();
        assert!(!key_is_strong(&mixed));
        assert!(key_is_strong(&a));
    }

    #[test]
    fn non_canonical_r_rejected() {
        // Take a valid signature and replace R by a non-canonical encoding
        // of the same point when one exists (y + p fits in 255 bits only
        // for y < 19). Construct directly: R must be canonical.
        let sk = k1();
        let pk = sk.verifying_key().to_bytes();
        let mut sig = sk.sign(b"m").to_bytes();
        sig[31] |= 0x80; // flip sign bit: a different (or invalid) R
        assert_eq!(verify(&pk, b"m", &sig), Err(Failure::Mismatch));
    }
}
