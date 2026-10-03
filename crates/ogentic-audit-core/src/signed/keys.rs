//! Public keys, algorithm identifiers and fingerprints (spec v0.2 §3.2,
//! §3.7).
//!
//! `key_id` is `SHA-256(key blob)`, exactly the value `ssh-keygen -l`
//! prints. Fingerprints are always handled whole: 32 bytes, compared by
//! equality, never by prefix.

use std::fmt;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;

use super::{ed25519, hex, sha256, unhex};

/// Signature algorithm (`sig_alg`, spec §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SigAlg {
    /// Ed25519 (`0x0001`).
    Ed25519,
}

impl SigAlg {
    /// The `sig_alg` code.
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            SigAlg::Ed25519 => 0x0001,
        }
    }

    /// The algorithm for a code, if implemented. `0x0002` (ML-DSA-65) is
    /// reserved and not implemented.
    #[must_use]
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            0x0001 => Some(SigAlg::Ed25519),
            _ => None,
        }
    }

    /// The JSON `alg` name.
    #[must_use]
    pub fn json_name(self) -> &'static str {
        match self {
            SigAlg::Ed25519 => "ed25519",
        }
    }

    /// The algorithm for a JSON `alg` name.
    #[must_use]
    pub fn from_json_name(name: &str) -> Option<Self> {
        match name {
            "ed25519" => Some(SigAlg::Ed25519),
            _ => None,
        }
    }

    /// The OpenSSH key type string.
    #[must_use]
    pub fn ssh_type(self) -> &'static str {
        match self {
            SigAlg::Ed25519 => "ssh-ed25519",
        }
    }

    /// Strength order of spec §3.2 (higher is stronger).
    #[must_use]
    pub fn strength(self) -> u8 {
        match self {
            SigAlg::Ed25519 => 1,
        }
    }
}

/// Why a public key or fingerprint string was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyParseError {
    /// Not any accepted format.
    #[error("not a public key: {0}")]
    Format(String),
    /// A key under which anyone can make signatures (spec §3.5 rules 1–3).
    #[error(
        "this key is one under which anyone can make signatures (small-order, non-canonical or with a small-order component); it cannot be trusted"
    )]
    WeakKey,
    /// A fingerprint that is not exactly 32 bytes.
    #[error(
        "a fingerprint must be exactly 64 hex digits (spaces, '-' and ':' allowed) or SHA256:<base64 of 32 bytes>: {0}"
    )]
    Fingerprint(String),
}

/// An Ed25519 public key.
///
/// Holding a `PublicKey` says nothing about trust: a key taken from a
/// segment header, an SSHSIG blob or a release is informational until it
/// matches a pin ([`super::TrustContext`]).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey {
    alg: SigAlg,
    bytes: [u8; 32],
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.fingerprint().to_grouped_hex())
    }
}

const SPKI_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

impl PublicKey {
    /// An Ed25519 key from its 32 bytes. No strength check: see
    /// [`PublicKey::is_strong`].
    #[must_use]
    pub fn ed25519(bytes: [u8; 32]) -> Self {
        Self {
            alg: SigAlg::Ed25519,
            bytes,
        }
    }

    /// The algorithm.
    #[must_use]
    pub fn alg(&self) -> SigAlg {
        self.alg
    }

    /// The raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Spec §3.5 rules 1–3. A key that fails is refused when pinned and
    /// reported as `weak_key` when found in an artefact.
    #[must_use]
    pub fn is_strong(&self) -> bool {
        ed25519::key_is_strong(&self.bytes)
    }

    /// OpenSSH key blob: `string("ssh-ed25519") ‖ string(key)`.
    #[must_use]
    pub fn key_blob(&self) -> Vec<u8> {
        let t = self.alg.ssh_type().as_bytes();
        let mut out = Vec::with_capacity(8 + t.len() + 32);
        out.extend_from_slice(&(t.len() as u32).to_be_bytes());
        out.extend_from_slice(t);
        out.extend_from_slice(&32u32.to_be_bytes());
        out.extend_from_slice(&self.bytes);
        out
    }

    /// Parse an OpenSSH key blob strictly: exactly
    /// `string("ssh-ed25519") ‖ string(32 bytes)`, nothing left over.
    pub fn from_key_blob(blob: &[u8]) -> Result<Self, KeyParseError> {
        let mut r = super::sshsig::WireReader::new(blob);
        let t = r
            .string()
            .ok_or_else(|| KeyParseError::Format("truncated key blob".into()))?;
        if t != b"ssh-ed25519" {
            return Err(KeyParseError::Format(format!(
                "key type {:?} is not ssh-ed25519",
                String::from_utf8_lossy(t)
            )));
        }
        let k = r
            .string()
            .ok_or_else(|| KeyParseError::Format("truncated key blob".into()))?;
        if k.len() != 32 || !r.is_empty() {
            return Err(KeyParseError::Format(
                "malformed ssh-ed25519 key blob".into(),
            ));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(k);
        Ok(Self::ed25519(bytes))
    }

    /// `key_id`: `SHA-256(key blob)`, the OpenSSH fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint(sha256(&self.key_blob()))
    }

    /// OpenSSH public-key line: `ssh-ed25519 <base64> [comment]`.
    #[must_use]
    pub fn to_openssh(&self, comment: &str) -> String {
        let b64 = STANDARD.encode(self.key_blob());
        if comment.is_empty() {
            format!("{} {b64}", self.alg.ssh_type())
        } else {
            format!("{} {b64} {comment}", self.alg.ssh_type())
        }
    }

    /// PEM SubjectPublicKeyInfo (RFC 8410).
    #[must_use]
    pub fn to_pem(&self) -> String {
        let mut der = SPKI_ED25519_PREFIX.to_vec();
        der.extend_from_slice(&self.bytes);
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            STANDARD.encode(der)
        )
    }

    /// Raw lowercase hex of the 32 key bytes.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex(&self.bytes)
    }

    /// Parse a public key in any spec §3.7 form: an OpenSSH line, PEM
    /// SubjectPublicKeyInfo, or 64 hex digits. Format only: strength is
    /// checked where the key is pinned.
    pub fn parse(text: &str) -> Result<Self, KeyParseError> {
        let t = text.trim();
        if t.starts_with("-----BEGIN PUBLIC KEY-----") {
            let body: String = t
                .lines()
                .map(str::trim)
                .filter(|l| !l.starts_with("-----"))
                .collect();
            let der = STANDARD
                .decode(body.as_bytes())
                .map_err(|e| KeyParseError::Format(format!("PEM base64: {e}")))?;
            if der.len() != 44 || der[..12] != SPKI_ED25519_PREFIX {
                return Err(KeyParseError::Format(
                    "PEM is not an Ed25519 SubjectPublicKeyInfo".into(),
                ));
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&der[12..]);
            return Ok(Self::ed25519(bytes));
        }
        if let Some(rest) = t.strip_prefix("ssh-ed25519 ") {
            let b64 = rest.split_whitespace().next().unwrap_or("");
            let blob = STANDARD
                .decode(b64.as_bytes())
                .map_err(|e| KeyParseError::Format(format!("OpenSSH base64: {e}")))?;
            return Self::from_key_blob(&blob);
        }
        if let Some(bytes) = unhex::<32>(t) {
            return Ok(Self::ed25519(bytes));
        }
        Err(KeyParseError::Format(
            "expected an OpenSSH line (ssh-ed25519 …), a PEM public key, or 64 hex digits".into(),
        ))
    }
}

/// A key fingerprint: `SHA-256(key blob)`, 32 bytes. Equality only.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint(pub [u8; 32]);

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.to_hex())
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_grouped_hex())
    }
}

impl Fingerprint {
    /// The 32 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 64 lowercase hex digits, no separators.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    /// 16 groups of 4 hex digits separated by spaces: the human form.
    #[must_use]
    pub fn to_grouped_hex(&self) -> String {
        self.grouped(' ')
    }

    /// 16 groups of 4 separated by `-`: one shell argument.
    #[must_use]
    pub fn to_dashed_hex(&self) -> String {
        self.grouped('-')
    }

    fn grouped(&self, sep: char) -> String {
        let h = self.to_hex();
        let mut out = String::with_capacity(79);
        for (i, chunk) in h.as_bytes().chunks(4).enumerate() {
            if i > 0 {
                out.push(sep);
            }
            out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        }
        out
    }

    /// `SHA256:<base64, no padding>`, as `ssh-keygen -l` prints it.
    #[must_use]
    pub fn to_openssh(&self) -> String {
        format!("SHA256:{}", STANDARD_NO_PAD.encode(self.0))
    }

    /// Parse any spec §3.7 form. Spaces, `-` and `:` are removed; what
    /// remains must be exactly 64 hex digits, or a `SHA256:` value whose
    /// base64 decodes to exactly 32 bytes. Never a prefix.
    pub fn parse(text: &str) -> Result<Self, KeyParseError> {
        let t = text.trim();
        if let Some(b64) = t.strip_prefix("SHA256:") {
            let b64 = b64.trim_end_matches('=');
            let bytes = STANDARD_NO_PAD
                .decode(b64.as_bytes())
                .map_err(|_| KeyParseError::Fingerprint(t.to_string()))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| KeyParseError::Fingerprint(t.to_string()))?;
            return Ok(Self(arr));
        }
        let cleaned: String = t
            .chars()
            .filter(|c| !matches!(c, ' ' | '-' | ':'))
            .collect();
        unhex::<32>(&cleaned)
            .map(Self)
            .ok_or_else(|| KeyParseError::Fingerprint(t.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1_PUB: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    #[test]
    fn spec_examples() {
        let k = PublicKey::parse(K1_PUB).unwrap();
        assert_eq!(
            k.to_openssh("c"),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea c"
        );
        assert!(k
            .to_pem()
            .contains("MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="));
        let fp = k.fingerprint();
        assert_eq!(
            fp.to_grouped_hex(),
            "6db5 e9b8 a1ba ce1c dd9a 7c6a db9e 9396 acc5 0734 65d9 fe8e 3a0e f6d9 c60d 6d4f"
        );
        assert_eq!(
            fp.to_openssh(),
            "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8"
        );
        for form in [
            fp.to_grouped_hex(),
            fp.to_dashed_hex(),
            fp.to_openssh(),
            fp.to_hex().to_uppercase(),
        ] {
            assert_eq!(Fingerprint::parse(&form).unwrap(), fp);
        }
        for form in [k.to_openssh(""), k.to_pem(), k.to_hex()] {
            assert_eq!(PublicKey::parse(&form).unwrap(), k);
        }
    }

    #[test]
    fn fingerprint_lengths_exact() {
        let h = "6db5e9b8a1bace1cdd9a7c6adb9e9396acc5073465d9fe8e3a0ef6d9c60d6d4f";
        assert!(Fingerprint::parse(&h[..63]).is_err());
        assert!(Fingerprint::parse(&format!("{h}0")).is_err());
        assert!(
            Fingerprint::parse(&format!("SHA256:{}", STANDARD_NO_PAD.encode([0u8; 31]))).is_err()
        );
    }
}
