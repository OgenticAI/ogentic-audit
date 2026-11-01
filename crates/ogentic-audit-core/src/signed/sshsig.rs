//! OpenSSH SSHSIG (spec v0.2 §3.3, OpenSSH `PROTOCOL.sshsig`).
//!
//! Every v0.2 signature is Ed25519 over [`signed_data`]. Detached
//! signatures are stored as the armored blob that `ssh-keygen -Y sign`
//! writes, so `ssh-keygen -Y verify` checks them with no `ogentic-audit`
//! software. Blobs are parsed strictly: exact lengths at every level,
//! `sha512` only, nothing left over.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha512};

use super::keys::PublicKey;

/// Maximum size of an armored `.sig` file (spec §3.8).
pub const MAX_SIG_FILE: usize = 64 * 1024;

const MAGIC: &[u8; 6] = b"SSHSIG";
const BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const END: &str = "-----END SSH SIGNATURE-----";

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// The SSHSIG signed data for `message` in `namespace`:
/// `"SSHSIG" ‖ string(ns) ‖ string("") ‖ string("sha512") ‖ string(SHA-512(message))`.
#[must_use]
pub fn signed_data(namespace: &str, message: &[u8]) -> Vec<u8> {
    signed_data_prehashed(namespace, &Sha512::digest(message).into())
}

/// [`signed_data`] given `SHA-512(message)` already computed.
#[must_use]
pub fn signed_data_prehashed(namespace: &str, message_sha512: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + 4 + namespace.len() + 4 + 4 + 6 + 4 + 64);
    out.extend_from_slice(MAGIC);
    put_string(&mut out, namespace.as_bytes());
    put_string(&mut out, b"");
    put_string(&mut out, b"sha512");
    put_string(&mut out, message_sha512);
    out
}

/// The SSHSIG blob for a signature.
#[must_use]
pub fn blob(key: &PublicKey, namespace: &str, signature: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut out, &key.key_blob());
    put_string(&mut out, namespace.as_bytes());
    put_string(&mut out, b"");
    put_string(&mut out, b"sha512");
    let mut sig = Vec::new();
    put_string(&mut sig, key.alg().ssh_type().as_bytes());
    put_string(&mut sig, signature);
    put_string(&mut out, &sig);
    out
}

/// The armored form `ssh-keygen -Y sign` writes: base64 wrapped at 70
/// characters per line.
#[must_use]
pub fn armor(key: &PublicKey, namespace: &str, signature: &[u8; 64]) -> String {
    let b64 = STANDARD.encode(blob(key, namespace, signature));
    let mut out = String::with_capacity(b64.len() + 80);
    out.push_str(BEGIN);
    out.push('\n');
    for chunk in b64.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(END);
    out.push('\n');
    out
}

/// A parsed, strictly validated SSHSIG. The key is the blob's key: it is
/// **not** trusted for anything until the caller matches it against the
/// signer the signed object names and the trust context (spec §3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSig {
    /// The key in the blob.
    pub key: PublicKey,
    /// The 64-byte Ed25519 signature.
    pub signature: [u8; 64],
}

/// Why a blob was rejected. Each maps onto a `SignatureInvalid` reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SshSigError {
    /// Structurally invalid, over the size limit, or a non-empty reserved
    /// field.
    #[error("malformed SSH signature: {0}")]
    Malformed(String),
    /// Signed for a different purpose.
    #[error("signature namespace is {found:?}, expected {expected:?}")]
    Namespace {
        /// The namespace required for this object.
        expected: String,
        /// The namespace in the blob.
        found: String,
    },
    /// A hash algorithm other than `sha512`.
    #[error("signature hash algorithm is {0:?}; only sha512 is accepted")]
    HashAlg(String),
    /// A key or signature type other than `ssh-ed25519`.
    #[error("signature key type is {0:?}; only ssh-ed25519 is accepted")]
    KeyType(String),
}

impl SshSigError {
    /// The report `reason` string.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            SshSigError::Malformed(_) => "malformed",
            SshSigError::Namespace { .. } => "namespace",
            SshSigError::HashAlg(_) => "hash_alg",
            SshSigError::KeyType(_) => "key_type",
        }
    }
}

/// Reader for SSH wire `string`s with bounds checks at every step.
#[derive(Debug)]
pub struct WireReader<'a> {
    buf: &'a [u8],
}

impl<'a> WireReader<'a> {
    /// Read from `buf`.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// Take `n` raw bytes.
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.buf.len() < n {
            return None;
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Some(head)
    }

    /// A big-endian u32.
    pub fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A `string`: u32 length, then that many bytes, within bounds.
    pub fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    /// Whether every byte has been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Remove the armor. Accepts any line length and ignores `\r`.
pub fn dearmor(text: &[u8]) -> Result<Vec<u8>, SshSigError> {
    if text.len() > MAX_SIG_FILE {
        return Err(SshSigError::Malformed(format!(
            "signature file larger than {MAX_SIG_FILE} bytes"
        )));
    }
    let text = std::str::from_utf8(text)
        .map_err(|_| SshSigError::Malformed("signature file is not UTF-8".into()))?;
    let cleaned = text.replace('\r', "");
    let lines: Vec<&str> = cleaned.lines().collect();
    let begin = lines.iter().position(|l| *l == BEGIN);
    let end = lines.iter().position(|l| *l == END);
    let (Some(b), Some(e)) = (begin, end) else {
        return Err(SshSigError::Malformed("missing SSH SIGNATURE armor".into()));
    };
    if e <= b
        || lines[..b].iter().any(|l| !l.trim().is_empty())
        || lines[e + 1..].iter().any(|l| !l.trim().is_empty())
    {
        return Err(SshSigError::Malformed("bad SSH SIGNATURE armor".into()));
    }
    let body: String = lines[b + 1..e].concat();
    STANDARD
        .decode(body.as_bytes())
        .map_err(|e| SshSigError::Malformed(format!("base64: {e}")))
}

/// Parse an SSHSIG blob strictly and require `namespace`.
pub fn parse_blob(blob: &[u8], namespace: &str) -> Result<SshSig, SshSigError> {
    let mal = |m: &str| SshSigError::Malformed(m.to_string());
    let mut r = WireReader::new(blob);
    if r.take(6) != Some(MAGIC.as_slice()) {
        return Err(mal("bad magic"));
    }
    if r.u32() != Some(1) {
        return Err(mal("unsupported SSHSIG version"));
    }
    let key_blob = r.string().ok_or_else(|| mal("truncated public key"))?;
    let mut kr = WireReader::new(key_blob);
    let ktype = kr.string().ok_or_else(|| mal("truncated key type"))?;
    if ktype != b"ssh-ed25519" {
        return Err(SshSigError::KeyType(lossy(ktype)));
    }
    let kbytes = kr.string().ok_or_else(|| mal("truncated key"))?;
    if kbytes.len() != 32 || !kr.is_empty() {
        return Err(mal("public key is not exactly 32 bytes"));
    }
    let ns = r.string().ok_or_else(|| mal("truncated namespace"))?;
    if ns != namespace.as_bytes() {
        return Err(SshSigError::Namespace {
            expected: namespace.to_string(),
            found: lossy(ns),
        });
    }
    let reserved = r.string().ok_or_else(|| mal("truncated reserved field"))?;
    if !reserved.is_empty() {
        return Err(mal("reserved field is not empty"));
    }
    let hash_alg = r.string().ok_or_else(|| mal("truncated hash algorithm"))?;
    if hash_alg != b"sha512" {
        return Err(SshSigError::HashAlg(lossy(hash_alg)));
    }
    let sig_blob = r.string().ok_or_else(|| mal("truncated signature"))?;
    if !r.is_empty() {
        return Err(mal("bytes after the signature"));
    }
    let mut sr = WireReader::new(sig_blob);
    let stype = sr.string().ok_or_else(|| mal("truncated signature type"))?;
    if stype != b"ssh-ed25519" {
        return Err(SshSigError::KeyType(lossy(stype)));
    }
    let sbytes = sr
        .string()
        .ok_or_else(|| mal("truncated signature bytes"))?;
    if sbytes.len() != 64 || !sr.is_empty() {
        return Err(mal("signature is not exactly 64 bytes"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(kbytes);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(sbytes);
    Ok(SshSig {
        key: PublicKey::ed25519(key),
        signature,
    })
}

/// [`dearmor`] then [`parse_blob`].
pub fn parse_armored(text: &[u8], namespace: &str) -> Result<SshSig, SshSigError> {
    parse_blob(&dearmor(text)?, namespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_strictness() {
        let key = PublicKey::ed25519([9u8; 32]);
        let sig = [7u8; 64];
        let text = armor(&key, "ns", &sig);
        assert!(text
            .lines()
            .all(|l| l.len() <= 70 || l.starts_with("-----")));
        let parsed = parse_armored(text.as_bytes(), "ns").unwrap();
        assert_eq!(parsed.key, key);
        assert_eq!(parsed.signature, sig);
        assert!(matches!(
            parse_armored(text.as_bytes(), "other"),
            Err(SshSigError::Namespace { .. })
        ));
        // CRLF and one long line are fine.
        let b64 = STANDARD.encode(blob(&key, "ns", &sig));
        let crlf = format!("{BEGIN}\r\n{b64}\r\n{END}\r\n");
        assert!(parse_armored(crlf.as_bytes(), "ns").is_ok());
        // Trailing bytes.
        let mut b = blob(&key, "ns", &sig);
        b.push(0);
        assert!(matches!(
            parse_blob(&b, "ns"),
            Err(SshSigError::Malformed(_))
        ));
    }
}
