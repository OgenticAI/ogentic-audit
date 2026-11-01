//! Names taken from untrusted input: string rules, path rules, display
//! escaping, and segment file names (spec v0.2 §7, §11.2, §11.4, §11.6).

use unicode_normalization::UnicodeNormalization;

/// Code points that may not occur in attested names (spec §11.2): they
/// could rewrite, reorder, or inject a line of verifier output.
#[must_use]
pub fn is_forbidden(c: char) -> bool {
    matches!(c as u32,
        0x0000..=0x001f
        | 0x007f..=0x009f
        | 0x2028..=0x2029
        | 0x200e..=0x200f
        | 0x202a..=0x202e
        | 0x2066..=0x2069)
}

/// Check the string rules of spec §11.2.
pub fn check_string(s: &str) -> Result<(), String> {
    match s.chars().find(|&c| is_forbidden(c)) {
        Some(c) => Err(format!(
            "contains the forbidden character U+{:04X}",
            c as u32
        )),
        None => Ok(()),
    }
}

/// Escape a name for printing: control, non-printing and bidirectional
/// characters become `\u{XXXX}` (spec §11.6). Applied to every name taken
/// from a bundle, whatever passed validation.
#[must_use]
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let invisible = is_forbidden(c)
            || matches!(c as u32, 0x200b..=0x200d | 0x2060..=0x2064 | 0xfeff | 0x061c | 0x00ad);
        if invisible || c == '\\' {
            if c == '\\' {
                out.push_str("\\\\");
            } else {
                out.push_str(&format!("\\u{{{:04X}}}", c as u32));
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The reserved bundle entries (spec §11.1). Never attested.
pub const RESERVED_ENTRIES: [&str; 5] = [
    "ogentic-audit-release.json",
    "ogentic-audit-release.json.sig",
    "ogentic-audit-signer.pub",
    "ogentic-audit-keys",
    "ogentic-audit-witness",
];

/// Whether `path` is a reserved bundle entry or inside one.
#[must_use]
pub fn is_reserved(path: &str) -> bool {
    let first = path.split('/').next().unwrap_or("");
    RESERVED_ENTRIES.contains(&first)
}

/// Check the path rules of spec §11.2 (relative, `/`-separated, NFC, no
/// empty, `.` or `..` component, no `\`, not reserved), plus the string
/// rules.
pub fn check_path(path: &str) -> Result<(), String> {
    check_string(path)?;
    if path.is_empty() {
        return Err("empty path".into());
    }
    if path.starts_with('/') {
        return Err("absolute path".into());
    }
    if path.contains('\\') {
        return Err("contains a backslash".into());
    }
    if path
        .split('/')
        .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err("empty, '.' or '..' path component".into());
    }
    if path.nfc().collect::<String>() != path {
        return Err("not in Unicode NFC".into());
    }
    if is_reserved(path) {
        return Err("is a reserved bundle entry".into());
    }
    Ok(())
}

/// NFC form of a name.
#[must_use]
pub fn nfc(s: &str) -> String {
    s.nfc().collect()
}

/// Operating-system litter ignored by `verify-release` at any depth
/// (spec §11.4): `.DS_Store`, `Thumbs.db`, `desktop.ini`, `._*`, and the
/// directories `__MACOSX/`, `.Spotlight-V100/`, `.Trashes/`.
#[must_use]
pub fn is_os_litter(path: &str) -> bool {
    let comps: Vec<&str> = path.split('/').collect();
    let (last, dirs) = comps.split_last().unwrap_or((&"", &[]));
    let litter_dir = |c: &&str| matches!(*c, "__MACOSX" | ".Spotlight-V100" | ".Trashes");
    dirs.iter().any(litter_dir)
        || litter_dir(last)
        || matches!(*last, ".DS_Store" | "Thumbs.db" | "desktop.ini")
        || last.starts_with("._")
}

/// `audit-NNNN.cbor` (exactly four decimal digits) → `NNNN`.
#[must_use]
pub fn segment_index(name: &str) -> Option<u16> {
    let body = name.strip_prefix("audit-")?.strip_suffix(".cbor")?;
    if body.len() != 4 || !body.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    body.parse().ok()
}

/// A name that looks like a segment file but is not exactly one
/// (`audit-1.cbor`, `AUDIT-0001.cbor`): a warning from `verify`.
#[must_use]
pub fn is_near_miss_segment(name: &str) -> bool {
    if segment_index(name).is_some() {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    lower.starts_with("audit-") && lower.ends_with(".cbor")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        assert!(check_path("pages/0001.pdf").is_ok());
        assert!(check_path("a/../b").is_err());
        assert!(check_path("a\nb").is_err());
        assert!(check_path("a\u{202e}b").is_err());
        assert!(check_path("e\u{301}").is_err());
        assert!(check_path("ogentic-audit-keys/x.json").is_err());
        assert_eq!(escape("a\u{202e}b\n"), "a\\u{202E}b\\u{000A}");
        assert!(is_os_litter("x/.DS_Store"));
        assert!(is_os_litter("__MACOSX/a"));
        assert!(is_os_litter("._a.pdf"));
        assert!(!is_os_litter("a.pdf"));
        assert_eq!(segment_index("audit-0012.cbor"), Some(12));
        assert!(is_near_miss_segment("audit-1.cbor"));
        assert!(is_near_miss_segment("AUDIT-0001.cbor"));
        assert!(!is_near_miss_segment("audit-0001.cbor"));
    }
}
