//! Output formatting helpers shared between subcommands.

/// Lowercase hex of arbitrary bytes.
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

/// Wildcard-glob match supporting `*` (any) and `?` (single char).
///
/// Used by `show --event-glob`. We roll our own rather than pulling
/// `globset` because the surface here is tiny and the test cases are
/// finite.
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    glob_rec(&pat, 0, &txt, 0)
}

fn glob_rec(pat: &[char], pi: usize, txt: &[char], ti: usize) -> bool {
    if pi >= pat.len() {
        return ti >= txt.len();
    }
    match pat[pi] {
        '*' => {
            // Try matching zero or more chars.
            (ti..=txt.len()).any(|k| glob_rec(pat, pi + 1, txt, k))
        },
        '?' => {
            if ti >= txt.len() {
                return false;
            }
            glob_rec(pat, pi + 1, txt, ti + 1)
        },
        c => {
            if ti >= txt.len() || txt[ti] != c {
                return false;
            }
            glob_rec(pat, pi + 1, txt, ti + 1)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_match_basic() {
        assert!(glob_match("foo", "foo"));
        assert!(!glob_match("foo", "bar"));
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("foo.*", "foo.bar"));
        assert!(glob_match("*.bar", "foo.bar"));
        assert!(glob_match("foo.?ar", "foo.bar"));
        assert!(!glob_match("foo.?ar", "foo.bbar"));
        assert!(glob_match("vault.*", "vault.unlocked"));
        assert!(!glob_match("vault.*", "shield.classified"));
    }

    #[test]
    fn hex_roundtrips() {
        assert_eq!(hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex(&[]), "");
    }
}
