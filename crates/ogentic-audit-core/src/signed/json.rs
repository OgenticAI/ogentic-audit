//! Canonical JSON (spec v0.2 §3.6) and a small JSON value type.
//!
//! Hand-rolled for the same reason as [`crate::cbor`]: the bytes are the
//! contract, and the code that decides whether two parsers could disagree
//! about a document is code an opposing expert should be able to read in
//! one sitting.
//!
//! Signed documents (checkpoints, witness co-signatures, attestations, key
//! statements) use the restricted subset: objects, arrays, strings, and
//! integers in `[0, 2^53 − 1]`. [`parse_canonical`] parses a document,
//! rejects anything outside the subset (floats, negatives, booleans,
//! `null`, duplicate keys, non-ASCII keys, excessive depth), re-serializes
//! it, and requires byte equality with the input.
//!
//! Reports are plain JSON and may also carry booleans and `null`; they are
//! produced with [`Value::to_pretty`] or [`Value::to_canonical`], which use the same escaping.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Largest integer allowed in a canonical document (2^53 − 1).
pub const MAX_SAFE_INT: u64 = (1 << 53) - 1;

/// A JSON value. `Bool` and `Null` never occur in a canonical document
/// but are used in reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// An object with keys in byte order.
    Object(BTreeMap<String, Value>),
    /// An array.
    Array(Vec<Value>),
    /// A string.
    String(String),
    /// A non-negative integer.
    Int(u64),
    /// A boolean (reports only).
    Bool(bool),
    /// `null` (reports only).
    Null,
}

impl Value {
    /// Shorthand for building an object.
    #[must_use]
    pub fn object<I: IntoIterator<Item = (&'static str, Value)>>(items: I) -> Value {
        Value::Object(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    /// Shorthand for a string value.
    #[must_use]
    pub fn str(s: impl Into<String>) -> Value {
        Value::String(s.into())
    }

    /// Serialize compactly with sorted keys (canonical form for the subset).
    #[must_use]
    pub fn to_canonical(&self) -> String {
        let mut out = String::new();
        write_value(&mut out, self, None, 0);
        out
    }

    /// Serialize with two-space indentation (reports for humans and `jq`).
    #[must_use]
    pub fn to_pretty(&self) -> String {
        let mut out = String::new();
        write_value(&mut out, self, Some(2), 0);
        out
    }

    /// Member of an object.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => m.get(key),
            _ => None,
        }
    }

    /// The string, if this is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// The integer, if this is an integer.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// The array, if this is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The object, if this is an object.
    #[must_use]
    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_canonical())
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_string())
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}
impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Value::Int(n)
    }
}
impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}
impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(o: Option<T>) -> Self {
        o.map_or(Value::Null, Into::into)
    }
}
impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(v: Vec<T>) -> Self {
        Value::Array(v.into_iter().map(Into::into).collect())
    }
}

fn write_value(out: &mut String, v: &Value, indent: Option<usize>, level: usize) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(n) => {
            let _ = write!(out, "{n}");
        },
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, indent, level + 1);
                write_value(out, item, indent, level + 1);
            }
            if !items.is_empty() {
                newline(out, indent, level);
            }
            out.push(']');
        },
        Value::Object(m) => {
            out.push('{');
            for (i, (k, item)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, indent, level + 1);
                write_string(out, k);
                out.push(':');
                if indent.is_some() {
                    out.push(' ');
                }
                write_value(out, item, indent, level + 1);
            }
            if !m.is_empty() {
                newline(out, indent, level);
            }
            out.push('}');
        },
    }
}

fn newline(out: &mut String, indent: Option<usize>, level: usize) {
    if let Some(n) = indent {
        out.push('\n');
        for _ in 0..n * level {
            out.push(' ');
        }
    }
}

/// Write a JSON string with the canonical escapes: `"`, `\`, and
/// U+0000–U+001F only (`\b \f \n \r \t`, else `\u00xx` lowercase).
pub fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            },
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Why a document is not canonical JSON in the v0.2 subset.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JsonError {
    /// Not well-formed JSON, or outside the subset.
    #[error("invalid JSON at byte {offset}: {message}")]
    Syntax {
        /// Byte offset of the problem.
        offset: usize,
        /// What was wrong.
        message: String,
    },
    /// An object repeats a key.
    #[error("duplicate key {key:?}")]
    DuplicateKey {
        /// The repeated key.
        key: String,
    },
    /// Nesting deeper than allowed.
    #[error("JSON nested deeper than {max} levels")]
    TooDeep {
        /// The limit.
        max: usize,
    },
    /// Well-formed, but not byte-identical to its canonical form.
    #[error("not in canonical form (sorted keys, no whitespace, minimal escapes)")]
    NotCanonical,
}

/// Parse a canonical JSON document of the v0.2 subset (§3.6), at most
/// `max_depth` levels deep, and require that it is byte-identical to its
/// own canonical serialization.
pub fn parse_canonical(bytes: &[u8], max_depth: usize) -> Result<Value, JsonError> {
    let text = std::str::from_utf8(bytes).map_err(|e| JsonError::Syntax {
        offset: e.valid_up_to(),
        message: "not UTF-8".into(),
    })?;
    let mut p = Parser {
        s: text.as_bytes(),
        text,
        pos: 0,
        max_depth,
    };
    let v = p.value(1)?;
    if p.pos != p.s.len() {
        return Err(p.err("trailing bytes after the document"));
    }
    if v.to_canonical().as_bytes() != bytes {
        return Err(JsonError::NotCanonical);
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    text: &'a str,
    pos: usize,
    max_depth: usize,
}

impl Parser<'_> {
    fn err(&self, message: &str) -> JsonError {
        JsonError::Syntax {
            offset: self.pos,
            message: message.to_string(),
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.s.len() && matches!(self.s[self.pos], b' ' | b'\t' | b'\n' | b'\r') {
            self.pos += 1;
        }
    }

    /// `depth` counts containers: the outermost object or array is level 1.
    fn value(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.skip_ws();
        let Some(&c) = self.s.get(self.pos) else {
            return Err(self.err("unexpected end of input"));
        };
        if matches!(c, b'{' | b'[') && depth > self.max_depth {
            return Err(JsonError::TooDeep {
                max: self.max_depth,
            });
        }
        let v = match c {
            b'{' => self.object(depth)?,
            b'[' => self.array(depth)?,
            b'"' => Value::String(self.string()?),
            b'0'..=b'9' => self.number()?,
            b'-' => return Err(self.err("negative numbers are not allowed")),
            b't' | b'f' => return Err(self.err("booleans are not allowed")),
            b'n' => return Err(self.err("null is not allowed")),
            _ => return Err(self.err("unexpected character")),
        };
        self.skip_ws();
        Ok(v)
    }

    fn object(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.pos += 1;
        let mut m = BTreeMap::new();
        self.skip_ws();
        if self.s.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok(Value::Object(m));
        }
        loop {
            self.skip_ws();
            if self.s.get(self.pos) != Some(&b'"') {
                return Err(self.err("expected a string key"));
            }
            let key = self.string()?;
            if !key.is_ascii() {
                return Err(self.err("object keys must be ASCII"));
            }
            self.skip_ws();
            if self.s.get(self.pos) != Some(&b':') {
                return Err(self.err("expected ':'"));
            }
            self.pos += 1;
            let v = self.value(depth + 1)?;
            if m.insert(key.clone(), v).is_some() {
                return Err(JsonError::DuplicateKey { key });
            }
            match self.s.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(m));
                },
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, JsonError> {
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.s.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            match self.s.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                },
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
    }

    fn number(&mut self) -> Result<Value, JsonError> {
        let start = self.pos;
        while self.pos < self.s.len() && self.s[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        if matches!(self.s.get(self.pos), Some(b'.' | b'e' | b'E')) {
            return Err(self.err("numbers must be integers"));
        }
        let digits = &self.text[start..self.pos];
        if digits.len() > 1 && digits.starts_with('0') {
            return Err(self.err("leading zero"));
        }
        let n: u64 = digits
            .parse()
            .map_err(|_| self.err("integer out of range"))?;
        if n > MAX_SAFE_INT {
            return Err(self.err("integer larger than 2^53 - 1"));
        }
        Ok(Value::Int(n))
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let h = self
            .text
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| self.err("short \\u escape"))?;
        let n = u32::from_str_radix(h, 16).map_err(|_| self.err("bad \\u escape"))?;
        self.pos += 4;
        Ok(n)
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            let Some(&c) = self.s.get(self.pos) else {
                return Err(self.err("unterminated string"));
            };
            match c {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                },
                b'\\' => {
                    self.pos += 1;
                    let Some(&e) = self.s.get(self.pos) else {
                        return Err(self.err("unterminated escape"));
                    };
                    self.pos += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xd800..0xdc00).contains(&hi) {
                                if self.s.get(self.pos..self.pos + 2) != Some(b"\\u") {
                                    return Err(self.err("unpaired surrogate"));
                                }
                                self.pos += 2;
                                let lo = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&lo) {
                                    return Err(self.err("unpaired surrogate"));
                                }
                                0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
                            } else {
                                hi
                            };
                            out.push(char::from_u32(cp).ok_or_else(|| self.err("bad code point"))?);
                        },
                        _ => return Err(self.err("unknown escape")),
                    }
                },
                0x00..=0x1f => return Err(self.err("unescaped control character in string")),
                _ => {
                    // Copy one UTF-8 character.
                    let ch = self.text[self.pos..]
                        .chars()
                        .next()
                        .ok_or_else(|| self.err("bad UTF-8"))?;
                    out.push(ch);
                    self.pos += ch.len_utf8();
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(s: &str) -> Result<Value, JsonError> {
        parse_canonical(s.as_bytes(), 5)
    }

    #[test]
    fn accepts_canonical() {
        let v = canon(r#"{"a":[1,"x\n"],"b":{"c":0}}"#).unwrap();
        assert_eq!(v.get("b").unwrap().get("c").unwrap().as_u64(), Some(0));
    }

    #[test]
    fn rejects_outside_subset() {
        for bad in [
            r#"{"a":1.0}"#,
            r#"{"a":-1}"#,
            r#"{"a":true}"#,
            r#"{"a":null}"#,
            r#"{"a":1,"a":2}"#,
            r#"{"b":1,"a":2}"#,
            r#"{"a": 1}"#,
            "{\"a\":\"\\u0041\"}",
            r#"{"a":"\/"}"#,
            r#"{"a":01}"#,
            r#"{"a":9007199254740992}"#,
            "{\"a\":1}\n",
            "\u{feff}{}",
            r#"{"é":1}"#,
            r#"{"a":"\u001F"}"#,
        ] {
            assert!(canon(bad).is_err(), "accepted {bad}");
        }
        assert!(matches!(
            canon(r#"{"a":1,"a":2}"#),
            Err(JsonError::DuplicateKey { .. })
        ));
    }

    #[test]
    fn escapes_round_trip() {
        let v = Value::str("a\"\\\u{1}\u{7f}é\u{2028}");
        let s = v.to_canonical();
        assert_eq!(s, "\"a\\\"\\\\\\u0001\u{7f}é\u{2028}\"");
        assert_eq!(canon(&s).unwrap(), v);
    }

    #[test]
    fn depth_limit() {
        assert!(canon("[[[[[[1]]]]]]").is_err());
        assert!(canon("[[[[[1]]]]]").is_ok());
    }
}
