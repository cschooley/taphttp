//! The traffic log schema taphttp writes, as a dependency-light crate.
//!
//! Every line of `taphttp start --log-file` (and of stdout, the lever API's
//! `/exchanges`, and its `/feed`) is one [`TrafficEntry`] as JSON. Tools that
//! consume that output depend on this crate instead of mirroring the type, so
//! a schema bump is a compile error rather than silent drift.
//!
//! Dependencies are `serde` and `chrono` (for `ts`) only.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Version of the traffic schema. Written as `"schema_version"` on every
/// serialized [`TrafficEntry`], so a tool tailing the log can detect a
/// breaking change per line.
///
/// - v1: initial schema.
/// - v2: added `replay_of`, linking a replayed exchange to its original.
/// - v3: `req_headers` / `res_headers` are arrays of `[name, value]` pairs in
///   wire order (repeated headers such as `Set-Cookie` are all kept; v2 was a
///   map, which kept one). Header values that are not valid UTF-8 are kept
///   lossily instead of becoming `""`. Bodies are byte-exact: new
///   `req_body_encoding` / `res_body_encoding` are `"utf8"` or `"base64"`,
///   and non-UTF-8 bodies are base64. Every line carries `schema_version`.
///
/// v1 and v2 lines still deserialize: a header map is read as pairs, and a
/// missing encoding means `"utf8"`.
pub const SCHEMA_VERSION: u32 = 3;

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

/// HTTP headers as an ordered list of `(name, value)` pairs.
///
/// Serializes as a JSON array of `[name, value]` arrays. Deserializes from
/// that, or from a v1/v2 `{name: value}` map. Name lookups are ASCII
/// case-insensitive; names are stored as captured (hyper lowercases them).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(Vec<(String, String)>);

impl Headers {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a value, keeping any existing values for the same name.
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.0.push((name.into(), value.into()));
    }

    /// Replace every value for `name` with a single `value`. The new value
    /// takes the position of the first existing one, or goes at the end.
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        match self.0.iter().position(|(k, _)| k.eq_ignore_ascii_case(&name)) {
            Some(first) => {
                self.0[first].1 = value;
                let mut i = 0;
                self.0.retain(|(k, _)| {
                    let keep = i <= first || !k.eq_ignore_ascii_case(&name);
                    i += 1;
                    keep
                });
            }
            None => self.0.push((name, value)),
        }
    }

    /// Remove every value for `name`.
    pub fn remove(&mut self, name: &str) {
        self.0.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    }

    /// The first value for `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Every value for `name`, in wire order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.0
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<K: Into<String>, V: Into<String>> FromIterator<(K, V)> for Headers {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        Self(iter.into_iter().map(|(k, v)| (k.into(), v.into())).collect())
    }
}

impl IntoIterator for Headers {
    type Item = (String, String);
    type IntoIter = std::vec::IntoIter<(String, String)>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Serialize for Headers {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for Headers {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Pairs(Vec<(String, String)>),
            // v1/v2: a map, which could only ever hold one value per name.
            Map(BTreeMap<String, String>),
        }
        match Wire::deserialize(d) {
            Ok(Wire::Pairs(p)) => Ok(Self(p)),
            Ok(Wire::Map(m)) => Ok(Self(m.into_iter().collect())),
            Err(_) => Err(serde::de::Error::custom(
                "headers must be an array of [name, value] pairs or a {name: value} map",
            )),
        }
    }
}

/// Render raw header-value bytes as a string without discarding them.
/// Valid UTF-8 is kept as is; invalid sequences become U+FFFD, so an odd
/// value is still visible rather than replaced with `""`.
pub fn header_value_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

/// How a body string in a [`TrafficEntry`] encodes the captured bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BodyEncoding {
    /// The body string is the bytes, which were valid UTF-8.
    #[default]
    Utf8,
    /// The body string is standard base64 (RFC 4648, padded) of the bytes.
    Base64,
}

/// Encode captured body bytes for storage: `None` for an empty body, the
/// text itself when it is valid UTF-8, base64 otherwise. Byte-exact either
/// way; [`decode_body`] reverses it.
pub fn encode_body(bytes: &[u8]) -> (Option<String>, BodyEncoding) {
    if bytes.is_empty() {
        return (None, BodyEncoding::Utf8);
    }
    match std::str::from_utf8(bytes) {
        Ok(s) => (Some(s.to_owned()), BodyEncoding::Utf8),
        Err(_) => (Some(base64_encode(bytes)), BodyEncoding::Base64),
    }
}

/// Recover the captured bytes from a stored body. `None` means no body.
pub fn decode_body(body: Option<&str>, encoding: BodyEncoding) -> Result<Option<Vec<u8>>, DecodeError> {
    match (body, encoding) {
        (None, _) => Ok(None),
        (Some(s), BodyEncoding::Utf8) => Ok(Some(s.as_bytes().to_vec())),
        (Some(s), BodyEncoding::Base64) => base64_decode(s).map(Some),
    }
}

/// A base64 body that could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(&'static str);

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid base64 body: {}", self.0)
    }
}

impl std::error::Error for DecodeError {}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Hand-rolled to keep this crate's dependencies at serde + chrono.
fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

fn base64_decode(s: &str) -> Result<Vec<u8>, DecodeError> {
    let s = s.as_bytes();
    if !s.len().is_multiple_of(4) {
        return Err(DecodeError("length is not a multiple of 4"));
    }
    let value = |c: u8| -> Result<u32, DecodeError> {
        match c {
            b'A'..=b'Z' => Ok(u32::from(c - b'A')),
            b'a'..=b'z' => Ok(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Ok(u32::from(c - b'0') + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(DecodeError("unexpected character")),
        }
    };
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let quads = s.len() / 4;
    for (i, q) in s.chunks(4).enumerate() {
        let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && i + 1 != quads) {
            return Err(DecodeError("misplaced padding"));
        }
        let mut n = 0u32;
        for &c in &q[..4 - pad] {
            n = (n << 6) | value(c)?;
        }
        n <<= 6 * pad as u32;
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// TrafficEntry
// ---------------------------------------------------------------------------

/// One captured (or replayed) HTTP exchange: a line of the traffic log.
///
/// Serializes with `"schema_version": SCHEMA_VERSION` as its first key. That
/// key is not a field: it describes the shape this crate writes, so an entry
/// read from an older line is re-serialized as the current version. To learn
/// the version of a raw line before parsing it, use [`SchemaProbe`].
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct TrafficEntry {
    /// Stable, never reused. Findings reference exchanges by this id.
    pub id: String,
    pub ts: DateTime<Utc>,
    pub host: String,
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub req_headers: Headers,
    /// Request body, encoded per `req_body_encoding`. Prefer
    /// [`TrafficEntry::req_body_bytes`] to read it.
    #[serde(default)]
    pub req_body: Option<String>,
    #[serde(default)]
    pub req_body_encoding: BodyEncoding,
    pub status: Option<u16>,
    #[serde(default)]
    pub res_headers: Headers,
    /// Response body, encoded per `res_body_encoding`. Prefer
    /// [`TrafficEntry::res_body_bytes`] to read it.
    #[serde(default)]
    pub res_body: Option<String>,
    #[serde(default)]
    pub res_body_encoding: BodyEncoding,
    pub duration_ms: Option<u64>,
    /// If this entry is a replay, the `id` of the original it was replayed from.
    #[serde(default)]
    pub replay_of: Option<String>,
}

impl TrafficEntry {
    /// The request body bytes exactly as captured.
    pub fn req_body_bytes(&self) -> Result<Option<Vec<u8>>, DecodeError> {
        decode_body(self.req_body.as_deref(), self.req_body_encoding)
    }

    /// The response body bytes exactly as captured.
    pub fn res_body_bytes(&self) -> Result<Option<Vec<u8>>, DecodeError> {
        decode_body(self.res_body.as_deref(), self.res_body_encoding)
    }

    /// Store `bytes` as the request body, choosing the encoding.
    pub fn set_req_body(&mut self, bytes: &[u8]) {
        (self.req_body, self.req_body_encoding) = encode_body(bytes);
    }

    /// Store `bytes` as the response body, choosing the encoding.
    pub fn set_res_body(&mut self, bytes: &[u8]) {
        (self.res_body, self.res_body_encoding) = encode_body(bytes);
    }
}

impl Serialize for TrafficEntry {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Keep this list in step with the struct; the
        // `serialized_keys_are_exactly_the_v3_schema` test enforces it.
        let mut st = s.serialize_struct("TrafficEntry", 15)?;
        st.serialize_field("schema_version", &SCHEMA_VERSION)?;
        st.serialize_field("id", &self.id)?;
        st.serialize_field("ts", &self.ts)?;
        st.serialize_field("host", &self.host)?;
        st.serialize_field("method", &self.method)?;
        st.serialize_field("url", &self.url)?;
        st.serialize_field("req_headers", &self.req_headers)?;
        st.serialize_field("req_body", &self.req_body)?;
        st.serialize_field("req_body_encoding", &self.req_body_encoding)?;
        st.serialize_field("status", &self.status)?;
        st.serialize_field("res_headers", &self.res_headers)?;
        st.serialize_field("res_body", &self.res_body)?;
        st.serialize_field("res_body_encoding", &self.res_body_encoding)?;
        st.serialize_field("duration_ms", &self.duration_ms)?;
        st.serialize_field("replay_of", &self.replay_of)?;
        st.end()
    }
}

/// Reads only `schema_version` from a raw log line, so a consumer can check
/// the version before committing to a full parse. `None` means the line
/// predates v3 (v1 or v2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct SchemaProbe {
    #[serde(default)]
    pub schema_version: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> TrafficEntry {
        TrafficEntry {
            id: "e1".into(),
            ts: "2026-11-20T00:00:00Z".parse().unwrap(),
            host: "example.com".into(),
            method: "GET".into(),
            url: "https://example.com/".into(),
            req_headers: Headers::new(),
            req_body: None,
            req_body_encoding: BodyEncoding::Utf8,
            status: Some(200),
            res_headers: Headers::new(),
            res_body: None,
            res_body_encoding: BodyEncoding::Utf8,
            duration_ms: Some(3),
            replay_of: None,
        }
    }

    // --- Headers ---

    #[test]
    fn headers_keep_repeated_values_in_wire_order() {
        let mut h = Headers::new();
        h.append("set-cookie", "a=1; Secure");
        h.append("content-type", "text/html");
        h.append("set-cookie", "b=2; HttpOnly");
        assert_eq!(h.get_all("set-cookie").collect::<Vec<_>>(), ["a=1; Secure", "b=2; HttpOnly"]);
        assert_eq!(h.get("content-type"), Some("text/html"));
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn headers_lookup_is_case_insensitive() {
        let h: Headers = [("Content-Type", "x")].into_iter().collect();
        assert_eq!(h.get("content-type"), Some("x"));
    }

    #[test]
    fn headers_set_replaces_every_value_for_the_name() {
        let mut h: Headers = [("a", "1"), ("cookie", "x"), ("b", "2"), ("Cookie", "y")]
            .into_iter()
            .collect();
        h.set("cookie", "z");
        let pairs: Vec<_> = h.iter().collect();
        assert_eq!(pairs, [("a", "1"), ("cookie", "z"), ("b", "2")]);
    }

    #[test]
    fn headers_set_appends_a_new_name() {
        let mut h: Headers = [("a", "1")].into_iter().collect();
        h.set("b", "2");
        assert_eq!(h.iter().collect::<Vec<_>>(), [("a", "1"), ("b", "2")]);
    }

    #[test]
    fn headers_remove_drops_every_value() {
        let mut h: Headers = [("x", "1"), ("y", "2"), ("X", "3")].into_iter().collect();
        h.remove("x");
        assert_eq!(h.iter().collect::<Vec<_>>(), [("y", "2")]);
    }

    #[test]
    fn headers_serialize_as_pairs() {
        let h: Headers = [("set-cookie", "a"), ("set-cookie", "b")].into_iter().collect();
        assert_eq!(serde_json::to_string(&h).unwrap(), r#"[["set-cookie","a"],["set-cookie","b"]]"#);
    }

    #[test]
    fn headers_deserialize_from_pairs_and_from_v2_map() {
        let pairs: Headers = serde_json::from_str(r#"[["a","1"],["a","2"]]"#).unwrap();
        assert_eq!(pairs.get_all("a").collect::<Vec<_>>(), ["1", "2"]);
        let map: Headers = serde_json::from_str(r#"{"b":"2","a":"1"}"#).unwrap();
        assert_eq!(map.get("a"), Some("1"));
        assert_eq!(map.get("b"), Some("2"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn headers_reject_other_shapes() {
        for bad in [r#""a""#, "[1,2]", r#"[["a"]]"#, r#"{"a":1}"#] {
            assert!(serde_json::from_str::<Headers>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn non_utf8_header_value_is_kept_not_emptied() {
        let s = header_value_to_string(b"caf\xe9");
        assert!(s.starts_with("caf"), "got {s:?}");
        assert_ne!(s, "caf", "the odd byte must remain visible");
        assert_eq!(header_value_to_string(b"plain"), "plain");
    }

    // --- bodies / base64 ---

    #[test]
    fn base64_matches_rfc4648_vectors() {
        let vectors = [
            ("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy"),
        ];
        for (plain, enc) in vectors {
            assert_eq!(base64_encode(plain.as_bytes()), enc);
            assert_eq!(base64_decode(enc).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn base64_roundtrips_every_byte_value() {
        let all: Vec<u8> = (0..=255u8).chain((0..=255u8).rev()).collect();
        for len in 0..all.len() {
            assert_eq!(base64_decode(&base64_encode(&all[..len])).unwrap(), &all[..len]);
        }
    }

    #[test]
    fn base64_rejects_malformed_input() {
        for bad in ["Zg=", "Z===", "Zg==Zg==", "Zm9v!A==", "Zm 9"] {
            assert!(base64_decode(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn encode_body_picks_utf8_base64_or_none() {
        assert_eq!(encode_body(b""), (None, BodyEncoding::Utf8));
        assert_eq!(encode_body(b"hi"), (Some("hi".into()), BodyEncoding::Utf8));
        let (s, enc) = encode_body(&[0x89, b'P', b'N', b'G', 0x00, 0xff]);
        assert_eq!(enc, BodyEncoding::Base64);
        assert_eq!(s.as_deref(), Some("iVBORwD/"));
    }

    #[test]
    fn body_roundtrips_byte_exact_through_json() {
        let bytes: Vec<u8> = vec![0x1f, 0x8b, 0x08, 0x00, 0xff, 0xfe, 0x00, 0x80];
        let mut e = entry();
        e.set_req_body(&bytes);
        e.set_res_body(&bytes);
        let back: TrafficEntry = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(back.req_body_bytes().unwrap().as_deref(), Some(&bytes[..]));
        assert_eq!(back.res_body_bytes().unwrap().as_deref(), Some(&bytes[..]));
    }

    // --- TrafficEntry wire format ---

    #[test]
    fn serialized_keys_are_exactly_the_v3_schema() {
        let v = serde_json::to_value(entry()).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "duration_ms", "host", "id", "method", "replay_of", "req_body",
                "req_body_encoding", "req_headers", "res_body", "res_body_encoding",
                "res_headers", "schema_version", "status", "ts", "url",
            ]
        );
        assert_eq!(v["schema_version"], 3);
        assert_eq!(v["req_body_encoding"], "utf8");
    }

    #[test]
    fn schema_version_is_the_first_key_on_the_line() {
        let line = serde_json::to_string(&entry()).unwrap();
        assert!(line.starts_with(r#"{"schema_version":3,"#), "{line}");
    }

    #[test]
    fn fully_populated_entry_roundtrips() {
        let mut e = entry();
        e.req_headers.append("cookie", "a=1");
        e.req_headers.append("cookie", "b=2");
        e.res_headers.append("set-cookie", "s=1; Secure");
        e.res_headers.append("set-cookie", "t=2; HttpOnly");
        e.set_req_body(b"text");
        e.set_res_body(&[0xff, 0x00]);
        e.replay_of = Some("orig".into());
        let back: TrafficEntry = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn v2_line_still_parses() {
        let v2 = r#"{"id":"old","ts":"2026-11-20T17:03:04.123456789Z","host":"h","method":"POST","url":"http://h/","req_headers":{"content-type":"text/plain"},"req_body":"hi","status":200,"res_headers":{"set-cookie":"a=1"},"res_body":"ok","duration_ms":4,"replay_of":"x"}"#;
        let e: TrafficEntry = serde_json::from_str(v2).unwrap();
        assert_eq!(e.req_headers.get("content-type"), Some("text/plain"));
        assert_eq!(e.res_headers.get_all("set-cookie").collect::<Vec<_>>(), ["a=1"]);
        assert_eq!(e.req_body_encoding, BodyEncoding::Utf8);
        assert_eq!(e.req_body_bytes().unwrap().as_deref(), Some(&b"hi"[..]));
        assert_eq!(e.replay_of.as_deref(), Some("x"));
    }

    #[test]
    fn v1_line_without_replay_of_parses() {
        let v1 = r#"{"id":"a","ts":"2026-01-01T00:00:00Z","host":"h","method":"GET","url":"http://h/","req_headers":{},"req_body":null,"status":null,"res_headers":{},"res_body":null,"duration_ms":null}"#;
        let e: TrafficEntry = serde_json::from_str(v1).unwrap();
        assert!(e.replay_of.is_none());
        assert!(e.req_headers.is_empty());
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let line = r#"{"schema_version":4,"id":"a","ts":"2026-11-20T00:00:00Z","host":"h","method":"GET","url":"/","status":null,"duration_ms":null,"something_new":[1]}"#;
        assert!(serde_json::from_str::<TrafficEntry>(line).is_ok());
    }

    #[test]
    fn unknown_body_encoding_is_an_error() {
        let line = r#"{"id":"a","ts":"2026-11-20T00:00:00Z","host":"h","method":"GET","url":"/","status":null,"duration_ms":null,"res_body":"x","res_body_encoding":"gzip"}"#;
        assert!(serde_json::from_str::<TrafficEntry>(line).is_err());
    }

    #[test]
    fn schema_probe_reads_the_version_or_none() {
        let v3 = serde_json::to_string(&entry()).unwrap();
        let p: SchemaProbe = serde_json::from_str(&v3).unwrap();
        assert_eq!(p.schema_version, Some(SCHEMA_VERSION));
        let p: SchemaProbe = serde_json::from_str(r#"{"id":"old"}"#).unwrap();
        assert_eq!(p.schema_version, None);
    }
}
