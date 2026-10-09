use crate::{crypto, fail, Document, Result, MAX_PUBLIC_ROOTS, MAX_PUBLIC_STATUS};
use serde::{
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Serialize,
};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, fmt};
use time::Date;
use zeroize::Zeroizing;

/// Complete public catalog. It has no documented detached signature; callers
/// remain responsible for authenticated acquisition and freshness.
pub struct PublicFeeds {
    roots: Vec<Zeroizing<Vec<u8>>>,
    entries: BTreeMap<String, String>,
}
impl fmt::Debug for PublicFeeds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicFeeds")
            .field("root_count", &self.roots.len())
            .field("entry_count", &self.entries.len())
            .finish()
    }
}
impl PublicFeeds {
    pub fn inventory(&self) -> (usize, usize) {
        (self.roots.len(), self.entries.len())
    }
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PublicKeyCheck {
    pub keybox_index: usize,
    pub key_index: usize,
    pub algorithm: String,
    pub google_root_key: bool,
    pub revocation: &'static str,
    pub listed_certificate_count: usize,
}

struct Unique<'a> {
    depth: usize,
    tokens: &'a mut usize,
    limit: &'a mut bool,
}
impl<'de> DeserializeSeed<'de> for Unique<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> std::result::Result<Value, D::Error> {
        if self.depth > 8 {
            return Err(de::Error::custom("bounded JSON depth exceeded"));
        }
        *self.tokens += 1;
        if *self.tokens > 400_000 {
            *self.limit = true;
            return Err(de::Error::custom("bounded JSON token count exceeded"));
        }
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Unique<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded value with unique object keys")
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: de::Error>(self, b: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(b))
    }
    fn visit_i64<E: de::Error>(self, n: i64) -> std::result::Result<Value, E> {
        Ok(n.into())
    }
    fn visit_u64<E: de::Error>(self, n: u64) -> std::result::Result<Value, E> {
        Ok(n.into())
    }
    fn visit_f64<E: de::Error>(self, n: f64) -> std::result::Result<Value, E> {
        serde_json::Number::from_f64(n)
            .map(Value::Number)
            .ok_or_else(|| de::Error::custom("finite JSON number required"))
    }
    fn visit_str<E: de::Error>(self, s: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(s.into()))
    }
    fn visit_string<E: de::Error>(self, s: String) -> std::result::Result<Value, E> {
        Ok(Value::String(s))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = a.next_element_seed(Unique {
            depth: self.depth + 1,
            tokens: self.tokens,
            limit: self.limit,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = a.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let value = a.next_value_seed(Unique {
                depth: self.depth + 1,
                tokens: self.tokens,
                limit: self.limit,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
fn unique_json(body: &[u8]) -> Result<Value> {
    std::str::from_utf8(body).map_err(|_| fail("E_PUBLIC_SCHEMA"))?;
    let mut d = serde_json::Deserializer::from_slice(body);
    let (mut tokens, mut limit) = (0, false);
    let value = Unique {
        depth: 0,
        tokens: &mut tokens,
        limit: &mut limit,
    }
    .deserialize(&mut d)
    .map_err(|_| {
        fail(if limit {
            "E_PUBLIC_LIMIT"
        } else {
            "E_PUBLIC_SCHEMA"
        })
    })?;
    d.end().map_err(|_| fail("E_PUBLIC_SCHEMA"))?;
    Ok(value)
}
fn serial_valid(serial: &str) -> bool {
    !serial.is_empty()
        && serial.as_bytes()[0] != b'0'
        && serial
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn parse_public_feeds(root_body: &[u8], status_body: &[u8]) -> Result<PublicFeeds> {
    if root_body.is_empty()
        || root_body.len() > MAX_PUBLIC_ROOTS
        || status_body.is_empty()
        || status_body.len() > MAX_PUBLIC_STATUS
    {
        return Err(fail("E_PUBLIC_LIMIT"));
    }
    let roots = unique_json(root_body)?;
    let status = unique_json(status_body)?;
    let roots = roots
        .as_array()
        .filter(|x| !x.is_empty() && x.len() <= 8)
        .ok_or(fail("E_PUBLIC_SCHEMA"))?;
    let mut f = PublicFeeds {
        roots: Vec::new(),
        entries: BTreeMap::new(),
    };
    for root in roots {
        let body = root.as_str().ok_or(fail("E_PUBLIC_SCHEMA"))?;
        if !body.trim().starts_with("-----BEGIN CERTIFICATE-----") {
            return Err(fail("E_PUBLIC_SCHEMA"));
        }
        let pem = crypto::complete_pem(body, false).map_err(|_| fail("E_PUBLIC_SCHEMA"))?;
        if pem.tag != "CERTIFICATE" {
            return Err(fail("E_PUBLIC_SCHEMA"));
        }
        let cert = crypto::certificate(&pem.contents).map_err(|_| fail("E_PUBLIC_SCHEMA"))?;
        crypto::verify_signature(&cert, &cert, true).map_err(|_| fail("E_PUBLIC_SCHEMA"))?;
        for old in &f.roots {
            if crypto::certificate(old)
                .map_err(|_| fail("E_PUBLIC_SCHEMA"))?
                .public_key()
                .raw
                == cert.public_key().raw
            {
                return Err(fail("E_PUBLIC_SCHEMA"));
            }
        }
        f.roots.push(pem.contents);
    }
    let top = status
        .as_object()
        .filter(|x| x.len() == 1)
        .ok_or(fail("E_PUBLIC_SCHEMA"))?;
    let entries = top
        .get("entries")
        .and_then(Value::as_object)
        .filter(|x| x.len() <= 50_000)
        .ok_or(fail("E_PUBLIC_SCHEMA"))?;
    for (serial, entry) in entries {
        if !serial_valid(serial) {
            return Err(fail("E_PUBLIC_SCHEMA"));
        }
        let entry = entry.as_object().ok_or(fail("E_PUBLIC_SCHEMA"))?;
        for (field, value) in entry {
            if !["status", "reason", "comment", "expires"].contains(&field.as_str())
                || !value.is_string()
            {
                return Err(fail("E_PUBLIC_SCHEMA"));
            }
        }
        let state = entry
            .get("status")
            .and_then(Value::as_str)
            .ok_or(fail("E_PUBLIC_SCHEMA"))?;
        if !["REVOKED", "SUSPENDED"].contains(&state) {
            return Err(fail("E_PUBLIC_SCHEMA"));
        }
        if entry
            .get("reason")
            .and_then(Value::as_str)
            .is_some_and(|x| {
                ![
                    "UNSPECIFIED",
                    "KEY_COMPROMISE",
                    "CA_COMPROMISE",
                    "SUPERSEDED",
                    "SOFTWARE_FLAW",
                ]
                .contains(&x)
            })
        {
            return Err(fail("E_PUBLIC_SCHEMA"));
        }
        if entry
            .get("comment")
            .and_then(Value::as_str)
            .is_some_and(|x| x.chars().count() > 140)
        {
            return Err(fail("E_PUBLIC_SCHEMA"));
        }
        if let Some(date) = entry.get("expires").and_then(Value::as_str) {
            let description = time::macros::format_description!("[year]-[month]-[day]");
            if date.len() != 10 || Date::parse(date, description).is_err() {
                return Err(fail("E_PUBLIC_SCHEMA"));
            }
        }
        f.entries.insert(serial.clone(), state.into());
    }
    Ok(f)
}
fn serial_hex(raw: &[u8]) -> String {
    let raw = raw
        .iter()
        .skip_while(|x| **x == 0)
        .copied()
        .collect::<Vec<_>>();
    if raw.is_empty() {
        return "0".into();
    }
    let mut result = String::with_capacity(raw.len() * 2);
    use std::fmt::Write;
    for byte in raw {
        let _ = write!(result, "{byte:02x}");
    }
    result.trim_start_matches('0').into()
}
impl Document {
    pub fn check_public(&self, f: &PublicFeeds) -> Result<Vec<PublicKeyCheck>> {
        if f.roots.is_empty() {
            return Err(fail("E_PUBLIC_SCHEMA"));
        }
        let mut result = Vec::new();
        for (bi, b) in self.boxes.iter().enumerate() {
            for (ki, key) in b.keys.iter().enumerate() {
                let mut ders = Vec::new();
                for body in &key.certificates {
                    let pem =
                        crypto::complete_pem(body, false).map_err(|_| fail("E_PUBLIC_SCHEMA"))?;
                    if pem.tag != "CERTIFICATE" {
                        return Err(fail("E_PUBLIC_SCHEMA"));
                    }
                    ders.push(pem.contents);
                }
                let certs = ders
                    .iter()
                    .map(|x| crypto::certificate(x).map_err(|_| fail("E_PUBLIC_SCHEMA")))
                    .collect::<Result<Vec<_>>>()?;
                let last = certs.last().ok_or(fail("E_PUBLIC_SCHEMA"))?;
                let mut check = PublicKeyCheck {
                    keybox_index: bi,
                    key_index: ki,
                    algorithm: key.algorithm.clone(),
                    google_root_key: false,
                    revocation: "unknown",
                    listed_certificate_count: 0,
                };
                for root in &f.roots {
                    if crypto::certificate(root)
                        .map_err(|_| fail("E_PUBLIC_SCHEMA"))?
                        .public_key()
                        .raw
                        == last.public_key().raw
                    {
                        check.google_root_key = true;
                    }
                }
                if check.google_root_key {
                    check.revocation = "not-listed-as-of-feed";
                    for cert in &certs {
                        if let Some(state) = f.entries.get(&serial_hex(cert.raw_serial())) {
                            check.listed_certificate_count += 1;
                            if state == "REVOKED" {
                                check.revocation = "listed-revoked";
                            } else if check.revocation != "listed-revoked" {
                                check.revocation = "listed-suspended";
                            }
                        }
                    }
                }
                result.push(check);
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_duplicate_utf8_and_depth() {
        for body in [
            br#"{"entries":{},"entries":{}}"#.as_slice(),
            br#"{"\u0065ntries":{},"entries":{}}"#,
            b"{\"x\":\"\xff\"}",
            br#"[[[[[[[[[[0]]]]]]]]]]"#,
            br#"{} true"#,
        ] {
            assert_eq!(unique_json(body).unwrap_err().code, "E_PUBLIC_SCHEMA");
        }
        assert!(unique_json(br#"{"entries":{}}"#).is_ok());
    }
    #[test]
    fn serial_format_and_normalization() {
        for bad in ["", "0", "00", "01", "A", "a-", "a ", "-1"] {
            assert!(!serial_valid(bad));
        }
        for good in ["1", "a", "deadbeef", "1a0"] {
            assert!(serial_valid(good));
        }
        assert_eq!(serial_hex(&[0, 0, 1, 15]), "10f");
        assert_eq!(serial_hex(&[0]), "0");
    }
}
