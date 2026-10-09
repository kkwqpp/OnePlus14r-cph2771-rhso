use crate::error::{Error, Result};
use rand::RngCore;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
pub fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
pub fn new_id() -> Result<String> {
    let mut b = [0; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut b)
        .map_err(|_| Error::new("E_IO", "Secure randomness is unavailable."))?;
    Ok(hex::encode(b))
}
pub fn valid_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn owner_id() -> i32 {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() as i32 }
    }
    #[cfg(not(unix))]
    {
        -1
    }
}
pub fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
pub fn time(t: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(t)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}
pub fn valid_time(s: &str) -> bool {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).is_ok()
}
pub fn parse_time(s: &str) -> Result<i64> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map(|v| v.unix_timestamp())
        .map_err(|_| Error::new("E_FORMAT", "The timestamp is invalid."))
}
pub fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap_or_default()
        .trim()
        .to_owned()
}
// Scan first, then parse with arbitrary_precision enabled. This prevents silent
// last-key wins and retains unknown HMA numbers without f64 conversion.
pub fn strict_json(b: &[u8]) -> Result<Value> {
    let mut d = serde_json::Deserializer::from_slice(b);
    Scan.deserialize(&mut d).map_err(|_| {
        Error::new(
            "E_INPUT",
            "JSON contains invalid, duplicate or ambiguous fields.",
        )
    })?;
    d.end()
        .map_err(|_| Error::new("E_INPUT", "JSON contains trailing data."))?;
    Ok(serde_json::from_slice(b)?)
}
struct Scan;
impl<'de> DeserializeSeed<'de> for Scan {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> std::result::Result<(), D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Scan {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("unambiguous JSON")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> std::result::Result<(), M::Error> {
        let mut keys = BTreeSet::new();
        while let Some(k) = m.next_key::<String>()? {
            if !keys.insert(k.to_lowercase()) {
                return Err(de::Error::custom("duplicate key"));
            }
            m.next_value_seed(Scan)?;
        }
        Ok(())
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut s: S) -> std::result::Result<(), S::Error> {
        while s.next_element_seed(Scan)?.is_some() {}
        Ok(())
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_str<E: de::Error>(self, _: &str) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_none<E: de::Error>(self) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<(), E> {
        Ok(())
    }
}
