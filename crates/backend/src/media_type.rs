//! Bounded media-type parsing shared by XML staging and public JSON feeds.
//! Names are case-insensitive; parameter values keep their case. Identical
//! duplicate parameters are accepted, while conflicting duplicates fail closed.
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
pub struct MediaType {
    pub essence: String,
    pub parameters: BTreeMap<String, String>,
}
fn token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`{|}~".contains(&b)
}
fn special(b: u8) -> bool {
    b"()<>@,;:\\\"/[]?=".contains(&b)
}
fn ows(b: u8) -> bool {
    matches!(b, b' ' | b'\t')
}
fn skip_ows(bytes: &[u8], at: &mut usize) {
    while bytes.get(*at).is_some_and(|b| ows(*b)) {
        *at += 1;
    }
}
fn take_token<'a>(value: &'a str, at: &mut usize) -> Option<&'a str> {
    let begin = *at;
    while value.as_bytes().get(*at).is_some_and(|b| token(*b)) {
        *at += 1;
    }
    if *at == begin {
        None
    } else {
        Some(&value[begin..*at])
    }
}
pub fn parse(value: &str) -> Option<MediaType> {
    if value.is_empty()
        || value.len() > 8192
        || value.bytes().any(|b| b < 32 && b != b'\t' || b == 127)
    {
        return None;
    }
    let bytes = value.as_bytes();
    let mut at = 0;
    skip_ows(bytes, &mut at);
    let kind = take_token(value, &mut at)?;
    if bytes.get(at) != Some(&b'/') {
        return None;
    }
    at += 1;
    let subtype = take_token(value, &mut at)?;
    let essence = format!(
        "{}/{}",
        kind.to_ascii_lowercase(),
        subtype.to_ascii_lowercase()
    );
    let mut parameters = BTreeMap::new();
    let mut count = 0;
    loop {
        skip_ows(bytes, &mut at);
        if at == bytes.len() {
            break;
        }
        if bytes.get(at) != Some(&b';') {
            return None;
        }
        at += 1;
        skip_ows(bytes, &mut at);
        if at == bytes.len() {
            break;
        }
        count += 1;
        if count > 64 {
            return None;
        }
        let name = take_token(value, &mut at)?.to_ascii_lowercase();
        // Extended/continued parameters are not silently ignored: encoded
        // charset syntax would require a separately reviewed RFC2231 decoder.
        if name.contains('*') {
            return None;
        }
        skip_ows(bytes, &mut at);
        if bytes.get(at) != Some(&b'=') {
            return None;
        }
        at += 1;
        skip_ows(bytes, &mut at);
        let parameter = if bytes.get(at) == Some(&b'"') {
            at += 1;
            let mut out = Vec::new();
            loop {
                let b = *bytes.get(at)?;
                at += 1;
                if b == b'"' {
                    break;
                }
                if b == b'\\' && bytes.get(at).is_some_and(|next| special(*next)) {
                    out.push(bytes[at]);
                    at += 1;
                } else {
                    out.push(b);
                }
            }
            String::from_utf8(out).ok()?
        } else {
            take_token(value, &mut at)?.to_owned()
        };
        if parameters.get(&name).is_some_and(|old| old != &parameter) {
            return None;
        }
        parameters.insert(name, parameter);
    }
    Some(MediaType {
        essence,
        parameters,
    })
}
pub fn single<'a>(headers: &'a BTreeMap<String, Vec<String>>, name: &str) -> Option<&'a str> {
    let v = headers.get(name)?;
    if v.len() == 1 { Some(&v[0]) } else { None }
}
pub fn uncompressed(headers: &BTreeMap<String, Vec<String>>) -> bool {
    headers
        .get("content-encoding")
        .is_none_or(|v| v.len() == 1 && (v[0].is_empty() || v[0].eq_ignore_ascii_case("identity")))
}
pub fn json_headers(headers: &BTreeMap<String, Vec<String>>) -> bool {
    single(headers, "content-type")
        .and_then(parse)
        .is_some_and(|m| m.essence == "application/json")
        && uncompressed(headers)
}
