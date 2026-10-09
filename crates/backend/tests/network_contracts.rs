use rhso::{api, inspect, network, public_attestation, util};
use std::collections::BTreeMap;
fn headers(v: &[(&str, &str)]) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::<String, Vec<String>>::new();
    for (k, v) in v {
        out.entry((*k).into()).or_default().push((*v).into());
    }
    out
}
#[test]
fn addresses_refuse_private_transition_documentation_and_benchmark_ranges() {
    for s in [
        "0.0.0.0",
        "0.2.3.4",
        "10.1.2.3",
        "127.0.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.1.1",
        "192.0.0.1",
        "192.0.2.1",
        "192.88.99.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fe80::1",
        "fc00::1",
        "ff00::1",
        "::ffff:127.0.0.1",
        "2001:db8::1",
        "2002:c0a8:101::1",
        "2001::1",
        "3fff::1",
        "64:ff9b::a00:1",
    ] {
        assert!(!network::public_address(s.parse().unwrap()), "{s}");
    }
    for s in [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
        "::ffff:8.8.8.8",
    ] {
        assert!(network::public_address(s.parse().unwrap()), "{s}");
    }
}
#[test]
fn http_framing_never_accepts_redirect_ambiguous_or_truncated_responses() {
    let good =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: 9\r\n\r\n<Keybox/>";
    let r = network::parse_response(good, 100).unwrap();
    assert_eq!(&*r.body, b"<Keybox/>");
    for raw in [
        b"HTTP/1.1 302 Found\r\nLocation: https://example.invalid\r\n\r\nx".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nxy",
        b"HTTP/1.1 200 OK\r\n folded: x\r\n\r\nx",
        b"HTTP/2 200 OK\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nx",
    ] {
        assert!(network::parse_response(raw, 100).is_err());
    }
    assert_eq!(
        network::parse_response(good, 8).err().unwrap().code,
        "E_API_LIMIT"
    );
}
#[test]
fn bounded_chunked_body_requires_complete_terminator() {
    let good=b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    assert_eq!(
        &*network::parse_response(good, 9).unwrap().body,
        b"Wikipedia"
    );
    for suffix in [
        "5\r\nabc\r\n0\r\n\r\n",
        "1\r\naXX0\r\n\r\n",
        "gg\r\nx\r\n0\r\n\r\n",
        "1\r\na\r\n0\r\n",
        "0\r\n\r\nextra",
    ] {
        let raw = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{suffix}");
        assert!(network::parse_response(raw.as_bytes(), 100).is_err());
    }
    assert_eq!(
        network::parse_response(good, 8).err().unwrap().code,
        "E_API_LIMIT"
    );
}
#[test]
fn public_expiry_obeys_age_date_duplicates_and_no_cache() {
    let now = util::parse_time("2026-10-09T00:00:00Z").unwrap();
    let date = "Fri, 09 Oct 2026 00:00:00 GMT";
    assert_eq!(
        public_attestation::expiry(
            &headers(&[("date", date), ("cache-control", "max-age=3600")]),
            now
        ),
        now + 3600
    );
    assert_eq!(
        public_attestation::expiry(
            &headers(&[
                ("date", date),
                ("cache-control", "max-age=3600"),
                ("age", "600")
            ]),
            now
        ),
        now + 3000
    );
    assert_eq!(
        public_attestation::expiry(
            &headers(&[("date", date), ("cache-control", "max-age=3600")]),
            now + 600
        ),
        now + 3600
    );
    for fields in [
        vec![("cache-control", "max-age=3600")],
        vec![("date", date), ("cache-control", "max-age=1, max-age=2")],
        vec![("date", date), ("cache-control", "max-age=-1")],
        vec![("date", date), ("cache-control", "max-age=3600, no-cache")],
        vec![("date", date), ("cache-control", "max-age=3600, no-store")],
        vec![
            ("date", date),
            ("date", date),
            ("cache-control", "max-age=3600"),
        ],
        vec![
            ("date", date),
            ("cache-control", "max-age=3600"),
            ("age", "600"),
            ("age", "0"),
        ],
    ] {
        assert_eq!(public_attestation::expiry(&headers(&fields), now), now);
    }
    assert_eq!(
        public_attestation::expiry(
            &headers(&[("date", date), ("cache-control", "max-age=999999")]),
            now
        ),
        now + 86400
    );
}
#[test]
fn raw_xml_stage_checks_structure_without_private_key_validation() {
    for body in [b"<Keybox/>".as_slice(),b"<?xml version=\"1.0\"?><AndroidAttestation><Keybox><Key>unvalidated staged input</Key></Keybox></AndroidAttestation>",b"<!--comment--><Keybox> text </Keybox>"]{assert!(api::raw_xml(body).is_ok());}
    for body in [
        b"".as_slice(),
        b"<html/>",
        b"<Keybox/><Keybox/>",
        b"<Keybox>",
        b"<Keybox></Different>",
        b"<!DOCTYPE Keybox [<!ENTITY e SYSTEM 'file:///secret'>]><Keybox>&e;</Keybox>",
        b"<Keybox xmlns=\"unexpected\"/>",
        b"<?other data?><Keybox/>",
        b"X<Keybox/>",
        b"\xff<Keybox/>",
        b"<Keybox>\0</Keybox>",
    ] {
        assert!(api::raw_xml(body).is_err(), "{body:?}");
    }
}
#[test]
fn xml_headers_refuse_encrypted_compressed_ambiguous_charsets() {
    for v in [
        "application/xml",
        "text/xml; charset=UTF-8",
        "application/xml; charset=\"us-ascii\"",
    ] {
        assert!(api::xml_headers(&headers(&[("content-type", v)])));
    }
    for v in [
        "application/octet-stream",
        "application/zip",
        "text/html",
        "text/xml; charset=utf-16",
        "text/xml; charset=utf-8; charset=us-ascii",
    ] {
        assert!(!api::xml_headers(&headers(&[("content-type", v)])));
    }
    assert!(!api::xml_headers(&headers(&[
        ("content-type", "text/xml"),
        ("content-type", "text/xml")
    ])));
    assert!(!api::xml_headers(&headers(&[
        ("content-type", "text/xml"),
        ("content-encoding", "gzip")
    ])));
}
#[test]
fn json_casefold_escapes_nested_duplicates_and_large_unknown_numbers() {
    for b in [
        br#"{"a":1,"A":2}"#.as_slice(),
        br#"{"a":{"x":1,"\u0078":2}}"#,
        br#"{"a":1} null"#,
        b"{\"a\":\"\xff\"}",
    ] {
        assert!(util::strict_json(b).is_err());
    }
    let b = br#"{"number":1234567890123456789012345678901234567890,"other":{"ok":true}}"#;
    let v = util::strict_json(b).unwrap();
    assert_eq!(
        v["number"].to_string(),
        "1234567890123456789012345678901234567890"
    );
}
#[test]
fn patch_alignment_rejects_unsupported_overrides_and_substring_coincidences() {
    assert_eq!(
        inspect::patch_alignment("2026-09-05", Some(b"#comments\nall=2026-09-05\n")),
        "aligned"
    );
    for body in [
        b"all=2026-09-05\nall=2026-09-05\n".as_slice(),
        b"all=2026-09-05\nboot=2026-09-05\n",
        b"all=2026-99-99\n",
        b"xall=2026-09-05\n",
    ] {
        assert_eq!(
            inspect::patch_alignment("2026-09-05", Some(body)),
            "ambiguous"
        );
    }
    assert_eq!(inspect::patch_alignment("bad", Some(b"all=bad")), "unknown");
    assert_eq!(inspect::patch_alignment("2026-09-05", None), "unknown");
}
