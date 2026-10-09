//! Offline, generated fixtures for the network audit boundaries. No endpoint,
//! credential, device certificate or real keybox participates in these tests.
use rhso::{api, fs, media_type, network, util};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

fn headers(value: &str) -> BTreeMap<String, Vec<String>> {
    BTreeMap::from([("content-type".into(), vec![value.into()])])
}

#[test]
fn six_audited_xml_inputs_fail_before_staging_with_format_code() {
    let base = "<?xml version=\"1.0\"?><AndroidAttestation><NumberOfKeyboxes>1</NumberOfKeyboxes><Keybox/></AndroidAttestation>";
    let cases = [
        format!("{base}<![CDATA[outside]]>"),
        format!("{base}&undefined;"),
        base.replacen(
            "<AndroidAttestation>",
            "<!-- a -- b --><AndroidAttestation>",
            1,
        ),
        base.replacen("<NumberOfKeyboxes>1", "<NumberOfKeyboxes>\u{1}1", 1),
        base.replacen(
            "version=\"1.0\"",
            "version=\"1.0\" encoding=\"ISO-8859-1\"",
            1,
        ),
        base.replacen("<NumberOfKeyboxes>", "<NumberOfKeyboxes bogus>", 1),
    ];
    assert!(api::raw_xml(base.as_bytes()).is_ok());
    for input in cases {
        assert_eq!(
            api::raw_xml(input.as_bytes()).unwrap_err().code,
            "E_API_FORMAT"
        );
    }
}

#[test]
fn xml_inspects_all_attributes_names_declarations_and_character_ranges() {
    for input in [
        "<Keybox><Nested a='1' a='1'/></Keybox>",
        "<Keybox><Nested xmlns='urn:unexpected'/></Keybox>",
        "<Keybox><Nested n:a='1'/></Keybox>",
        "<Keybox><Nested a='x<y'/></Keybox>",
        "<Keybox><Nested a='&amp;'/></Keybox>",
        "<Keybox><Nested>&#65;</Nested></Keybox>",
        "<Keybox><n:Nested/></Keybox>",
        "<Keybox><1Nested/></Keybox>",
        "<Keybox>\u{fffe}</Keybox>",
        "<Keybox>\u{ffff}</Keybox>",
        "<Keybox/>\u{b}",
        "<Keybox/><?xml version='1.0'?>",
        "<?xml version='1.0'?><?xml version='1.0'?><Keybox/>",
        "<?xml version='1.1'?><Keybox/>",
        "<?xml version='1.0\"?><Keybox/>",
        "<?xml encoding='utf-8' version='1.0'?><Keybox/>",
        "<Keybox><A></B></Keybox>",
        "<Keybox/>after",
        "<!DOCTYPE Keybox><Keybox/>",
        "<Keybox><?processing data?></Keybox>",
    ] {
        assert_eq!(
            api::raw_xml(input.as_bytes()).unwrap_err().code,
            "E_API_FORMAT",
            "{input}"
        );
    }
    for input in [
        "<Keybox/>",
        "<?xml version='1.0' encoding='UTF-8' standalone='no'?><Keybox a='safe'><Nested><![CDATA[plain staged text]]></Nested></Keybox>",
        "<!-- before --><Keybox>\t\r\n \u{1f600}</Keybox><!-- after -->",
    ] {
        assert!(api::raw_xml(input.as_bytes()).is_ok(), "{input}");
    }
    // Staging deliberately checks supported XML syntax, not key ownership,
    // signature validity, provider identity or whether a keybox can be applied.
    assert!(api::raw_xml(b"<Keybox><Key>not a private key</Key></Keybox>").is_ok());
    let deep = format!("<Keybox>{}{}</Keybox>", "<A>".repeat(32), "</A>".repeat(32));
    assert_eq!(
        api::raw_xml(deep.as_bytes()).unwrap_err().code,
        "E_API_LIMIT"
    );
}

#[test]
fn media_type_matches_go_ordinary_parameter_semantics() {
    for value in [
        "text/xml; a=one; a=one",
        "text/xml; charset=utf-8; CHARSET=utf-8",
        "TEXT/XML ; Charset = \"UTF-8\" ; a = one\t; A = one;",
        "\tapplication/XML\t; a=\"a\\\"b\"; A=\"a\\\"b\"\t",
        "text/xml; charset=\"\"",
    ] {
        assert!(api::xml_headers(&headers(value)), "{value}");
    }
    for value in [
        "text/xml; a=one; A=two",
        "text/xml; charset=UTF-8; charset=utf-8",
        "text/xml; a=\"open",
        "text/xml; a=",
        "text/xml; a=one two",
        "text/xml;;",
        "text/xml; a=\"x\r\ny\"",
        "text/xml; charset=utf-16",
        "text /xml",
        "text/xml; charset*=UTF-8''utf-16",
    ] {
        assert!(!api::xml_headers(&headers(value)), "{value}");
    }
    let parsed = media_type::parse(r#"Text/XML; A="a\"b"; b="x\qy"; c="x\\y""#).unwrap();
    assert_eq!(parsed.essence, "text/xml");
    assert_eq!(parsed.parameters["a"], "a\"b");
    assert_eq!(parsed.parameters["b"], "x\\qy");
    assert_eq!(parsed.parameters["c"], "x\\y");
    assert!(media_type::parse(&"a".repeat(8193)).is_none());
    let too_many = format!("text/xml{}", "; a=one".repeat(65));
    assert!(media_type::parse(&too_many).is_none());
}

#[test]
fn json_and_xml_share_duplicate_rejection_before_body_reads() {
    for essence in ["application/xml", "application/json"] {
        let xml = essence.ends_with("xml");
        for (parameters, good) in [
            ("; a=one; A=one", true),
            ("; a=one; a=two", false),
            ("; a=\"quoted\\\"value\"", true),
        ] {
            let body = if xml { "<Keybox/>" } else { "{}" };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {essence}{parameters}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let actual = network::read_response(&mut response.as_bytes(), 100, xml);
            assert_eq!(actual.is_ok(), good, "{essence}{parameters}");
            if !good {
                assert_eq!(
                    actual.err().unwrap().code,
                    if xml { "E_API_FORMAT" } else { "E_PUBLIC_FEED" }
                );
            }
        }
    }
    let mut h = headers("application/json");
    assert!(media_type::json_headers(&h));
    h.insert("content-encoding".into(), vec!["gzip".into()]);
    assert!(!media_type::json_headers(&h));
    h.insert(
        "content-encoding".into(),
        vec!["identity".into(), "identity".into()],
    );
    assert!(!media_type::json_headers(&h));
    h.remove("content-encoding");
    h.get_mut("content-type")
        .unwrap()
        .push("application/json".into());
    assert!(!media_type::json_headers(&h));
}

fn directory(path: &Path) {
    fs::private_dir(path).unwrap();
}
fn certificate() -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["offline-root.invalid".into()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.self_signed(&key).unwrap().pem()
}

#[test]
fn android_aliases_only_resolve_to_fixed_system_paths() {
    let apex = Path::new("/apex/com.android.conscrypt/cacerts");
    let legacy = Path::new("/system/etc/security/cacerts");
    for path in [
        "/apex/com.android.conscrypt/cacerts",
        "/apex/com.android.conscrypt@350000000/cacerts",
    ] {
        assert!(network::approved_android_trust_path(apex, Path::new(path)));
    }
    assert!(network::approved_android_trust_path(legacy, legacy));
    for path in [
        "/data/misc/keychain/cacerts-added",
        "/tmp/cacerts",
        "/apex/com.android.conscrypt@/cacerts",
        "/apex/com.android.conscrypt@x/cacerts",
        "/apex/com.android.conscrypt@123/cacerts/extra",
        "/apex/com.android.conscrypt@123/../cacerts",
    ] {
        assert!(
            !network::approved_android_trust_path(apex, Path::new(path)),
            "{path}"
        );
    }
    assert!(!network::approved_android_trust_path(legacy, apex));
    assert!(!network::approved_android_trust_path(
        Path::new("/data/user-roots"),
        legacy
    ));
}

#[test]
fn android_system_fixture_skips_individual_bad_roots_without_mozilla_fallback() {
    let t = tempfile::tempdir().unwrap();
    let apex = t.path().join("apex");
    let legacy = t.path().join("legacy");
    directory(&apex);
    directory(&legacy);
    std::fs::write(
        apex.join("bad-pem.0"),
        "-----BEGIN CERTIFICATE-----\n!invalid!\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(apex.join("oversized.0"), vec![b'x'; (16 << 10) + 1]).unwrap();
    std::fs::write(
        apex.join("invalid-and-good.0"),
        format!(
            "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n{}",
            certificate()
        ),
    )
    .unwrap();
    std::fs::write(legacy.join("good.0"), certificate()).unwrap();
    let loaded = network::load_system_root_directories(&[apex, legacy], util::owner_id()).unwrap();
    assert_eq!(loaded.usable_certificates, 2);
    assert_eq!(loaded.roots.len(), 2); // An empty initial pool, never Mozilla+system.
    assert!(loaded.skipped_files >= 2);
    assert!(loaded.skipped_certificates >= 2);
}

#[test]
fn android_system_fixture_fails_with_empty_bad_unowned_or_unbounded_store() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("store");
    directory(&p);
    for paths in [Vec::<PathBuf>::new(), vec![p.clone()]] {
        assert_eq!(
            network::load_system_root_directories(&paths, util::owner_id())
                .err()
                .unwrap()
                .code,
            "E_API_TLS"
        );
    }
    std::fs::write(p.join("bad.0"), "not a certificate").unwrap();
    assert_eq!(
        network::load_system_root_directories(std::slice::from_ref(&p), util::owner_id())
            .err()
            .unwrap()
            .code,
        "E_API_TLS"
    );
    std::fs::write(p.join("good.0"), certificate()).unwrap();
    assert!(
        network::load_system_root_directories(std::slice::from_ref(&p), util::owner_id() + 1)
            .is_err()
    );
    assert!(
        network::load_system_root_directories(&[p.clone(), p.clone(), p.clone()], util::owner_id())
            .is_err()
    );
    assert!(
        network::load_system_root_directories(&[PathBuf::from("relative")], util::owner_id())
            .is_err()
    );
    for index in 0..1000 {
        std::fs::write(p.join(format!("entry-{index}")), []).unwrap();
    }
    assert_eq!(
        network::load_system_root_directories(&[p], util::owner_id())
            .err()
            .unwrap()
            .code,
        "E_API_TLS"
    );
}

#[cfg(unix)]
#[test]
fn android_system_fixture_rejects_links_and_writable_roots() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("store");
    directory(&p);
    let good = t.path().join("external");
    std::fs::write(&good, certificate()).unwrap();
    symlink(&good, p.join("linked.0")).unwrap();
    assert!(
        network::load_system_root_directories(std::slice::from_ref(&p), util::owner_id()).is_err()
    );
    std::fs::write(p.join("good.0"), certificate()).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        network::load_system_root_directories(std::slice::from_ref(&p), util::owner_id()).is_err()
    );
}
