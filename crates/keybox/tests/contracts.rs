use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SerialNumber, PKCS_ECDSA_P384_SHA384, PKCS_RSA_SHA256,
};
use rhso_keybox::*;
use rsa::{pkcs1::EncodeRsaPrivateKey, RsaPrivateKey};
use std::sync::OnceLock;
use time::OffsetDateTime;

const NOW: i64 = 1_791_547_200;
#[derive(Clone)]
struct Fixture {
    algorithm: &'static str,
    private: String,
    certs: Vec<String>,
}
fn parameters(name: &str, serial: u64, until: i64, path: u8) -> CertificateParams {
    let mut p = CertificateParams::default();
    p.distinguished_name.push(DnType::CommonName, name);
    p.serial_number = Some(SerialNumber::from(serial));
    p.not_before = OffsetDateTime::from_unix_timestamp(NOW - 3600).unwrap();
    p.not_after = OffsetDateTime::from_unix_timestamp(until).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(path));
    p.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    p
}
fn fixture(algorithm: &'static str, bits: usize) -> Fixture {
    let root_key = KeyPair::generate().unwrap();
    let root = parameters("Sensitive root identity", 1, NOW + 172800, 5)
        .self_signed(&root_key)
        .unwrap();
    let (key, private) = if algorithm == "rsa" {
        let pk = RsaPrivateKey::new(&mut rand::thread_rng(), bits).unwrap();
        let private = pk.to_pkcs8_pem(pkcs8::LineEnding::LF).unwrap().to_string();
        let key = KeyPair::from_pem_and_sign_algo(&private, &PKCS_RSA_SHA256).unwrap();
        (key, private)
    } else {
        let key = if bits == 384 {
            KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap()
        } else {
            KeyPair::generate().unwrap()
        };
        let private = key.serialize_pem();
        (key, private)
    };
    let leaf = parameters("Sensitive signing identity", 2, NOW + 86400, 5)
        .signed_by(&key, &root, &root_key)
        .unwrap();
    Fixture {
        algorithm,
        private,
        certs: vec![leaf.pem(), root.pem()],
    }
}
fn ec() -> Fixture {
    static VALUE: OnceLock<Fixture> = OnceLock::new();
    VALUE.get_or_init(|| fixture("ecdsa", 256)).clone()
}
fn rsa2048() -> Fixture {
    static VALUE: OnceLock<Fixture> = OnceLock::new();
    VALUE.get_or_init(|| fixture("rsa", 2048)).clone()
}
fn xml(boxes: &[Vec<Fixture>]) -> Vec<u8> {
    let mut out = format!(
        "<?xml version=\"1.0\"?><AndroidAttestation><NumberOfKeyboxes>{}</NumberOfKeyboxes>",
        boxes.len()
    );
    for b in boxes {
        out.push_str("<Keybox DeviceID=\"owner-secret-device-id\">");
        for f in b {
            out.push_str(&format!("<Key algorithm=\"{}\"><PrivateKey format=\"pem\">{}</PrivateKey><CertificateChain><NumberOfCertificates>{}</NumberOfCertificates>",f.algorithm,f.private,f.certs.len()));
            for c in &f.certs {
                out.push_str(&format!("<Certificate format=\"pem\">{c}</Certificate>"));
            }
            out.push_str("</CertificateChain></Key>");
        }
        out.push_str("</Keybox>");
    }
    out.push_str("</AndroidAttestation>");
    out.into_bytes()
}
fn reject(data: &[u8], code: &str) {
    assert_eq!(parse(data, NOW).unwrap_err().code, code);
}
fn selection(source: i64, keybox: i64, key: i64, algorithm: &str) -> Selection {
    Selection {
        source,
        keybox,
        key,
        algorithm: algorithm.into(),
    }
}

#[test]
fn algorithms_and_merge_preserve_math_and_chains() {
    let e = ec();
    let r = rsa2048();
    let p = fixture("ecdsa", 384);
    for (f, param) in [(&e, "P-256"), (&r, "2048"), (&p, "P-384")] {
        let doc = parse(&xml(&[vec![f.clone()]]), NOW).unwrap();
        let summary = doc.summary();
        assert_eq!(summary.keyboxes[0].keys[0].parameter, param);
        assert_eq!(summary.trust, "unknown");
        assert_eq!(summary.revocation, "unknown");
    }
    let a = parse(&xml(&[vec![e.clone()]]), NOW).unwrap();
    let b = parse(&xml(&[vec![r.clone()]]), NOW).unwrap();
    let merged = merge(
        &[&a, &b],
        &[selection(1, 0, 0, "rsa"), selection(0, 0, 0, "ecdsa")],
        NOW,
    )
    .unwrap();
    let output = merged.xml().unwrap();
    let text = String::from_utf8(output.to_vec()).unwrap();
    assert!(text.contains("BEGIN EC PRIVATE KEY"));
    assert!(text.contains("BEGIN RSA PRIVATE KEY"));
    assert!(!text.contains("BEGIN PRIVATE KEY"));
    for c in e.certs.iter().chain(r.certs.iter()) {
        assert!(text.contains(c.trim()));
    }
    let round = parse(&output, NOW).unwrap();
    assert_eq!(round.summary().keyboxes[0].keys.len(), 2);
    assert_eq!(round.summary().keyboxes[0].keys[0].algorithm, "ecdsa");
    assert_eq!(merged.summary().metadata_device_id, Some(OUTPUT_DEVICE_ID));
    assert!(merged.summary().keyboxes[0].keys.iter().all(|k| k
        .warnings
        .contains(&"private_key_encoding_normalized_for_installed_engine".into())));
}
#[test]
fn explicit_selection_duplicate_and_expiry_guards() {
    let e = ec();
    let p = fixture("ecdsa", 384);
    let doc = parse(&xml(&[vec![e.clone(), p], vec![e]]), NOW).unwrap();
    assert_eq!(doc.summary().keyboxes.len(), 2);
    assert!(doc.summary().keyboxes[0]
        .warnings
        .contains(&"duplicate_algorithm_explicit_selection_required".into()));
    let selected = merge(&[&doc], &[selection(0, 0, 1, "ecdsa")], NOW).unwrap();
    assert_eq!(selected.summary().keyboxes[0].keys[0].parameter, "P-384");
    for (selection, code) in [
        (vec![], "E_SELECTION"),
        (vec![selection(-1, 0, 0, "ecdsa")], "E_SELECTION"),
        (vec![selection(0, 8, 0, "ecdsa")], "E_SELECTION"),
        (vec![selection(0, 0, 8, "ecdsa")], "E_SELECTION"),
        (vec![selection(0, 0, 0, "rsa")], "E_SELECTION_ALGORITHM"),
        (
            vec![selection(0, 0, 0, "ecdsa"), selection(0, 0, 1, "ecdsa")],
            "E_SELECTION_CONFLICT",
        ),
    ] {
        assert_eq!(merge(&[&doc], &selection, NOW).unwrap_err().code, code);
    }
    assert_eq!(
        merge(&[&doc], &[selection(0, 0, 0, "ecdsa")], NOW + 259200)
            .unwrap_err()
            .code,
        "E_CERT_TIME"
    );
}
#[test]
fn hostile_xml_and_pem_reject_with_fixed_codes() {
    let f = ec();
    let valid = String::from_utf8(xml(&[vec![f.clone()]])).unwrap();
    let cases = vec![
        (
            format!("<!DOCTYPE AndroidAttestation SYSTEM \"file:///private\">{valid}"),
            "E_XML_DIRECTIVE",
        ),
        (
            valid.replacen("owner-secret-device-id", "owner&amp;id", 1),
            "E_XML_ENTITY",
        ),
        (
            valid.replacen("</Keybox>", "<Unexpected/></Keybox>", 1),
            "E_SCHEMA",
        ),
        (
            valid.replacen("<Keybox ", "<Keybox extra=\"x\" ", 1),
            "E_SCHEMA",
        ),
        (
            valid.replacen(
                "<AndroidAttestation>",
                "<AndroidAttestation xmlns=\"urn:x\">",
                1,
            ),
            "E_SCHEMA",
        ),
        (
            valid.replacen("<Keybox ", "<Keybox DeviceID=\"extra\" ", 1),
            "E_SCHEMA",
        ),
        (
            valid.replacen("<NumberOfCertificates>2", "<NumberOfCertificates>3", 1),
            "E_COUNT",
        ),
        (
            valid.replacen("<NumberOfKeyboxes>1", "<NumberOfKeyboxes>2", 1),
            "E_COUNT",
        ),
        (
            valid.replacen("algorithm=\"ecdsa\"", "algorithm=\"ECDSA\"", 1),
            "E_ALGORITHM",
        ),
        (
            valid.replacen("format=\"pem\"", "format=\"der\"", 1),
            "E_SCHEMA",
        ),
        (
            valid.replacen("?>", "?><?run command?>", 1),
            "E_XML_PROCESSING",
        ),
        (
            valid.replacen(
                "version=\"1.0\"",
                "version=\"1.0\" encoding=\"ISO-8859-1\"",
                1,
            ),
            "E_XML",
        ),
        (format!("{valid}<AndroidAttestation/>"), "E_SCHEMA"),
        (valid[..valid.len() - 10].to_owned(), "E_XML"),
        (
            valid.replacen(&f.private, &format!("garbage\n{}", f.private), 1),
            "E_PRIVATE_PEM",
        ),
        (
            valid.replacen(&f.private, &format!("{}{}", f.private, f.private), 1),
            "E_PRIVATE_PEM",
        ),
        (
            valid.replacen("-----END PRIVATE KEY-----", "", 1),
            "E_PRIVATE_PEM",
        ),
        (
            valid.replacen(&f.certs[0], &format!("garbage\n{}", f.certs[0]), 1),
            "E_CERT_PEM",
        ),
        (
            valid.replacen(&f.certs[0], &format!("{}{}", f.certs[0], f.certs[0]), 1),
            "E_CERT_PEM",
        ),
    ];
    for (data, code) in cases {
        reject(data.as_bytes(), code);
    }
    reject(&[], "E_SIZE");
    reject(&vec![b'x'; MAX_INPUT + 1], "E_SIZE");
    reject(
        format!(
            "<AndroidAttestation>{}</AndroidAttestation>",
            "<!--x-->".repeat(4096)
        )
        .as_bytes(),
        "E_LIMIT",
    );
    reject(
        format!(
            "<AndroidAttestation><!--{}--></AndroidAttestation>",
            "x".repeat(4097)
        )
        .as_bytes(),
        "E_LIMIT",
    );
    assert_eq!(
        parse(valid.as_bytes(), -62_135_596_800).unwrap_err().code,
        "E_TIME"
    );
}
#[test]
fn rejects_crypto_mismatch_order_signature_duplicate_and_dates() {
    let f = ec();
    let other = fixture("ecdsa", 256);
    let mut invalid = f.clone();
    invalid.private = other.private.clone();
    reject(&xml(&[vec![invalid]]), "E_KEY_MISMATCH");
    let mut invalid = f.clone();
    invalid.certs.reverse();
    reject(&xml(&[vec![invalid]]), "E_KEY_MISMATCH");
    let mut invalid = f.clone();
    invalid.certs[1] = other.certs[1].clone();
    reject(&xml(&[vec![invalid]]), "E_CHAIN_SIGNATURE");
    let mut invalid = f.clone();
    invalid.certs.truncate(1);
    reject(&xml(&[vec![invalid]]), "E_CHAIN_INCOMPLETE");
    let mut invalid = f.clone();
    invalid.certs.push(f.certs[1].clone());
    reject(&xml(&[vec![invalid]]), "E_CHAIN_DUPLICATE");
    let mut invalid = f.clone();
    invalid.algorithm = "rsa";
    reject(&xml(&[vec![invalid]]), "E_ALGORITHM_MISMATCH");
    for now in [NOW - 259200, NOW + 259200] {
        assert_eq!(
            parse(&xml(&[vec![f.clone()]]), now).unwrap_err().code,
            "E_CERT_TIME"
        );
    }
    let pk = RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
    let mut invalid = rsa2048();
    invalid.private = pk.to_pkcs1_pem(pkcs8::LineEnding::LF).unwrap().to_string();
    reject(&xml(&[vec![invalid]]), "E_PARAMETERS");
}
#[test]
fn traditional_and_indented_pem_are_supported_without_repairing_damage() {
    use pkcs8::der::{Decode, Encode};
    let mut f = ec();
    let pk = p256::SecretKey::from_pkcs8_pem(&f.private).unwrap();
    let der = pk.to_sec1_der().unwrap();
    let mut encoded = sec1::EcPrivateKey::from_der(&der).unwrap();
    encoded.parameters = Some(sec1::EcParameters::NamedCurve(
        pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"),
    ));
    f.private = pem::encode(&pem::Pem::new("EC PRIVATE KEY", encoded.to_der().unwrap()));
    assert_eq!(
        parse(&xml(&[vec![f.clone()]]), NOW)
            .unwrap()
            .summary()
            .keyboxes[0]
            .keys[0]
            .private_key_format,
        "sec1"
    );
    let indent = |s: &str| {
        format!(
            "\n{}\n",
            s.trim()
                .split('\n')
                .map(|x| format!(" \t {x}\t "))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };
    f.private = indent(&f.private);
    for c in &mut f.certs {
        *c = indent(c);
    }
    let d = parse(&xml(&[vec![f.clone()]]), NOW).unwrap();
    let key = &d.summary().keyboxes[0].keys[0];
    assert!(key
        .warnings
        .contains(&"private_key_pem_whitespace_normalized".into()));
    assert!(key
        .warnings
        .contains(&"certificate_pem_whitespace_normalized".into()));
    let m = merge(&[&d], &[selection(0, 0, 0, "ecdsa")], NOW).unwrap();
    assert!(parse(&m.xml().unwrap(), NOW).is_ok());
    f.private = format!("\u{00a0}{}", f.private.trim());
    reject(&xml(&[vec![f]]), "E_PRIVATE_PEM");
}
#[test]
fn all_document_formatting_redacts_original_material() {
    let f = ec();
    let d = parse(&xml(&[vec![f.clone()]]), NOW).unwrap();
    for text in [
        serde_json::to_string(&d).unwrap(),
        format!("{d}"),
        format!("{d:?}"),
        format!("{d:#?}"),
    ] {
        for secret in [
            "owner-secret-device-id",
            "Sensitive root identity",
            "Sensitive signing identity",
            "BEGIN PRIVATE KEY",
            "BEGIN CERTIFICATE",
            f.private.trim(),
        ] {
            assert!(!text.contains(secret));
        }
        assert!(text.contains("\"trust\":\"unknown\""));
        assert!(text.contains("\"wallet_acceptance\":\"not_assessed\""));
    }
    let damaged = xml(&[vec![Fixture {
        private: "secret-sentinel".into(),
        ..f
    }]]);
    let audited = audit(&damaged, NOW);
    let text = serde_json::to_string(&audited).unwrap();
    assert!(!text.contains("secret-sentinel"));
    assert!(audited["structural_inventory_only"].as_bool().unwrap());
}
fn public(root: &str, entries: serde_json::Value) -> PublicFeeds {
    parse_public_feeds(
        &serde_json::to_vec(&vec![root]).unwrap(),
        &serde_json::to_vec(&serde_json::json!({"entries":entries})).unwrap(),
    )
    .unwrap()
}
#[test]
fn public_schema_status_precedence_and_unknown_context() {
    let f = ec();
    let other = fixture("ecdsa", 256);
    let d = parse(&xml(&[vec![f.clone()], vec![other]]), NOW).unwrap();
    let feed = public(
        &f.certs[1],
        serde_json::json!({"1":{"status":"SUSPENDED"},"2":{"status":"REVOKED","reason":"KEY_COMPROMISE","comment":"界".repeat(140),"expires":"2028-02-29"}}),
    );
    assert_eq!(feed.inventory(), (1, 2));
    let checks = d.check_public(&feed).unwrap();
    assert_eq!(checks.len(), 2);
    assert!(checks[0].google_root_key);
    assert_eq!(checks[0].revocation, "listed-revoked");
    assert_eq!(checks[0].listed_certificate_count, 2);
    assert!(!checks[1].google_root_key);
    assert_eq!(checks[1].revocation, "unknown");
    assert_eq!(checks[1].listed_certificate_count, 0);
    let empty = d
        .check_public(&public(&f.certs[1], serde_json::json!({})))
        .unwrap();
    assert_eq!(empty[0].revocation, "not-listed-as-of-feed");
    let suspended = d
        .check_public(&public(
            &f.certs[1],
            serde_json::json!({"2":{"status":"SUSPENDED","expires":"2020-01-01"}}),
        ))
        .unwrap();
    assert_eq!(suspended[0].revocation, "listed-suspended");
    let text = serde_json::to_string(&checks).unwrap();
    for secret in [
        "Sensitive",
        "BEGIN",
        "owner-secret",
        "hardware_valid",
        "wallet_passed",
    ] {
        assert!(!text.contains(secret));
    }
}
#[test]
fn public_rejects_ambiguous_malformed_and_out_of_contract_fields() {
    let f = ec();
    let roots = serde_json::to_vec(&vec![&f.certs[1]]).unwrap();
    let status_cases = [
        r#"null"#,
        r#"{"entries":null}"#,
        r#"{"entries":{},"x":true}"#,
        r#"{"entries":{"01":{"status":"REVOKED"}}}"#,
        r#"{"entries":{"A":{"status":"REVOKED"}}}"#,
        r#"{"entries":{"a":{"status":"VALID"}}}"#,
        r#"{"entries":{"a":{"status":null}}}"#,
        r#"{"entries":{"a":{"status":"REVOKED","reason":"UNKNOWN"}}}"#,
        r#"{"entries":{"a":{"status":"REVOKED","comment":false}}}"#,
        r#"{"entries":{"a":{"status":"REVOKED","expires":"2027-02-29"}}}"#,
        r#"{"entries":{"a":{"status":"REVOKED","x":"secret-sentinel"}}}"#,
        r#"{"entries":{},"entries":{}}"#,
        r#"{"entries":{"a":{"status":"REVOKED","status":"SUSPENDED"}}}"#,
        r#"{"entries":{}} true"#,
    ];
    for status in status_cases {
        let err = parse_public_feeds(&roots, status.as_bytes()).unwrap_err();
        assert_eq!(err.code, "E_PUBLIC_SCHEMA");
        assert!(!err.to_string().contains("secret-sentinel"));
    }
    for roots in [
        serde_json::json!([]),
        serde_json::json!([null]),
        serde_json::json!([f.private]),
        serde_json::json!([f.certs[1], f.certs[1]]),
    ] {
        assert_eq!(
            parse_public_feeds(&serde_json::to_vec(&roots).unwrap(), br#"{"entries":{}}"#)
                .unwrap_err()
                .code,
            "E_PUBLIC_SCHEMA"
        );
    }
    assert_eq!(
        parse_public_feeds(&[], br#"{"entries":{}}"#)
            .unwrap_err()
            .code,
        "E_PUBLIC_LIMIT"
    );
    for reason in [
        "UNSPECIFIED",
        "KEY_COMPROMISE",
        "CA_COMPROMISE",
        "SUPERSEDED",
        "SOFTWARE_FLAW",
    ] {
        assert_eq!(
            public(
                &ec().certs[1],
                serde_json::json!({"a":{"status":"REVOKED","reason":reason}})
            )
            .inventory(),
            (1, 1)
        );
    }
}
#[test]
fn expired_non_ca_public_root_uses_only_its_signature_policy() {
    let key = KeyPair::generate().unwrap();
    let mut params = parameters("Synthetic expired catalog root", 3, NOW - 172800, 5);
    params.not_before = OffsetDateTime::from_unix_timestamp(NOW - 259200).unwrap();
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let root = params.self_signed(&key).unwrap();
    assert_eq!(
        public(&root.pem(), serde_json::json!({})).inventory(),
        (1, 0)
    );
}
fn chain_fixture(path: u8, ca: bool, key_sign: bool, critical: bool) -> Fixture {
    let root_key = KeyPair::generate().unwrap();
    let root = parameters("Root", 1, NOW + 172800, path)
        .self_signed(&root_key)
        .unwrap();
    let inter_key = KeyPair::generate().unwrap();
    let mut inter_params = parameters("Intermediate", 2, NOW + 172800, 5);
    if !ca {
        inter_params.is_ca = IsCa::NoCa;
    }
    if !key_sign {
        inter_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    }
    let inter = inter_params
        .signed_by(&inter_key, &root, &root_key)
        .unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = parameters("Leaf", 3, NOW + 86400, 5);
    if critical {
        let mut ext = rcgen::CustomExtension::from_oid_content(&[1, 2, 3, 4], vec![5, 0]);
        ext.set_criticality(true);
        leaf_params.custom_extensions.push(ext);
    }
    let leaf: Certificate = leaf_params
        .signed_by(&leaf_key, &inter, &inter_key)
        .unwrap();
    Fixture {
        algorithm: "ecdsa",
        private: leaf_key.serialize_pem(),
        certs: vec![leaf.pem(), inter.pem(), root.pem()],
    }
}
#[test]
fn ca_key_usage_path_length_and_unknown_critical_are_enforced() {
    reject(
        &xml(&[vec![chain_fixture(0, true, true, false)]]),
        "E_CHAIN_CONSTRAINT",
    );
    reject(
        &xml(&[vec![chain_fixture(5, false, true, false)]]),
        "E_CHAIN_SIGNATURE",
    );
    reject(
        &xml(&[vec![chain_fixture(5, true, false, false)]]),
        "E_CHAIN_SIGNATURE",
    );
    reject(
        &xml(&[vec![chain_fixture(5, true, true, true)]]),
        "E_CERT_CRITICAL",
    );
    assert!(parse(&xml(&[vec![chain_fixture(1, true, true, false)]]), NOW).is_ok());
}
#[test]
fn rsa_crt_and_ec_der_parameters_are_validated() {
    use pkcs8::der::{asn1::UintRef, Decode, Encode};
    let f = rsa2048();
    let block = pem::parse(&f.private).unwrap();
    let info = pkcs8::PrivateKeyInfo::from_der(block.contents()).unwrap();
    let mut key = rsa::pkcs1::RsaPrivateKey::from_der(info.private_key).unwrap();
    key.coefficient = UintRef::new(&[0]).unwrap();
    let mut invalid = f;
    invalid.private = pem::encode(&pem::Pem::new("RSA PRIVATE KEY", key.to_der().unwrap()));
    reject(&xml(&[vec![invalid]]), "E_PRIVATE_KEY");
    let f = ec();
    let block = pem::parse(&f.private).unwrap();
    let mut info = pkcs8::PrivateKeyInfo::from_der(block.contents()).unwrap();
    let oid = pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.35");
    info.algorithm.parameters = Some((&oid).into());
    let mut invalid = f;
    invalid.private = pem::encode(&pem::Pem::new("PRIVATE KEY", info.to_der().unwrap()));
    reject(&xml(&[vec![invalid]]), "E_PARAMETERS");
}

#[test]
fn unreduced_rsa_crt_coefficient_is_rejected_in_both_private_encodings() {
    use pkcs8::der::{asn1::UintRef, Decode, Encode};
    let canonical = rsa2048();
    let pem = pem::parse(&canonical.private).unwrap();
    let mut wrapper = pkcs8::PrivateKeyInfo::from_der(pem.contents()).unwrap();
    let mut encoded = rsa::pkcs1::RsaPrivateKey::from_der(wrapper.private_key).unwrap();
    let unreduced = (rsa::BigUint::from_bytes_be(encoded.coefficient.as_bytes())
        + rsa::BigUint::from_bytes_be(encoded.prime1.as_bytes()))
    .to_bytes_be();
    encoded.coefficient = UintRef::new(&unreduced).unwrap();
    let malformed = encoded.to_der().unwrap();
    wrapper.private_key = &malformed;
    let cases = [
        ("RSA PRIVATE KEY", malformed.clone()),
        ("PRIVATE KEY", wrapper.to_der().unwrap()),
    ];
    let mut results = Vec::new();
    for (tag, bytes) in cases {
        let mut invalid = canonical.clone();
        invalid.private = pem::encode(&pem::Pem::new(tag, bytes));
        results.push(parse(&xml(&[vec![invalid]]), NOW).err().map(|e| e.code));
    }
    assert_eq!(results, [Some("E_PRIVATE_KEY"), Some("E_PRIVATE_KEY")]);
}

#[test]
fn canonical_rsa_crt_survives_merge_in_both_private_encodings() {
    use pkcs8::der::{Decode, Encode};
    let source = rsa2048();
    let pem = pem::parse(&source.private).unwrap();
    let wrapper = pkcs8::PrivateKeyInfo::from_der(pem.contents()).unwrap();
    let encoded = rsa::pkcs1::RsaPrivateKey::from_der(wrapper.private_key).unwrap();
    let canonical = encoded.to_der().unwrap();
    for private in [
        source.private.clone(),
        pem::encode(&pem::Pem::new("RSA PRIVATE KEY", canonical.clone())),
    ] {
        let mut fixture = source.clone();
        fixture.private = private;
        let input = parse(&xml(&[vec![fixture]]), NOW).unwrap();
        let merged = merge(&[&input], &[selection(0, 0, 0, "rsa")], NOW).unwrap();
        let output = String::from_utf8(merged.xml().unwrap().to_vec()).unwrap();
        let start = output.find("-----BEGIN RSA PRIVATE KEY-----").unwrap();
        let end = output[start..]
            .find("-----END RSA PRIVATE KEY-----")
            .unwrap()
            + start
            + "-----END RSA PRIVATE KEY-----".len();
        let block = pem::parse(&output[start..end]).unwrap();
        assert_eq!(block.contents(), canonical);
        assert!(parse(output.as_bytes(), NOW).is_ok());
    }
}

fn rsa_issuer_fixture(key: &RsaPrivateKey, pss: bool) -> Fixture {
    use pkcs8::{
        der::{
            asn1::{Any, BitString},
            Decode, Encode,
        },
        EncodePublicKey,
    };
    use sha2::{Digest, Sha256};
    let mut f = ec();
    let public = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(
        key.to_public_key().to_public_key_der().unwrap().as_bytes(),
    )
    .unwrap();
    let algorithm = if pss {
        // SHA-256, MGF1 SHA-256 and the 32-byte salt required by this profile.
        let parameters = [
            0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
            0x04, 0x02, 0x01, 0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48,
            0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
            0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x20,
        ];
        pkcs8::spki::AlgorithmIdentifierOwned {
            oid: pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10"),
            parameters: Some(Any::from_der(&parameters).unwrap()),
        }
    } else {
        pkcs8::spki::AlgorithmIdentifierOwned {
            oid: pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
            parameters: Some(Any::from_der(&[0x05, 0]).unwrap()),
        }
    };
    for (index, encoded) in f.certs.iter_mut().enumerate() {
        let mut cert =
            x509_cert::Certificate::from_der(pem::parse(&*encoded).unwrap().contents()).unwrap();
        if index == 1 {
            cert.tbs_certificate.subject_public_key_info = public.clone();
        }
        cert.signature_algorithm = algorithm.clone();
        cert.tbs_certificate.signature = algorithm.clone();
        let digest = Sha256::digest(cert.tbs_certificate.to_der().unwrap());
        let signature = if pss {
            key.sign_with_rng(&mut rand::thread_rng(), rsa::Pss::new::<Sha256>(), &digest)
        } else {
            key.sign(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest)
        }
        .unwrap();
        cert.signature = BitString::from_bytes(&signature).unwrap();
        *encoded = pem::encode(&pem::Pem::new("CERTIFICATE", cert.to_der().unwrap()));
    }
    f
}

#[test]
fn weak_rsa_issuer_is_rejected_for_pkcs1_and_pss_signatures() {
    let mut results = Vec::new();
    let mut catalog_results = Vec::new();
    // A 512-bit modulus cannot fit SHA-256 PSS with its required 32-byte salt;
    // 768 bits exercises that fallback with an otherwise valid PSS signature.
    for (bits, pss) in [(512, false), (768, true)] {
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), bits).unwrap();
        let fixture = rsa_issuer_fixture(&key, pss);
        catalog_results.push(
            parse_public_feeds(
                &serde_json::to_vec(&vec![&fixture.certs[1]]).unwrap(),
                br#"{"entries":{}}"#,
            )
            .err()
            .map(|e| e.code),
        );
        results.push(parse(&xml(&[vec![fixture]]), NOW).err().map(|e| e.code));
    }
    assert_eq!(
        results,
        [Some("E_CHAIN_SIGNATURE"), Some("E_CHAIN_SIGNATURE")]
    );
    assert_eq!(
        catalog_results,
        [Some("E_PUBLIC_SCHEMA"), Some("E_PUBLIC_SCHEMA")]
    );
}

#[test]
fn supported_rsa_issuer_profiles_keep_fallback_and_wide_ring_paths() {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    let standard = RsaPrivateKey::from_pkcs8_pem(&rsa2048().private).unwrap();
    let small = RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
    let mut primes = standard.primes().to_vec();
    while primes.len() < 10 {
        let additional = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        primes.extend_from_slice(additional.primes());
    }
    // Multi-prime keys keep synthetic wide-modulus signatures inexpensive. Only
    // their RSA public modulus is placed in issuer certificates. Private input
    // policy remains two-prime RSA 2048–4096 and is unchanged by these fixtures.
    let from_primes = |count: usize| {
        RsaPrivateKey::from_primes(primes[..count].to_vec(), standard.e().clone()).unwrap()
    };
    let intermediate = from_primes(3);
    let upper_fallback = from_primes(4);
    let wide = from_primes(8);
    assert!((3000..=3072).contains(&intermediate.n().bits()));
    assert!((4000..=4096).contains(&upper_fallback.n().bits()));
    assert!((8000..=8192).contains(&wide.n().bits()));
    for key in [&small, &standard, &intermediate, &upper_fallback, &wide] {
        for pss in [false, true] {
            let fixture = rsa_issuer_fixture(key, pss);
            let root = fixture.certs[1].clone();
            assert!(
                parse(&xml(&[vec![fixture]]), NOW).is_ok(),
                "{} bits; PSS={pss}",
                key.n().bits()
            );
            assert_eq!(public(&root, serde_json::json!({})).inventory(), (1, 0));
        }
    }
    let oversized = from_primes(10);
    assert!(oversized.n().bits() > 8192);
    for pss in [false, true] {
        reject(
            &xml(&[vec![rsa_issuer_fixture(&oversized, pss)]]),
            "E_CHAIN_SIGNATURE",
        );
    }
}

#[test]
fn malformed_san_ip_and_non_ascii_ia5_names_are_rejected() {
    let root_key = KeyPair::generate().unwrap();
    let root = parameters("SAN root", 1, NOW + 172800, 5)
        .self_signed(&root_key)
        .unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let cases: &[&[u8]] = &[
        &[0x30, 0x05, 0x87, 0x03, 1, 2, 3], // IP address must contain 4 or 16 octets.
        &[0x30, 0x04, 0x81, 0x02, 0xc3, 0xa9], // RFC822 IA5String.
        &[0x30, 0x04, 0x82, 0x02, 0xc3, 0xa9], // DNS IA5String.
        &[0x30, 0x04, 0x86, 0x02, 0xc3, 0xa9], // URI IA5String.
        &[0x30, 0x03, 0x82, 0x01, 0xff],    // Malformed known general name.
        &[
            0x30, 0x12, 0x87, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 0, 2, 1,
        ], // IPv4-mapped IPv6 is not a SAN IPv6 address.
    ];
    let mut results = Vec::new();
    for bytes in cases {
        let mut params = parameters("SAN leaf", 2, NOW + 86400, 5);
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 17],
                bytes.to_vec(),
            ));
        let leaf = params.signed_by(&leaf_key, &root, &root_key).unwrap();
        let fixture = Fixture {
            algorithm: "ecdsa",
            private: leaf_key.serialize_pem(),
            certs: vec![leaf.pem(), root.pem()],
        };
        results.push(parse(&xml(&[vec![fixture]]), NOW).err().map(|e| e.code));
    }
    assert_eq!(results, vec![Some("E_CERTIFICATE"); cases.len()]);
}

fn name_constraint_fixture(value: Vec<u8>, critical: bool) -> Fixture {
    let root_key = KeyPair::generate().unwrap();
    let mut root_params = parameters("Name constraints root", 1, NOW + 172800, 5);
    let mut extension = rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 30], value);
    extension.set_criticality(critical);
    root_params.custom_extensions.push(extension);
    let root = root_params.self_signed(&root_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = parameters("Leaf", 2, NOW + 86400, 5)
        .signed_by(&leaf_key, &root, &root_key)
        .unwrap();
    Fixture {
        algorithm: "ecdsa",
        private: leaf_key.serialize_pem(),
        certs: vec![leaf.pem(), root.pem()],
    }
}
fn name_constraint_der(tag: u8, value: &[u8]) -> Vec<u8> {
    // NameConstraints permittedSubtrees holds one GeneralSubtree/base.
    let mut out = vec![
        0x30,
        (value.len() + 6) as u8,
        0xa0,
        (value.len() + 4) as u8,
        0x30,
        (value.len() + 2) as u8,
        tag,
        value.len() as u8,
    ];
    out.extend(value);
    out
}
#[test]
fn malformed_name_constraints_ip_shape_masks_and_ia5_are_rejected() {
    let mut mapped = vec![0; 32];
    mapped[10] = 255;
    mapped[11] = 255;
    mapped[12..16].copy_from_slice(&[192, 0, 2, 1]);
    mapped[16..].fill(255);
    let cases = [
        vec![0x30, 0], // An empty extension has no subtree.
        name_constraint_der(0x87, &[192, 0, 2, 0, 255, 255, 255]),
        name_constraint_der(0x87, &[192, 0, 2, 0, 255, 0, 255, 0]),
        name_constraint_der(0x87, &mapped),
        name_constraint_der(0x82, &[0xc3, 0xa9]),
        name_constraint_der(0x82, &[0xff]),
    ];
    let mut results = Vec::new();
    for value in cases {
        results.push(
            parse(&xml(&[vec![name_constraint_fixture(value, false)]]), NOW)
                .err()
                .map(|e| e.code),
        );
    }
    assert_eq!(results, vec![Some("E_CERTIFICATE"); 6]);
}
#[test]
fn valid_name_constraints_ip_masks_remain_accepted() {
    let ipv4 = name_constraint_der(0x87, &[192, 0, 2, 0, 255, 255, 255, 128]);
    let mut ipv6 = vec![0; 32];
    ipv6[..4].copy_from_slice(&[0x20, 1, 0x0d, 0xb8]);
    ipv6[16..20].fill(255);
    ipv6[20] = 0xf0;
    for critical in [false, true] {
        for value in [
            &ipv4,
            &name_constraint_der(0x87, &ipv6),
            &name_constraint_der(0x82, b".example.test"),
        ] {
            let f = name_constraint_fixture(value.clone(), critical);
            assert!(parse(&xml(&[vec![f]]), NOW).is_ok());
        }
    }
}

#[test]
fn valid_san_ip_and_ascii_ia5_names_remain_accepted() {
    let root_key = KeyPair::generate().unwrap();
    let root = parameters("SAN root", 1, NOW + 172800, 5)
        .self_signed(&root_key)
        .unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    for critical in [false, true] {
        let mut params = parameters("SAN leaf", 2, NOW + 86400, 5);
        let mut names = vec![0x87, 4, 192, 0, 2, 1, 0x87, 16];
        names.extend([0u8; 15]);
        names.push(1);
        for (tag, value) in [
            (0x81, "synthetic@example.test"),
            (0x82, "example.test"),
            (0x86, "https://example.test/"),
        ] {
            names.extend([tag, value.len() as u8]);
            names.extend(value.as_bytes());
        }
        let mut sequence = vec![0x30, names.len() as u8];
        sequence.extend(names);
        let mut extension = rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 17], sequence);
        extension.set_criticality(critical);
        params.custom_extensions.push(extension);
        let leaf = params.signed_by(&leaf_key, &root, &root_key).unwrap();
        let fixture = Fixture {
            algorithm: "ecdsa",
            private: leaf_key.serialize_pem(),
            certs: vec![leaf.pem(), root.pem()],
        };
        assert!(parse(&xml(&[vec![fixture]]), NOW).is_ok());
    }
}
#[test]
fn public_counts_and_document_size_bound_resource_use() {
    let roots = serde_json::to_vec(&vec![&ec().certs[1]]).unwrap();
    assert_eq!(
        parse_public_feeds(&vec![b' '; MAX_PUBLIC_ROOTS + 1], br#"{"entries":{}}"#)
            .unwrap_err()
            .code,
        "E_PUBLIC_LIMIT"
    );
    assert_eq!(
        parse_public_feeds(&roots, &vec![b' '; MAX_PUBLIC_STATUS + 1])
            .unwrap_err()
            .code,
        "E_PUBLIC_LIMIT"
    );
    let long_serial = "a".repeat(4096);
    assert_eq!(
        public(
            &ec().certs[1],
            serde_json::json!({long_serial:{"status":"REVOKED"}})
        )
        .inventory(),
        (1, 1)
    );
    let status = serde_json::to_vec(
        &serde_json::json!({"entries":{"a":{"status":"REVOKED","comment":"界".repeat(141)}}}),
    )
    .unwrap();
    assert_eq!(
        parse_public_feeds(&roots, &status).unwrap_err().code,
        "E_PUBLIC_SCHEMA"
    );
    let entries = (1u32..=50_001)
        .map(|i| (format!("{i:x}"), serde_json::json!({"status":"REVOKED"})))
        .collect::<serde_json::Map<_, _>>();
    let status = serde_json::to_vec(&serde_json::json!({"entries":entries})).unwrap();
    assert!(status.len() < MAX_PUBLIC_STATUS);
    assert_eq!(
        parse_public_feeds(&roots, &status).unwrap_err().code,
        "E_PUBLIC_SCHEMA"
    );
}
#[test]
fn ecdsa_sha512_chain_signature_is_verified_and_tampering_rejected() {
    use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
    use pkcs8::der::{asn1::BitString, Decode, Encode};
    use sha2::{Digest, Sha512};
    let root_key = KeyPair::generate().unwrap();
    let root = parameters("Root", 1, NOW + 172800, 5)
        .self_signed(&root_key)
        .unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = parameters("Leaf", 2, NOW + 86400, 5)
        .signed_by(&leaf_key, &root, &root_key)
        .unwrap();
    let mut cert = x509_cert::Certificate::from_der(leaf.der()).unwrap();
    let algorithm = pkcs8::spki::AlgorithmIdentifierOwned {
        oid: pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4"),
        parameters: None,
    };
    cert.signature_algorithm = algorithm.clone();
    cert.tbs_certificate.signature = algorithm;
    let sk = p256::SecretKey::from_pkcs8_der(&root_key.serialize_der()).unwrap();
    let signer = SigningKey::from(sk);
    let digest = Sha512::digest(cert.tbs_certificate.to_der().unwrap());
    let signature: Signature = signer.sign_prehash(&digest).unwrap();
    cert.signature = BitString::from_bytes(signature.to_der().as_bytes()).unwrap();
    let mut f = Fixture {
        algorithm: "ecdsa",
        private: leaf_key.serialize_pem(),
        certs: vec![
            pem::encode(&pem::Pem::new("CERTIFICATE", cert.to_der().unwrap())),
            root.pem(),
        ],
    };
    assert!(parse(&xml(&[vec![f.clone()]]), NOW).is_ok());
    cert.tbs_certificate.serial_number = x509_cert::serial_number::SerialNumber::new(&[3]).unwrap();
    f.certs[0] = pem::encode(&pem::Pem::new("CERTIFICATE", cert.to_der().unwrap()));
    reject(&xml(&[vec![f]]), "E_CHAIN_SIGNATURE");
}
#[test]
fn rsa_pss_parameters_have_to_match_the_actual_signature_profile() {
    use pkcs8::der::{
        asn1::{Any, BitString},
        Decode, Encode,
    };
    use sha2::{Digest, Sha256};
    let private = rsa2048().private;
    let root_key = KeyPair::from_pem_and_sign_algo(&private, &PKCS_RSA_SHA256).unwrap();
    let pk = RsaPrivateKey::from_pkcs8_pem(&private).unwrap();
    let root = parameters("RSA root", 1, NOW + 172800, 5)
        .self_signed(&root_key)
        .unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = parameters("Leaf", 2, NOW + 86400, 5)
        .signed_by(&leaf_key, &root, &root_key)
        .unwrap();
    let leaf_cert = x509_cert::Certificate::from_der(leaf.der()).unwrap();
    // Standard SHA-256 MGF1, digest-size salt, trailer 1 (RFC 4055).
    let params = vec![
        0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x02, 0x01, 0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
        0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x02, 0x01, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x20,
    ];
    let produce = |parameters: &[u8]| {
        let mut cert = leaf_cert.clone();
        let algorithm = pkcs8::spki::AlgorithmIdentifierOwned {
            oid: pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10"),
            parameters: Some(Any::from_der(parameters).unwrap()),
        };
        cert.signature_algorithm = algorithm.clone();
        cert.tbs_certificate.signature = algorithm;
        let signature = pk
            .sign_with_rng(
                &mut rand::thread_rng(),
                rsa::Pss::new::<Sha256>(),
                &Sha256::digest(cert.tbs_certificate.to_der().unwrap()),
            )
            .unwrap();
        cert.signature = BitString::from_bytes(&signature).unwrap();
        Fixture {
            algorithm: "ecdsa",
            private: leaf_key.serialize_pem(),
            certs: vec![
                pem::encode(&pem::Pem::new("CERTIFICATE", cert.to_der().unwrap())),
                root.pem(),
            ],
        }
    };
    assert!(parse(&xml(&[vec![produce(&params)]]), NOW).is_ok());
    let mut bad = params.clone();
    bad[46] = 0x02;
    reject(&xml(&[vec![produce(&bad)]]), "E_CHAIN_SIGNATURE"); // MGF SHA-384 with SHA-256 signature.
    let mut bad = params.clone();
    *bad.last_mut().unwrap() = 31;
    reject(&xml(&[vec![produce(&bad)]]), "E_CHAIN_SIGNATURE");
    let mut bad = params.clone();
    bad[1] += 5;
    bad.extend([0xa3, 0x03, 0x02, 0x01, 0x02]);
    reject(&xml(&[vec![produce(&bad)]]), "E_CHAIN_SIGNATURE");
    let mut bad = params.clone();
    bad[1] += 5;
    bad.extend([0xa2, 0x03, 0x02, 0x01, 0x20]);
    reject(&xml(&[vec![produce(&bad)]]), "E_CHAIN_SIGNATURE");
}

#[test]
fn p521_issuer_chain_and_public_root_signature_are_verified() {
    use p521::ecdsa::signature::hazmat::RandomizedPrehashSigner;
    use pkcs8::{
        der::{asn1::BitString, Decode, Encode},
        EncodePublicKey,
    };
    use sha2::{Digest, Sha512};
    let root_key = KeyPair::generate().unwrap();
    let root = parameters("P521 issuer", 1, NOW + 172800, 5)
        .self_signed(&root_key)
        .unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = parameters("Leaf", 2, NOW + 86400, 5)
        .signed_by(&leaf_key, &root, &root_key)
        .unwrap();
    let secret = p521::SecretKey::random(&mut rand::thread_rng());
    let signer = p521::ecdsa::SigningKey::from_slice(&secret.to_bytes()).unwrap();
    let public_key = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(
        secret.public_key().to_public_key_der().unwrap().as_bytes(),
    )
    .unwrap();
    let sign = |mut cert: x509_cert::Certificate, replace_key: bool| {
        if replace_key {
            cert.tbs_certificate.subject_public_key_info = public_key.clone();
        }
        let algorithm = pkcs8::spki::AlgorithmIdentifierOwned {
            oid: pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4"),
            parameters: None,
        };
        cert.signature_algorithm = algorithm.clone();
        cert.tbs_certificate.signature = algorithm;
        let signature: p521::ecdsa::Signature = signer
            .sign_prehash_with_rng(
                &mut rand::thread_rng(),
                &Sha512::digest(cert.tbs_certificate.to_der().unwrap()),
            )
            .unwrap();
        cert.signature = BitString::from_bytes(signature.to_der().as_bytes()).unwrap();
        pem::encode(&pem::Pem::new("CERTIFICATE", cert.to_der().unwrap()))
    };
    let root = sign(x509_cert::Certificate::from_der(root.der()).unwrap(), true);
    let leaf = sign(x509_cert::Certificate::from_der(leaf.der()).unwrap(), false);
    let f = Fixture {
        algorithm: "ecdsa",
        private: leaf_key.serialize_pem(),
        certs: vec![leaf, root.clone()],
    };
    let doc = parse(&xml(&[vec![f]]), NOW).unwrap();
    assert!(
        doc.check_public(&public(&root, serde_json::json!({})))
            .unwrap()[0]
            .google_root_key
    );
}
