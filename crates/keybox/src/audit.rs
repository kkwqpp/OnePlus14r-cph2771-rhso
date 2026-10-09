use crate::{crypto, parse, timestamp, xml};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Structural inventory on rejection. Fixed schema labels and bounded counts
/// are exposed; original metadata, PEM, certificate names and serials stay private.
pub fn audit(data: &[u8], now_unix: i64) -> Value {
    let mut out = json!({"structural_valid":false,"cryptographic_consistent":false,"trust":"unknown","revocation":"unknown","engine_adoption":"pending","wallet_acceptance":"unverified","algorithms":[],"keyboxes":[]});
    let root = match xml::parse(data) {
        Ok(x) => x,
        Err(e) => {
            out["validation_error"] = json!(e.to_string());
            return out;
        }
    };
    let error = match parse(data, now_unix) {
        Ok(doc) => {
            return serde_json::to_value(doc.summary()).unwrap_or_else(
                |_| json!({"validation_error":"keybox validation failed (E_SCHEMA)"}),
            )
        }
        Err(e) => e,
    };
    out["validation_error"] = json!(error.to_string());
    let mut algorithms = Vec::new();
    let mut boxes = Vec::new();
    for (bi, b) in root
        .children
        .iter()
        .enumerate()
        .filter(|(_, b)| b.name == "Keybox")
    {
        let mut keys = Vec::new();
        for (ki, k) in b
            .children
            .iter()
            .enumerate()
            .filter(|(_, k)| k.name == "Key")
        {
            let algorithm = k
                .attrs
                .get("algorithm")
                .filter(|x| x.as_str() == "rsa" || x.as_str() == "ecdsa")
                .map(String::as_str)
                .unwrap_or("unsupported");
            algorithms.push(algorithm.to_owned());
            let mut entry = json!({"index":ki,"algorithm":algorithm,"certificate_count":0,"private_key_format":"unavailable"});
            for node in &k.children {
                if node.name == "PrivateKey" {
                    let text = node.text.trim();
                    entry["pem_begin_count"] = json!(text.matches("-----BEGIN ").count());
                    entry["pem_end_count"] = json!(text.matches("-----END ").count());
                    entry["pem_lines"] = json!(text.split('\n').count());
                    entry["literal_backslash_n"] = json!(text.contains("\\n"));
                    entry["indented_boundary"] = json!(text
                        .split('\n')
                        .any(|x| x.starts_with(' ') && x.trim().starts_with("-----")));
                    for label in ["EC PRIVATE KEY", "RSA PRIVATE KEY", "PRIVATE KEY"] {
                        if text.starts_with(&format!("-----BEGIN {label}-----")) {
                            entry["private_key_format"] = json!(label);
                        }
                    }
                }
                if node.name == "CertificateChain" {
                    let mut certs = Vec::new();
                    let mut count = 0usize;
                    for child in node.children.iter().filter(|x| x.name == "Certificate") {
                        count += 1;
                        if let Ok(pem) = crypto::complete_pem(&child.text, false) {
                            if pem.tag == "CERTIFICATE" {
                                if let Ok(cert) = crypto::certificate(&pem.contents) {
                                    let not_before = cert.validity().not_before.timestamp();
                                    let not_after = cert.validity().not_after.timestamp();
                                    let validity = if now_unix > not_after {
                                        "expired"
                                    } else if now_unix < not_before {
                                        "not-yet-valid"
                                    } else {
                                        "valid-at-collection"
                                    };
                                    let digest = Sha256::digest(cert.as_raw())
                                        .iter()
                                        .map(|x| format!("{x:02x}"))
                                        .collect::<String>();
                                    certs.push(json!({"index":count-1,"validity":validity,"not_before":timestamp(not_before),"not_after":timestamp(not_after),"sha256":digest,"placeholder_indicator":crypto::cert_placeholder(&cert)}));
                                }
                            }
                        }
                    }
                    entry["certificate_count"] = json!(count);
                    entry["certificates"] = json!(certs);
                }
            }
            keys.push(entry);
        }
        boxes.push(json!({"index":bi.saturating_sub(1),"keys":keys}));
    }
    out["algorithms"] = json!(algorithms);
    out["keyboxes"] = json!(boxes);
    out["structural_inventory_only"] = json!(true);
    out
}
