use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rhso_webui::core::*;
use serde_json::{Value, json};

#[test]
fn closeouts_require_exact_phrases_and_bound_review_tokens() {
    let args = json!({"action":"resolve","id":"a".repeat(32),"confirmation":STACK_RESOLVE_PHRASE,"review_hash":"b".repeat(64)});
    assert!(encode_request("stack", &args).is_ok());
    for field in ["id", "confirmation", "review_hash"] {
        let mut bad = args.clone();
        bad[field] = json!("invalid");
        assert!(encode_request("stack", &bad).is_err());
    }
    let mut status = json!({"profiles":[],"allowed_targets":[],"unfinished":true,"stack_pending":true,"manual_reboot_required":true,"runtime_adoption":"unknown","operation":{"id":"a".repeat(32),"profile":"hma-scope","state":"recovery-required","can_resolve":true,"resolution_review_hash":"b".repeat(64),"private_locator":"PRIVATE_STACK_SENTINEL"}});
    let redacted = stack_status_view(&status).unwrap();
    assert_eq!(redacted["operation"]["can_resolve"], true);
    assert!(!redacted.to_string().contains("PRIVATE_STACK_SENTINEL"));
    status["operation"]["resolution_review_hash"] = json!("invalid");
    assert_eq!(
        stack_status_view(&status).unwrap()["operation"]["can_resolve"],
        false
    );
    assert!(encode_request("reset",&json!({"action":"close","confirmation":RESET_CLOSE_PHRASE,"review_hash":"b".repeat(64)})).is_ok());
}

#[test]
fn requests_are_bounded_inert_and_do_not_accept_api_credentials() {
    let path = "/data/adb/wallet_diagnostic/inbox/quoted \" $(touch injected); 日本語.xml";
    let encoded = encode_request("ingest", &json!({"path":path})).unwrap();
    assert!(
        encoded
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    );
    let decoded: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
    assert_eq!(decoded["args"]["path"], path);
    for (command, args) in [
        ("shell", json!({})),
        ("api", json!({"action":"import","token":"SECRET"})),
        (
            "api",
            json!({"action":"config","path":"https://private.example/secret"}),
        ),
        (
            "api",
            json!({"action":"config","path":"/sdcard/keybox_inbox/api.json"}),
        ),
        ("ingest", json!({"path":{"nested":true}})),
        ("ingest", json!({"path":"x".repeat(4097)})),
        (
            "plan",
            json!({"a":"x".repeat(4096),"b":"x".repeat(4096),"c":"x".repeat(4096)}),
        ),
    ] {
        assert!(encode_request(command, &args).is_err());
    }
    assert!(
        encode_request(
            "api",
            &json!({"action":"config","path":"/data/adb/wallet_diagnostic/inbox/api-config.json"})
        )
        .is_ok()
    );
}
#[test]
fn schema_and_sensitive_display_fail_closed() {
    assert!(read_result("shell output").is_err());
    assert!(
        read_result(&json!({"schema":2,"ok":true,"code":"OK","message":"new"}).to_string())
            .is_err()
    );
    assert!(read_result(&"x".repeat(1_048_577)).is_err());
    let r = read_result(
        &json!({"schema":1,"ok":false,"code":"E_STALE","message":"Replan","data":{}}).to_string(),
    )
    .unwrap();
    assert!(!r.ok);
    for input in [
        "-----BEGIN PRIVATE KEY-----\nsecret",
        "api_token=secret",
        "authorization: secret",
    ] {
        assert_eq!(safe_text(&json!(input), "missing"), OMITTED);
    }
    assert_eq!(
        safe_text(&json!({"privateKey":"secret"}), "missing"),
        "missing"
    );
    assert_eq!(safe_text(&json!("<img onerror=x>"), ""), "<img onerror=x>");
    assert_eq!(safe_text(&json!("safe\0 text"), ""), "safe text");
}
#[test]
fn deliberate_selection_and_compaction_counts_are_consistent() {
    assert_eq!(
        selection_value(&"a".repeat(32), 0.0, 2.0, "ecdsa").unwrap(),
        format!("{}:0:2:ecdsa", "a".repeat(32))
    );
    for index in [-1.0, 0.5, f64::NAN, f64::INFINITY, 9_007_199_254_740_992.0] {
        assert!(selection_value("valid", index, 0.0, "rsa").is_err());
    }
    assert!(selection_value("input;id", 0.0, 0.0, "rsa").is_err());
    assert!(selection_value("valid", 0.0, 0.0, "dsa").is_err());
    let counts =
        json!({"entries_before":4,"entries_after":2,"removed_entries":2,"packages_before":2});
    assert_eq!(compaction_counts(&counts).unwrap(), counts);
    for field in [
        "entries_before",
        "entries_after",
        "removed_entries",
        "packages_before",
    ] {
        let mut invalid = counts.clone();
        invalid[field] = json!(-1);
        assert!(compaction_counts(&invalid).is_err());
    }
    let mut invalid = counts.clone();
    invalid["removed_entries"] = json!(1);
    assert!(compaction_counts(&invalid).is_err());
}
#[test]
fn private_api_dtos_never_contain_url_auth_body_or_raw_errors() {
    let secret = "https://private.example/feed?token=SECRET_SENTINEL";
    let status = json!({"api_status":"generic-https-raw-xml","supported_format":"raw-xml","state":"configured","configured":true,"available":true,"auth_configured":true,"source_generation":"d".repeat(32),"exact_endpoint_available":false,"provider_contract_verified":false,"url":secret,"authorization":"SECRET_SENTINEL","body":"-----BEGIN PRIVATE KEY-----"});
    let r = redact_api_value(
        &json!({"schema":1,"ok":false,"code":"E_API_TLS","message":secret,"extra":secret,"data":status}),
    );
    assert_eq!(r["code"], "E_API_TLS");
    assert!(!r.to_string().contains("SECRET_SENTINEL"));
    assert!(!r.to_string().contains("private.example"));
    let mut status = status;
    for field in ["provider_contract_verified", "exact_endpoint_available"] {
        status[field] = json!(true);
        assert!(!yes(get(&api_status_view(&status).unwrap(), "available")));
        status[field] = json!(false);
    }
    assert!(api_status_view(&json!({"available":true,"endpoint":secret})).is_none());
}
#[test]
fn stack_review_requires_explicit_supported_scope_and_backup_policy() {
    let p = json!({"id":"a".repeat(32),"profile":"hma-scope","changes":[{"target":"com.google.android.gms","added_count":1,"scopes_created":1}],"manual_reboot_required":true,"runtime_adoption":"unknown","private_backup":"created-on-apply","private_list":"SECRET"});
    assert!(!stack_plan_view(&p).unwrap().to_string().contains("SECRET"));
    for (field, value) in [
        ("private_backup", json!("absent")),
        ("runtime_adoption", json!("verified")),
        ("manual_reboot_required", json!(false)),
        (
            "changes",
            json!([{"target":"org.example.target","added_count":1,"scopes_created":1}]),
        ),
    ] {
        let mut p = p.clone();
        p[field] = value;
        assert!(stack_plan_view(&p).is_err());
    }
    assert!(encode_request("stack",&json!({"action":"plan","profile":"brezygisk-unmount","enabled":"true","targets":"com.google.android.gms"})).is_err());
    assert!(
        encode_request(
            "stack",
            &json!({"action":"rollback","id":"/private/backup"})
        )
        .is_err()
    );
    assert_eq!(
        stack_package_list(" org.example.manager,org.example.manager ").unwrap(),
        vec!["org.example.manager"]
    );
    for s in [
        "",
        "org.example.manager;id",
        "https://private.example",
        "org.example.manager,",
    ] {
        assert!(stack_package_list(s).is_err());
    }
}
#[test]
fn evidence_binds_user_stack_and_all_file_metadata() {
    let active: Value = FILES
        .into_iter()
        .map(|name| (name.to_owned(), json!({"exists":false})))
        .collect();
    let mut v = json!({"active":active,"device":{"current_android_user":"0"}});
    let baseline = evidence_binding(&v).unwrap();
    v["stack_evidence_binding"] = json!("a".repeat(64));
    assert_ne!(baseline, evidence_binding(&v).unwrap());
    let a = evidence_binding(&v).unwrap();
    v["stack_evidence_binding"] = json!("b".repeat(64));
    assert_ne!(a, evidence_binding(&v).unwrap());
    v["device"]["current_android_user"] = json!("10");
    assert_ne!(a, evidence_binding(&v).unwrap());
    v["stack_evidence_binding"] = json!("invalid");
    assert!(evidence_binding(&v).is_none());
}
