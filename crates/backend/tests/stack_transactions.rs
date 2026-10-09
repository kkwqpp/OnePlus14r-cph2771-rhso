//! Temporary fake-engine fixtures only. Protected bytes are deliberately opaque
//! synthetic data: Stack may back them up, but may never parse or rewrite them.
use rhso::{
    App,
    error::{Error, Result},
    fs::{self as safe_fs, FileState, Metadata},
    util,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tempfile::TempDir;

const NOW: i64 = 1_791_547_200;
const FIXTURE: &[u8] = br#"{"configVersion":93,"futureGlobal":{"keep":123456789012345678901234567890},"altAppDataIsolation":true,"defaultConfig":{"useWhitelist":false,"extraAppList":["org.example.previous"],"extraOppositeAppList":[],"futureDefault":{"retain":true}},"scope":{"com.google.android.gms":{"useWhitelist":false,"extraAppList":["org.example.previous"],"extraOppositeAppList":[],"hideInstallationSource":true,"futureLocal":[1,2,3]},"org.example.unrelated":{"useWhitelist":true,"extraAppList":["org.example.privatefixture"],"futureApp":"synthetic-sensitive-private-app"}},"templates":{"synthetic-sensitive-template":{"future":true}},"settingsTemplates":{}}"#;
struct Sandbox {
    _dir: TempDir,
    app: App,
    config: PathBuf,
    marker: PathBuf,
    before: FileState,
    parent: Metadata,
    protected: BTreeMap<String, FileState>,
    original: Vec<u8>,
}
fn write(path: &Path, bytes: &[u8]) {
    safe_fs::atomic_write(
        path,
        bytes,
        &Metadata {
            mode: 0o600,
            uid: util::owner_id(),
            gid: util::owner_id(),
            selinux: String::new(),
        },
    )
    .unwrap();
}
fn value(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
fn store(path: &Path, value: &Value) {
    safe_fs::write_json(path, value).unwrap();
}
fn sandbox(body: Option<&[u8]>) -> Sandbox {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let mut app = App::new(
        root.join("private"),
        root.join("active"),
        root.join("modules"),
        true,
    );
    app.clock = Arc::new(|| NOW);
    app.shared_inbox = root.join("shared-inbox");
    for p in [
        &app.active,
        &app.shared_inbox,
        &app.modules.join("playintegrityfix"),
        &root.join("stack-system/data/misc/hide_my_applist_abcdefghijklmnop"),
        &root.join("stack-system/data/adb/brezygisk"),
    ] {
        safe_fs::private_dir(p).unwrap();
    }
    app.init().unwrap();
    for (name, bytes) in [
        (
            "keybox.xml",
            b"synthetic opaque protected keybox bytes".as_slice(),
        ),
        (
            "target.txt",
            b"# preserve comment\norg.example.unrelated?\n  com.google.android.gms\n".as_slice(),
        ),
        (
            "security_patch.txt",
            b"# preserve comment\nall=2026-08-05\nno=retain\n".as_slice(),
        ),
    ] {
        write(&app.active.join(name), bytes);
    }
    write(
        &app.modules.join("playintegrityfix/custom.pif.prop"),
        b"FINGERPRINT=synthetic/fixture\nSECURITY_PATCH=2026-09-05\nspoofBuild=0\n",
    );
    let config = root.join("stack-system/data/misc/hide_my_applist_abcdefghijklmnop/config.json");
    let marker = root.join("stack-system/data/adb/brezygisk/unmount");
    let original = body.unwrap_or(FIXTURE).to_vec();
    write(&config, &original);
    let before = safe_fs::snapshot_file(&config, 1 << 20).unwrap();
    let parent = safe_fs::metadata(config.parent().unwrap()).unwrap();
    let protected = app.snapshot().unwrap();
    Sandbox {
        _dir: dir,
        app,
        config,
        marker,
        before,
        parent,
        protected,
        original,
    }
}
fn plan(s: &Sandbox, profile: &str, targets: &str, hide: &str, enabled: &str) -> String {
    s.app
        .stack("plan", profile, targets, hide, enabled, "")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}
fn hma_plan(s: &Sandbox) -> String {
    plan(
        s,
        "hma-scope",
        "com.google.android.gms",
        "org.example.hidden",
        "",
    )
}
fn call(s: &Sandbox, action: &str, id: &str) -> Value {
    let v = s.app.stack(action, "", "", "", "", id).unwrap();
    assert_eq!(v["manual_reboot_required"], true);
    assert_eq!(v["runtime_adoption"], "unknown");
    redacted(&v);
    v
}
fn code<T: std::fmt::Debug>(r: Result<T>, wanted: &str) -> Error {
    let e = r.unwrap_err();
    assert_eq!(e.code, wanted, "{e}");
    e
}
fn original(s: &Sandbox) {
    assert_eq!(std::fs::read(&s.config).unwrap(), s.original);
    assert_eq!(
        safe_fs::snapshot_file(&s.config, 1 << 20).unwrap(),
        s.before
    );
    assert_eq!(
        safe_fs::metadata(s.config.parent().unwrap()).unwrap(),
        s.parent
    );
    assert_eq!(s.app.snapshot().unwrap(), s.protected);
}
fn redacted(v: &Value) {
    let text = serde_json::to_string(v).unwrap();
    for fragment in [
        "synthetic-sensitive-private-app",
        "synthetic-sensitive-template",
        "org.example.privatefixture",
        "org.example.hidden",
        "hide_my_applist_abcdefghijklmnop",
        "config.json",
        "resource.bin",
        "futureGlobal",
    ] {
        assert!(
            !text.contains(fragment),
            "private configuration leaked: {fragment}"
        );
    }
}
fn pending(s: &Sandbox) -> bool {
    s.app.stack("status", "", "", "", "", "").unwrap()["stack_pending"] == true
}
fn backup_dir(s: &Sandbox, id: &str) -> PathBuf {
    s.app.root.join("stack/backups").join(id)
}
fn plan_dir(s: &Sandbox, id: &str) -> PathBuf {
    s.app.root.join("stack/plans").join(id)
}

#[test]
fn hma_preserves_unknown_and_unrelated_fields_and_exact_rollback() {
    let s = sandbox(None);
    let id = plan(
        &s,
        "hma-scope",
        "com.google.android.gms,com.android.vending",
        "org.example.hidden",
        "",
    );
    let review = value(&plan_dir(&s, &id).join("plan.json"));
    assert_eq!(review["changes"].as_array().unwrap().len(), 2);
    assert_eq!(call(&s, "apply", &id)["state"], "committed");
    let after = value(&s.config);
    let before: Value = serde_json::from_slice(&s.original).unwrap();
    for k in [
        "futureGlobal",
        "altAppDataIsolation",
        "templates",
        "settingsTemplates",
        "defaultConfig",
    ] {
        assert_eq!(after[k], before[k], "unrelated {k} changed");
    }
    assert_eq!(
        after["futureGlobal"]["keep"].to_string(),
        "123456789012345678901234567890"
    );
    assert_eq!(
        after["scope"]["org.example.unrelated"],
        before["scope"]["org.example.unrelated"]
    );
    for k in [
        "useWhitelist",
        "hideInstallationSource",
        "futureLocal",
        "extraOppositeAppList",
    ] {
        assert_eq!(
            after["scope"]["com.google.android.gms"][k],
            before["scope"]["com.google.android.gms"][k]
        );
    }
    assert_eq!(
        after["scope"]["com.google.android.gms"]["extraAppList"],
        json!(["org.example.previous", "org.example.hidden"])
    );
    assert_eq!(call(&s, "verify", &id)["readback_verified"], true);
    assert_eq!(s.app.snapshot().unwrap(), s.protected);
    assert_eq!(call(&s, "rollback", &id)["state"], "restored");
    original(&s);
    call(&s, "verify", &id);
    let r = value(&backup_dir(&s, &id).join("rollback-current.json"));
    assert_eq!(r["before"]["exists"], true);
    let saved = value(&backup_dir(&s, &id).join("rollback-current.bin"));
    assert_eq!(saved, after);
}
#[test]
fn marker_both_directions_restore_bytes_metadata_and_absence() {
    for existing in [false, true] {
        let s = sandbox(None);
        if existing {
            write(&s.marker, b"existing synthetic marker bytes\n");
        }
        let before = safe_fs::snapshot_file(&s.marker, 1 << 20).unwrap();
        let id = plan(
            &s,
            "brezygisk-unmount",
            "",
            "",
            if existing { "false" } else { "true" },
        );
        call(&s, "apply", &id);
        assert_eq!(s.marker.exists(), !existing);
        call(&s, "rollback", &id);
        assert_eq!(safe_fs::snapshot_file(&s.marker, 1 << 20).unwrap(), before);
        original(&s);
        let r = value(&backup_dir(&s, &id).join("rollback-current.json"));
        assert_eq!(r["before"]["exists"], !existing);
        assert_eq!(
            backup_dir(&s, &id).join("rollback-current.bin").exists(),
            !existing
        );
    }
}
#[test]
fn nullable_or_absent_default_creates_only_selected_minimal_scope() {
    for default in [None, Some(Value::Null)] {
        let mut v = json!({"configVersion":93,"scope":{},"future":{"retain":true}});
        if let Some(d) = default {
            v["defaultConfig"] = d;
        }
        let bytes = serde_json::to_vec(&v).unwrap();
        let s = sandbox(Some(&bytes));
        let id = hma_plan(&s);
        assert_eq!(
            value(&plan_dir(&s, &id).join("plan.json"))["changes"][0]["scopes_created"],
            1
        );
        call(&s, "apply", &id);
        let v = value(&s.config);
        assert_eq!(
            v["scope"]["com.google.android.gms"],
            json!({"useWhitelist":false,"extraAppList":["org.example.hidden"]})
        );
        call(&s, "rollback", &id);
        original(&s);
    }
}
#[test]
fn rejected_hma_ambiguity_protected_packages_and_unsupported_schema() {
    for (field, wanted) in [
        ("schema", "E_CAPABILITY"),
        ("null-whitelist", "E_FORMAT"),
        ("whitelist", "E_SELECTION"),
        ("default-whitelist", "E_SELECTION"),
        ("opposite", "E_SELECTION"),
        ("null-set", "E_FORMAT"),
        ("duplicate-set", "E_FORMAT"),
    ] {
        let mut v: Value = serde_json::from_slice(FIXTURE).unwrap();
        match field {
            "schema" => v["configVersion"] = json!(94),
            "null-whitelist" => v["scope"]["com.google.android.gms"]["useWhitelist"] = Value::Null,
            "whitelist" => v["scope"]["com.google.android.gms"]["useWhitelist"] = json!(true),
            "default-whitelist" => v["defaultConfig"]["useWhitelist"] = json!(true),
            "opposite" => {
                v["scope"]["com.google.android.gms"]["extraOppositeAppList"] =
                    json!(["org.example.hidden"])
            }
            "null-set" => v["scope"]["com.google.android.gms"]["extraAppList"] = Value::Null,
            _ => {
                v["scope"]["com.google.android.gms"]["extraAppList"] =
                    json!(["org.example.previous", "org.example.previous"])
            }
        }
        let bytes = serde_json::to_vec(&v).unwrap();
        let s = sandbox(Some(&bytes));
        code(
            s.app.stack(
                "plan",
                "hma-scope",
                "com.google.android.gms",
                "org.example.hidden",
                "",
                "",
            ),
            wanted,
        );
        original(&s);
    }
    for name in [
        "com.google.android.gms",
        "android.uid.system",
        "com.android.settings",
        "org.frknkrc44.hma_oss",
        "io.github.a13e300.ksuwebui",
        "invalid",
        "org.example.hidden,org.example.hidden",
    ] {
        let s = sandbox(None);
        code(
            s.app
                .stack("plan", "hma-scope", "com.google.android.gms", name, "", ""),
            "E_SELECTION",
        );
        original(&s);
    }
}
#[test]
fn strict_json_duplicate_utf8_depth_case_alias_and_arguments() {
    for bytes in [
        br#"{"configVersion":93,"scope":{},"future":{"a":1,"a":2}}"#.to_vec(),
        b"{\"configVersion\":93,\"scope\":{},\"future\":\"\xff\"}".to_vec(),
        format!(
            "{{\"configVersion\":93,\"scope\":{{}},\"future\":{}0{}}}",
            "[".repeat(33),
            "]".repeat(33)
        )
        .into_bytes(),
    ] {
        let s = sandbox(Some(&bytes));
        code(
            s.app.stack(
                "plan",
                "hma-scope",
                "com.google.android.gms",
                "org.example.hidden",
                "",
                "",
            ),
            "E_CAPABILITY",
        );
        original(&s);
    }
    let s = sandbox(None);
    let id = hma_plan(&s);
    let p = plan_dir(&s, &id).join("plan.json");
    let mut b = std::fs::read(&p).unwrap();
    while b.last().is_some_and(u8::is_ascii_whitespace) {
        b.pop();
    }
    b.pop();
    b.extend_from_slice(format!(",\"ID\":\"{}\"}}", "a".repeat(32)).as_bytes());
    write(&p, &b);
    code(s.app.stack("apply", "", "", "", "", &id), "E_FORMAT");
    original(&s);
    for action in ["status", "apply", "verify", "rollback"] {
        for idx in 1..5 {
            let mut args = [action, "", "", "", "", ""];
            args[idx] = "unrelated-selection";
            code(
                s.app
                    .stack(args[0], args[1], args[2], args[3], args[4], args[5]),
                "E_REQUEST",
            );
        }
    }
    code(
        s.app.stack(
            "plan",
            "hma-scope",
            "com.google.android.gms",
            "org.example.hidden",
            "",
            &"a".repeat(32),
        ),
        "E_REQUEST",
    );
    code(
        s.app.stack("status", "", "", "", "", &"a".repeat(32)),
        "E_REQUEST",
    );
}
#[test]
fn noop_duplicate_apply_and_expired_review_fail_without_writes() {
    let s = sandbox(None);
    code(
        s.app
            .stack("plan", "brezygisk-unmount", "", "", "false", ""),
        "E_SELECTION",
    );
    let id = hma_plan(&s);
    call(&s, "apply", &id);
    code(s.app.stack("apply", "", "", "", "", &id), "E_DUPLICATE");
    code(
        s.app.stack(
            "plan",
            "hma-scope",
            "com.google.android.gms",
            "org.example.hidden",
            "",
            "",
        ),
        "E_SELECTION",
    );
    let mut s = sandbox(None);
    let id = hma_plan(&s);
    s.app.clock = Arc::new(|| NOW + 1801);
    code(s.app.stack("apply", "", "", "", "", &id), "E_STALE");
    original(&s);
}
#[test]
fn stale_resource_protected_pif_module_other_resource_and_intent() {
    for kind in [
        "resource",
        "protected",
        "pif",
        "module",
        "other",
        "intent",
        "metadata",
    ] {
        let s = sandbox(None);
        let id = hma_plan(&s);
        match kind {
            "resource" => write(&s.config, &[s.original.as_slice(), b"\n "].concat()),
            "protected" => write(&s.app.active.join("target.txt"), b"external target"),
            "pif" => write(
                &s.app.modules.join("playintegrityfix/custom.pif.prop"),
                b"external pif",
            ),
            "module" => write(
                &s.app.modules.join("playintegrityfix/module.prop"),
                b"external module",
            ),
            "other" => write(&s.marker, b"external marker"),
            "intent" => write(&plan_dir(&s, &id).join("intent.bin"), b"changed intent"),
            _ => {
                let path = plan_dir(&s, &id).join("plan.json");
                let mut p = value(&path);
                p["after"]["metadata"]["mode"] = json!(511);
                store(&path, &p);
            }
        }
        assert!(s.app.stack("apply", "", "", "", "", &id).is_err());
        if kind != "resource" {
            assert_eq!(std::fs::read(&s.config).unwrap(), s.original);
        }
    }
}
#[test]
fn apply_faults_at_every_hook_restore_or_stop_before_write() {
    for point in [
        "stack-before-backup",
        "before-backup",
        "after-backup",
        "stack-after-backup",
        "stack-before-write",
        "stack-after-write",
        "stack-before-commit",
        "stack-after-commit",
    ] {
        let mut s = sandbox(None);
        let id = hma_plan(&s);
        let hit = Arc::new(AtomicBool::new(false));
        let h = hit.clone();
        s.app.fault = Some(Arc::new(move |p| {
            if p == point && !h.swap(true, Ordering::SeqCst) {
                Err(Error::new("E_SYNTHETIC", "injected failure"))
            } else {
                Ok(())
            }
        }));
        assert!(s.app.stack("apply", "", "", "", "", &id).is_err());
        assert!(hit.load(Ordering::SeqCst), "hook {point} missing");
        original(&s);
        assert!(!pending(&s));
    }
}
#[test]
fn interrupted_process_recovers_and_corrupt_backup_blocks_recovery() {
    for corrupt in [false, true] {
        let mut s = sandbox(None);
        let id = hma_plan(&s);
        s.app.fault = Some(Arc::new(|p| {
            if p == "stack-after-write" {
                panic!("synthetic process loss");
            }
            Ok(())
        }));
        let loss = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            s.app.stack("apply", "", "", "", "", &id)
        }));
        assert!(loss.is_err());
        s.app.fault = None;
        assert!(pending(&s));
        code(
            s.app.stack("plan", "brezygisk-unmount", "", "", "true", ""),
            "E_RECOVERY",
        );
        if corrupt {
            write(
                &backup_dir(&s, &id).join("resource.bin"),
                b"corrupt original",
            );
            let current = std::fs::read(&s.config).unwrap();
            code(s.app.stack("rollback", "", "", "", "", &id), "E_BACKUP");
            assert_eq!(std::fs::read(&s.config).unwrap(), current);
            assert!(pending(&s));
        } else {
            call(&s, "rollback", &id);
            original(&s);
            assert!(!pending(&s));
        }
    }
}
#[test]
fn external_selected_writers_never_get_overwritten() {
    for point in [
        "stack-before-write",
        "stack-after-write",
        "stack-before-commit",
        "stack-after-commit",
        "stack-before-restore",
    ] {
        let mut s = sandbox(None);
        let id = hma_plan(&s);
        if point == "stack-before-restore" {
            call(&s, "apply", &id);
        }
        let path = s.config.clone();
        let conflict = [s.original.as_slice(), b"\n "].concat();
        let expected = conflict.clone();
        let hit = Arc::new(AtomicBool::new(false));
        let h = hit.clone();
        s.app.fault = Some(Arc::new(move |p| {
            if p == point && !h.swap(true, Ordering::SeqCst) {
                write(&path, &conflict);
            }
            Ok(())
        }));
        let action = if point == "stack-before-restore" {
            "rollback"
        } else {
            "apply"
        };
        code(s.app.stack(action, "", "", "", "", &id), "E_STALE");
        assert!(hit.load(Ordering::SeqCst));
        assert_eq!(std::fs::read(&s.config).unwrap(), expected);
        assert_eq!(
            pending(&s),
            !["stack-before-restore", "stack-after-commit"].contains(&point)
        );
        assert_eq!(
            std::fs::read(backup_dir(&s, &id).join("conflict.bin")).unwrap(),
            expected
        );
    }
}
#[test]
fn late_other_resource_commit_change_compensates_only_selected_resource() {
    let mut s = sandbox(None);
    let id = hma_plan(&s);
    let marker = s.marker.clone();
    s.app.fault = Some(Arc::new(move |p| {
        if p == "stack-after-commit" {
            write(&marker, b"external other marker");
        }
        Ok(())
    }));
    let e = code(s.app.stack("apply", "", "", "", "", &id), "E_ROLLED_BACK");
    assert_eq!(e.data.unwrap()["state"], "restored");
    original(&s);
    assert_eq!(std::fs::read(&s.marker).unwrap(), b"external other marker");
}
#[test]
fn protected_backup_corruption_removes_verified_claims() {
    let s = sandbox(None);
    let id = hma_plan(&s);
    call(&s, "apply", &id);
    let b = value(&backup_dir(&s, &id).join("backup.json"));
    let pid = b["protected_backup"].as_str().unwrap();
    write(
        &s.app.root.join("backups").join(pid).join("target.txt"),
        b"corrupt protected backup",
    );
    code(s.app.stack("verify", "", "", "", "", &id), "E_BACKUP");
    let st = s.app.stack("status", "", "", "", "", "").unwrap();
    assert_eq!(st["operation"]["backup_available"], false);
    assert_eq!(st["operation"]["can_rollback"], false);
    redacted(&st);
    let current = std::fs::read(&s.config).unwrap();
    code(s.app.stack("rollback", "", "", "", "", &id), "E_BACKUP");
    assert_eq!(std::fs::read(&s.config).unwrap(), current);
    assert_eq!(s.app.snapshot().unwrap(), s.protected);
}
#[test]
fn restore_late_context_backup_faults_are_fail_closed() {
    for kind in [
        "protected",
        "pif",
        "other",
        "current-corrupt",
        "backup-failure",
        "after-restore-corrupt",
        "before-restore-failure",
        "after-restore-failure",
    ] {
        let mut s = sandbox(None);
        let id = hma_plan(&s);
        call(&s, "apply", &id);
        let applied = std::fs::read(&s.config).unwrap();
        let original_backup = value(&backup_dir(&s, &id).join("backup.json"));
        let selected = match kind {
            "protected" => s.app.active.join("target.txt"),
            "pif" => s.app.modules.join("playintegrityfix/custom.pif.prop"),
            _ => s.marker.clone(),
        };
        let current = backup_dir(&s, &id).join("rollback-current.bin");
        let protected = s
            .app
            .root
            .join("backups")
            .join(original_backup["protected_backup"].as_str().unwrap())
            .join("target.txt");
        let hit = Arc::new(AtomicBool::new(false));
        let h = hit.clone();
        s.app.fault = Some(Arc::new(move |p| {
            if p == "stack-before-restore" && ["protected", "pif", "other"].contains(&kind) {
                h.store(true, Ordering::SeqCst);
                write(&selected, b"external context");
            }
            if p == "stack-after-rollback-backup" && kind == "current-corrupt" {
                h.store(true, Ordering::SeqCst);
                write(&current, b"corrupt current snapshot");
            }
            if p == "stack-after-restore" && kind == "after-restore-corrupt" {
                h.store(true, Ordering::SeqCst);
                write(&protected, b"corrupt protected backup");
            }
            if (p == "before-backup" && kind == "backup-failure")
                || (p == "stack-before-restore" && kind == "before-restore-failure")
                || (p == "stack-after-restore" && kind == "after-restore-failure")
            {
                h.store(true, Ordering::SeqCst);
                return Err(Error::new("E_SYNTHETIC", "synthetic restore failure"));
            }
            Ok(())
        }));
        let wanted = match kind {
            "protected" | "pif" | "other" => "E_STALE",
            "current-corrupt" => "E_BACKUP",
            "backup-failure" | "before-restore-failure" => "E_SYNTHETIC",
            _ => "E_RECOVERY",
        };
        code(s.app.stack("rollback", "", "", "", "", &id), wanted);
        assert!(hit.load(Ordering::SeqCst));
        assert_eq!(pending(&s), kind.starts_with("after-restore"));
        let expected = if kind.starts_with("after-restore") {
            &s.original
        } else {
            &applied
        };
        assert_eq!(&std::fs::read(&s.config).unwrap(), expected);
        if kind == "protected" {
            assert_eq!(
                std::fs::read(s.app.active.join("target.txt")).unwrap(),
                b"external context"
            );
        }
    }
}
#[test]
fn repeated_rollback_checks_immutable_backup_again() {
    let s = sandbox(None);
    let id = hma_plan(&s);
    call(&s, "apply", &id);
    call(&s, "rollback", &id);
    write(
        &backup_dir(&s, &id).join("resource.bin"),
        b"corrupt restored backup",
    );
    code(s.app.stack("rollback", "", "", "", "", &id), "E_BACKUP");
    original(&s);
    let st = s.app.stack("status", "", "", "", "", "").unwrap();
    assert_eq!(st["operation"]["can_verify"], false);
}
#[test]
fn corrupt_foreign_or_stack_journals_and_metadata_gate_new_writes() {
    for name in ["journal.json", "reset-journal.json", "stack-journal.json"] {
        let s = sandbox(None);
        write(
            &s.app.root.join(name),
            br#"{"invalid":"synthetic-sensitive-private-app"}"#,
        );
        code(
            s.app.stack(
                "plan",
                "hma-scope",
                "com.google.android.gms",
                "org.example.hidden",
                "",
                "",
            ),
            "E_RECOVERY",
        );
        redacted(&s.app.stack("status", "", "", "", "", "").unwrap());
        original(&s);
    }
    for field in [
        "parent-mode",
        "parent-context",
        "hma-absent",
        "after-mode",
        "case-alias",
    ] {
        let s = sandbox(None);
        let id = hma_plan(&s);
        call(&s, "apply", &id);
        let path = s.app.root.join("stack-journal.json");
        let mut j = value(&path);
        match field {
            "parent-mode" => j["parent"]["mode"] = json!(511),
            "parent-context" => j["parent"]["selinux"] = json!("invalid context"),
            "hma-absent" => j["before"] = json!(FileState::default()),
            "after-mode" => j["after"]["metadata"]["mode"] = json!(256),
            _ => j["State"] = json!("restored"),
        };
        store(&path, &j);
        assert!(pending(&s));
        code(
            s.app.stack("plan", "brezygisk-unmount", "", "", "true", ""),
            "E_RECOVERY",
        );
        redacted(&s.app.stack("status", "", "", "", "", "").unwrap());
    }
}
#[test]
fn ambiguous_backend_and_symlink_resources_are_rejected() {
    let s = sandbox(None);
    safe_fs::private_dir(
        &s.config
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("hide_my_applist_ponmlkjihgfedcba"),
    )
    .unwrap();
    assert!(
        s.app
            .stack(
                "plan",
                "hma-scope",
                "com.google.android.gms",
                "org.example.hidden",
                "",
                ""
            )
            .is_err()
    );
    original(&s);
    let s = sandbox(None);
    std::fs::remove_file(&s.config).unwrap();
    std::fs::create_dir(&s.config).unwrap();
    assert!(
        s.app
            .stack(
                "plan",
                "hma-scope",
                "com.google.android.gms",
                "org.example.hidden",
                "",
                ""
            )
            .is_err()
    );
    #[cfg(unix)]
    {
        let s = sandbox(None);
        std::fs::remove_file(&s.config).unwrap();
        let outside = s._dir.path().join("outside");
        write(&outside, FIXTURE);
        std::os::unix::fs::symlink(&outside, &s.config).unwrap();
        code(
            s.app.stack(
                "plan",
                "hma-scope",
                "com.google.android.gms",
                "org.example.hidden",
                "",
                "",
            ),
            "E_CAPABILITY",
        );
        assert_eq!(std::fs::read(&outside).unwrap(), FIXTURE);
    }
}
#[test]
fn optional_hma_absence_does_not_block_other_profile() {
    let s = sandbox(None);
    std::fs::remove_dir_all(s.config.parent().unwrap()).unwrap();
    let id = plan(&s, "brezygisk-unmount", "", "", "true");
    call(&s, "apply", &id);
    call(&s, "rollback", &id);
    assert!(!s.marker.exists());
    assert_eq!(s.app.snapshot().unwrap(), s.protected);
}

#[test]
fn prior_go_null_marker_selection_arrays_remain_readable() {
    let s = sandbox(None);
    let id = plan(&s, "brezygisk-unmount", "", "", "true");
    let path = plan_dir(&s, &id).join("plan.json");
    let mut p = value(&path);
    p["targets"] = Value::Null;
    p["hide_packages"] = Value::Null;
    store(&path, &p);
    call(&s, "apply", &id);
    call(&s, "rollback", &id);
    original(&s);
    assert!(!s.marker.exists());
}

#[test]
fn status_binding_reads_live_resources_after_committed_stack_journal() {
    for kind in ["hma", "marker", "pif"] {
        let s = sandbox(None);
        let id = hma_plan(&s);
        call(&s, "apply", &id);
        let before = s.app.status().unwrap();
        let path = match kind {
            "hma" => s.config.clone(),
            "marker" => s.marker.clone(),
            _ => s.app.modules.join("playintegrityfix/custom.pif.prop"),
        };
        let bytes = if kind == "hma" {
            [std::fs::read(&path).unwrap().as_slice(), b"\n "].concat()
        } else {
            b"synthetic changed resource".to_vec()
        };
        write(&path, &bytes);
        let after = s.app.status().unwrap();
        assert_ne!(
            before["stack_evidence_binding"],
            after["stack_evidence_binding"]
        );
        assert_ne!(after["stack_evidence_binding"], "unavailable");
        assert_eq!(after["stack"]["operation"]["state"], "committed");
        assert_eq!(after["stack_pending"], false);
        assert!(s.app.stack("verify", "", "", "", "", &id).is_err());
    }
}

#[test]
fn core_verification_persistence_rechecks_stack_and_pif_binding() {
    for kind in ["marker", "pif"] {
        let mut s = sandbox(None);
        // A synthetic file-state journal tests evidence persistence only. It
        // carries no crypto, identity, Wallet-readiness or payment assertion.
        let journal = rhso::transaction::Journal {
            schema: 1,
            plan: "b".repeat(32),
            backup: "c".repeat(32),
            state: "committed".into(),
            time: s.app.time(),
            intended: s.protected.clone(),
        };
        safe_fs::write_json(&s.app.root.join("journal.json"), &journal).unwrap();
        let path = if kind == "marker" {
            s.marker.clone()
        } else {
            s.app.modules.join("playintegrityfix/custom.pif.prop")
        };
        s.app.fault = Some(Arc::new(move |point| {
            if point == "before-verification-persist" {
                write(&path, b"synthetic external context");
            }
            Ok(())
        }));
        code(s.app.verify(false, false, ""), "E_STALE");
        assert!(!s.app.root.join("verification.json").exists());
        assert_eq!(s.app.snapshot().unwrap(), s.protected);
    }
}

fn resolution_review(s: &Sandbox) -> String {
    let status = s.app.stack("status", "", "", "", "", "").unwrap();
    redacted(&status);
    assert_eq!(status["operation"]["can_resolve"], true);
    status["operation"]["resolution_review_hash"]
        .as_str()
        .unwrap()
        .into()
}
fn resolve(s: &Sandbox, id: &str, review: &str) -> Result<Value> {
    s.app.stack_confirmed(
        "resolve",
        "",
        "",
        "",
        "",
        id,
        rhso::stack::RESOLVE_PHRASE,
        review,
    )
}
fn ingest_after(s: &Sandbox) -> Value {
    let p = s.app.root.join("inbox/closure-fixture.xml");
    write(&p, b"<AndroidAttestation/>");
    s.app.ingest(p.to_str().unwrap()).unwrap()
}
#[test]
fn audit_s1_prewrite_conflict_preserves_committed_journal_and_recovery_access() {
    let s = sandbox(None);
    let id = hma_plan(&s);
    call(&s, "apply", &id);
    let journal_path = s.app.root.join("stack-journal.json");
    let prior = std::fs::read(&journal_path).unwrap();
    let external = [std::fs::read(&s.config).unwrap().as_slice(), b"\n"].concat();
    write(&s.config, &external);
    code(s.app.stack("rollback", "", "", "", "", &id), "E_STALE");
    assert_eq!(std::fs::read(&journal_path).unwrap(), prior);
    assert!(!pending(&s));
    assert_eq!(
        std::fs::read(backup_dir(&s, &id).join("conflict.bin")).unwrap(),
        external
    );
    ingest_after(&s);
    let b = value(&backup_dir(&s, &id).join("backup.json"));
    assert_eq!(
        s.app
            .rollback(b["protected_backup"].as_str().unwrap())
            .unwrap()["state"],
        "already-restored"
    );
    plan(&s, "brezygisk-unmount", "", "", "true");
    assert_eq!(s.app.snapshot().unwrap(), s.protected);
    assert_eq!(std::fs::read(&s.config).unwrap(), external);
    let first = std::fs::read(backup_dir(&s, &id).join("conflict.json")).unwrap();
    code(s.app.stack("rollback", "", "", "", "", &id), "E_STALE");
    assert_eq!(
        std::fs::read(backup_dir(&s, &id).join("conflict.json")).unwrap(),
        first
    );
    assert!(std::fs::read_dir(backup_dir(&s, &id)).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("conflict-")
    }));
}
#[test]
fn late_module_rollback_refusal_keeps_previous_committed_state() {
    let mut s = sandbox(None);
    let path = s.app.modules.join("playintegrityfix/module.prop");
    write(&path, b"id=playintegrityfix\n");
    let id = hma_plan(&s);
    call(&s, "apply", &id);
    let before = std::fs::read(s.app.root.join("stack-journal.json")).unwrap();
    let active = std::fs::read(&s.config).unwrap();
    s.app.fault = Some(Arc::new(move |p| {
        if p == "stack-before-restore" {
            write(&path, b"id=playintegrityfix\nversion=changed\n");
        }
        Ok(())
    }));
    code(s.app.stack("rollback", "", "", "", "", &id), "E_STALE");
    assert_eq!(
        std::fs::read(s.app.root.join("stack-journal.json")).unwrap(),
        before
    );
    assert_eq!(std::fs::read(&s.config).unwrap(), active);
    assert!(!pending(&s));
    ingest_after(&s);
}
#[test]
fn resolve_keeps_current_file_and_legacy_pending_evidence_then_is_idempotent() {
    for legacy in [false, true] {
        let s = sandbox(None);
        let id = hma_plan(&s);
        call(&s, "apply", &id);
        if legacy {
            let path = s.app.root.join("stack-journal.json");
            let mut j = value(&path);
            j["state"] = json!("recovery-required");
            j.as_object_mut().unwrap().remove("resolution_id");
            store(&path, &j);
            let path = plan_dir(&s, &id).join("plan.json");
            let mut p = value(&path);
            p["capabilities"]["xml_x509"] = json!("bundled-go-standard-library");
            store(&path, &p);
            assert!(pending(&s));
        }
        let external = [
            std::fs::read(&s.config).unwrap().as_slice(),
            b"\n externally retained opaque bytes",
        ]
        .concat();
        write(&s.config, &external);
        let before = safe_fs::snapshot_file(&s.config, 1 << 20).unwrap();
        let old = value(&s.app.root.join("stack-journal.json"));
        let review = resolution_review(&s);
        code(
            s.app
                .stack_confirmed("resolve", "", "", "", "", &id, "wrong", &review),
            "E_CONFIRM",
        );
        code(resolve(&s, &"f".repeat(32), &review), "E_STALE");
        let v = resolve(&s, &id, &review).unwrap();
        redacted(&v);
        assert_eq!(v["state"], "superseded");
        assert_eq!(v["active_resource_written"], false);
        assert_eq!(v["evidence_preserved"], true);
        assert_eq!(v["runtime_adoption"], "unknown");
        assert_eq!(safe_fs::snapshot_file(&s.config, 1 << 20).unwrap(), before);
        assert_eq!(s.app.snapshot().unwrap(), s.protected);
        assert!(!pending(&s));
        let j = value(&s.app.root.join("stack-journal.json"));
        let rid = j["resolution_id"].as_str().unwrap();
        let ev = value(&backup_dir(&s, &id).join(format!("resolution-{rid}.json")));
        assert_eq!(ev["prior"], old);
        assert_eq!(
            std::fs::read(backup_dir(&s, &id).join(format!("resolution-{rid}.bin"))).unwrap(),
            external
        );
        let history = std::fs::read(s.app.root.join("history.json")).unwrap();
        let journal = std::fs::read(s.app.root.join("stack-journal.json")).unwrap();
        assert_eq!(resolve(&s, &id, &review).unwrap(), v);
        assert_eq!(
            std::fs::read(s.app.root.join("history.json")).unwrap(),
            history
        );
        assert_eq!(
            std::fs::read(s.app.root.join("stack-journal.json")).unwrap(),
            journal
        );
        let st = s.app.stack("status", "", "", "", "", "").unwrap();
        assert_eq!(st["operation"]["can_resolve"], false);
        assert_eq!(st["operation"]["can_verify"], false);
        assert_eq!(st["operation"]["can_rollback"], false);
        code(s.app.stack("rollback", "", "", "", "", &id), "E_RECOVERY");
        ingest_after(&s);
    }
}
#[test]
fn resolve_review_binds_current_resource_journal_and_preserved_bytes() {
    for kind in ["file", "journal", "evidence", "after-commit"] {
        let mut s = sandbox(None);
        let id = hma_plan(&s);
        call(&s, "apply", &id);
        let review = resolution_review(&s);
        let path = s.config.clone();
        let jpath = s.app.root.join("stack-journal.json");
        let bk = backup_dir(&s, &id);
        let hook = if kind == "after-commit" {
            "stack-after-resolve-commit"
        } else if kind == "evidence" {
            "stack-before-resolve-commit"
        } else {
            "stack-before-resolve-evidence"
        };
        s.app.fault = Some(Arc::new(move |p| {
            if p == hook {
                match kind {
                    "file" | "after-commit" => write(&path, b"external retained file"),
                    "journal" => {
                        let mut j = value(&jpath);
                        j["state"] = json!("recovery-required");
                        store(&jpath, &j);
                    }
                    _ => {
                        for e in std::fs::read_dir(&bk).unwrap() {
                            let e = e.unwrap();
                            if e.file_name().to_string_lossy().starts_with("resolution-")
                                && e.path().extension().is_some_and(|v| v == "bin")
                            {
                                write(&e.path(), b"corrupt preserved evidence");
                            }
                        }
                    }
                }
            }
            Ok(())
        }));
        let e = resolve(&s, &id, &review).unwrap_err();
        assert_eq!(
            e.code,
            if kind == "evidence" {
                "E_RECOVERY"
            } else {
                "E_STALE"
            }
        );
        assert_eq!(
            value(&s.app.root.join("stack-journal.json"))["state"] == "superseded",
            kind == "after-commit"
        );
        assert_eq!(s.app.snapshot().unwrap(), s.protected);
    }
}
#[test]
fn resolve_faults_and_process_loss_never_write_active_files_and_can_retry() {
    for hook in [
        "stack-before-resolve-evidence",
        "stack-before-resolve-commit",
        "stack-after-resolve-commit",
    ] {
        for panic in [false, true] {
            let mut s = sandbox(None);
            let id = hma_plan(&s);
            call(&s, "apply", &id);
            let current = safe_fs::snapshot_file(&s.config, 1 << 20).unwrap();
            let review = resolution_review(&s);
            s.app.fault = Some(Arc::new(move |p| {
                if p == hook {
                    if panic {
                        panic!("synthetic closure process loss");
                    }
                    return Err(Error::new("E_SYNTHETIC", "synthetic closure failure"));
                }
                Ok(())
            }));
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                resolve(&s, &id, &review)
            }));
            if panic {
                assert!(r.is_err());
            } else {
                code(r.unwrap(), "E_SYNTHETIC");
            }
            s.app.fault = None;
            assert_eq!(safe_fs::snapshot_file(&s.config, 1 << 20).unwrap(), current);
            assert_eq!(s.app.snapshot().unwrap(), s.protected);
            assert_eq!(resolve(&s, &id, &review).unwrap()["state"], "superseded");
            assert!(!pending(&s));
            let h: Vec<Value> = safe_fs::read_json(&s.app.root.join("history.json")).unwrap();
            assert_eq!(h.iter().filter(|v| v["type"] == "stack-resolve").count(), 1);
        }
    }
}
#[test]
fn absent_kept_resource_and_corrupt_terminal_resolution_fail_closed() {
    for kind in ["absent", "corrupt", "metadata"] {
        let s = sandbox(None);
        let id = hma_plan(&s);
        call(&s, "apply", &id);
        if kind == "absent" {
            std::fs::remove_file(&s.config).unwrap();
        }
        let review = resolution_review(&s);
        resolve(&s, &id, &review).unwrap();
        let j = value(&s.app.root.join("stack-journal.json"));
        let rid = j["resolution_id"].as_str().unwrap();
        if kind == "absent" {
            assert!(!s.config.exists());
            assert!(
                !backup_dir(&s, &id)
                    .join(format!("resolution-{rid}.bin"))
                    .exists()
            );
            assert!(!pending(&s));
        } else {
            let path = backup_dir(&s, &id).join(format!("resolution-{rid}.json"));
            if kind == "corrupt" {
                write(
                    &backup_dir(&s, &id).join(format!("resolution-{rid}.bin")),
                    b"corrupt",
                );
            } else {
                let mut ev = value(&path);
                ev["parent"]["mode"] = json!(511);
                store(&path, &ev);
            }
            assert!(pending(&s));
            code(resolve(&s, &id, &review), "E_RECOVERY");
            assert!(s.app.require_recovered().is_err());
        }
        assert_eq!(s.app.snapshot().unwrap(), s.protected);
    }
}
#[test]
fn closure_options_and_unknown_terminal_evidence_are_never_ignored() {
    let s = sandbox(None);
    for action in ["status", "plan", "apply", "verify", "rollback"] {
        code(
            s.app.stack_confirmed(
                action,
                "",
                "",
                "",
                "",
                "",
                rhso::stack::RESOLVE_PHRASE,
                &"a".repeat(64),
            ),
            "E_REQUEST",
        );
    }
    let id = hma_plan(&s);
    call(&s, "apply", &id);
    let path = s.app.root.join("stack-journal.json");
    let mut j = value(&path);
    j["state"] = json!("superseded");
    store(&path, &j);
    assert!(pending(&s));
    code(resolve(&s, &id, &"a".repeat(64)), "E_RECOVERY");
}
