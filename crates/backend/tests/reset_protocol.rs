//! Reset protocol fixtures use inert script text and a fake engine. No pm clear,
//! PIF action, process control, reboot or network operation is dispatched.
use rhso::{
    App,
    error::{Error, Result},
    fs::{self, Metadata},
    reset::ResetJournal,
    util,
};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tempfile::TempDir;
const PHRASE: &str = "CLEAR WALLET AND GOOGLE SERVICES";
const COMPLETE: &str = "PIF ACTION AND GMS FORCE-STOP COMPLETED";
struct Sandbox {
    _dir: TempDir,
    app: App,
    journal: PathBuf,
}
fn write(path: &Path, bytes: &[u8]) {
    fs::atomic_write(
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
fn sandbox() -> Sandbox {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let mut app = App::new(
        root.join("private"),
        root.join("active"),
        root.join("modules"),
        true,
    );
    app.clock = Arc::new(|| 1791547200);
    fs::private_dir(&app.active).unwrap();
    fs::private_dir(&app.modules.join("playintegrityfix")).unwrap();
    app.init().unwrap();
    for name in ["keybox.xml", "target.txt", "security_patch.txt"] {
        write(
            &app.active.join(name),
            format!("synthetic opaque {name}").as_bytes(),
        );
    }
    for (name, text) in [
        ("action.sh", "action"),
        ("autopif4.sh", "autopif"),
        ("killpi.sh", "kill"),
        ("custom.pif.prop", "pif"),
    ] {
        write(
            &app.modules.join("playintegrityfix").join(name),
            text.as_bytes(),
        );
    }
    let journal = app.root.join("reset-journal.json");
    Sandbox {
        _dir: dir,
        app,
        journal,
    }
}
fn record() -> ResetJournal {
    ResetJournal {
        schema: 1,
        state: "awaiting-manual-reboot".into(),
        boot: "synthetic-previous-boot".into(),
        user: "0".into(),
        review_hash: util::hash(b"review"),
        scripts: [
            ("action.sh", b"action".as_slice()),
            ("autopif4.sh", b"autopif".as_slice()),
            ("killpi.sh", b"kill".as_slice()),
        ]
        .into_iter()
        .map(|(n, b)| (n.into(), util::hash(b)))
        .collect(),
        step: 5,
        time: util::time(1791547200),
        backup: "a".repeat(32),
        pif_hash: util::hash(b"pif"),
    }
}
fn code<T: std::fmt::Debug>(r: Result<T>, expected: &str) -> Error {
    let e = r.unwrap_err();
    assert_eq!(e.code, expected, "{e}");
    e
}
fn preserve(
    s: &Sandbox,
    before: &[u8],
    protected: &std::collections::BTreeMap<String, fs::FileState>,
) {
    assert_eq!(std::fs::read(&s.journal).unwrap(), before);
    assert_eq!(&s.app.snapshot().unwrap(), protected);
}
#[test]
fn preview_binds_local_context_and_leaves_destructive_state_absent() {
    let s = sandbox();
    let protected = s.app.snapshot().unwrap();
    let v = s.app.reset("preview", "", "").unwrap();
    assert_eq!(v["user"], "0");
    assert_eq!(v["confirmation"], PHRASE);
    assert_eq!(v["steps"].as_array().unwrap().len(), 7);
    assert!(util::valid_hash(v["review_hash"].as_str().unwrap()));
    assert!(!s.journal.exists());
    assert!(s.app.root.join("reset-review.json").is_file());
    assert_eq!(
        std::fs::read_dir(s.app.root.join("backups"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(s.app.snapshot().unwrap(), protected);
    let mut review: Value = fs::read_json(&s.app.root.join("reset-review.json")).unwrap();
    assert_eq!(review["state"], "reviewed");
    assert_eq!(review["backup"], "");
    assert_eq!(review["step"], 0);
    review["user"] = json!("10");
    assert_eq!(
        s.app.reset("status", "", "").unwrap(),
        json!({"state":"none"})
    );
}
#[test]
fn fake_confirmation_never_reaches_backup_or_dispatch() {
    let mut s = sandbox();
    let protected = s.app.snapshot().unwrap();
    s.app.fault = Some(Arc::new(|_| {
        panic!("fake destructive reset reached transaction hook")
    }));
    code(
        s.app.reset("confirm", "wrong", &"a".repeat(64)),
        "E_CONFIRM",
    );
    code(
        s.app.reset("confirm", PHRASE, &"a".repeat(64)),
        "E_CAPABILITY",
    );
    assert!(!s.journal.exists());
    assert!(!s.app.root.join("journal.json").exists());
    assert_eq!(
        std::fs::read_dir(s.app.root.join("backups"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(s.app.snapshot().unwrap(), protected);
}
#[test]
fn resume_requires_new_boot_same_user_unchanged_scripts_and_manual_pif() {
    for (kind, wanted) in [
        ("boot", "E_CONFIRM"),
        ("user", "E_STALE"),
        ("script", "E_STALE"),
        ("manual", "E_CAPABILITY"),
    ] {
        let s = sandbox();
        let mut r = record();
        if kind == "boot" {
            r.boot = util::boot_id();
        }
        if kind == "user" {
            r.user = "10".into();
        }
        fs::write_json(&s.journal, &r).unwrap();
        if kind == "script" {
            write(
                &s.app.modules.join("playintegrityfix/autopif4.sh"),
                b"changed inert fixture",
            );
        }
        let before = std::fs::read(&s.journal).unwrap();
        let protected = s.app.snapshot().unwrap();
        let e = code(s.app.reset("resume", "", ""), wanted);
        if kind == "manual" {
            let data = e.data.unwrap();
            assert_eq!(data["state"], "awaiting-manual-reboot");
            assert_eq!(data["user"], "0");
            assert!(data["next_step"].as_str().unwrap().contains("manually"));
        }
        preserve(&s, &before, &protected);
    }
}
#[test]
fn explicit_completion_preserves_legacy_journal_and_does_not_clear_again() {
    let s = sandbox();
    let r = record();
    fs::write_json(&s.journal, &r).unwrap();
    let protected = s.app.snapshot().unwrap();
    let before = std::fs::read(&s.journal).unwrap();
    code(s.app.reset("complete", "wrong", ""), "E_CONFIRM");
    preserve(&s, &before, &protected);
    assert_eq!(
        s.app.reset("complete", COMPLETE, "").unwrap()["state"],
        "completed"
    );
    let completed: ResetJournal = fs::read_json(&s.journal).unwrap();
    assert_eq!(completed.step, 5);
    assert_eq!(completed.scripts, r.scripts);
    assert_eq!(completed.backup, r.backup);
    assert_eq!(completed.review_hash, r.review_hash);
    assert_eq!(completed.pif_hash, r.pif_hash);
    assert_eq!(completed.user, r.user);
    let bytes = std::fs::read(&s.journal).unwrap();
    assert_eq!(s.app.reset("status", "", "").unwrap()["state"], "completed");
    code(s.app.reset("resume", "", ""), "E_RESET");
    preserve(&s, &bytes, &protected);
    assert_eq!(
        std::fs::read_dir(s.app.root.join("backups"))
            .unwrap()
            .count(),
        0
    );
    // A valid prior Go schema-1 completed record is accepted without rewriting.
    assert!(s.app.require_recovered().is_ok());
}
#[test]
fn attempted_failed_or_partial_steps_are_never_resumed_or_retried() {
    for state in ["attempting-clear", "failed-do-not-repeat", "clearing"] {
        let s = sandbox();
        let mut r = record();
        r.state = state.into();
        r.step = 2;
        fs::write_json(&s.journal, &r).unwrap();
        let before = std::fs::read(&s.journal).unwrap();
        let protected = s.app.snapshot().unwrap();
        assert_eq!(s.app.reset("status", "", "").unwrap()["completed_steps"], 2);
        code(s.app.reset("resume", "", ""), "E_RESET");
        code(s.app.reset("complete", COMPLETE, ""), "E_CONFIRM");
        assert!(s.app.require_recovered().is_err());
        code(s.app.reset("preview", "", ""), "E_RECOVERY");
        preserve(&s, &before, &protected);
    }
}
#[test]
fn corrupt_terminal_metadata_and_numeric_users_fail_closed_without_rewrite() {
    for field in [
        "schema",
        "step",
        "state",
        "review",
        "script",
        "time",
        "backup",
        "user",
        "attempted-step",
        "alias",
        "unknown",
    ] {
        let s = sandbox();
        let mut v = serde_json::to_value(record()).unwrap();
        match field {
            "schema" => v["schema"] = json!(99),
            "step" => {
                v["state"] = json!("completed");
                v["step"] = json!(4);
            }
            "state" => v["state"] = json!("synthetic-sensitive-reset-field"),
            "review" => v["review_hash"] = json!(""),
            "script" => {
                v["scripts"].as_object_mut().unwrap().remove("autopif4.sh");
            }
            "time" => v["time"] = json!("synthetic-sensitive-reset-field"),
            "backup" => v["backup"] = json!("../outside"),
            "user" => v["user"] = json!("current"),
            "attempted-step" => {
                v["state"] = json!("attempting-clear");
                v["step"] = json!(5);
            }
            "alias" => v["State"] = json!("completed"),
            _ => v["private"] = json!("synthetic-sensitive-reset-field"),
        };
        fs::write_json(&s.journal, &v).unwrap();
        let before = std::fs::read(&s.journal).unwrap();
        let protected = s.app.snapshot().unwrap();
        for action in ["status", "resume", "complete"] {
            let e = code(s.app.reset(action, COMPLETE, ""), "E_RECOVERY");
            assert!(
                !serde_json::to_string(&e)
                    .unwrap()
                    .contains("synthetic-sensitive-reset-field")
            );
        }
        assert!(s.app.require_recovered().is_err());
        preserve(&s, &before, &protected);
    }
    for user in [
        "",
        "current",
        "-1",
        "00",
        "01",
        "1000000",
        "0; command",
        "synthetic-sensitive-private-metadata",
    ] {
        assert!(!rhso::reset::valid_user(user));
    }
    for user in ["0", "1", "10", "999999"] {
        assert!(rhso::reset::valid_user(user));
    }
}
#[test]
fn malformed_duplicate_and_unsafe_journals_are_not_absent() {
    for bytes in [
        b"{".as_slice(),
        br#"{"state":"completed","state":"none"}"#.as_slice(),
        b"{\"state\":\"\xff\"}".as_slice(),
    ] {
        let s = sandbox();
        write(&s.journal, bytes);
        code(s.app.reset("status", "", ""), "E_RECOVERY");
        assert!(s.app.require_recovered().is_err());
        assert_eq!(std::fs::read(&s.journal).unwrap(), bytes);
    }
    #[cfg(unix)]
    {
        let s = sandbox();
        std::os::unix::fs::symlink(s._dir.path().join("nonexistent"), &s.journal).unwrap();
        code(s.app.reset("status", "", ""), "E_RECOVERY");
        assert!(s.app.require_recovered().is_err());
    }
}
#[test]
fn preview_requires_every_script_and_failed_completion_preserves_journal() {
    let s = sandbox();
    std::fs::remove_file(s.app.modules.join("playintegrityfix/killpi.sh")).unwrap();
    code(s.app.reset("preview", "", ""), "E_CAPABILITY");
    assert!(!s.app.root.join("reset-review.json").exists());
    let s = sandbox();
    let mut r = record();
    r.boot = util::boot_id();
    fs::write_json(&s.journal, &r).unwrap();
    let before = std::fs::read(&s.journal).unwrap();
    let protected = s.app.snapshot().unwrap();
    code(s.app.reset("complete", COMPLETE, ""), "E_CONFIRM");
    preserve(&s, &before, &protected);
}

fn close_token(s: &Sandbox) -> String {
    let status = s.app.reset("status", "", "").unwrap();
    assert_eq!(status["can_close"], true);
    status["close_review_hash"].as_str().unwrap().into()
}
fn close(s: &Sandbox, token: &str) -> Result<Value> {
    s.app.reset("close", rhso::reset::CLOSE_PHRASE, token)
}
#[test]
fn audit_s2_close_preserves_all_incomplete_ledger_fields_without_dispatch() {
    for (state, step) in [
        ("clearing", 0),
        ("clearing", 5),
        ("attempting-clear", 2),
        ("failed-do-not-repeat", 4),
    ] {
        let s = sandbox();
        let protected = s.app.snapshot().unwrap();
        let preparation = s
            .app
            .backup("wallet-reset-preparation", &protected)
            .unwrap();
        let mut r = record();
        r.state = state.into();
        r.step = step;
        r.backup = preparation.id.clone();
        fs::write_json(&s.journal, &r).unwrap();
        fs::write_json(
            &s.app.root.join("journal.json"),
            &rhso::transaction::Journal {
                schema: 1,
                plan: "b".repeat(32),
                backup: preparation.id.clone(),
                state: "committed".into(),
                time: s.app.time(),
                intended: protected.clone(),
            },
        )
        .unwrap();
        let token = close_token(&s);
        code(s.app.reset("close", "wrong", &token), "E_CONFIRM");
        code(
            s.app.reset("close", rhso::reset::CLOSE_PHRASE, ""),
            "E_CONFIRM",
        );
        assert!(s.app.require_recovered().is_err());
        let v = close(&s, &token).unwrap();
        assert_eq!(v["state"], "closed-incomplete");
        assert_eq!(v["clear_dispatched"], false);
        assert_eq!(v["evidence_preserved"], true);
        let mut expected = r.clone();
        expected.state = "closed-incomplete".into();
        let saved: ResetJournal = fs::read_json(&s.journal).unwrap();
        assert_eq!(saved, expected);
        let evidence: Value =
            fs::read_json(&s.app.root.join(format!("reset-close-{}.json", r.backup))).unwrap();
        assert_eq!(evidence["prior"], serde_json::to_value(&r).unwrap());
        assert_eq!(s.app.snapshot().unwrap(), protected);
        assert!(s.app.require_recovered().is_ok());
        let source = s.app.root.join("inbox/after-close.xml");
        write(&source, b"<AndroidAttestation/>");
        s.app.ingest(source.to_str().unwrap()).unwrap();
        assert_eq!(
            s.app.rollback("previous").unwrap()["state"],
            "already-restored"
        );
        assert_eq!(
            std::fs::read_dir(s.app.root.join("backups"))
                .unwrap()
                .count(),
            1
        );
        let status = s.app.reset("status", "", "").unwrap();
        assert_eq!(status["can_close"], false);
        let history = std::fs::read(s.app.root.join("history.json")).unwrap();
        let journal = std::fs::read(&s.journal).unwrap();
        assert_eq!(close(&s, &token).unwrap(), v);
        assert_eq!(std::fs::read(&s.journal).unwrap(), journal);
        assert_eq!(
            std::fs::read(s.app.root.join("history.json")).unwrap(),
            history
        );
        code(s.app.reset("resume", "", ""), "E_RESET");
        code(s.app.reset("complete", COMPLETE, ""), "E_CONFIRM");
        let history: Vec<Value> = fs::read_json(&s.app.root.join("history.json")).unwrap();
        assert_eq!(
            history
                .iter()
                .filter(|v| v["state"] == "closed-incomplete")
                .count(),
            1
        );
    }
}
#[test]
fn close_refuses_reviewed_awaiting_completed_and_stale_ledger() {
    for state in ["reviewed", "awaiting-manual-reboot", "completed", "stale"] {
        let s = sandbox();
        let mut r = record();
        if state == "reviewed" {
            r.state = state.into();
            r.step = 0;
            r.backup = String::new();
        } else if state == "stale" {
            r.state = "clearing".into();
            r.step = 1;
        } else {
            r.state = state.into();
        }
        fs::write_json(&s.journal, &r).unwrap();
        let protected = s.app.snapshot().unwrap();
        let token = if state == "stale" {
            close_token(&s)
        } else {
            "a".repeat(64)
        };
        if state == "stale" {
            r.step = 2;
            fs::write_json(&s.journal, &r).unwrap();
        }
        let before = std::fs::read(&s.journal).unwrap();
        code(
            close(&s, &token),
            if state == "reviewed" {
                "E_RECOVERY"
            } else if state == "stale" {
                "E_STALE"
            } else {
                "E_RESET"
            },
        );
        preserve(&s, &before, &protected);
    }
}
#[test]
fn close_faults_and_process_loss_preserve_evidence_and_retry_without_clears() {
    for hook in [
        "reset-before-close-evidence",
        "reset-before-close-commit",
        "reset-after-close-commit",
    ] {
        for panic in [false, true] {
            let mut s = sandbox();
            let mut r = record();
            r.state = "attempting-clear".into();
            r.step = 3;
            fs::write_json(&s.journal, &r).unwrap();
            let protected = s.app.snapshot().unwrap();
            let token = close_token(&s);
            s.app.fault = Some(Arc::new(move |p| {
                if p == hook {
                    if panic {
                        panic!("synthetic reset close process loss");
                    }
                    return Err(Error::new("E_SYNTHETIC", "synthetic close failure"));
                }
                assert!(!p.contains("backup"));
                Ok(())
            }));
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| close(&s, &token)));
            if panic {
                assert!(result.is_err());
            } else {
                code(result.unwrap(), "E_SYNTHETIC");
            }
            s.app.fault = None;
            assert_eq!(s.app.snapshot().unwrap(), protected);
            assert_eq!(close(&s, &token).unwrap()["state"], "closed-incomplete");
            assert!(s.app.require_recovered().is_ok());
            let history: Vec<Value> = fs::read_json(&s.app.root.join("history.json")).unwrap();
            assert_eq!(
                history
                    .iter()
                    .filter(|v| v["state"] == "closed-incomplete")
                    .count(),
                1
            );
            assert_eq!(
                std::fs::read_dir(s.app.root.join("backups"))
                    .unwrap()
                    .count(),
                0
            );
        }
    }
}
#[test]
fn close_late_ledger_or_evidence_mutation_never_records_unsupported_terminal_state() {
    for kind in ["ledger", "evidence", "history", "after-commit"] {
        let mut s = sandbox();
        let mut r = record();
        r.state = "failed-do-not-repeat".into();
        r.step = 2;
        fs::write_json(&s.journal, &r).unwrap();
        let token = close_token(&s);
        let jp = s.journal.clone();
        let root = s.app.root.clone();
        let bid = r.backup.clone();
        s.app.fault = Some(Arc::new(move |p| {
            if p == if kind == "after-commit" {
                "reset-after-close-commit"
            } else {
                "reset-before-close-commit"
            } {
                match kind {
                    "ledger" | "after-commit" => {
                        let mut v: Value = fs::read_json(&jp).unwrap();
                        v["step"] = json!(3);
                        fs::write_json(&jp, &v).unwrap();
                    }
                    "evidence" => write(
                        &root.join(format!("reset-close-{bid}.json")),
                        b"corrupt retained ledger",
                    ),
                    _ => write(&root.join("history.json"), b"corrupt history"),
                }
            }
            Ok(())
        }));
        code(
            close(&s, &token),
            if ["ledger", "after-commit"].contains(&kind) {
                "E_STALE"
            } else if kind == "evidence" {
                "E_RECOVERY"
            } else {
                "E_INPUT"
            },
        );
        let saved: ResetJournal = fs::read_json(&s.journal).unwrap();
        assert_eq!(saved.state == "closed-incomplete", kind == "after-commit");
        assert!(s.app.require_recovered().is_err());
    }
}
#[test]
fn missing_corrupt_or_forged_closed_evidence_stays_fail_closed() {
    for kind in ["missing", "corrupt", "prior", "unknown", "alias"] {
        let s = sandbox();
        let mut r = record();
        r.state = "clearing".into();
        r.step = 1;
        fs::write_json(&s.journal, &r).unwrap();
        let token = close_token(&s);
        close(&s, &token).unwrap();
        let path = s.app.root.join(format!("reset-close-{}.json", r.backup));
        match kind {
            "missing" => std::fs::remove_file(&path).unwrap(),
            "corrupt" => write(&path, b"{"),
            _ => {
                let mut v: Value = fs::read_json(&path).unwrap();
                match kind {
                    "prior" => v["prior"]["state"] = json!("completed"),
                    "unknown" => v["extra"] = json!("synthetic-private-value"),
                    _ => v["Schema"] = json!(1),
                }
                fs::write_json(&path, &v).unwrap();
            }
        }
        let before = std::fs::read(&s.journal).unwrap();
        let protected = s.app.snapshot().unwrap();
        code(close(&s, &token), "E_RECOVERY");
        code(s.app.reset("status", "", ""), "E_RECOVERY");
        assert!(s.app.require_recovered().is_err());
        preserve(&s, &before, &protected);
    }
}
