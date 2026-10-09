//! Independently generated synthetic fixtures. These tests never read a phone,
//! real keybox, TLS credential, or root installation.
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SerialNumber,
};
use rhso::{
    App, FILES,
    error::Error,
    fs::{self, FileState},
    store::{Plan, private_metadata},
    transaction::{Backup, Journal},
    util,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs as io,
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
use tempfile::TempDir;
use time::OffsetDateTime;

const NOW: i64 = 1_791_547_200;
#[derive(Clone)]
struct Fixture {
    xml: Vec<u8>,
    root: String,
}
fn fixture() -> Fixture {
    static VALUE: OnceLock<Fixture> = OnceLock::new();
    VALUE.get_or_init(||{
        let parameters=|name:&str,serial:u64|{let mut p=CertificateParams::default();p.distinguished_name.push(DnType::CommonName,name);p.serial_number=Some(SerialNumber::from(serial));p.not_before=OffsetDateTime::from_unix_timestamp(NOW-3600).unwrap();p.not_after=OffsetDateTime::from_unix_timestamp(NOW+7*86400).unwrap();p.is_ca=IsCa::Ca(BasicConstraints::Constrained(5));p.key_usages=vec![KeyUsagePurpose::DigitalSignature,KeyUsagePurpose::KeyCertSign];p};
        let root_key=KeyPair::generate().unwrap();let root=parameters("Synthetic private issuer",1).self_signed(&root_key).unwrap();let leaf_key=KeyPair::generate().unwrap();let leaf=parameters("Synthetic private leaf",2).signed_by(&leaf_key,&root,&root_key).unwrap();
        let xml=format!("<?xml version=\"1.0\"?><AndroidAttestation><NumberOfKeyboxes>1</NumberOfKeyboxes><Keybox DeviceID=\"private-owner-sentinel\"><Key algorithm=\"ecdsa\"><PrivateKey format=\"pem\">{}</PrivateKey><CertificateChain><NumberOfCertificates>2</NumberOfCertificates><Certificate format=\"pem\">{}</Certificate><Certificate format=\"pem\">{}</Certificate></CertificateChain></Key></Keybox></AndroidAttestation>",leaf_key.serialize_pem(),leaf.pem(),root.pem()).into_bytes();
        Fixture{xml,root:root.pem()}
    }).clone()
}
struct Sandbox {
    _dir: TempDir,
    app: App,
}
impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("private");
        let active = dir.path().join("active");
        let modules = dir.path().join("modules");
        fs::private_dir(&active).unwrap();
        fs::private_dir(&modules).unwrap();
        fs::private_dir(&modules.join("playintegrityfix")).unwrap();
        let mut app = App::new(root, active, modules, true);
        app.clock = Arc::new(|| NOW);
        app.shared_inbox = dir.path().join("shared");
        app.init().unwrap();
        write(&app.active.join("keybox.xml"), &fixture().xml);
        write(
            &app.active.join("target.txt"),
            b"# retained operator note\ncom.google.android.gms\ncom.sample.retained?\n",
        );
        write(
            &app.active.join("security_patch.txt"),
            b"# retained patch note\nall=2026-09-05\n",
        );
        write(&app.modules.join("playintegrityfix/custom.pif.prop"),b"SECURITY_PATCH=2026-10-05\nFINGERPRINT=synthetic/fixture/device:16/test/1:user/release-keys\nspoofBuild=1\nspoofProps=1\nspoofProvider=0\nspoofSignature=0\nspoofVendingFinger=0\nspoofVendingSdk=0\nverboseLogs=0\n");
        Self { _dir: dir, app }
    }
    fn source(&self) -> PathBuf {
        let p = self.app.root.join("inbox/source.xml");
        write(&p, &fixture().xml);
        p
    }
    fn ingest(&self) -> String {
        self.app.ingest(self.source().to_str().unwrap()).unwrap()["id"]
            .as_str()
            .unwrap()
            .into()
    }
    fn plan(&self) -> Value {
        let id = self.ingest();
        self.app
            .plan(&format!("{id}:0:0:ecdsa"), true, "2026-10-05", false)
            .unwrap()
    }
    fn files(&self) -> BTreeMap<String, FileState> {
        self.app.snapshot().unwrap()
    }
    fn journal(&self) -> Journal {
        fs::read_json(&self.app.root.join("journal.json")).unwrap()
    }
}
fn write(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        io::create_dir_all(parent).unwrap();
    }
    fs::atomic_write(path, bytes, &private_metadata()).unwrap();
}
fn id(value: &Value) -> String {
    value["id"].as_str().unwrap().into()
}
fn fail_once(name: &str) -> rhso::Fault {
    let target = name.to_owned();
    let hit = AtomicBool::new(false);
    Arc::new(move |point| {
        if point == target && !hit.swap(true, Ordering::SeqCst) {
            Err(Error::new("E_FIXTURE", "Synthetic fault"))
        } else {
            Ok(())
        }
    })
}
fn install_cache(s: &Sandbox, status: Value, ttl: i64) {
    let roots = serde_json::to_vec(&vec![fixture().root]).unwrap();
    let status = serde_json::to_vec(&json!({"entries":status})).unwrap();
    let snapshot = |bytes: &[u8]| json!({"body":STANDARD.encode(bytes),"sha256":util::hash(bytes),"expires_at":util::time(NOW+ttl)});
    fs::write_json(&s.app.root.join("public-attestation.json"),&json!({"schema":1,"checked_at":util::time(NOW),"roots":snapshot(&roots),"status":snapshot(&status)})).unwrap();
}

#[test]
fn initialization_is_idempotent_and_refuses_unmarked_or_unknown_state() {
    let s = Sandbox::new();
    let before = fs::bounded(&s.app.root.join("format.json"), 4096).unwrap();
    s.app.init().unwrap();
    assert_eq!(
        before,
        fs::bounded(&s.app.root.join("format.json"), 4096).unwrap()
    );
    fs::write_json(
        &s.app.root.join("format.json"),
        &json!({"schema":99,"kind":"wallet-diagnostic-private-store"}),
    )
    .unwrap();
    assert_eq!(s.app.init().unwrap_err().code, "E_FORMAT");
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("unmarked");
    fs::private_dir(&root).unwrap();
    write(&root.join("old-private-sentinel"), b"preserve");
    let app = App::new(
        &root,
        dir.path().join("active"),
        dir.path().join("modules"),
        true,
    );
    assert_eq!(app.init().unwrap_err().code, "E_FORMAT");
    assert!(!root.join("format.json").exists());
    assert_eq!(
        io::read(root.join("old-private-sentinel")).unwrap(),
        b"preserve"
    );
}
#[test]
fn bounded_reads_validate_regular_files_and_store_object_paths() {
    let s = Sandbox::new();
    let p = s.source();
    assert_eq!(fs::bounded(&p, fixture().xml.len()).unwrap(), fixture().xml);
    assert_eq!(fs::bounded(&p, 1).unwrap_err().code, "E_INPUT");
    assert_eq!(
        fs::bounded(&s.app.root, 1 << 20).unwrap_err().code,
        "E_INPUT"
    );
    for (kind, id) in [
        ("../active", "a".repeat(32)),
        ("staged", "../source".into()),
        ("staged", "A".repeat(32)),
        ("staged", "a".repeat(31)),
    ] {
        assert_eq!(s.app.object(kind, &id).unwrap_err().code, "E_ID");
    }
    assert_eq!(
        s.app
            .ingest(s.app.modules.join("source.xml").to_str().unwrap())
            .unwrap_err()
            .code,
        "E_PATH"
    );
    assert_eq!(s.app.ingest("source.xml").unwrap_err().code, "E_PATH");
}
#[test]
fn staged_input_is_immutable_and_corrupt_metadata_cannot_validate() {
    let s = Sandbox::new();
    let stage = s.ingest();
    let valid = s.app.validate(&stage).unwrap();
    assert_eq!(valid["summary"]["trust"], "unknown");
    write(&s.source(), b"later unrelated source mutation");
    assert!(s.app.validate(&stage).is_ok());
    let dir = s.app.object("staged", &stage).unwrap();
    write(&dir.join("input.xml"), b"mutated staged bytes");
    assert_eq!(s.app.validate(&stage).unwrap_err().code, "E_STALE");
    let stage = s.ingest();
    let path = s.app.object("staged", &stage).unwrap().join("stage.json");
    let mut meta: Value = fs::read_json(&path).unwrap();
    meta["bytes"] = json!(0);
    fs::write_json(&path, &meta).unwrap();
    assert_eq!(s.app.validate(&stage).unwrap_err().code, "E_FORMAT");
}
#[test]
fn plan_apply_preserves_metadata_original_backup_and_uncertainty() {
    let s = Sandbox::new();
    let before = s.files();
    let pif = fs::bounded(
        &s.app.modules.join("playintegrityfix/custom.pif.prop"),
        65536,
    )
    .unwrap();
    let plan = s.plan();
    assert_eq!(plan["changes"].as_array().unwrap().len(), 3);
    assert!(
        plan["required_capabilities"]["stack_evidence_binding"]
            .as_str()
            .is_some_and(util::valid_hash)
    );
    let operation = s.app.apply(&id(&plan)).unwrap();
    assert_eq!(operation["adoption"], "pending");
    assert_eq!(operation["wallet_acceptance"], "unverified");
    let after = s.files();
    for name in FILES {
        assert_eq!(after[name].metadata, before[name].metadata);
        assert_ne!(after[name].sha256, before[name].sha256);
    }
    assert_eq!(
        pif,
        fs::bounded(
            &s.app.modules.join("playintegrityfix/custom.pif.prop"),
            65536
        )
        .unwrap()
    );
    let backup = operation["backup"].as_str().unwrap();
    assert_eq!(s.app.load_backup(backup).unwrap().files, before);
    assert!(
        s.app
            .object("backups", backup)
            .unwrap()
            .join("keybox.xml")
            .exists()
    );
    assert_eq!(s.app.apply(&id(&plan)).unwrap_err().code, "E_DUPLICATE");
    assert_eq!(
        s.app.verify(false, false, "").unwrap()["wallet_readiness"],
        "unverified"
    );
    s.app.rollback(backup).unwrap();
    assert_eq!(s.files(), before);
    assert_eq!(s.app.load_backup(backup).unwrap().files, before);
}
#[test]
fn all_commit_fault_boundaries_restore_the_complete_original_set() {
    for boundary in [
        "after-journal",
        "before-write-security_patch.txt",
        "after-write-security_patch.txt",
        "before-write-target.txt",
        "after-write-target.txt",
        "before-write-keybox.xml",
        "after-write-keybox.xml",
        "after-file-set",
        "before-commit-marker",
        "after-commit-marker",
    ] {
        let mut s = Sandbox::new();
        let before = s.files();
        let plan = s.plan();
        s.app.fault = Some(fail_once(boundary));
        let error = s.app.apply(&id(&plan)).unwrap_err();
        assert_eq!(error.code, "E_APPLY", "{boundary}");
        assert_eq!(s.files(), before, "{boundary}");
        assert_eq!(s.journal().state, "restored", "{boundary}");
        let backup = error.data.unwrap()["backup"].as_str().unwrap().to_owned();
        assert_eq!(s.app.load_backup(&backup).unwrap().files, before);
        assert!(s.app.require_recovered().is_ok());
    }
}
#[test]
fn backup_faults_leave_active_data_untouched_and_submitted_plan_consumed() {
    for boundary in ["before-backup", "after-backup"] {
        let mut s = Sandbox::new();
        let before = s.files();
        let p = s.plan();
        s.app.fault = Some(fail_once(boundary));
        assert_eq!(s.app.apply(&id(&p)).unwrap_err().code, "E_FIXTURE");
        assert_eq!(s.files(), before);
        assert!(!s.app.root.join("journal.json").exists());
        assert_eq!(s.app.apply(&id(&p)).unwrap_err().code, "E_DUPLICATE");
    }
}
#[test]
fn failed_restoration_requires_explicit_recovery_and_preserves_evidence() {
    for boundary in [
        "before-restore-keybox.xml",
        "before-restore-security_patch.txt",
        "before-restore-target.txt",
    ] {
        let mut s = Sandbox::new();
        let before = s.files();
        let p = s.plan();
        s.app.fault = Some(Arc::new(move |point| {
            if point == "after-file-set" || point == boundary {
                Err(Error::new("E_FIXTURE", "Synthetic failure"))
            } else {
                Ok(())
            }
        }));
        assert_eq!(s.app.apply(&id(&p)).unwrap_err().code, "E_RECOVERY");
        assert!(s.app.require_recovered().is_err());
        assert!(matches!(
            s.journal().state.as_str(),
            "restoring" | "recovery-required"
        ));
        let backup = s.journal().backup;
        assert_eq!(s.app.load_backup(&backup).unwrap().files, before);
        s.app.fault = None;
        assert_eq!(s.app.recovery("restore").unwrap()["state"], "restored");
        assert_eq!(s.files(), before);
        assert!(s.app.require_recovered().is_ok());
    }
}
#[test]
fn corrupted_backup_blocks_restore_without_overwriting_current_files() {
    let s = Sandbox::new();
    let p = s.plan();
    let apply = s.app.apply(&id(&p)).unwrap();
    let original = apply["backup"].as_str().unwrap();
    let before = s.files();
    write(
        &s.app
            .object("backups", original)
            .unwrap()
            .join("keybox.xml"),
        b"corrupt backup fixture",
    );
    assert_eq!(s.app.rollback(original).unwrap_err().code, "E_BACKUP");
    assert_eq!(s.files(), before);
    assert!(
        s.app.backups().unwrap()["backups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["id"] == original && b["integrity"] == "failed")
    );
}
#[test]
fn stale_active_source_proposal_capabilities_and_public_feed_are_rejected() {
    for what in [
        "active",
        "stage",
        "proposal",
        "pif",
        "public",
        "stack-program",
    ] {
        let s = Sandbox::new();
        let p = s.plan();
        let before = s.files();
        let plan_path = s.app.object("plans", &id(&p)).unwrap();
        match what {
            "active" => write(
                &s.app.active.join("target.txt"),
                b"external reviewed state change\n",
            ),
            "stage" => {
                let private: Plan = fs::read_json(&plan_path.join("plan.json")).unwrap();
                write(
                    &s.app
                        .object("staged", &private.inputs[0].id)
                        .unwrap()
                        .join("input.xml"),
                    b"changed staged input",
                );
            }
            "proposal" => write(&plan_path.join("target.txt"), b"mutated planned target\n"),
            "pif" => write(
                &s.app.modules.join("playintegrityfix/custom.pif.prop"),
                b"SECURITY_PATCH=2026-10-06\n",
            ),
            "public" => install_cache(&s, json!({}), 3600),
            _ => write(
                &s.app.modules.join("rezygisk/bin/zygiskd64"),
                b"changed executable fixture",
            ),
        }
        let current = s.files();
        assert_eq!(s.app.apply(&id(&p)).unwrap_err().code, "E_STALE", "{what}");
        assert_eq!(s.files(), current);
        assert!(!s.app.root.join("journal.json").exists());
        if what != "active" {
            assert_eq!(current, before);
        }
    }
}
#[test]
fn external_writers_are_preserved_as_evidence_before_restoring_previous_state() {
    let mut s = Sandbox::new();
    let before = s.files();
    let p = s.plan();
    let path = s.app.active.join("target.txt");
    let hit = AtomicBool::new(false);
    s.app.fault = Some(Arc::new(move |point| {
        if point == "before-commit-marker" && !hit.swap(true, Ordering::SeqCst) {
            write(&path, b"com.external.writer!\n");
        }
        Ok(())
    }));
    let failure = s.app.apply(&id(&p)).unwrap_err();
    assert_eq!(failure.code, "E_APPLY");
    assert_eq!(s.files(), before);
    let backups = s.app.backups().unwrap();
    let evidence = backups["backups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["type"] == "external-writer-evidence")
        .unwrap();
    let data = failure.data.unwrap();
    assert_eq!(data["external_writer_evidence_backup"], evidence["id"]);
    assert_eq!(data["external_change_reverted"], true);
    let path = s
        .app
        .object("backups", evidence["id"].as_str().unwrap())
        .unwrap()
        .join("target.txt");
    assert_eq!(fs::bounded(&path, 4096).unwrap(), b"com.external.writer!\n");
}

#[test]
fn recovery_rechecks_the_journal_after_acquiring_the_operation_lock() {
    let mut s = Sandbox::new();
    let p = s.plan();
    s.app.apply(&id(&p)).unwrap();
    let mut pending = s.journal();
    pending.state = "recovery-required".into();
    let jp = s.app.root.join("journal.json");
    fs::write_json(&jp, &pending).unwrap();
    let mut successor = pending.clone();
    successor.plan = "e".repeat(32);
    successor.state = "committed".into();
    let before = s.files();
    let expected = successor.clone();
    s.app.fault = Some(Arc::new(move |point| {
        if point == "before-recovery-lock" {
            fs::write_json(&jp, &successor)?;
        }
        Ok(())
    }));
    let e = s.app.recovery("restore").unwrap_err();
    assert_eq!(e.code, "E_STALE");
    assert_eq!(s.files(), before);
    assert_eq!(s.journal(), expected);
}

#[test]
fn capability_only_drift_is_not_reported_as_reverted() {
    let mut s = Sandbox::new();
    let before = s.files();
    let plan = s.plan();
    let path = s.app.modules.join("playintegrityfix/custom.pif.prop");
    let mut changed = fs::bounded(&path, 64 << 10).unwrap();
    changed.extend_from_slice(b"# external capability edit\n");
    let expected = changed.clone();
    let hook_path = path.clone();
    s.app.fault = Some(Arc::new(move |point| {
        if point == "before-write-target.txt" {
            write(&hook_path, &changed);
        }
        Ok(())
    }));
    let e = s.app.apply(&id(&plan)).unwrap_err();
    assert_eq!(e.code, "E_APPLY");
    let data = e.data.unwrap();
    assert_eq!(data["external_change_reverted"], false);
    assert_eq!(data["previous_file_set_restored"], true);
    assert_eq!(data["external_capability_changes_may_remain"], true);
    assert!(
        data["external_writer_evidence_backup"]
            .as_str()
            .is_some_and(util::valid_id)
    );
    assert_eq!(s.files(), before);
    assert_eq!(fs::bounded(&path, 64 << 10).unwrap(), expected);
}

#[test]
fn stale_lock_release_is_bound_to_the_quarantined_owner() {
    for changed in [false, true] {
        let mut s = Sandbox::new();
        let lp = s.app.root.join("operation.lock");
        fs::private_dir(&lp).unwrap();
        fs::write_json(
            &lp.join("owner.json"),
            &json!({"pid":42,"boot":"old-fixture-boot"}),
        )
        .unwrap();
        let owner = lp.join("owner.json");
        s.app.fault = Some(Arc::new(move |point| {
            if changed && point == "before-lock-quarantine" {
                fs::write_json(&owner, &json!({"pid":43,"boot":"new-fixture-boot"}))?;
            }
            Ok(())
        }));
        let result = s.app.recovery("release-lock");
        let quarantines: Vec<_> = io::read_dir(&s.app.root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("released-lock-")
            })
            .collect();
        if changed {
            assert_eq!(result.unwrap_err().code, "E_BUSY");
            assert!(
                lp.exists(),
                "changed evidence leaves a gate for manual inspection"
            );
            assert_eq!(quarantines.len(), 1);
            let kept: Value = fs::read_json(&quarantines[0].join("owner.json")).unwrap();
            assert_eq!(kept["pid"], 43);
        } else {
            assert_eq!(result.unwrap()["state"], "lock-released");
            assert!(!lp.exists());
            assert!(quarantines.is_empty());
        }
    }
}

#[test]
fn recovery_engine_failure_keeps_go_exit_and_redacted_engine_data() {
    let mut s = Sandbox::new();
    let p = s.plan();
    s.app.apply(&id(&p)).unwrap();
    let mut pending = s.journal();
    let original = s.app.load_backup(&pending.backup).unwrap();
    pending.state = "recovery-required".into();
    fs::write_json(&s.app.root.join("journal.json"), &pending).unwrap();
    s.app.fault = Some(Arc::new(|point| {
        if point == "before-adoption" {
            return Err(Error::new("E_ADOPTION", "Synthetic unavailable engine")
                .with_data(json!({"health":"failed","verified_engine_instances":0})));
        }
        Ok(())
    }));
    let response = rhso::request::execute(
        &s.app,
        &["recovery".into(), "--action".into(), "restore".into()],
    );
    assert!(!response.ok);
    assert_eq!(response.code, "E_RECOVERY");
    assert_eq!(rhso::error::exit_code(&response.code), 7);
    assert_eq!(response.data.unwrap()["engine"]["health"], "failed");
    assert_eq!(s.files(), original.files);
    assert_eq!(s.journal().state, "restored");
}

#[test]
fn unavailable_user_cannot_record_readiness_and_returns_go_data() {
    let mut s = Sandbox::new();
    let p = s.plan();
    s.app.apply(&id(&p)).unwrap();
    s.app.fault = Some(Arc::new(|point| {
        if point == "verification-current-user" {
            return Err(Error::new("E_CAPABILITY", "Synthetic user unavailable"));
        }
        Ok(())
    }));
    let response = rhso::request::execute(
        &s.app,
        &[
            "verify".into(),
            "--wallet-ready".into(),
            "true".into(),
            "--reviewed-user".into(),
            "0".into(),
        ],
    );
    assert!(!response.ok);
    assert_eq!(response.code, "E_CAPABILITY");
    assert_eq!(rhso::error::exit_code(&response.code), 5);
    assert_eq!(
        response.data.unwrap(),
        json!({"current_android_user":"unavailable","wallet_readiness":"unverified","tap_to_pay":"unverified"})
    );
    assert!(!s.app.root.join("verification.json").exists());
}
#[test]
fn verification_staleness_and_user_declarations_do_not_manufacture_acceptance() {
    let mut s = Sandbox::new();
    let p = s.plan();
    s.app.apply(&id(&p)).unwrap();
    assert_eq!(s.app.verify(true, false, "").unwrap_err().code, "E_CONFIRM");
    assert_eq!(s.app.verify(false, true, "1").unwrap_err().code, "E_STALE");
    let status = s.app.status().unwrap();
    let verified = s.app.verify(false, false, "").unwrap();
    assert_eq!(
        status["stack_evidence_binding"],
        verified["stack_evidence_binding"]
    );
    assert_eq!(verified["tap_to_pay"], "unverified");
    let original_report = fs::bounded(&s.app.root.join("verification.json"), 1 << 20).unwrap();
    let path = s.app.modules.join("playintegrityfix/custom.pif.prop");
    s.app.fault = Some(Arc::new(move |point| {
        if point == "before-verification-persist" {
            write(&path, b"SECURITY_PATCH=2026-10-06\n");
        }
        Ok(())
    }));
    assert_eq!(s.app.verify(true, true, "0").unwrap_err().code, "E_STALE");
    assert_eq!(
        original_report,
        fs::bounded(&s.app.root.join("verification.json"), 1 << 20).unwrap()
    );
}
#[test]
fn fresh_catalog_rejects_listed_material_unknown_or_expired_context_stays_separate() {
    let s = Sandbox::new();
    install_cache(&s, json!({"2":{"status":"REVOKED"}}), 3600);
    let before = s.files();
    assert_eq!(
        s.app.plan("", true, "", false).unwrap_err().code,
        "E_VALIDATION"
    );
    assert_eq!(s.files(), before);
    let source = s.ingest();
    assert_eq!(
        s.app
            .plan(&format!("{source}:0:0:ecdsa"), false, "", false)
            .unwrap_err()
            .code,
        "E_VALIDATION"
    );
    install_cache(&s, json!({"2":{"status":"REVOKED"}}), 0);
    assert!(s.app.plan("", true, "", false).is_ok());
    assert_eq!(s.app.trust("status").unwrap()["state"], "stale");
    assert_eq!(s.app.trust("refresh").unwrap_err().code, "E_CAPABILITY");
}
#[test]
fn reviewed_target_compaction_removes_only_identical_modes() {
    let s = Sandbox::new();
    write(&s.app.active.join("target.txt"),b"# original\r\ncom.sample.same!\r\ncom.sample.same!\r\ncom.sample.other?\ncom.google.android.gms\n");
    let before = s.files();
    let p = s.app.plan("", true, "", true).unwrap();
    assert_eq!(p["target_compaction"]["removed_entries"], 1);
    s.app.apply(&id(&p)).unwrap();
    assert_eq!(s.files()["keybox.xml"], before["keybox.xml"]);
    let target =
        String::from_utf8(fs::bounded(&s.app.active.join("target.txt"), 1 << 20).unwrap()).unwrap();
    assert!(target.starts_with("# original\r\n"));
    assert_eq!(target.matches("com.sample.same!").count(), 1);
    assert!(target.contains("com.sample.other?\n"));
    for conflicting in [
        b"com.sample.same\ncom.sample.same!\n".as_slice(),
        b"com.sample.same!\ncom.sample.same?\n",
        b" unsupported path /x\n",
    ] {
        write(&s.app.active.join("target.txt"), conflicting);
        assert_eq!(
            s.app.plan("", false, "", true).unwrap_err().code,
            "E_SELECTION"
        );
    }
}
#[test]
fn private_json_legacy_null_vectors_and_go_omitted_optional_fields_decode() {
    let s = Sandbox::new();
    let p = s.plan();
    let planpath = s.app.object("plans", &id(&p)).unwrap().join("plan.json");
    let mut stored: Value = fs::read_json(&planpath).unwrap();
    stored["warnings"] = Value::Null;
    stored["preview"] = Value::Null;
    stored.as_object_mut().unwrap().remove("source_backup");
    stored.as_object_mut().unwrap().remove("target_compaction");
    fs::write_json(&planpath, &stored).unwrap();
    let parsed: Plan = fs::read_json(&planpath).unwrap();
    assert!(parsed.warnings.is_empty());
    assert!(parsed.preview.is_empty());
    assert_eq!(parsed.source_backup, "");
    assert!(s.app.apply(&id(&p)).is_ok());
    let backupid = s.journal().backup;
    let path = s
        .app
        .object("backups", &backupid)
        .unwrap()
        .join("backup.json");
    let b: Backup = fs::read_json(&path).unwrap();
    assert_eq!(b.id, backupid);
    let duplicate = s.app.root.join("duplicate-fixture.json");
    write(&duplicate, br#"{"schema":1,"Schema":2}"#);
    assert!(fs::read_json::<Value>(&duplicate).is_err());
}
#[test]
fn go_null_history_and_base64_public_cache_remain_upgradeable() {
    let s = Sandbox::new();
    write(&s.app.root.join("history.json"), b"null\n");
    let stage = s.app.ingest(s.source().to_str().unwrap()).unwrap();
    assert!(stage["id"].as_str().is_some_and(util::valid_id));
    let history: Value = fs::read_json(&s.app.root.join("history.json")).unwrap();
    assert_eq!(history.as_array().unwrap().len(), 1);
    install_cache(&s, json!({}), 3600);
    assert_eq!(s.app.trust("status").unwrap()["state"], "fresh");
    let mut cache: Value = fs::read_json(&s.app.root.join("public-attestation.json")).unwrap();
    assert!(cache["roots"]["body"].is_string());
    cache["status"]["sha256"] = json!("0".repeat(64));
    fs::write_json(&s.app.root.join("public-attestation.json"), &cache).unwrap();
    assert_eq!(s.app.trust("status").unwrap()["state"], "invalid");
}
#[test]
fn rollback_under_a_later_stack_marker_uses_a_fresh_reviewed_binding() {
    let s = Sandbox::new();
    let before = s.files();
    let p = s.plan();
    let applied = s.app.apply(&id(&p)).unwrap();
    let original = applied["backup"].as_str().unwrap().to_owned();
    let resource = s
        .app
        .active
        .parent()
        .unwrap()
        .join("stack-system/data/adb/brezygisk");
    fs::private_dir(&resource).unwrap();
    write(&resource.join("unmount"), b"");
    let marker = fs::snapshot_file(&resource.join("unmount"), 1024).unwrap();
    s.app.rollback(&original).unwrap();
    assert_eq!(s.files(), before);
    assert_eq!(
        fs::snapshot_file(&resource.join("unmount"), 1024).unwrap(),
        marker
    );
    assert_eq!(s.app.load_backup(&original).unwrap().files, before);
}
#[test]
fn request_parser_preserves_strict_bridge_and_cli_options() {
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).into()).collect()
    }
    for bad in [
        args(&["plan", "--targets", "1"]),
        args(&["plan", "--targets", "true", "--targets", "false"]),
        args(&["api", "--url", "https://example.com"]),
        args(&["api", "--token", "private-sentinel"]),
        args(&["stack", "--enabled", "TRUE"]),
        args(&["verify", "--wallet-ready", "yes"]),
        args(&["init", "--x", "y"]),
        args(&["plan", "--unknown", "x"]),
    ] {
        assert_eq!(rhso::request::parse(&bad).unwrap_err().code, "E_REQUEST");
    }
    for bad in [
        br#"{"command":"status","command":"init"}"#.as_slice(),
        br#"{"command":"status","Command":"init"}"#,
        br#"{"command":"status","args":{},"private-sentinel":"leak"}"#,
        br#"{"command":"status","args":{"url":"https://example.com"}}"#,
        br#"{"command":"plan","args":{"targets":true}}"#,
        br#"{"command":"status","args":{}} true"#,
    ] {
        let encoded = URL_SAFE_NO_PAD.encode(bad);
        assert_eq!(
            rhso::request::parse(&args(&["request", &encoded]))
                .unwrap_err()
                .code,
            "E_REQUEST"
        );
    }
    let encoded = URL_SAFE_NO_PAD.encode(br#"{"command":"status","args":null}"#);
    assert!(
        rhso::request::parse(&args(&["request", &encoded]))
            .unwrap()
            .args
            .is_empty()
    );
    assert_eq!(
        rhso::request::parse(&args(&["reset", "--review_hash", "abc"]))
            .unwrap()
            .args["review-hash"],
        "abc"
    );
    assert!(
        rhso::request::parse(&args(&[
            "reset",
            "--review_hash",
            "abc",
            "--review-hash",
            "def"
        ]))
        .is_err()
    );
}
#[test]
fn malformed_requests_emit_fixed_errors_without_raw_inputs() {
    let s = Sandbox::new();
    let response = rhso::request::execute(
        &s.app,
        &["api".into(), "--token".into(), "private-sentinel".into()],
    );
    let text = serde_json::to_string(&response).unwrap();
    assert!(!text.contains("private-sentinel"));
    assert_eq!(response.code, "E_REQUEST");
    assert!(!response.ok);
    assert_eq!(response.schema, 1);
}

fn api_config(s: &Sandbox, auth: Value, url: &str) -> PathBuf {
    let p = s.app.root.join("inbox/feed.json");
    fs::write_json(&p,&json!({"schema":1,"url":url,"provenance_declaration":"I am authorized to use this synthetic fixture feed.","auth":auth})).unwrap();
    p
}
#[test]
fn api_credentials_stay_private_and_source_changes_get_fresh_generations() {
    let s = Sandbox::new();
    let mut previous = String::new();
    for auth in [
        json!({"mode":"NONE"}),
        json!({"mode":"BEARER","token":"private-bearer-sentinel"}),
        json!({"mode":"BASIC","username":"private-user-sentinel","password":"private-password-sentinel"}),
        json!({"mode":"API_KEY","header":"X-Private-Key","key":"private-api-sentinel"}),
    ] {
        let p = api_config(
            &s,
            auth,
            "https://your-authorized-feed.example/input.xml?private-query-sentinel",
        );
        let out = s.app.api("config", p.to_str().unwrap()).unwrap();
        assert_eq!(out["configured"], true);
        assert_eq!(out["available"], false);
        assert_eq!(out["provider_contract_verified"], false);
        assert_eq!(out["exact_endpoint_available"], false);
        let generation = out["source_generation"].as_str().unwrap();
        assert_ne!(generation, previous);
        previous = generation.into();
        let text = serde_json::to_string(&out).unwrap();
        for secret in [
            "private-bearer-sentinel",
            "private-user-sentinel",
            "private-password-sentinel",
            "private-api-sentinel",
            "your-authorized-feed.example",
            "private-query-sentinel",
            "X-Private-Key",
        ] {
            assert!(!text.contains(secret));
        }
        assert_eq!(s.app.api("import", "").unwrap_err().code, "E_CAPABILITY");
    }
    let stored = fs::metadata(&s.app.root.join("api-source.json")).unwrap();
    assert_eq!(stored.mode, 0o600);
    assert_eq!(stored.uid, util::owner_id());
    assert_eq!(stored.gid, util::owner_id());
    assert!(s.app.api("status", "private-sentinel").is_err());
}
#[test]
fn api_config_refuses_bad_auth_ambiguous_json_and_private_network_urls() {
    let s = Sandbox::new();
    let before = s.files();
    for url in [
        "http://example.com/key.xml",
        "https://user:pass@example.com/key.xml",
        "https://127.0.0.1/key.xml",
        "https://10.0.0.1/key.xml",
        "https://[::1]/key.xml",
        "https://192.0.2.1/key.xml",
        "https://example.com/key.xml#fragment",
        "https://example.com:/key.xml",
        "https://example.com\n/key.xml",
    ] {
        let p = api_config(&s, json!({"mode":"NONE"}), url);
        assert_eq!(
            s.app.api("config", p.to_str().unwrap()).unwrap_err().code,
            "E_API_CONFIG",
            "{url}"
        );
    }
    for auth in [
        json!({"mode":"NONE","token":"private-sentinel"}),
        json!({"mode":"CUSTOM","header":"X"}),
        json!({"mode":"BEARER","token":"two words"}),
        json!({"mode":"BASIC","username":"a:b","password":"c"}),
        json!({"mode":"API_KEY","header":"Authorization","key":"private-sentinel"}),
        json!({"mode":"API_KEY","header":"Proxy-Authorization","key":"private-sentinel"}),
        json!({"mode":"API_KEY","header":"X-Key","key":"private\nsecret"}),
        json!({"mode":"API_KEY","header":"X-Key","key":" secret "}),
    ] {
        let p = api_config(&s, auth, "https://your-authorized-feed.example/key.xml");
        let e = s.app.api("config", p.to_str().unwrap()).unwrap_err();
        assert_eq!(e.code, "E_API_CONFIG");
        assert!(!e.to_string().contains("private-sentinel"));
    }
    let p = s.app.root.join("inbox/feed.json");
    write(&p,br#"{"schema":1,"url":"https://example.com","url":"https://127.0.0.1","provenance_declaration":"authorized","auth":{"mode":"NONE"}}"#);
    assert_eq!(
        s.app.api("config", p.to_str().unwrap()).unwrap_err().code,
        "E_API_CONFIG"
    );
    assert_eq!(s.files(), before);
    assert!(!s.app.root.join("api-source.json").exists());
    assert_eq!(
        s.app
            .api("config", s.app.root.join("outside.json").to_str().unwrap())
            .unwrap_err()
            .code,
        "E_PATH"
    );
}
#[test]
fn configured_xml_inspection_and_http_framing_reject_unsupported_formats() {
    for body in [
        b"<AndroidAttestation/>".as_slice(),
        b"<?xml version=\"1.0\"?><Keybox DeviceID=\"synthetic\"/>",
    ] {
        assert!(rhso::api::raw_xml(body).is_ok());
    }
    for body in [
        b"<html>private-sentinel</html>".as_slice(),
        b"<AndroidAttestation>",
        b"<AndroidAttestation/><Keybox/>",
        b"<!DOCTYPE Keybox><Keybox/>",
        b"PK\x03\x04archive",
        b"<Keybox xmlns=\"unsupported\"/>",
        b"<Keybox>\0</Keybox>",
    ] {
        assert!(rhso::api::raw_xml(body).is_err());
    }
    let mut headers = BTreeMap::from([(
        "content-type".into(),
        vec!["application/xml; charset=UTF-8".into()],
    )]);
    assert!(rhso::api::xml_headers(&headers));
    headers.insert("content-encoding".into(), vec!["gzip".into()]);
    assert!(!rhso::api::xml_headers(&headers));
    headers.remove("content-encoding");
    headers.insert("content-type".into(), vec!["text/html".into()]);
    assert!(!rhso::api::xml_headers(&headers));
    let good =
        b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nContent-Type: application/xml\r\n\r\n<Keybox/>";
    assert_eq!(
        *rhso::network::parse_response(good, 1024).unwrap().body,
        b"<Keybox/>"
    );
    let chunked=b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/xml\r\n\r\n9\r\n<Keybox/>\r\n0\r\n\r\n";
    assert_eq!(
        *rhso::network::parse_response(chunked, 1024).unwrap().body,
        b"<Keybox/>"
    );
    for bad in [b"HTTP/1.1 302 Found\r\nLocation: https://private.example/\r\n\r\nprivate".as_slice(),b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nContent-Length: 9\r\n\r\n<Keybox/>",b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nTransfer-Encoding: chunked\r\n\r\n<Keybox/>",b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n<Keybox/>",b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\n<Keybox/>\r\n0\r\nX-Private: secret\r\n\r\n"] {let e=rhso::network::parse_response(bad,1024).err().unwrap();assert!(!e.to_string().contains("private.example"));assert!(!e.to_string().contains("secret"));}
    assert_eq!(
        rhso::network::parse_response(good, 8).err().unwrap().code,
        "E_API_LIMIT"
    );
}
#[test]
fn all_private_and_reserved_address_classes_are_rejected_before_dial() {
    for ip in [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "100.64.0.1",
        "192.0.2.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "2001:db8::1",
        "::ffff:127.0.0.1",
        "2002:7f00:1::",
    ] {
        assert!(!rhso::network::public_address(ip.parse().unwrap()), "{ip}");
    }
    for ip in [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
    ] {
        assert!(rhso::network::public_address(ip.parse().unwrap()), "{ip}");
    }
}

#[test]
fn http_framing_refuses_signed_lengths_and_control_characters() {
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: +9\r\n\r\n<Keybox/>".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+9\r\n<Keybox/>\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX-Header: value\nembedded\r\nContent-Length: 9\r\n\r\n<Keybox/>",
        b"HTTP/1.1 200 OK\r\nX-Header: value\x01control\r\nContent-Length: 9\r\n\r\n<Keybox/>",
    ] {
        assert!(
            rhso::network::parse_response(response, 1024).is_err(),
            "Malformed framing must not be accepted"
        );
    }
}

#[test]
fn xml_media_type_tokens_are_case_insensitive_and_quotes_must_balance() {
    for media_type in [
        "application/xml",
        "Application/XML; charset=UTF-8",
        "TEXT/XML; Charset=\"UTF-8\"",
        "text/xml;charset=us-ascii",
        "application/xml; charset=utf-8; charset=utf-8",
    ] {
        let h = BTreeMap::from([("content-type".into(), vec![media_type.into()])]);
        assert!(
            rhso::api::xml_headers(&h),
            "Valid MIME spelling must be supported: {media_type}"
        );
    }
    for media_type in [
        "application/xml; charset=\"utf-8",
        "application/xml; charset=utf-8\"",
        "application/xml; charset=iso-8859-1",
    ] {
        let h = BTreeMap::from([("content-type".into(), vec![media_type.into()])]);
        assert!(
            !rhso::api::xml_headers(&h),
            "Invalid/unsupported MIME declaration must be refused"
        );
    }
}

#[cfg(unix)]
#[test]
fn symlinked_inputs_active_paths_and_private_state_fail_closed() {
    use std::os::unix::fs::symlink;
    let s = Sandbox::new();
    let source = s.source();
    let link = s.app.root.join("inbox/link.xml");
    symlink(&source, &link).unwrap();
    assert_eq!(
        s.app.ingest(link.to_str().unwrap()).unwrap_err().code,
        "E_PATH"
    );
    let target = s.app.active.join("target.txt");
    io::remove_file(&target).unwrap();
    symlink(&source, &target).unwrap();
    assert_eq!(s.app.snapshot().unwrap_err().code, "E_PATH");
    let s = Sandbox::new();
    let original = s.app.root.join("format.json");
    let displaced = s.app.root.join("format-original.json");
    io::rename(&original, &displaced).unwrap();
    symlink(&displaced, &original).unwrap();
    assert_eq!(s.app.init().unwrap_err().code, "E_FORMAT");
    assert_eq!(fs::bounded(&displaced, 1024).unwrap().len() > 0, true);
}
