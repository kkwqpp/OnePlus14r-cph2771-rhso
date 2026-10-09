use crate::{
    App, FILES,
    error::{Error, Result},
    fs::{self, FileState},
    store::{LockRecord, Plan, key_error, private_metadata},
    util,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs as io, path::Path};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    pub schema: u32,
    pub id: String,
    pub time: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub files: BTreeMap<String, FileState>,
    pub verified: bool,
    pub adoption: String,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub schema: u32,
    pub plan: String,
    pub backup: String,
    pub state: String,
    pub time: String,
    pub intended: BTreeMap<String, FileState>,
}
impl App {
    pub(crate) fn validate_journal(&self, j: &Journal) -> Result<()> {
        let valid = matches!(
            j.state.as_str(),
            "applying" | "committed" | "restored" | "restoring" | "recovery-required"
        ) || FILES.iter().any(|n| j.state == format!("writing-{n}"));
        if j.schema != 1
            || !util::valid_id(&j.plan)
            || !util::valid_id(&j.backup)
            || !util::valid_time(&j.time)
            || j.intended.len() != 3
            || !valid
            || FILES
                .iter()
                .any(|n| !j.intended.get(*n).is_some_and(|s| self.valid_state(s)))
        {
            return Err(Error::new(
                "E_RECOVERY",
                "Journal is incomplete or has an unsupported format. Preserve it and all backups.",
            ));
        }
        Ok(())
    }
    pub fn backup(&self, kind: &str, expected: &BTreeMap<String, FileState>) -> Result<Backup> {
        self.checkpoint("before-backup")?;
        if expected.len() != 3
            || FILES
                .iter()
                .any(|n| !expected.get(*n).is_some_and(|s| self.valid_state(s)))
        {
            return Err(Error::new(
                "E_BACKUP",
                "Incomplete snapshot; backup stopped.",
            ));
        }
        let total = (16 << 20) + expected.values().map(|s| s.size as u64 * 3).sum::<u64>();
        fs::enough_space(&self.root, total)?;
        fs::enough_space(&self.active, total)?;
        let id = util::new_id()?;
        let dir = self.object("backups", &id)?;
        fs::private_dir(&dir)?;
        let b = Backup {
            schema: 1,
            id: id.clone(),
            time: self.time(),
            kind: kind.into(),
            files: expected.clone(),
            verified: false,
            adoption: "unknown".into(),
        };
        for n in FILES {
            let st = &expected[n];
            if !st.exists {
                continue;
            }
            let body = zeroize::Zeroizing::new(fs::bounded(&self.active.join(n), 1 << 20)?);
            if util::hash(&body) != st.sha256 || body.len() as i64 != st.size {
                return Err(Error::new(
                    "E_STALE",
                    "Configuration changed during backup. Nothing was applied.",
                ));
            }
            fs::atomic_write(&dir.join(n), &body, &private_metadata())?;
        }
        fs::write_json(&dir.join("backup.json"), &b)?;
        fs::sync_dir(&dir)?;
        fs::sync_dir(&self.root.join("backups"))?;
        self.load_backup(&id)?;
        if self.snapshot()? != *expected {
            return Err(Error::new(
                "E_STALE",
                "Configuration changed during backup. Nothing was applied.",
            ));
        }
        self.checkpoint("after-backup")?;
        Ok(b)
    }
    pub fn load_backup(&self, id: &str) -> Result<Backup> {
        let dir = self.object("backups", id)?;
        let b: Backup = fs::read_json(&dir.join("backup.json"))?;
        if b.schema != 1
            || b.id != id
            || b.files.len() != 3
            || !util::valid_time(&b.time)
            || !matches!(
                b.kind.as_str(),
                "apply"
                    | "rollback"
                    | "wallet-reset-preparation"
                    | "external-writer-evidence"
                    | "verified-configuration"
                    | "pre-recovery"
                    | "stack-profile"
            )
            || !matches!(b.adoption.as_str(), "unknown" | "pending" | "verified")
            || b.verified && b.adoption != "verified"
        {
            return Err(Error::new("E_BACKUP", "Unsupported or incomplete backup."));
        }
        for n in FILES {
            let s = b
                .files
                .get(n)
                .filter(|s| self.valid_state(s))
                .ok_or_else(|| {
                    Error::new(
                        "E_BACKUP",
                        "Backup has missing or invalid file metadata. Nothing was restored.",
                    )
                })?;
            let p = dir.join(n);
            fs::no_links(&p)?;
            if !s.exists {
                if p.try_exists()? {
                    return Err(Error::new(
                        "E_BACKUP",
                        "An absent-file backup contains unexpected data.",
                    ));
                }
                continue;
            }
            let body =
                zeroize::Zeroizing::new(fs::bounded(&p, 1 << 20).map_err(|_| {
                    Error::new("E_BACKUP", "A backup file is missing or unreadable.")
                })?);
            if util::hash(&body) != s.sha256 || body.len() as i64 != s.size {
                return Err(Error::new(
                    "E_BACKUP",
                    "Backup checksum validation failed. Keep this backup for investigation.",
                ));
            }
        }
        Ok(b)
    }
    pub fn backups(&self) -> Result<Value> {
        let mut out = Vec::new();
        for e in io::read_dir(self.root.join("backups"))? {
            let e = e?;
            let id = e.file_name().to_string_lossy().into_owned();
            if !e.file_type()?.is_dir() || !util::valid_id(&id) {
                continue;
            }
            match self.load_backup(&id){Ok(b)=>out.push(json!({"id":b.id,"time":b.time,"type":b.kind,"verified":b.verified,"adoption":b.adoption,"integrity":"checked","changes":b.files})),Err(_)=>out.push(json!({"id":id,"integrity":"failed","verified":false}))}
        }
        out.sort_by(|a, b| b["time"].as_str().cmp(&a["time"].as_str()));
        Ok(json!({"backups":out}))
    }
    pub fn apply(&self, id: &str) -> Result<Value> {
        self.with_lock(|| self.apply_locked(id))
    }
    pub(crate) fn apply_locked(&self, id: &str) -> Result<Value> {
        self.require_recovered()?;
        let jp = self.root.join("journal.json");
        fs::no_links(&jp)?;
        if jp.try_exists()? && fs::read_json::<Journal>(&jp)?.plan == id {
            return Err(Error::new(
                "E_DUPLICATE",
                "This plan was already submitted. Inspect its recorded operation instead.",
            ));
        }
        let (p, dir) = self.load_plan(id)?;
        fs::no_links(&dir.join("submitted.json"))?;
        if dir.join("submitted.json").try_exists()? {
            return Err(Error::new(
                "E_DUPLICATE",
                "This plan was already submitted. Create a fresh plan after reviewing its outcome.",
            ));
        }
        if self.plan_capabilities()? != p.capabilities {
            return Err(Error::new(
                "E_STALE",
                "Engine, PIF, writer or runtime capabilities changed. Make a new plan.",
            ));
        }
        let current = self.snapshot()?;
        if current != p.active {
            return Err(Error::new(
                "E_STALE",
                "Active files or their metadata changed. Inspect and make a fresh plan.",
            ));
        }
        if p.kind == "apply" && p.selections.is_empty() {
            let b = zeroize::Zeroizing::new(fs::bounded(
                &self.active.join("keybox.xml"),
                rhso_keybox::MAX_INPUT,
            )?);
            let d = rhso_keybox::parse(&b, self.now()).map_err(key_error)?;
            self.reject_public_listed(&d)?;
        }
        let mut docs = Vec::new();
        for s in &p.inputs {
            let (d, now) = self.stage(&s.id)?;
            if now != *s {
                return Err(Error::new(
                    "E_STALE",
                    "Selected input changed. Import and review it again.",
                ));
            }
            docs.push(d);
        }
        if p.kind == "apply" && !p.selections.is_empty() {
            let refs: Vec<_> = docs.iter().collect();
            let d = rhso_keybox::merge(&refs, &p.selections, self.now()).map_err(key_error)?;
            self.reject_public_listed(&d)?;
            if util::hash(&d.xml().map_err(key_error)?) != p.intended["keybox.xml"].sha256 {
                return Err(Error::new(
                    "E_STALE",
                    "Planned keybox no longer matches its selected validated inputs.",
                ));
            }
        }
        for n in &p.changes {
            self.checked_proposed(&dir, n, &p.intended[n])?;
        }
        fs::write_json(&dir.join("submitted.json"), &json!({"time":self.time()}))?;
        let b = self.backup(&p.kind, &current)?;
        let mut j = Journal {
            schema: 1,
            plan: p.id.clone(),
            backup: b.id.clone(),
            state: "applying".into(),
            time: self.time(),
            intended: p.intended.clone(),
        };
        fs::write_json(&jp, &j)?;
        if let Err(e) = self.commit(&p, &dir, &mut j) {
            j.state = "recovery-required".into();
            fs::write_json(&jp, &j)?;
            let mut evidence_backup = None;
            if e.code == "E_WRITER" {
                let current=self.snapshot().map_err(|_|Error::new("E_RECOVERY","Concurrent writer evidence could not be read; preserve journal and backups."))?;
                evidence_backup = Some(self.backup("external-writer-evidence",&current).map_err(|_|Error::new("E_RECOVERY","Concurrent writer evidence could not be preserved. Recovery is pending; do not overwrite it."))?.id);
            }
            self.restore(&b,&mut j).map_err(|_|Error::new("E_RECOVERY","Commit and restoration failed. Preserve the journal and backups; open Advanced Recovery."))?;
            let _ = self.history(&p.kind, &p.id, "restored-after-failure");
            let mut data = json!({"backup":b.id,"state":"restored"});
            if let Some(id) = evidence_backup {
                data["external_writer_evidence_backup"] = json!(id);
                let files_changed = e
                    .data
                    .as_ref()
                    .is_some_and(|d| d["active_files_changed"] == true);
                data["external_change_reverted"] = json!(files_changed);
                data["previous_file_set_restored"] = json!(true);
                data["external_capability_changes_may_remain"] = json!(true);
                data["message"] = json!(if files_changed {
                    "An external change to the three-file set was preserved as evidence and reverted. Changes outside that set may remain."
                } else {
                    "The current three-file set was preserved as evidence and the previous set restored. External capability changes were not reverted."
                });
            }
            return Err(Error::new("E_APPLY","Commit failed; the complete previous file set was restored and checked. Adoption needs verification.").with_data(data));
        }
        let _ = self.history(&p.kind, &p.id, "committed-adoption-pending");
        Ok(
            json!({"id":p.id,"backup":b.id,"files_committed":true,"engine_health":"healthy","adoption":"pending","wallet_acceptance":"unverified","manual_reboot_required":false,"message":"Files checked; per-file engine reload is documented and observed in installed code. Fresh identity evidence and Wallet testing remain required."}),
        )
    }
    fn checked_proposed(&self, dir: &Path, n: &str, st: &FileState) -> Result<Vec<u8>> {
        if !FILES.contains(&n) {
            return Err(Error::new("E_FORMAT", "Plan includes an unsupported path."));
        }
        if !st.exists {
            return Ok(Vec::new());
        }
        let b = fs::bounded(&dir.join(n), 1 << 20)?;
        if util::hash(&b) != st.sha256 || b.len() as i64 != st.size {
            return Err(Error::new(
                "E_STALE",
                "Prepared bytes changed at a write boundary; no changed bytes were applied.",
            ));
        }
        Ok(b)
    }
    fn commit(&self, p: &Plan, dir: &Path, j: &mut Journal) -> Result<()> {
        self.checkpoint("after-journal")?;
        let jp = self.root.join("journal.json");
        fs::no_links(&jp)?;
        let mut expected = p.active.clone();
        for n in ["security_patch.txt", "target.txt", "keybox.xml"] {
            if !p.changes.iter().any(|x| x == n) {
                continue;
            }
            if self.snapshot()? != expected {
                return Err(writer_error(true));
            }
            self.checkpoint(&format!("before-write-{n}"))?;
            self.check_commit_boundary(&expected, p)?;
            j.state = format!("writing-{n}");
            fs::write_json(&jp, j)?;
            let st = &p.intended[n];
            if st.exists {
                let b = zeroize::Zeroizing::new(self.checked_proposed(dir, n, st)?);
                fs::atomic_write(&self.active.join(n), &b, &st.metadata)?;
            } else {
                fs::remove_file(&self.active.join(n))?;
            }
            expected.insert(n.into(), st.clone());
            self.checkpoint(&format!("after-write-{n}"))?;
        }
        self.checkpoint("after-file-set")?;
        if self.snapshot()? != p.intended {
            return Err(writer_error(true));
        }
        self.adoption()?;
        self.checkpoint("before-commit-marker")?;
        self.check_commit_boundary(&p.intended, p)?;
        j.state = "committed".into();
        j.time = self.time();
        fs::write_json(&jp, j)?;
        self.checkpoint("after-commit-marker")?;
        self.check_commit_boundary(&p.intended, p)?;
        Ok(())
    }
    fn check_commit_boundary(
        &self,
        expected: &BTreeMap<String, FileState>,
        p: &Plan,
    ) -> Result<()> {
        if self.snapshot()? != *expected {
            return Err(writer_error(true));
        }
        if self.plan_capabilities()? != p.capabilities {
            return Err(writer_error(false));
        }
        Ok(())
    }
    pub(crate) fn restore(&self, b: &Backup, j: &mut Journal) -> Result<()> {
        let b = self.load_backup(&b.id)?;
        let current = self.snapshot()?;
        self.backup("pre-recovery", &current)?;
        let dir = self.object("backups", &b.id)?;
        j.state = "restoring".into();
        fs::write_json(&self.root.join("journal.json"), j)?;
        for n in FILES {
            self.checkpoint(&format!("before-restore-{n}"))?;
            let st = &b.files[n];
            if st.exists {
                let body = zeroize::Zeroizing::new(fs::bounded(&dir.join(n), 1 << 20)?);
                if util::hash(&body) != st.sha256 || body.len() as i64 != st.size {
                    return Err(Error::new(
                        "E_BACKUP",
                        "Backup bytes changed at the restoration boundary; changed bytes were not restored. Preserve the recovery journal.",
                    ));
                }
                fs::atomic_write(&self.active.join(n), &body, &st.metadata)?;
            } else {
                fs::remove_file(&self.active.join(n))?;
            }
        }
        if self.snapshot()? != b.files {
            return Err(Error::new(
                "E_RECOVERY",
                "Restored file checksums or metadata do not match the backup.",
            ));
        }
        j.state = "restored".into();
        j.time = self.time();
        fs::write_json(&self.root.join("journal.json"), j)
    }
    pub fn rollback(&self, id: &str) -> Result<Value> {
        self.with_lock(||{self.require_recovered()?;let last=id=="last-verified";let id=match id{"previous"=>fs::read_json::<Journal>(&self.root.join("journal.json"))?.backup,"last-verified"=>{let v:Value=fs::read_json(&self.root.join("last-verified.json"))?;v["backup"].as_str().unwrap_or("").into()},_=>id.into()};let b=self.load_backup(&id)?;if last&&(!b.verified||b.adoption!="verified"||b.kind!="verified-configuration"){return Err(Error::new("E_BACKUP","The last-verified pointer does not identify a checked configuration with verified identity adoption."));}let caps=self.plan_capabilities()?;let active=self.snapshot()?;let pid=util::new_id()?;let dir=self.object("plans",&pid)?;fs::private_dir(&dir)?;let mut p=Plan{schema:1,id:pid.clone(),time:self.time(),kind:"rollback".into(),inputs:Vec::new(),active:active.clone(),intended:b.files.clone(),changes:Vec::new(),capabilities:caps,source_backup:id.clone(),summary:Value::Null,preview:Vec::new(),warnings:Vec::new(),selections:Vec::new(),target_compaction:None};for n in FILES{if active[n]==b.files[n]{continue;}p.changes.push(n.into());let st=&b.files[n];if st.exists{let body=zeroize::Zeroizing::new(fs::bounded(&self.object("backups",&id)?.join(n),1<<20)?);if util::hash(&body)!=st.sha256||body.len() as i64!=st.size{return Err(Error::new("E_BACKUP","Backup bytes changed while preparing rollback."));}fs::atomic_write(&dir.join(n),&body,&private_metadata())?;}}
if p.changes.is_empty(){return Ok(json!({"state":"already-restored","adoption":"pending"}));}fs::write_json(&dir.join("plan.json"),&p)?;self.apply_locked(&pid)})
    }
    pub fn recovery(&self, action: &str) -> Result<Value> {
        let jp = self.root.join("journal.json");
        fs::no_links(&jp)?;
        let mut j = Journal::default();
        let state = if jp.try_exists()? {
            j = fs::read_json(&jp).map_err(|_| {
                Error::new(
                    "E_RECOVERY",
                    "The journal is unreadable; preserve all recovery data for investigation.",
                )
            })?;
            self.validate_journal(&j)?;
            j.state.clone()
        } else {
            "none".into()
        };
        let lp = self.root.join("operation.lock");
        fs::no_links(&lp)?;
        let exists = lp.try_exists()?;
        if exists && !io::metadata(&lp)?.is_dir() {
            return Err(Error::new(
                "E_BUSY",
                "Operation lock is an unsafe path; inspect it manually.",
            ));
        }
        let l = fs::read_json::<LockRecord>(&lp.join("owner.json"));
        if action.is_empty() || action == "status" {
            return Ok(
                json!({"state":state,"journal":j,"lock_present":exists,"lock_owner_verified":l.as_ref().is_ok_and(|l|self.valid_lock(l)),"next_step":"If an operation stopped, restore its backup. An ownerless lock needs manual inspection. Lock release is allowed only after its verified process ended or the boot changed."}),
            );
        }
        if action != "restore" && action != "release-lock" {
            return Err(Error::new(
                "E_REQUEST",
                "Recovery action must be status, restore or release-lock.",
            ));
        }
        if exists {
            let l=l.map_err(|_|Error::new("E_BUSY","An ownerless or corrupt operation lock cannot be safely released automatically. Inspect it manually; preserve the journal."))?;
            if !self.valid_lock(&l) {
                return Err(Error::new(
                    "E_BUSY",
                    "Lock owner is invalid; manual inspection is required.",
                ));
            }
            if l.boot == util::boot_id() && fs::pid_alive(l.pid) {
                return Err(Error::new(
                    "E_BUSY",
                    "The lock-owning process is still running. Wait for it to finish.",
                ));
            }
            self.release_stale_lock(&lp, &l)?;
        }
        if action == "release-lock" {
            return Ok(json!({"state":"lock-released"}));
        }
        self.checkpoint("before-recovery-lock")?;
        self.with_lock(|| {
            // A complete CLI operation can run between the preview and acquisition.
            // Restore only the journal actually inspected, never its successor.
            fs::no_links(&jp)?;
            let fresh = if jp.try_exists()? {
                let fresh: Journal = fs::read_json(&jp).map_err(|_| Error::new("E_RECOVERY", "The recovery journal changed or is unreadable; preserve the evidence."))?;
                self.validate_journal(&fresh)?;
                fresh
            } else {
                Journal::default()
            };
            if fresh != j {
                return Err(Error::new("E_STALE", "The recovery journal changed before the lock was acquired. Inspect its current state before restoring."));
            }
            if matches!(state.as_str(), "none" | "committed" | "restored") {
                return Ok(json!({"state":state}));
            }
            let b = self.load_backup(&j.backup)?;
            self.restore(&b, &mut j)?;
            let _ = self.history("recovery", &j.plan, "restored");
            match self.adoption() {
                Ok(v) => Ok(json!({"state":"restored","engine":v,"adoption":"pending"})),
                Err(e) => Err(Error::new("E_RECOVERY", "Files are restored but engine health remains failed. Preserve the evidence; do not restart unrelated services.").with_data(json!({"state":"files-restored","adoption":"failed","engine":e.data}))),
            }
        })
    }

    fn release_stale_lock(&self, path: &Path, expected: &LockRecord) -> Result<()> {
        let owner = path.join("owner.json");
        let before = fs::snapshot_file(&owner, 64 << 10)?;
        let record: LockRecord = fs::read_json(&owner)?;
        if &record != expected
            || !self.valid_lock(&record)
            || record.boot == util::boot_id() && fs::pid_alive(record.pid)
        {
            return Err(Error::new(
                "E_BUSY",
                "The lock owner changed or is still running. Inspect recovery again.",
            ));
        }
        let quarantine = self.root.join(format!("released-lock-{}", util::new_id()?));
        fs::no_links(&quarantine)?;
        self.checkpoint("before-lock-quarantine")?;
        io::rename(path, &quarantine)?;
        fs::sync_dir(&self.root)?;
        let moved = quarantine.join("owner.json");
        let checked = fs::snapshot_file(&moved, 64 << 10).and_then(|after| {
            let current: LockRecord = fs::read_json(&moved)?;
            if after != before
                || current != record
                || !self.valid_lock(&current)
                || current.boot == util::boot_id() && fs::pid_alive(current.pid)
            {
                return Err(Error::new(
                    "E_BUSY",
                    "The moved lock does not match the inspected stale owner.",
                ));
            }
            Ok(())
        });
        if checked.is_err() {
            // Keep all evidence and block new acquisition if another lock has not
            // already appeared. Never delete an owner record we did not inspect.
            let _ = io::create_dir(path);
            fs::sync_dir(&self.root)?;
            return Err(Error::new(
                "E_BUSY",
                "Lock release encountered changed evidence. Preserve the quarantined directory and inspect the operation lock manually.",
            ));
        }
        fs::remove_file(&moved)?;
        io::remove_dir(&quarantine)?;
        fs::sync_dir(&self.root)
    }
}
fn writer_error(files_changed: bool) -> Error {
    Error::new(
        "E_WRITER",
        "An external writer changed the reviewed file set or capabilities at a commit boundary.",
    )
    .with_data(json!({"active_files_changed":files_changed}))
}
