//! Explicit one-shot destructive reset protocol. A durable attempted step is
//! never retried automatically, and fake-engine mode never dispatches a clear.
use crate::{
    App,
    error::{Error, Result},
    fs::{self, FileState},
    inspect::run,
    store::private_metadata,
    util,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const PHRASE: &str = "CLEAR WALLET AND GOOGLE SERVICES";
const COMPLETE_PHRASE: &str = "PIF ACTION AND GMS FORCE-STOP COMPLETED";
pub const CLOSE_PHRASE: &str = "CLOSE INCOMPLETE RESET WITHOUT REPEATING";
const SCRIPTS: [&str; 3] = ["action.sh", "autopif4.sh", "killpi.sh"];
const CLEARS: [&str; 5] = [
    "com.google.android.apps.walletnfcrel",
    "com.android.vending",
    "com.google.android.gsf",
    "com.google.android.gms",
    "com.google.android.gms",
];
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetJournal {
    pub schema: u32,
    pub state: String,
    pub boot: String,
    pub user: String,
    pub review_hash: String,
    pub scripts: BTreeMap<String, String>,
    pub step: i32,
    pub time: String,
    pub backup: String,
    pub pif_hash: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResetClose {
    schema: u32,
    prior: ResetJournal,
    review_hash: String,
    time: String,
}
fn closable(state: &str) -> bool {
    matches!(
        state,
        "clearing" | "attempting-clear" | "failed-do-not-repeat"
    )
}
fn close_review(r: &ResetJournal) -> Result<String> {
    Ok(util::hash(&serde_json::to_vec(r).map_err(|_| invalid())?))
}
pub fn valid_user(user: &str) -> bool {
    user == "0"
        || (!user.is_empty()
            && user.len() <= 6
            && matches!(user.as_bytes()[0], b'1'..=b'9')
            && user.bytes().all(|b| b.is_ascii_digit()))
}
fn invalid() -> Error {
    Error::new(
        "E_RECOVERY",
        "Reset journal or review is incomplete, corrupt or unsupported. Preserve it; do not repeat app-data clearing.",
    )
}
// The ledger is independent of command execution so synthetic tests can assert
// durable attempted-step behavior without granting the fake App a clear path.
fn record_clear_steps<F>(
    path: &std::path::Path,
    r: &mut ResetJournal,
    mut dispatch: F,
) -> Result<()>
where
    F: FnMut(&str, &str) -> Result<String>,
{
    for (i, pkg) in CLEARS.iter().enumerate() {
        r.step = i as i32;
        r.state = "attempting-clear".into();
        fs::write_json(path, r)?;
        if !dispatch(&r.user, pkg).is_ok_and(|out| out.trim() == "Success") {
            r.state = "failed-do-not-repeat".into();
            let _ = fs::write_json(path, r);
            return Err(Error::new(
                "E_RESET",
                "An app-data clear failed or returned unexpected output. Stop and inspect; prior clears are irreversible.",
            ));
        }
        r.step = i as i32 + 1;
        r.state = "clearing".into();
        fs::write_json(path, r)?;
    }
    Ok(())
}
fn review_hash(
    scripts: &BTreeMap<String, String>,
    pif: &[u8],
    config: &BTreeMap<String, FileState>,
    user: &str,
) -> String {
    let mut text = String::new();
    for script in SCRIPTS {
        text.push_str(scripts.get(script).map(String::as_str).unwrap_or(""));
    }
    text.push_str(&util::hash(pif));
    for name in ["keybox.xml", "target.txt", "security_patch.txt"] {
        text.push_str(config.get(name).map(|s| s.sha256.as_str()).unwrap_or(""));
    }
    text.push_str(&util::hash(user.as_bytes()));
    util::hash(text.as_bytes())
}
impl App {
    pub(crate) fn validate_reset(&self, r: &ResetJournal, review: bool) -> Result<()> {
        if r.schema != 1
            || !util::valid_hash(&r.review_hash)
            || !util::valid_hash(&r.pif_hash)
            || r.scripts.len() != 3
            || SCRIPTS
                .iter()
                .any(|n| !r.scripts.get(*n).is_some_and(|h| util::valid_hash(h)))
            || !util::valid_time(&r.time)
            || !valid_user(&r.user)
            || (!self.fake && !crate::store::valid_boot(&r.boot))
        {
            return Err(invalid());
        }
        if review {
            if r.state != "reviewed" || r.step != 0 || !r.backup.is_empty() {
                return Err(invalid());
            }
            return Ok(());
        }
        if !util::valid_id(&r.backup) || !(0..=5).contains(&r.step) {
            return Err(invalid());
        }
        match r.state.as_str() {
            "clearing" => (),
            "attempting-clear" | "failed-do-not-repeat" if r.step <= 4 => (),
            "awaiting-manual-reboot" | "completed" if r.step == 5 => (),
            "closed-incomplete" => {
                self.reset_load_close(r)?;
            }
            _ => return Err(invalid()),
        }
        Ok(())
    }
    fn reset_close_path(&self, r: &ResetJournal) -> Result<std::path::PathBuf> {
        if !util::valid_id(&r.backup) {
            return Err(invalid());
        }
        Ok(self.root.join(format!("reset-close-{}.json", r.backup)))
    }
    fn reset_load_close(&self, r: &ResetJournal) -> Result<ResetClose> {
        let evidence: ResetClose =
            fs::read_json(&self.reset_close_path(r)?).map_err(|_| invalid())?;
        if evidence.schema != 1
            || !closable(&evidence.prior.state)
            || !util::valid_time(&evidence.time)
            || self.validate_reset(&evidence.prior, false).is_err()
            || close_review(&evidence.prior)? != evidence.review_hash
        {
            return Err(invalid());
        }
        let mut expected = evidence.prior.clone();
        expected.state = "closed-incomplete".into();
        if &expected != r {
            return Err(invalid());
        }
        Ok(evidence)
    }
    pub(crate) fn closure_history_check(&self) -> Result<Vec<Value>> {
        let path = self.root.join("history.json");
        fs::no_links(&path)?;
        let v: Vec<Value> = if path.try_exists()? {
            fs::read_json::<Option<Vec<Value>>>(&path)?.unwrap_or_default()
        } else {
            Vec::new()
        };
        if v.iter().any(|x| !crate::store::valid_history(x)) {
            return Err(Error::new(
                "E_REPORT",
                "History has an unsupported record; preserve it for redacted inspection.",
            ));
        }
        Ok(v)
    }
    pub(crate) fn closure_history(&self, kind: &str, id: &str, state: &str) -> Result<()> {
        let prior = self.closure_history_check()?;
        if prior
            .iter()
            .any(|v| v["type"] == kind && v["id"] == id && v["state"] == state)
        {
            return Ok(());
        }
        self.history(kind, id, state)
    }
    fn reset_close(&self, confirmation: &str, submitted: &str) -> Result<Value> {
        let path = self.root.join("reset-journal.json");
        let mut r: ResetJournal = fs::read_json(&path).map_err(|_| invalid())?;
        self.validate_reset(&r, false)?;
        if confirmation != CLOSE_PHRASE || !util::valid_hash(submitted) {
            return Err(Error::new(
                "E_CONFIRM",
                "Incomplete reset closure requires the exact confirmation phrase and current reviewed ledger hash.",
            ));
        }
        if r.state == "closed-incomplete" {
            let evidence = self.reset_load_close(&r)?;
            if evidence.review_hash != submitted {
                return Err(Error::new(
                    "E_STALE",
                    "The reset closure review does not match the preserved ledger.",
                ));
            }
            self.closure_history("wallet-reset", &r.backup, "closed-incomplete")?;
            return Ok(
                json!({"state":"closed-incomplete","completed_steps":r.step,"evidence_preserved":true,"clear_dispatched":false,"next_step":"The incomplete reset was closed without repeating any app-data clear. Prior app-data loss remains irreversible; Wallet readiness remains unverified."}),
            );
        }
        if !closable(&r.state) {
            return Err(Error::new(
                "E_RESET",
                "Only a clearing, attempted or failed incomplete reset may be closed.",
            ));
        }
        if close_review(&r)? != submitted {
            return Err(Error::new(
                "E_STALE",
                "The incomplete reset ledger changed. Read current status again before closure.",
            ));
        }
        self.checkpoint("reset-before-close-evidence")?;
        let fresh: ResetJournal = fs::read_json(&path).map_err(|_| invalid())?;
        if fresh != r {
            return Err(Error::new(
                "E_STALE",
                "The incomplete reset ledger changed before preservation.",
            ));
        }
        let evidence = ResetClose {
            schema: 1,
            prior: r.clone(),
            review_hash: submitted.into(),
            time: self.time(),
        };
        let evidence_path = self.reset_close_path(&r)?;
        fs::no_links(&evidence_path)?;
        r.state = "closed-incomplete".into();
        if evidence_path.try_exists()? {
            self.reset_load_close(&r)?;
        } else {
            fs::write_json(&evidence_path, &evidence)?;
        }
        self.reset_load_close(&r)?;
        self.checkpoint("reset-before-close-commit")?;
        let fresh: ResetJournal = fs::read_json(&path).map_err(|_| invalid())?;
        if fresh != evidence.prior {
            return Err(Error::new(
                "E_STALE",
                "The incomplete reset ledger changed before closure. No app-data clear was dispatched.",
            ));
        }
        self.reset_load_close(&r)?;
        self.closure_history_check()?;
        fs::write_json(&path, &r)?;
        self.checkpoint("reset-after-close-commit")?;
        self.closure_history("wallet-reset", &r.backup, "closed-incomplete")?;
        let fresh: ResetJournal = fs::read_json(&path).map_err(|_| invalid())?;
        if fresh != r {
            return Err(Error::new(
                "E_STALE",
                "The reset ledger changed after closure was recorded. No app-data clear was dispatched; inspect fresh status.",
            ));
        }
        self.reset_load_close(&r)?;
        Ok(
            json!({"state":"closed-incomplete","completed_steps":r.step,"evidence_preserved":true,"clear_dispatched":false,"next_step":"The incomplete reset was closed without repeating any app-data clear. Prior app-data loss remains irreversible; Wallet readiness remains unverified."}),
        )
    }
    pub(crate) fn current_user(&self) -> Result<String> {
        if self.fake {
            return Ok("0".into());
        }
        let user = run("/system/bin/am", &["get-current-user"]).map_err(|_| {
            Error::new(
                "E_CAPABILITY",
                "The current Android user could not be verified; reset is blocked.",
            )
        })?;
        let user = user.trim();
        if !valid_user(user) {
            return Err(Error::new(
                "E_CAPABILITY",
                "The current Android user could not be verified; reset is blocked.",
            ));
        }
        Ok(user.into())
    }
    fn reset_boot(&self) -> Result<String> {
        let boot = util::boot_id();
        if !self.fake && !crate::store::valid_boot(&boot) {
            return Err(Error::new(
                "E_CAPABILITY",
                "The current boot identity could not be verified; reset is blocked.",
            ));
        }
        Ok(boot)
    }
    fn reset_resume_context(&self, r: &ResetJournal) -> Result<()> {
        if r.boot == self.reset_boot()? {
            return Err(Error::new(
                "E_CONFIRM",
                "The device has not rebooted since the confirmed clears. Reboot manually before resume.",
            ));
        }
        if self.current_user()? != r.user {
            return Err(Error::new(
                "E_STALE",
                "The Android user changed since reset confirmation. Return to the reviewed user before resuming; do not repeat the clears.",
            ));
        }
        Ok(())
    }
    fn reset_scripts(&self) -> Result<BTreeMap<String, String>> {
        let mut scripts = BTreeMap::new();
        for name in SCRIPTS {
            let body=fs::bounded(&self.modules.join("playintegrityfix").join(name),1<<20).map_err(|_|Error::new("E_CAPABILITY","The installed PIF action or a required dependency is unavailable. Reset is blocked."))?;
            scripts.insert(name.into(), util::hash(&body));
        }
        Ok(scripts)
    }
    fn reset_preview(&self) -> Result<Value> {
        let user = self.current_user()?;
        let boot = self.reset_boot()?;
        let scripts = self.reset_scripts()?;
        let config = self.snapshot()?;
        let pif = fs::bounded(
            &self.modules.join("playintegrityfix/custom.pif.prop"),
            64 << 10,
        )?;
        let r = ResetJournal {
            schema: 1,
            state: "reviewed".into(),
            boot,
            user: user.clone(),
            review_hash: review_hash(&scripts, &pif, &config, &user),
            scripts,
            step: 0,
            time: self.time(),
            backup: String::new(),
            pif_hash: util::hash(&pif),
        };
        fs::write_json(&self.root.join("reset-review.json"), &r)?;
        Ok(
            json!({"review_hash":r.review_hash,"user":r.user,"confirmation":PHRASE,"steps":[
        "Clear Wallet for the reviewed numeric Android user shown here.","Clear Play Store for the same reviewed user.","Clear Google Services Framework for the same reviewed user.","Clear Google Play services twice (as requested by the owner).","Stop and ask the owner to reboot manually. No unattended reboot or automatic resume.","After reboot, explicitly resume to recheck PIF scripts. Automatic execution is unavailable; separately review and run the manual PIF action and GMS force-stop, then record completion.","Sign back in if needed, re-provision cards and check Wallet."],"consequences":[
        "App-data clearing is destructive and cannot be undone by configuration backups.","Wallet/card setup and Google sign-in may need to be repeated. GSF state and Android ID may be regenerated.","The repeated GMS clear is the owner's requested sequence; its technical rationale is unverified.","The installed PIF action runs autopif4.sh -m. It can change custom.pif.prop, TrickyStore patch settings and kill Play services; this is a separate scoped authorization from ordinary Apply.","Review the installed action and its dependencies locally before confirmation. Network output is not displayed by the helper."]}),
        )
    }
    fn reset_check_review(
        &self,
        r: &ResetJournal,
        submitted: &str,
    ) -> Result<(BTreeMap<String, FileState>, Vec<u8>, String)> {
        self.validate_reset(r, true)?;
        if submitted != r.review_hash {
            return Err(Error::new(
                "E_STALE",
                "Reset review does not match; preview again.",
            ));
        }
        let user = self.current_user()?;
        let boot = self.reset_boot()?;
        if user != r.user || boot != r.boot {
            return Err(Error::new(
                "E_STALE",
                "Android user or boot changed since reset review; preview again before any app-data clearing.",
            ));
        }
        let scripts = self.reset_scripts()?;
        if scripts != r.scripts {
            return Err(Error::new(
                "E_STALE",
                "A reviewed PIF script changed; inspect and preview again.",
            ));
        }
        let pif = fs::bounded(
            &self.modules.join("playintegrityfix/custom.pif.prop"),
            64 << 10,
        )
        .map_err(|_| Error::new("E_STALE", "PIF configuration changed since reset review."))?;
        if util::hash(&pif) != r.pif_hash {
            return Err(Error::new(
                "E_STALE",
                "PIF configuration changed since reset review.",
            ));
        }
        let snapshot = self.snapshot()?;
        if review_hash(&scripts, &pif, &snapshot, &user) != r.review_hash {
            return Err(Error::new(
                "E_STALE",
                "Active configuration changed since reset review.",
            ));
        }
        Ok((snapshot, pif, boot))
    }
    pub(crate) fn reset_diagnostic(&self) -> (Value, bool, String) {
        let path = self.root.join("reset-journal.json");
        // symlink_metadata distinguishes genuine absence from unsafe dangling
        // symlinks; the bounded read then rejects all links.
        let r: ResetJournal = match fs::read_json(&path) {
            Ok(r) => r,
            Err(_) => {
                if std::fs::symlink_metadata(&path)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                {
                    return (json!({"state":"none"}), false, String::new());
                }
                return (json!({"state":"unreadable"}),true,"Inspect the one-shot reset journal. Preserve unreadable evidence; never repeat app-data clearing automatically.".into());
            }
        };
        if self.validate_reset(&r, false).is_err() {
            return (json!({"state":"invalid"}),true,"Inspect the one-shot reset journal. Preserve corrupt evidence; never repeat app-data clearing automatically.".into());
        }
        let v = json!({"state":r.state,"user":r.user,"completed_steps":r.step,"time":r.time});
        match r.state.as_str(){"completed"|"closed-incomplete"=>(v,false,String::new()),"awaiting-manual-reboot"=>(v,true,"Follow the one-shot reset's manual reboot, reset resume and separately reviewed manual completion steps. Do not repeat the clears; configuration rollback cannot restore app data.".into()),_=>(v,true,"Inspect the unfinished one-shot reset before any other change. Some app-data clears may have happened; do not repeat them. Configuration rollback cannot restore app data.".into())}
    }
    pub fn reset(&self, action: &str, confirmation: &str, submitted_review: &str) -> Result<Value> {
        self.with_lock(||{
            let path=self.root.join("reset-journal.json");
            match action{
                "preview"=>{self.require_recovered()?;self.reset_preview()}
                "status"=>{
                    let r:ResetJournal=match fs::read_json(&path){Ok(r)=>r,Err(_)=>{
                        if std::fs::symlink_metadata(&path).is_err_and(|e|e.kind()==std::io::ErrorKind::NotFound){return Ok(json!({"state":"none"}));}
                        return Err(Error::new("E_RECOVERY","Reset journal is unreadable. Preserve it; do not repeat app-data clearing."));
                    }};self.validate_reset(&r,false)?;
                    let can_close=closable(&r.state);
                    Ok(json!({"state":r.state,"user":r.user,"completed_steps":r.step,"time":r.time,"can_close":can_close,"close_review_hash":if can_close {Some(close_review(&r)?)}else{None},"close_confirmation":if can_close {CLOSE_PHRASE}else{""},"next_step":if r.state=="closed-incomplete" {"The incomplete ledger is closed. Do not repeat any clear automatically; prior app-data loss is irreversible and Wallet readiness remains unverified."}else{"Resume manually only after reboot and a separate review; never repeat failed app-data clearing automatically."}}))
                }
                "confirm"=>{
                    if confirmation!=PHRASE{return Err(Error::new("E_CONFIRM","Review the destructive consequences and type the exact reset confirmation phrase."));}
                    if self.fake{return Err(Error::new("E_CAPABILITY","Destructive reset is disabled in the fake-engine test backend."));}
                    self.require_recovered()?;fs::no_links(&path)?;
                    if path.try_exists()?{let old:ResetJournal=fs::read_json(&path).map_err(|_|Error::new("E_RECOVERY","Reset journal is unreadable; preserve it."))?;self.validate_reset(&old,false)?;if !matches!(old.state.as_str(),"completed"|"closed-incomplete"){return Err(Error::new("E_RECOVERY","A reset is already recorded. Inspect its state; never repeat destructive steps automatically."));}}
                    let mut r:ResetJournal=fs::read_json(&self.root.join("reset-review.json")).map_err(|_|Error::new("E_CONFIRM","Preview the installed PIF action and reset steps first."))?;
                    let(snapshot,pif,boot)=self.reset_check_review(&r,submitted_review)?;
                    let b=self.backup("wallet-reset-preparation",&snapshot)?;r.backup=b.id.clone();
                    fs::atomic_write(&self.root.join("backups").join(&b.id).join("custom.pif.prop"),&pif,&private_metadata())?;
                    r.state="clearing".into();r.boot=boot;fs::write_json(&path,&r)?;
                    record_clear_steps(&path,&mut r,|user,pkg|{
                        if self.fake{return Err(Error::new("E_CAPABILITY","Destructive reset is disabled in the fake-engine test backend."));}
                        run("/system/bin/pm",&["clear","--user",user,pkg])
                    })?;
                    r.state="awaiting-manual-reboot".into();fs::write_json(&path,&r)?;let _=self.history("wallet-reset",&b.id,&r.state);
                    Ok(json!({"state":r.state,"message":"The five separately confirmed clears completed. Reboot manually, then invoke reset --action resume. No background continuation is installed."}))
                }
                "resume"=>{
                    let r:ResetJournal=fs::read_json(&path).map_err(|_|{
                        if std::fs::symlink_metadata(&path).is_err_and(|e|e.kind()==std::io::ErrorKind::NotFound){Error::new("E_RESET","No one-shot reset journal is available.")}
                        else{invalid()}
                    })?;self.validate_reset(&r,false)?;
                    if r.state!="awaiting-manual-reboot"{return Err(Error::new("E_RESET","Reset cannot resume from this state; inspect without repeating destructive steps."));}
                    self.reset_resume_context(&r)?;if self.reset_scripts()?!=r.scripts{return Err(Error::new("E_STALE","PIF scripts changed across reboot. Inspect them; no action was run."));}
                    Err(Error::new("E_CAPABILITY","Automatic post-reboot PIF execution is unavailable: its network mutation contract is not verified. Follow the reviewed manual completion steps; do not repeat the clears.").with_data(json!({"state":r.state,"user":r.user,"backup":r.backup,"next_step":"Inspect the pinned installed PIF action and run it manually as documented, then force-stop GMS. Record completion only after each command succeeds."})))
                }
                "complete"=>{
                    let mut r:ResetJournal=fs::read_json(&path).map_err(|e|{
                        if std::fs::symlink_metadata(&path).is_err_and(|e|e.kind()==std::io::ErrorKind::NotFound){e}else{invalid()}
                    })?;self.validate_reset(&r,false)?;
                    if confirmation!=COMPLETE_PHRASE||r.state!="awaiting-manual-reboot"{return Err(Error::new("E_CONFIRM","Complete requires a reboot and explicit confirmation of the documented successful manual post-reboot commands."));}
                    self.reset_resume_context(&r)?;r.state="completed".into();r.time=self.time();fs::write_json(&path,&r)?;
                    Ok(json!({"state":"completed","next_step":"Sign back in if needed, re-provision cards and check Wallet. Actual readiness and Tap-to-Pay remain unverified."}))
                }
                "close"=>self.reset_close(confirmation,submitted_review),
                _=>Err(Error::new("E_REQUEST","Reset actions: preview, status, confirm, resume, complete, close.")),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, App) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut app = App::new(
            root.join("private"),
            root.join("active"),
            root.join("modules"),
            true,
        );
        app.clock = std::sync::Arc::new(|| 1791547200);
        fs::private_dir(&app.active).unwrap();
        fs::private_dir(&app.modules.join("playintegrityfix")).unwrap();
        app.init().unwrap();
        for name in crate::FILES {
            fs::atomic_write(
                &app.active.join(name),
                b"synthetic opaque protected bytes",
                &private_metadata(),
            )
            .unwrap();
        }
        for name in SCRIPTS.iter().chain(["custom.pif.prop"].iter()) {
            fs::atomic_write(
                &app.modules.join("playintegrityfix").join(name),
                b"inert synthetic source",
                &private_metadata(),
            )
            .unwrap();
        }
        (dir, app)
    }
    #[test]
    fn reviewed_context_rejects_every_stale_binding_without_dispatch() {
        for kind in ["submitted", "boot", "user", "script", "pif", "protected"] {
            let (_dir, app) = fixture();
            app.reset("preview", "", "").unwrap();
            let mut r: ResetJournal = fs::read_json(&app.root.join("reset-review.json")).unwrap();
            let submitted = r.review_hash.clone();
            let mut token = submitted.clone();
            match kind {
                "submitted" => token = util::hash(b"other review"),
                "boot" => r.boot = "other boot".into(),
                "user" => r.user = "10".into(),
                "script" => fs::atomic_write(
                    &app.modules.join("playintegrityfix/action.sh"),
                    b"changed inert script",
                    &private_metadata(),
                )
                .unwrap(),
                "pif" => fs::atomic_write(
                    &app.modules.join("playintegrityfix/custom.pif.prop"),
                    b"changed inert pif",
                    &private_metadata(),
                )
                .unwrap(),
                _ => fs::atomic_write(
                    &app.active.join("target.txt"),
                    b"changed protected bytes",
                    &private_metadata(),
                )
                .unwrap(),
            };
            assert_eq!(
                app.reset_check_review(&r, &token).unwrap_err().code,
                "E_STALE"
            );
            assert!(!app.root.join("reset-journal.json").exists());
            assert_eq!(
                std::fs::read_dir(app.root.join("backups")).unwrap().count(),
                0
            );
        }
    }
    #[test]
    fn production_journal_formats_reject_unverified_boot_and_user() {
        let (_dir, mut app) = fixture();
        app.reset("preview", "", "").unwrap();
        let mut r: ResetJournal = fs::read_json(&app.root.join("reset-review.json")).unwrap();
        app.fake = false;
        for boot in [
            "",
            "garbage",
            "------------------------------------",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            r.boot = boot.into();
            assert_eq!(app.validate_reset(&r, true).unwrap_err().code, "E_RECOVERY");
        }
        r.boot = "00000000-0000-0000-0000-000000000001".into();
        assert!(app.validate_reset(&r, true).is_ok());
        for user in ["", "-1", "current", "00", "0; command"] {
            r.user = user.into();
            assert_eq!(app.validate_reset(&r, true).unwrap_err().code, "E_RECOVERY");
        }
    }
    #[test]
    fn clear_ledger_records_attempt_before_callback_and_exact_fixed_order() {
        let (_dir, app) = fixture();
        app.reset("preview", "", "").unwrap();
        let mut r: ResetJournal = fs::read_json(&app.root.join("reset-review.json")).unwrap();
        r.backup = "a".repeat(32);
        let path = app.root.join("synthetic-clear-ledger.json");
        let mut seen = Vec::new();
        record_clear_steps(&path, &mut r, |user, pkg| {
            let saved: ResetJournal = fs::read_json(&path).unwrap();
            assert_eq!(saved.state, "attempting-clear");
            assert_eq!(saved.step, seen.len() as i32);
            assert_eq!(user, "0");
            seen.push(pkg.to_owned());
            Ok("Success\n".into())
        })
        .unwrap();
        assert_eq!(seen, CLEARS.map(str::to_owned));
        let saved: ResetJournal = fs::read_json(&path).unwrap();
        assert_eq!(saved.state, "clearing");
        assert_eq!(saved.step, 5);
        assert!(!app.root.join("reset-journal.json").exists());
    }
    #[test]
    fn clear_ledger_failure_and_process_loss_preserve_next_attempt() {
        for crash in [false, true] {
            let (_dir, app) = fixture();
            app.reset("preview", "", "").unwrap();
            let mut r: ResetJournal = fs::read_json(&app.root.join("reset-review.json")).unwrap();
            r.backup = "a".repeat(32);
            let path = app.root.join("synthetic-clear-ledger.json");
            let mut count = 0;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                record_clear_steps(&path, &mut r, |_, _| {
                    count += 1;
                    if count == 3 {
                        if crash {
                            panic!("synthetic process loss before result");
                        }
                        return Ok("unexpected output".into());
                    }
                    Ok("Success".into())
                })
            }));
            assert_eq!(count, 3);
            if crash {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap().unwrap_err().code, "E_RESET");
            }
            let saved: ResetJournal = fs::read_json(&path).unwrap();
            assert_eq!(saved.step, 2);
            assert_eq!(
                saved.state,
                if crash {
                    "attempting-clear"
                } else {
                    "failed-do-not-repeat"
                }
            );
            assert!(app.validate_reset(&saved, false).is_ok());
            assert!(!app.root.join("reset-journal.json").exists());
        }
    }
}
