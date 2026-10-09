use crate::{
    App, FILES,
    error::{Error, Result},
    fs::{self, FileState, Metadata},
    util,
};
use rhso_keybox::{self as keybox, Document, Selection};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs as io,
    path::{Path, PathBuf},
};
pub fn key_error(_: keybox::Error) -> Error {
    Error::new(
        "E_VALIDATION",
        "Validation failed; check the input inventory for a redacted explanation.",
    )
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Stage {
    pub schema: u32,
    pub id: String,
    pub sha256: String,
    pub time: String,
    pub bytes: usize,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Compaction {
    pub entries_before: usize,
    pub entries_after: usize,
    pub removed_entries: usize,
    pub packages_before: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: u32,
    pub id: String,
    pub time: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, deserialize_with = "null_vec")]
    pub inputs: Vec<Stage>,
    pub active: BTreeMap<String, FileState>,
    pub intended: BTreeMap<String, FileState>,
    #[serde(default, deserialize_with = "null_vec")]
    pub changes: Vec<String>,
    pub capabilities: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_backup: String,
    #[serde(default)]
    pub summary: Value,
    #[serde(default, deserialize_with = "null_vec")]
    pub preview: Vec<Value>,
    #[serde(default, deserialize_with = "null_vec")]
    pub warnings: Vec<String>,
    #[serde(default, deserialize_with = "null_vec")]
    pub selections: Vec<Selection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_compaction: Option<Compaction>,
}
fn null_vec<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> std::result::Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}
impl Plan {
    pub fn view(&self) -> Value {
        let mut warnings = self.warnings.clone();
        warnings.extend(["Configuration-set replacement is recoverable, not atomic. Other root writers are outside this helper's lock.".into(),"Public-chain evidence is a separate bounded check, not proof of hardware identity or Wallet acceptance. Wallet acceptance requires a real check.".into()]);
        let mut v = json!({"id":self.id,"time":self.time,"type":self.kind,"changes":self.changes,"preview":self.preview,"summary":self.summary,"active":self.active,"intended":self.intended,"metadata":"Selected inputs are emitted with DeviceID WalletDiagnosticHelper; no hardware identity is recreated.","adoption":"Per-file FileObserver reload; identity adoption remains pending fresh evidence.","required_capabilities":self.capabilities,"warnings":warnings});
        if let Some(c) = &self.target_compaction {
            v["target_compaction"] = json!(c);
        }
        v
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LockRecord {
    pub pid: i32,
    pub boot: String,
}
pub(crate) struct Lock {
    path: PathBuf,
}
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = io::remove_file(self.path.join("owner.json"));
        let _ = io::remove_dir(&self.path);
        if let Some(p) = self.path.parent() {
            let _ = fs::sync_dir(p);
        }
    }
}
impl App {
    pub fn init(&self) -> Result<()> {
        if !self.fake && util::owner_id() != 0 {
            return Err(Error::new(
                "E_ROOT",
                "Run this backend through KernelSU as root.",
            ));
        }
        for p in [
            &self.root,
            &self.root.join("inbox"),
            &self.root.join("staged"),
            &self.root.join("plans"),
            &self.root.join("backups"),
        ] {
            fs::private_dir(p)?;
            let m = fs::metadata(p)?;
            if m.mode != 0o700 || (!self.fake && (m.uid != 0 || m.gid != 0)) {
                return Err(Error::new(
                    "E_IO",
                    "Private storage ownership or permissions could not be verified.",
                ));
            }
        }
        let p = self.root.join("format.json");
        if !p.try_exists()? {
            for e in io::read_dir(&self.root)? {
                let e = e?;
                if !e.file_type()?.is_dir()
                    || !matches!(
                        e.file_name().to_str(),
                        Some("inbox" | "staged" | "plans" | "backups")
                    )
                    || io::read_dir(e.path())?.next().is_some()
                {
                    return Err(Error::new(
                        "E_FORMAT",
                        "Unmarked private data requires explicit migration review; no automatic format stamp was written.",
                    ));
                }
            }
            return fs::write_json(
                &p,
                &json!({"schema":1,"kind":"wallet-diagnostic-private-store"}),
            );
        }
        let v:Value=fs::read_json(&p).map_err(|_|Error::new("E_FORMAT","Private storage has an unsupported or corrupt format. Preserve it; automatic migration is unavailable."))?;
        if v != json!({"schema":1,"kind":"wallet-diagnostic-private-store"}) {
            return Err(Error::new(
                "E_FORMAT",
                "Private storage has an unsupported or corrupt format. Preserve it; automatic migration is unavailable.",
            ));
        }
        Ok(())
    }
    pub(crate) fn lock(&self) -> Result<Lock> {
        self.init()?;
        let p = self.root.join("operation.lock");
        fs::no_links(&p)?;
        io::create_dir(&p).map_err(|_|Error::new("E_BUSY","Another operation or an interrupted lock is present. Open Recovery before retrying."))?;
        let l = Lock { path: p.clone() };
        fs::set_metadata(
            &p,
            &Metadata {
                mode: 0o700,
                uid: util::owner_id(),
                gid: util::owner_id(),
                selinux: String::new(),
            },
        )?;
        fs::write_json(
            &p.join("owner.json"),
            &LockRecord {
                pid: std::process::id() as i32,
                boot: util::boot_id(),
            },
        )?;
        fs::sync_dir(&self.root)?;
        Ok(l)
    }
    pub(crate) fn valid_lock(&self, l: &LockRecord) -> bool {
        l.pid > 0 && (self.fake || valid_boot(&l.boot) && valid_boot(&util::boot_id()))
    }
    pub fn object(&self, kind: &str, id: &str) -> Result<PathBuf> {
        if !matches!(kind, "staged" | "plans" | "backups") || !util::valid_id(id) {
            return Err(Error::new(
                "E_ID",
                "Choose a valid inventory, plan or backup ID.",
            ));
        }
        let p = self.root.join(kind).join(id);
        fs::no_links(&p)?;
        Ok(p)
    }
    pub(crate) fn require_foreign_recovered(&self) -> Result<()> {
        let p = self.root.join("journal.json");
        fs::no_links(&p)?;
        if p.try_exists()? {
            let j: crate::transaction::Journal = fs::read_json(&p).map_err(|_| recovery_error())?;
            self.validate_journal(&j)?;
            if !matches!(j.state.as_str(), "committed" | "restored") {
                return Err(recovery_error());
            }
        }
        let p = self.root.join("reset-journal.json");
        fs::no_links(&p)?;
        if p.try_exists()? {
            let r: crate::reset::ResetJournal = fs::read_json(&p).map_err(|_| recovery_error())?;
            self.validate_reset(&r, false)?;
            if !matches!(r.state.as_str(), "completed" | "closed-incomplete") {
                return Err(recovery_error());
            }
        }
        Ok(())
    }
    pub fn require_recovered(&self) -> Result<()> {
        self.require_foreign_recovered()?;
        if self.stack_unfinished() {
            return Err(recovery_error());
        }
        Ok(())
    }
    pub(crate) fn unfinished(&self) -> bool {
        self.require_recovered().is_err()
    }
    pub fn ingest(&self, path: &str) -> Result<Value> {
        self.with_lock(||{self.require_recovered()?;let mut p=PathBuf::from(path);if !p.is_absolute()||path.contains(['\r','\n','\0'])||p.components().any(|c|matches!(c,std::path::Component::ParentDir|std::path::Component::CurDir)){return Err(Error::new("E_PATH","Use a clean absolute path inside the private inbox or optional shared inbox."));}let permitted=[self.root.join("inbox"),self.shared_inbox.clone()].iter().any(|d|p!=*d&&p.starts_with(d))||p==self.active.join("keybox.xml");if !permitted{return Err(Error::new("E_PATH","Copy the file to the private inbox; active keybox.xml is also an allowed source for a reviewed merge."));}
if !self.fake&&self.shared_inbox==PathBuf::from("/sdcard/keybox_inbox")&&p.starts_with(&self.shared_inbox){let base=io::canonicalize("/sdcard")?;if !base.starts_with("/storage/emulated")&&!base.starts_with("/mnt/user"){return Err(Error::new("E_PATH","Shared storage alias has an unrecognized target. Use the private inbox."));}p=base.join("keybox_inbox").join(p.strip_prefix(&self.shared_inbox).map_err(|_|Error::new("E_PATH","The source path is unsupported."))?);}let b=zeroize::Zeroizing::new(fs::bounded(&p,keybox::MAX_INPUT)?);Ok(json!(self.stage_bytes(&b)?))})
    }
    pub(crate) fn stage_bytes(&self, b: &[u8]) -> Result<Stage> {
        if b.is_empty() || b.len() > keybox::MAX_INPUT {
            return Err(Error::new(
                "E_INPUT",
                "The staged input is empty or exceeds the size limit.",
            ));
        }
        let id = util::new_id()?;
        let dir = self.object("staged", &id)?;
        fs::private_dir(&dir)?;
        fs::atomic_write(&dir.join("input.xml"), b, &private_metadata())?;
        let s = Stage {
            schema: 1,
            id: id.clone(),
            sha256: util::hash(b),
            time: self.time(),
            bytes: b.len(),
        };
        fs::write_json(&dir.join("stage.json"), &s)?;
        self.history("ingest", &id, "staged")?;
        Ok(s)
    }
    pub(crate) fn stage(&self, id: &str) -> Result<(Document, Stage)> {
        let p = self.object("staged", id)?;
        let s: Stage = fs::read_json(&p.join("stage.json"))?;
        if !valid_stage(&s, id) {
            return Err(Error::new(
                "E_FORMAT",
                "Staged metadata is incomplete or corrupt.",
            ));
        }
        let b = zeroize::Zeroizing::new(fs::bounded(&p.join("input.xml"), keybox::MAX_INPUT)?);
        if util::hash(&b) != s.sha256 || b.len() != s.bytes {
            return Err(Error::new(
                "E_STALE",
                "Staged input changed. Import it again.",
            ));
        }
        Ok((keybox::parse(&b, self.now()).map_err(key_error)?, s))
    }
    pub fn validate(&self, id: &str) -> Result<Value> {
        let (d, s) = self.stage(id)?;
        Ok(json!({"id":id,"sha256":s.sha256,"summary":d.summary()}))
    }
    pub(crate) fn history(&self, kind: &str, id: &str, state: &str) -> Result<()> {
        let p = self.root.join("history.json");
        let mut v: Vec<Value> = if p.try_exists()? {
            fs::read_json::<Option<Vec<Value>>>(&p)?.unwrap_or_default()
        } else {
            Vec::new()
        };
        if v.iter().any(|x| !valid_history(x)) {
            return Err(Error::new(
                "E_REPORT",
                "History has an unsupported record; preserve it for redacted inspection.",
            ));
        }
        v.push(json!({"time":self.time(),"type":kind,"id":id,"state":state}));
        fs::write_json(&p, &v)
    }
    pub(crate) fn public_history(&self) -> (Vec<Value>, usize) {
        let p = self.root.join("history.json");
        if !p.exists() {
            return (Vec::new(), 0);
        }
        let Ok(v) = fs::read_json::<Option<Vec<Value>>>(&p) else {
            return (Vec::new(), 1);
        };
        let mut out = Vec::new();
        let mut bad = 0;
        for x in v.unwrap_or_default() {
            if valid_history(&x) {
                out.push(x);
            } else {
                bad += 1;
            }
        }
        (out, bad)
    }
    pub fn plan(
        &self,
        selections: &str,
        targets: bool,
        patch: &str,
        compact: bool,
    ) -> Result<Value> {
        self.with_lock(||{
  self.require_recovered()?;let caps=self.plan_capabilities()?;let before=self.snapshot()?;let id=util::new_id()?;let dir=self.object("plans",&id)?;fs::private_dir(&dir)?;
  let mut p=Plan{schema:1,id:id.clone(),time:self.time(),kind:"apply".into(),inputs:Vec::new(),active:before.clone(),intended:before.clone(),changes:Vec::new(),capabilities:caps,source_backup:String::new(),summary:Value::Null,preview:Vec::new(),warnings:Vec::new(),selections:Vec::new(),target_compaction:None};
  p.warnings.push(if p.capabilities.get("public_feed_state").is_some_and(|v|v=="fresh"){"Google-anchored selected/retained chains were checked locally against the current full Google public status snapshot. Other anchors retain unknown revocation status. Absence from that snapshot does not establish hardware identity or Wallet approval."}else{"No fresh independently acquired Google public status snapshot is available; public root/revocation assessment remains unknown. Refresh explicitly before relying on it."}.into());
  if selections.is_empty(){let b=zeroize::Zeroizing::new(fs::bounded(&self.active.join("keybox.xml"),keybox::MAX_INPUT).map_err(|_|Error::new("E_VALIDATION","A target or patch repair requires a validated retained keybox; select a validated replacement first."))?);let d=keybox::parse(&b,self.now()).map_err(key_error)?;self.reject_public_listed(&d)?;}
  let mut docs=Vec::new();let mut sources=BTreeMap::new();if !selections.is_empty(){for s in selections.split(','){let v:Vec<_>=s.split(':').collect();if v.len()!=4||!util::valid_id(v[0]){return Err(Error::new("E_SELECTION","Choose an explicit input ID, Keybox index, Key index and algorithm."));}let bi=v[1].parse::<i64>().map_err(|_|Error::new("E_SELECTION","Invalid Keybox index."))?;let ki=v[2].parse::<i64>().map_err(|_|Error::new("E_SELECTION","Invalid Key index."))?;let idx=if let Some(i)=sources.get(v[0]){*i}else{let(d,st)=self.stage(v[0])?;let i=docs.len();sources.insert(v[0].to_owned(),i);docs.push(d);p.inputs.push(st);i};p.selections.push(Selection{source:idx as i64,keybox:bi,key:ki,algorithm:v[3].into()});}let refs:Vec<_>=docs.iter().collect();let d=keybox::merge(&refs,&p.selections,self.now()).map_err(key_error)?;self.reject_public_listed(&d)?;p.summary=json!(d.summary());if before["keybox.xml"].exists&& let Ok(b)=fs::bounded(&self.active.join("keybox.xml"),keybox::MAX_INPUT){if let Ok(old)=keybox::parse(&b,self.now()){for bx in old.summary().keyboxes{for k in bx.keys{if !p.selections.iter().any(|s|s.algorithm==k.algorithm){p.warnings.push(format!("The current {} entry is omitted by this explicit replacement selection.",k.algorithm));}}}}else{p.warnings.push("Current keybox did not validate; its algorithm inventory could not be established.".into());}}self.propose(&dir,&mut p,"keybox.xml",&d.xml().map_err(key_error)?)?;}
  if targets||compact{let b=if before["target.txt"].exists{fs::bounded(&self.active.join("target.txt"),1<<20)?}else{Vec::new()};let mut out=b;if compact{let (v,s)=compact_targets(&out)?;out=v;p.target_compaction=Some(s);}
if targets{out=repair_targets(&out)?;}self.propose(&dir,&mut p,"target.txt",&out)?;}
  if !patch.is_empty(){if !valid_patch(patch){return Err(Error::new("E_INPUT","Patch date must be a valid YYYY-MM-DD date."));}
if self.pif()?.get("SECURITY_PATCH").map(String::as_str)!=Some(patch){return Err(Error::new("E_SELECTION","Patch repair must match the inspected PIF SECURITY_PATCH. PIF changes need separate authorization."));}let b=if before["security_patch.txt"].exists{fs::bounded(&self.active.join("security_patch.txt"),1<<20)?}else{Vec::new()};self.propose(&dir,&mut p,"security_patch.txt",&repair_patch(&b,patch)?)?;}
  if p.changes.is_empty(){return Err(Error::new("E_SELECTION","The plan has no selected configuration change."));}fs::write_json(&dir.join("plan.json"),&p)?;self.history("plan",&id,"review")?;Ok(p.view())
 })
    }
    fn propose(&self, dir: &Path, p: &mut Plan, name: &str, b: &[u8]) -> Result<()> {
        let old = &p.active[name];
        let hash = util::hash(b);
        if old.exists && old.sha256 == hash {
            return Ok(());
        }
        let m = if old.exists {
            old.metadata.clone()
        } else {
            Metadata {
                selinux: fs::metadata(&self.active)?.selinux,
                ..private_metadata()
            }
        };
        p.intended.insert(
            name.into(),
            FileState {
                exists: true,
                sha256: hash.clone(),
                size: b.len() as i64,
                metadata: m.clone(),
            },
        );
        p.changes.push(name.into());
        let mut preview = json!({"file":name,"old_exists":old.exists,"old_sha256":old.sha256,"new_sha256":hash,"metadata":m});
        if name != "keybox.xml" {
            let previous = if old.exists {
                fs::bounded(&self.active.join(name), 1 << 20)?
            } else {
                Vec::new()
            };
            preview["added_lines"] = json!(line_delta(&previous, b));
            preview["removed_lines"] = json!(line_delta(b, &previous));
        }
        p.preview.push(preview);
        fs::atomic_write(&dir.join(name), b, &private_metadata())
    }
    pub(crate) fn load_plan(&self, id: &str) -> Result<(Plan, PathBuf)> {
        let dir = self.object("plans", id)?;
        let p: Plan = fs::read_json(&dir.join("plan.json"))?;
        let bad = || {
            Error::new(
                "E_FORMAT",
                "Unsupported, incomplete or corrupt configuration-set plan.",
            )
        };
        if p.schema != 1
            || p.id != id
            || !util::valid_time(&p.time)
            || !matches!(p.kind.as_str(), "apply" | "rollback")
            || p.active.len() != 3
            || p.intended.len() != 3
            || p.changes.is_empty()
        {
            return Err(bad());
        }
        if let Some(c) = &p.target_compaction
            && (p.kind != "apply"
                || c.entries_before > 1 << 20
                || c.removed_entries > c.entries_before
                || c.entries_after != c.entries_before - c.removed_entries
                || c.packages_before != c.entries_after)
        {
            return Err(bad());
        }
        let mut seen = BTreeSet::new();
        for n in &p.changes {
            if !FILES.contains(&n.as_str()) || !seen.insert(n) {
                return Err(bad());
            }
        }
        for name in FILES {
            let (old, next) = match (p.active.get(name), p.intended.get(name)) {
                (Some(o), Some(n)) => (o, n),
                _ => return Err(bad()),
            };
            if !self.valid_state(old)
                || !self.valid_state(next)
                || (old != next) != seen.contains(&name.to_owned())
            {
                return Err(bad());
            }
        }
        if p.kind == "apply"
            && seen.contains(&"keybox.xml".to_owned())
            && (p.inputs.is_empty() || p.selections.is_empty())
        {
            return Err(bad());
        }
        if p.inputs.iter().any(|s| !valid_stage(s, &s.id)) {
            return Err(bad());
        }
        Ok((p, dir))
    }
}
pub fn private_metadata() -> Metadata {
    Metadata {
        mode: 0o600,
        uid: util::owner_id(),
        gid: util::owner_id(),
        selinux: String::new(),
    }
}
pub fn valid_stage(s: &Stage, id: &str) -> bool {
    s.schema == 1
        && s.id == id
        && util::valid_id(id)
        && util::valid_hash(&s.sha256)
        && s.bytes > 0
        && s.bytes <= keybox::MAX_INPUT
        && util::valid_time(&s.time)
}
pub fn valid_boot(s: &str) -> bool {
    regex::Regex::new("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")
        .unwrap()
        .is_match(s)
}
pub fn valid_history(v: &Value) -> bool {
    v.as_object().is_some_and(|o| o.len() == 4)
        && v["id"].as_str().is_some_and(util::valid_id)
        && v["time"].as_str().is_some_and(util::valid_time)
        && matches!(
            v["type"].as_str(),
            Some(
                "ingest"
                    | "plan"
                    | "apply"
                    | "rollback"
                    | "recovery"
                    | "wallet-reset"
                    | "stack-resolve"
            )
        )
        && matches!(
            v["state"].as_str(),
            Some(
                "staged"
                    | "review"
                    | "committed-adoption-pending"
                    | "restored-after-failure"
                    | "restored"
                    | "awaiting-manual-reboot"
                    | "closed-incomplete"
                    | "superseded"
            )
        )
        && (v["state"] != "closed-incomplete" || v["type"] == "wallet-reset")
        && (v["state"] != "superseded" || v["type"] == "stack-resolve")
}
pub fn valid_patch(s: &str) -> bool {
    s.len() == 10
        && time::Date::parse(
            s,
            &time::macros::format_description!("[year]-[month]-[day]"),
        )
        .is_ok()
}
pub fn recovery_error() -> Error {
    Error::new(
        "E_RECOVERY",
        "An unfinished transaction must be restored through Recovery before another change.",
    )
}
pub const REQUIRED_PACKAGES: [&str; 4] = [
    "com.google.android.apps.walletnfcrel",
    "com.google.android.gms",
    "com.android.vending",
    "com.google.android.gsf",
];
pub fn repair_targets(b: &[u8]) -> Result<Vec<u8>> {
    let mut s = String::from_utf8(b.to_vec())
        .map_err(|_| Error::new("E_INPUT", "Target configuration must be UTF-8."))?;
    for pkg in REQUIRED_PACKAGES {
        let mut found = false;
        let mut lines: Vec<String> = s.split('\n').map(str::to_owned).collect();
        for line in &mut lines {
            let v = line.trim();
            if v.is_empty() || v.starts_with('#') || v.trim_end_matches(['!', '?']) != pkg {
                continue;
            }
            if found {
                return Err(Error::new(
                    "E_SELECTION",
                    "A required target has duplicate entries. Resolve its selection explicitly.",
                ));
            }
            found = true;
            if v != format!("{pkg}!") {
                if v != pkg {
                    return Err(Error::new(
                        "E_SELECTION",
                        "Conflicting target flags require explicit review.",
                    ));
                }
                *line = line.replacen(pkg, &format!("{pkg}!"), 1);
            }
        }
        s = lines.join("\n");
        if !found {
            if !s.is_empty() && !s.ends_with('\n') {
                s.push('\n');
            }
            s.push_str(&format!("{pkg}!\n"));
        }
    }
    Ok(s.into_bytes())
}
pub fn repair_patch(b: &[u8], patch: &str) -> Result<Vec<u8>> {
    let s = String::from_utf8(b.to_vec())
        .map_err(|_| Error::new("E_INPUT", "Patch configuration must be UTF-8."))?;
    let mut found = false;
    let mut lines = Vec::new();
    for l in s.split('\n') {
        let v = l.trim();
        if v.starts_with("all=") {
            if found {
                return Err(Error::new(
                    "E_SELECTION",
                    "Duplicate global patch settings require manual review.",
                ));
            }
            found = true;
            lines.push(format!("all={patch}"));
        } else if ["system=", "boot=", "vendor="]
            .iter()
            .any(|p| v.starts_with(p))
        {
            return Err(Error::new(
                "E_SELECTION",
                "Per-partition patch settings require a separate reviewed plan.",
            ));
        } else {
            lines.push(l.into());
        }
    }
    let mut s = lines.join("\n");
    if !found {
        if !s.is_empty() && !s.ends_with('\n') {
            s.push('\n');
        }
        s.push_str(&format!("all={patch}\n"));
    }
    Ok(s.into_bytes())
}
pub fn compact_targets(b: &[u8]) -> Result<(Vec<u8>, Compaction)> {
    let s = std::str::from_utf8(b)
        .map_err(|_| Error::new("E_INPUT", "Target compaction requires UTF-8."))?;
    if b.len() > 1 << 20 || s.contains('\0') {
        return Err(Error::new(
            "E_INPUT",
            "Target compaction requires a bounded target list without NUL bytes.",
        ));
    }
    let re =
        regex::Regex::new(r"^(android|[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+)$").unwrap();
    let mut modes = BTreeMap::new();
    let mut out = Vec::new();
    let mut c = Compaction::default();
    for line in s.split_inclusive('\n') {
        let content = line.trim_end_matches('\n').trim_end_matches('\r');
        if content.trim().is_empty() || content.starts_with('#') {
            out.extend_from_slice(line.as_bytes());
            continue;
        }
        let token = content.trim_matches([' ', '\t']);
        let (pkg, mode) = if token.ends_with(['!', '?']) {
            token.split_at(token.len() - 1)
        } else {
            (token, "")
        };
        if !re.is_match(pkg) {
            return Err(Error::new(
                "E_SELECTION",
                "Target compaction supports android or dotted package names with one optional trailing ! or ?. Unsupported syntax must be reviewed explicitly.",
            ));
        }
        c.entries_before += 1;
        if let Some(previous) = modes.get(pkg) {
            if previous != &mode {
                return Err(Error::new(
                    "E_SELECTION",
                    "A target package has conflicting modes. Compaction cannot choose a mode; review the entries explicitly.",
                ));
            }
            c.removed_entries += 1;
        } else {
            modes.insert(pkg, mode);
            out.extend_from_slice(line.as_bytes());
        }
    }
    c.packages_before = modes.len();
    c.entries_after = c.entries_before - c.removed_entries;
    Ok((out, c))
}
pub fn line_delta(from: &[u8], to: &[u8]) -> Vec<String> {
    let mut counts = BTreeMap::<&str, usize>::new();
    let a = String::from_utf8_lossy(from);
    let b = String::from_utf8_lossy(to);
    for l in a.split('\n') {
        *counts.entry(l).or_default() += 1;
    }
    let mut out = Vec::new();
    for l in b.split('\n') {
        if let Some(c) = counts.get_mut(l).filter(|c| **c > 0) {
            *c -= 1;
        } else if !l.is_empty() {
            out.push(l.into());
        }
    }
    out
}
