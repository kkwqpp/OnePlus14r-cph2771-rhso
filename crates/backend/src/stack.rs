//! Independently authored fixed-resource stack transactions. No protected-file
//! writes, process control, runtime-adoption claim, or payment approval claim.
use crate::App;
use crate::error::{Error, Result};
use crate::fs::{self as safe_fs, FileState, Metadata};
use crate::util::{hash, new_id, owner_id, valid_hash, valid_id};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json, value::RawValue};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const LIMIT: usize = 1 << 20;
const TARGETS: [&str; 4] = [
    "com.google.android.apps.walletnfcrel",
    "com.google.android.gms",
    "com.android.vending",
    "com.google.android.gsf",
];
const PROTECTED: [&str; 3] = ["keybox.xml", "security_patch.txt", "target.txt"];
const PROFILES: [&str; 2] = ["hma-scope", "brezygisk-unmount"];
pub const RESOLVE_PHRASE: &str = "KEEP CURRENT STACK FILE";
type RawObject = BTreeMap<String, Box<RawValue>>;
type States = BTreeMap<String, FileState>;
type Capabilities = BTreeMap<String, String>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: u32,
    id: String,
    time: String,
    profile: String,
    resource: String,
    locator: String,
    #[serde(deserialize_with = "nullable_list")]
    targets: Vec<String>,
    #[serde(deserialize_with = "nullable_list")]
    hide_packages: Vec<String>,
    enabled: bool,
    before: FileState,
    after: FileState,
    parent: Metadata,
    protected: States,
    capabilities: Capabilities,
    evidence_before: String,
    changes: Vec<Value>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: u32,
    id: String,
    profile: String,
    resource: String,
    locator: String,
    state: String,
    time: String,
    before: FileState,
    after: FileState,
    parent: Metadata,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    resolution_id: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Resolution {
    schema: u32,
    id: String,
    time: String,
    prior: Journal,
    current: FileState,
    parent: Metadata,
    review_hash: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StackBackup {
    schema: u32,
    id: String,
    resource: String,
    locator: String,
    time: String,
    before: FileState,
    parent: Metadata,
    protected_backup: String,
    protected: States,
}
fn error(code: &str, message: &str) -> Error {
    Error::new(code, message)
}
fn io<T>(result: std::io::Result<T>) -> Result<T> {
    result.map_err(|_| error("E_IO", "Private stack storage is unavailable."))
}
fn absent() -> FileState {
    FileState {
        exists: false,
        sha256: String::new(),
        size: 0,
        metadata: Metadata {
            mode: 0,
            uid: 0,
            gid: 0,
            selinux: String::new(),
        },
    }
}
fn private_metadata() -> Metadata {
    Metadata {
        mode: 0o600,
        uid: owner_id(),
        gid: owner_id(),
        selinux: String::new(),
    }
}
fn exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(error("E_IO", "Private stack storage is unavailable.")),
    }
}
fn resource(profile: &str) -> &str {
    match profile {
        "hma-scope" => "hma-config",
        "brezygisk-unmount" => "brezygisk-unmount",
        _ => "",
    }
}
fn backend_name(name: &str) -> bool {
    name.strip_prefix("hide_my_applist_")
        .map(|tail| tail.len() == 16 && tail.bytes().all(|b| b.is_ascii_lowercase()))
        .unwrap_or(false)
}
fn package(name: &str) -> bool {
    name.len() <= 255
        && name.contains('.')
        && name.split('.').all(|p| {
            let mut b = p.bytes();
            b.next().map(|x| x.is_ascii_alphabetic()).unwrap_or(false)
                && b.all(|x| x.is_ascii_alphanumeric() || x == b'_')
        })
}
fn context(label: &str) -> bool {
    let label = label.strip_suffix('\0').unwrap_or(label);
    let Some(rest) = label.strip_prefix("u:object_r:") else {
        return false;
    };
    let Some((kind, level)) = rest.split_once(":s0") else {
        return false;
    };
    !kind.is_empty()
        && kind.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && (level.is_empty()
            || level
                .strip_prefix(':')
                .map(|v| {
                    v.split(',').all(|c| {
                        c.strip_prefix('c')
                            .map(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false))
}
fn warnings() -> Vec<&'static str> {
    vec![
        "Manual reboot and fresh application checks are required for activation and rollback. File readback does not prove runtime adoption.",
        "Other root writers are outside the helper lock. Conflicts are preserved privately and require review.",
        "Root-stack configuration is not proof of hardware identity, integrity verdicts or Wallet acceptance.",
    ]
}
fn result(j: &Journal) -> Value {
    json!({"id":j.id,"profile":j.profile,"state":j.state,"private_backup":"verified","manual_reboot_required":true,"runtime_adoption":"unknown","readback_verified":true,"warnings":warnings()})
}
fn pins(profile: &str) -> &'static [(&'static str, &'static str)] {
    match profile {
        "hma-scope" => &[
            (
                "hma_oss_zygisk/classes.dex",
                "a23261736dad9c0110b2cd481e20cc2f4cd970121a8701571ff023ec296f3a27",
            ),
            (
                "hma_oss_zygisk/manager.apk",
                "e2f28be0689080ba205de90b9f9f2be13fbcd28b9938f2c52dbe766562a765ac",
            ),
            (
                "hma_oss_zygisk/zygisk/arm64-v8a.so",
                "dfa7bd47ed7a89610f93c7545999d8c1c998fd83b459ca0a8e84b708f192d7c1",
            ),
        ],
        "brezygisk-unmount" => &[
            (
                "rezygisk/bin/zygiskd64",
                "f28aeaaa6a61e282106a07a834ec83554f2d5601d34dc1039605f8da7ad9e196",
            ),
            (
                "rezygisk/bin/zygisk-ptrace64",
                "fd6e647a7dc5c7593082843aeab49af589b3be9f712c826906a4e0c48c1259ae",
            ),
            (
                "rezygisk/lib64/libzygisk.so",
                "94819756ff8d2ea51e4368ff3b90dac99f7e16fd92da8fa52f85f6108d72b895",
            ),
        ],
        _ => &[],
    }
}

// Scan duplicate members before serde can replace them. Exact-key mode retains
// unknown HMA fields, while private typed metadata rejects case-fold aliases.
struct Scanner<'a> {
    bytes: &'a [u8],
    pos: usize,
    nodes: usize,
    fold: bool,
}
impl Scanner<'_> {
    fn fail<T>(&self) -> Result<T> {
        Err(error("E_FORMAT", "Stack JSON is ambiguous or unsupported."))
    }
    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.pos)
            .map(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
            .unwrap_or(false)
        {
            self.pos += 1;
        }
    }
    fn take(&mut self, ch: u8) -> bool {
        self.whitespace();
        if self.bytes.get(self.pos) == Some(&ch) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn string(&mut self) -> Result<String> {
        self.whitespace();
        let start = self.pos;
        if self.bytes.get(self.pos) != Some(&b'"') {
            return self.fail();
        }
        self.pos += 1;
        while let Some(&b) = self.bytes.get(self.pos) {
            self.pos += 1;
            if b == b'\\' {
                if self.pos >= self.bytes.len() {
                    return self.fail();
                }
                self.pos += 1;
            } else if b == b'"' {
                return serde_json::from_slice(&self.bytes[start..self.pos])
                    .map_err(|_| error("E_FORMAT", "Stack JSON is ambiguous or unsupported."));
            } else if b < 32 {
                return self.fail();
            }
        }
        self.fail()
    }
    fn value(&mut self, depth: usize) -> Result<()> {
        self.nodes += 1;
        if depth > 32 || self.nodes > 200_000 {
            return self.fail();
        }
        self.whitespace();
        match self.bytes.get(self.pos).copied() {
            Some(b'{') => {
                self.pos += 1;
                let mut keys = BTreeSet::new();
                if self.take(b'}') {
                    return Ok(());
                }
                loop {
                    let key = self.string()?;
                    let key = if self.fold { key.to_lowercase() } else { key };
                    if !keys.insert(key) || !self.take(b':') {
                        return self.fail();
                    }
                    self.value(depth + 1)?;
                    if self.take(b'}') {
                        break;
                    }
                    if !self.take(b',') {
                        return self.fail();
                    }
                }
            }
            Some(b'[') => {
                self.pos += 1;
                if self.take(b']') {
                    return Ok(());
                }
                loop {
                    self.value(depth + 1)?;
                    if self.take(b']') {
                        break;
                    }
                    if !self.take(b',') {
                        return self.fail();
                    }
                }
            }
            Some(b'"') => {
                self.string()?;
            }
            Some(_) => {
                let start = self.pos;
                while self
                    .bytes
                    .get(self.pos)
                    .map(|b| !matches!(b, b' ' | b'\n' | b'\r' | b'\t' | b',' | b']' | b'}'))
                    .unwrap_or(false)
                {
                    self.pos += 1;
                }
                if start == self.pos {
                    return self.fail();
                }
            }
            None => return self.fail(),
        }
        Ok(())
    }
}
fn parse<T: DeserializeOwned>(body: &[u8], fold: bool) -> Result<T> {
    if body.is_empty() || body.len() > LIMIT || std::str::from_utf8(body).is_err() {
        return Err(error("E_FORMAT", "Stack JSON is ambiguous or unsupported."));
    }
    let mut s = Scanner {
        bytes: body,
        pos: 0,
        nodes: 0,
        fold,
    };
    s.value(0)?;
    s.whitespace();
    if s.pos != body.len() {
        return Err(error("E_FORMAT", "Stack JSON is ambiguous or unsupported."));
    }
    serde_json::from_slice(body)
        .map_err(|_| error("E_FORMAT", "Stack JSON is ambiguous or unsupported."))
}
fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    parse(&safe_fs::bounded(path, LIMIT)?, true)
}
fn raw<T: Serialize>(value: &T) -> Result<Box<RawValue>> {
    serde_json::value::to_raw_value(value)
        .map_err(|_| error("E_FORMAT", "Stack JSON is ambiguous or unsupported."))
}
fn list(input: &str, scopes: bool) -> Result<Vec<String>> {
    if input.is_empty() || input.len() > 16384 {
        return Err(error(
            "E_SELECTION",
            "Select an explicit bounded package list.",
        ));
    }
    let mut out = BTreeSet::new();
    for name in input.split(',').map(str::trim) {
        if !package(name) || !out.insert(name.to_string()) {
            return Err(error(
                "E_SELECTION",
                "Package selections must be valid and unique.",
            ));
        }
        if scopes && !TARGETS.contains(&name) {
            return Err(error(
                "E_SELECTION",
                "Only the four supported Google scopes may be selected.",
            ));
        }
    }
    if out.len() > if scopes { 4 } else { 32 } {
        return Err(error(
            "E_SELECTION",
            "Select at most four Google scopes and 32 packages.",
        ));
    }
    Ok(out.into_iter().collect())
}
fn forbidden(name: &str) -> bool {
    TARGETS.contains(&name)
        || [
            "android",
            "android.media",
            "android.uid.system",
            "android.uid.shell",
            "android.uid.systemui",
            "com.android.permissioncontroller",
            "com.android.providers.downloads",
            "com.android.providers.downloads.ui",
            "com.android.providers.media",
            "com.android.providers.media.module",
            "com.android.providers.settings",
            "com.google.android.providers.media.module",
            "com.google.android.permissioncontroller",
            "com.miui.securitycenter",
            "com.android.settings",
            "com.android.systemui",
            "org.frknkrc44.hma_oss",
            "com.tsng.hidemyapplist",
            "io.github.a13e300.ksuwebui",
        ]
        .contains(&name)
}
fn app_list(obj: &RawObject, key: &str) -> Result<Vec<String>> {
    let Some(value) = obj.get(key) else {
        return Ok(Vec::new());
    };
    let out: Vec<String> = serde_json::from_str(value.get())
        .map_err(|_| error("E_FORMAT", "A selected HMA package set is unsupported."))?;
    let mut seen = BTreeSet::new();
    if out.len() > 4096 || out.iter().any(|n| !package(n) || !seen.insert(n)) {
        return Err(error(
            "E_FORMAT",
            "A selected HMA package set is ambiguous.",
        ));
    }
    Ok(out)
}
fn blacklist(obj: &RawObject) -> Result<()> {
    if let Some(value) = obj.get("useWhitelist") {
        match value.get().trim() {
            "false" => (),
            "true" => {
                return Err(error(
                    "E_SELECTION",
                    "Whitelist scopes require separate review; this profile only adds blacklist entries.",
                ));
            }
            _ => {
                return Err(error(
                    "E_FORMAT",
                    "A selected HMA whitelist field is not a boolean.",
                ));
            }
        }
    }
    Ok(())
}
fn schema(body: &[u8]) -> Result<RawObject> {
    let obj: RawObject = parse(body, false)?;
    if obj.get("configVersion").map(|v| v.get().trim()) != Some("93") {
        return Err(error(
            "E_CAPABILITY",
            "Only the inspected HMA configuration schema 93 is supported.",
        ));
    }
    Ok(obj)
}
fn hma(body: &[u8], targets: &[String], hide: &[String]) -> Result<(Vec<u8>, Vec<Value>)> {
    let mut root = schema(body)?;
    let mut scope: RawObject = root
        .get("scope")
        .and_then(|v| serde_json::from_str(v.get()).ok())
        .ok_or_else(|| error("E_FORMAT", "HMA scope configuration is unsupported."))?;
    let defaults: Option<RawObject> = match root.get("defaultConfig") {
        None => None,
        Some(v) if v.get().trim() == "null" => None,
        Some(v) => Some(
            serde_json::from_str(v.get())
                .map_err(|_| error("E_FORMAT", "HMA default configuration is unsupported."))?,
        ),
    };
    if let Some(ref defaults) = defaults {
        blacklist(defaults)?;
    }
    let mut changes = Vec::new();
    for target in targets {
        let (mut obj, created): (RawObject, u32) = match scope.get(target) {
            Some(v) => (
                serde_json::from_str(v.get())
                    .map_err(|_| error("E_FORMAT", "A selected HMA scope is unsupported."))?,
                0,
            ),
            None => (
                defaults.clone().unwrap_or_else(|| {
                    BTreeMap::from([(
                        "useWhitelist".to_string(),
                        RawValue::from_string("false".to_string()).expect("fixed valid JSON"),
                    )])
                }),
                1,
            ),
        };
        blacklist(&obj)?;
        let mut existing = app_list(&obj, "extraAppList")?;
        let opposite = app_list(&obj, "extraOppositeAppList")?;
        let mut seen: BTreeSet<String> = existing.iter().cloned().collect();
        let mut added = 0;
        for name in hide {
            if opposite.contains(name) {
                return Err(error(
                    "E_SELECTION",
                    "A selected package conflicts with the scope's opposite list.",
                ));
            }
            if seen.insert(name.clone()) {
                existing.push(name.clone());
                added += 1;
            }
        }
        if added == 0 {
            continue;
        }
        obj.insert("extraAppList".into(), raw(&existing)?);
        scope.insert(target.clone(), raw(&obj)?);
        changes.push(json!({"target":target,"added_count":added,"scopes_created":created}));
    }
    if changes.is_empty() {
        return Err(error(
            "E_SELECTION",
            "The selected stack profile has no configuration change.",
        ));
    }
    root.insert("scope".into(), raw(&scope)?);
    let mut out = serde_json::to_vec_pretty(&root)
        .map_err(|_| error("E_FORMAT", "Stack JSON is ambiguous or unsupported."))?;
    out.push(b'\n');
    if out.len() > LIMIT {
        return Err(error(
            "E_FORMAT",
            "The proposed HMA configuration exceeds its supported bound.",
        ));
    }
    Ok((out, changes))
}

fn timestamp(value: &str) -> Result<i64> {
    crate::util::parse_time(value)
}
fn nullable_list<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<String>, D::Error> {
    Ok(Option::<Vec<String>>::deserialize(d)?.unwrap_or_default())
}
impl Plan {
    fn view(&self) -> Value {
        json!({"id":self.id,"profile":self.profile,"resource":self.resource,"changes":self.changes,"manual_reboot_required":true,"runtime_adoption":"unknown","private_backup":"created-on-apply","warnings":warnings()})
    }
    fn journal(&self, state: &str) -> Journal {
        Journal {
            schema: self.schema,
            id: self.id.clone(),
            profile: self.profile.clone(),
            resource: self.resource.clone(),
            locator: self.locator.clone(),
            state: state.into(),
            time: self.time.clone(),
            before: self.before.clone(),
            after: self.after.clone(),
            parent: self.parent.clone(),
            resolution_id: String::new(),
        }
    }
}
impl App {
    fn stack_base(&self) -> PathBuf {
        if self.fake {
            self.active
                .parent()
                .unwrap_or(&self.active)
                .join("stack-system/data")
        } else {
            PathBuf::from("/data")
        }
    }
    fn stack_dir(&self) -> PathBuf {
        self.root.join("stack")
    }
    fn stack_init(&self) -> Result<()> {
        for path in [
            self.stack_dir(),
            self.stack_dir().join("plans"),
            self.stack_dir().join("backups"),
        ] {
            safe_fs::no_links(&path)?;
            io(std::fs::create_dir_all(&path))?;
            safe_fs::set_metadata(
                &path,
                &Metadata {
                    mode: 0o700,
                    ..private_metadata()
                },
            )?;
            safe_fs::sync_dir(&path)?;
            safe_fs::sync_dir(
                path.parent()
                    .ok_or_else(|| error("E_PATH", "Private stack parent is unavailable."))?,
            )?;
        }
        Ok(())
    }
    fn stack_object(&self, kind: &str, id: &str) -> Result<PathBuf> {
        if !["plans", "backups"].contains(&kind) || !valid_id(id) {
            return Err(error("E_ID", "Choose a valid stack plan ID."));
        }
        let path = self.stack_dir().join(kind).join(id);
        safe_fs::no_links(&path)?;
        Ok(path)
    }
    fn stack_path(&self, resource: &str, locator: &str) -> Result<(PathBuf, String)> {
        let base = self.stack_base();
        safe_fs::no_links(&base)?;
        match resource {
            "hma-config" => {
                let parent = base.join("misc");
                safe_fs::no_links(&parent)?;
                let entries = std::fs::read_dir(&parent).map_err(|_| {
                    error("E_CAPABILITY", "The supported HMA resource is unavailable.")
                })?;
                let mut names = Vec::new();
                for entry in entries {
                    let entry = io(entry)?;
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if backend_name(&name) {
                        let kind = io(entry.file_type())?;
                        if kind.is_symlink() || !kind.is_dir() {
                            return Err(error("E_PATH", "The supported HMA backend is unsafe."));
                        }
                        names.push(name);
                    }
                }
                if names.len() != 1 {
                    return Err(error(
                        "E_CAPABILITY",
                        "Exactly one supported HMA backend directory is required.",
                    ));
                }
                let name = names.remove(0);
                if !locator.is_empty() && name != locator {
                    return Err(error(
                        "E_STALE",
                        "The HMA backend location changed. Create a new review.",
                    ));
                }
                let path = parent.join(&name).join("config.json");
                safe_fs::no_links(&path)?;
                Ok((path, name))
            }
            "brezygisk-unmount" => {
                if !locator.is_empty() {
                    return Err(error(
                        "E_FORMAT",
                        "The marker resource contains an unsupported locator.",
                    ));
                }
                let path = base.join("adb/brezygisk/unmount");
                safe_fs::no_links(&path)?;
                Ok((path, String::new()))
            }
            _ => Err(error("E_REQUEST", "Choose a supported stack profile.")),
        }
    }
    fn stack_read(
        &self,
        resource: &str,
        locator: &str,
    ) -> Result<(FileState, Vec<u8>, Metadata, String)> {
        let (path, locator) = self.stack_path(resource, locator)?;
        let parent = safe_fs::metadata(
            path.parent()
                .ok_or_else(|| error("E_PATH", "Stack parent is unavailable."))?,
        )
        .map_err(|_| error("E_CAPABILITY", "The stack resource parent is unavailable."))?;
        let expected_owner = if resource == "hma-config" { 1000 } else { 0 };
        if !self.fake
            && (parent.uid != expected_owner
                || parent.gid != expected_owner
                || parent.mode & 0o077 != 0
                || parent.selinux.is_empty())
        {
            return Err(error(
                "E_CAPABILITY",
                "Stack resource parent ownership and access are not verified.",
            ));
        }
        if !exists(&path)? && resource == "brezygisk-unmount" {
            return Ok((absent(), Vec::new(), parent, locator));
        }
        let body = safe_fs::bounded(&path, LIMIT)?;
        let metadata = safe_fs::metadata(&path)?;
        let state = FileState {
            exists: true,
            sha256: hash(&body),
            size: body.len() as i64,
            metadata,
        };
        if !self.valid_state(&state) {
            return Err(error(
                "E_CAPABILITY",
                "Stack resource metadata is unsupported.",
            ));
        }
        if !self.fake
            && (state.metadata.uid != expected_owner
                || state.metadata.gid != expected_owner
                || (resource == "hma-config" && state.metadata.mode != 0o600)
                || state.metadata.selinux.is_empty())
        {
            return Err(error(
                "E_CAPABILITY",
                "Stack resource ownership, permissions or SELinux metadata are not verified.",
            ));
        }
        Ok((state, body, parent, locator))
    }
    fn stack_code(&self, profile: &str) -> Result<Capabilities> {
        if resource(profile).is_empty() {
            return Err(error("E_REQUEST", "Choose a supported stack profile."));
        }
        if self.fake {
            return Ok(BTreeMap::from([(
                "stack-code-mode".into(),
                "synthetic".into(),
            )]));
        }
        let mut out = BTreeMap::new();
        for &(relative, want) in pins(profile) {
            let body = safe_fs::bounded(&self.modules.join(relative), 32 << 20).map_err(|_| {
                error(
                    "E_CAPABILITY",
                    "The installed stack programs do not match the inspected version.",
                )
            })?;
            if hash(&body) != want {
                return Err(error(
                    "E_CAPABILITY",
                    "The installed stack programs do not match the inspected version.",
                ));
            }
            out.insert(relative.into(), want.into());
        }
        let module = if profile == "hma-scope" {
            "hma_oss_zygisk"
        } else {
            "rezygisk"
        };
        for marker in ["disable", "remove"] {
            if exists(&self.modules.join(module).join(marker))? {
                return Err(error(
                    "E_CAPABILITY",
                    "The selected stack module is disabled or pending removal.",
                ));
            }
        }
        Ok(out)
    }
    fn stack_capabilities(&self, profile: &str) -> Result<Capabilities> {
        let mut out = self.capabilities()?;
        out.remove("stack_evidence_binding");
        out.extend(self.stack_code(profile)?);
        out.insert(
            "other_stack_evidence".into(),
            self.stack_evidence_except(resource(profile))?,
        );
        out.insert(
            "pif_hash".into(),
            hash(&safe_fs::bounded(
                &self.modules.join("playintegrityfix/custom.pif.prop"),
                64 << 10,
            )?),
        );
        let mut states = Vec::new();
        for entry in io(std::fs::read_dir(&self.modules))? {
            let entry = io(entry)?;
            if !io(entry.file_type())?.is_dir() {
                continue;
            }
            let path = entry.path();
            safe_fs::no_links(&path)?;
            let prop = path.join("module.prop");
            safe_fs::no_links(&prop)?;
            let body = if exists(&prop)? {
                safe_fs::bounded(&prop, 64 << 10)?
            } else {
                Vec::new()
            };
            let mut state = format!("{}:{}", entry.file_name().to_string_lossy(), hash(&body));
            for marker in ["disable", "remove"] {
                let p = path.join(marker);
                safe_fs::no_links(&p)?;
                if exists(&p)? {
                    state.push(':');
                    state.push_str(marker);
                }
            }
            states.push(state);
        }
        states.sort();
        out.insert(
            "module_state_hash".into(),
            hash(states.join("\n").as_bytes()),
        );
        out.insert("boot".into(), "offline".into());
        out.insert("user".into(), "0".into());
        if !self.fake {
            let boot = crate::util::boot_id();
            if boot.len() != 36
                || !boot.bytes().enumerate().all(|(i, b)| {
                    if [8, 13, 18, 23].contains(&i) {
                        b == b'-'
                    } else {
                        b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                    }
                })
            {
                return Err(error(
                    "E_CAPABILITY",
                    "Current boot identity is unavailable.",
                ));
            }
            if crate::inspect::run("/system/bin/am", &["get-current-user"])?.trim() != "0" {
                return Err(error(
                    "E_CAPABILITY",
                    "Only the verified owner user is supported for stack changes.",
                ));
            }
            out.insert("boot".into(), boot);
        }
        Ok(out)
    }
    fn stack_installed(&self, targets: &[String], packages: &[String]) -> Result<()> {
        if self.fake {
            return Ok(());
        }
        let out = crate::inspect::run("/system/bin/pm", &["list", "packages", "--user", "0"])
            .map_err(|_| {
                error(
                    "E_CAPABILITY",
                    "Installed package availability could not be verified.",
                )
            })?;
        let installed: BTreeSet<&str> = out
            .lines()
            .filter_map(|line| line.trim().strip_prefix("package:"))
            .collect();
        if targets
            .iter()
            .chain(packages)
            .any(|p| !installed.contains(p.as_str()))
        {
            return Err(error(
                "E_SELECTION",
                "A selected scope or hide package is unavailable for the owner user.",
            ));
        }
        Ok(())
    }
    pub(crate) fn stack_evidence_binding(&self) -> Result<String> {
        self.stack_evidence_except("")
    }
    fn stack_evidence_except(&self, exclude: &str) -> Result<String> {
        let mut out = BTreeMap::<String, Value>::new();
        let path = self.modules.join("playintegrityfix/custom.pif.prop");
        safe_fs::no_links(&path)
            .map_err(|_| error("E_CAPABILITY", "PIF evidence is unsafe or unavailable."))?;
        let pif = if exists(&path)? {
            let body = safe_fs::bounded(&path, 64 << 10)
                .map_err(|_| error("E_CAPABILITY", "PIF evidence is unsafe or unavailable."))?;
            let st = FileState {
                exists: true,
                sha256: hash(&body),
                size: body.len() as i64,
                metadata: safe_fs::metadata(&path)?,
            };
            if !self.valid_state(&st) {
                return Err(error("E_CAPABILITY", "PIF metadata is unsupported."));
            }
            st
        } else {
            absent()
        };
        out.insert("pif".into(), json!(pif));
        for profile in PROFILES {
            let res = resource(profile);
            let mut code = BTreeMap::new();
            for &(relative, _) in pins(profile) {
                let path = self.modules.join(relative);
                safe_fs::no_links(&path).map_err(|_| {
                    error(
                        "E_CAPABILITY",
                        "Stack program evidence is unsafe or unavailable.",
                    )
                })?;
                code.insert(
                    relative,
                    if exists(&path)? {
                        hash(&safe_fs::bounded(&path, 32 << 20).map_err(|_| {
                            error(
                                "E_CAPABILITY",
                                "Stack program evidence is unsafe or unavailable.",
                            )
                        })?)
                    } else {
                        "absent".into()
                    },
                );
            }
            match self.stack_read(res, "") {
                Ok((file, body, parent, locator)) => {
                    if res == "hma-config" {
                        schema(&body).map_err(|_| {
                            error(
                                "E_CAPABILITY",
                                "HMA evidence has unsupported configuration structure.",
                            )
                        })?;
                    }
                    out.insert(
                        res.into(),
                        if res == exclude {
                            json!({"parent":parent,"locator":locator,"code":code})
                        } else {
                            json!({"file":file,"parent":parent,"locator":locator,"code":code})
                        },
                    );
                }
                Err(_) => {
                    let path = if res == "hma-config" {
                        self.stack_base().join("misc")
                    } else {
                        self.stack_base().join("adb/brezygisk")
                    };
                    safe_fs::no_links(&path)
                        .map_err(|_| error("E_CAPABILITY", "Stack resource evidence is unsafe."))?;
                    let mut is_absent = !exists(&path)?;
                    if res == "hma-config"
                        && !is_absent
                        && let Ok(entries) = std::fs::read_dir(&path)
                    {
                        is_absent = true;
                        for entry in entries {
                            let entry = io(entry)?;
                            if backend_name(&entry.file_name().to_string_lossy()) {
                                is_absent = false;
                            }
                        }
                    }
                    if !is_absent {
                        return Err(error(
                            "E_CAPABILITY",
                            "Stack resource evidence is ambiguous or unavailable.",
                        ));
                    }
                    out.insert(res.into(), json!({"state":"absent","code":code}));
                }
            }
        }
        Ok(hash(&serde_json::to_vec(&out).map_err(|_| {
            error("E_FORMAT", "Stack evidence is unavailable.")
        })?))
    }
    fn valid_stack_original(&self, state: &FileState, resource: &str) -> bool {
        if !self.valid_state(state) {
            return false;
        }
        if !state.exists {
            return resource == "brezygisk-unmount";
        }
        if resource == "hma-config" && state.metadata.mode != 0o600 {
            return false;
        }
        let owner = if self.fake {
            owner_id()
        } else if resource == "hma-config" {
            1000
        } else {
            0
        };
        state.metadata.uid == owner
            && state.metadata.gid == owner
            && (self.fake || !state.metadata.selinux.is_empty())
    }
    fn valid_stack_parent(&self, meta: &Metadata, resource: &str) -> bool {
        if meta.mode != 0o700
            || meta.selinux.len() > 256
            || (!meta.selinux.is_empty() && !context(&meta.selinux))
        {
            return false;
        }
        let owner = if self.fake {
            owner_id()
        } else if resource == "hma-config" {
            1000
        } else {
            0
        };
        meta.uid == owner && meta.gid == owner && (self.fake || !meta.selinux.is_empty())
    }
    fn stack_resolution_read(&self, j: &Journal) -> Result<(FileState, Vec<u8>, Metadata)> {
        let (path, _) = self.stack_path(&j.resource, &j.locator)?;
        let parent = safe_fs::metadata(
            path.parent()
                .ok_or_else(|| error("E_PATH", "Stack parent is unavailable."))?,
        )?;
        if !self.valid_stack_parent(&parent, &j.resource) {
            return Err(error(
                "E_CAPABILITY",
                "Current stack parent metadata is unsupported.",
            ));
        }
        if !exists(&path)? {
            return Ok((absent(), Vec::new(), parent));
        }
        let (current, body, read_parent, _) = self.stack_read(&j.resource, &j.locator)?;
        if read_parent != parent {
            return Err(error(
                "E_STALE",
                "Stack parent changed during closure review.",
            ));
        }
        Ok((current, body, parent))
    }
    fn stack_resolution_hash(
        j: &Journal,
        current: &FileState,
        parent: &Metadata,
    ) -> Result<String> {
        Ok(hash(
            &serde_json::to_vec(&json!({"journal":j,"current":current,"parent":parent}))
                .map_err(|_| error("E_FORMAT", "Stack closure review is unavailable."))?,
        ))
    }
    fn stack_resolution_review(&self, j: &Journal) -> Result<Resolution> {
        if ["restored", "superseded"].contains(&j.state.as_str()) {
            return Err(error(
                "E_RECOVERY",
                "This Stack transaction is already terminal.",
            ));
        }
        let (current, _, parent) = self.stack_resolution_read(j)?;
        Ok(Resolution {
            schema: 1,
            id: String::new(),
            time: self.time(),
            prior: j.clone(),
            review_hash: Self::stack_resolution_hash(j, &current, &parent)?,
            current,
            parent,
        })
    }
    fn stack_resolution_path(&self, j: &Journal, suffix: &str) -> Result<PathBuf> {
        if !valid_id(&j.resolution_id) || !["json", "bin"].contains(&suffix) {
            return Err(error(
                "E_RECOVERY",
                "Stack closure evidence binding is invalid.",
            ));
        }
        Ok(self
            .stack_object("backups", &j.id)?
            .join(format!("resolution-{}.{}", j.resolution_id, suffix)))
    }
    fn stack_load_resolution(&self, j: &Journal) -> Result<Resolution> {
        let r: Resolution = read(&self.stack_resolution_path(j, "json")?).map_err(|_| {
            error(
                "E_RECOVERY",
                "Stack closure evidence is unreadable. Preserve the private ledger.",
            )
        })?;
        if r.schema != 1
            || r.id != j.resolution_id
            || timestamp(&r.time).is_err()
            || ["restored", "superseded"].contains(&r.prior.state.as_str())
            || !r.prior.resolution_id.is_empty()
            || self.validate_stack_journal(&r.prior).is_err()
            || !self.valid_state(&r.current)
            || (r.current.exists && !self.valid_stack_original(&r.current, &j.resource))
            || !self.valid_stack_parent(&r.parent, &j.resource)
            || !valid_hash(&r.review_hash)
            || Self::stack_resolution_hash(&r.prior, &r.current, &r.parent)? != r.review_hash
        {
            return Err(error(
                "E_RECOVERY",
                "Stack closure evidence is corrupt or unsupported.",
            ));
        }
        let mut terminal = r.prior.clone();
        terminal.state = "superseded".into();
        terminal.resolution_id = r.id.clone();
        if &terminal != j {
            return Err(error(
                "E_RECOVERY",
                "Stack closure evidence does not match the terminal journal.",
            ));
        }
        let body_path = self.stack_resolution_path(j, "bin")?;
        safe_fs::no_links(&body_path)?;
        if r.current.exists {
            let body = safe_fs::bounded(&body_path, LIMIT)?;
            if hash(&body) != r.current.sha256 || body.len() as i64 != r.current.size {
                return Err(error(
                    "E_RECOVERY",
                    "Preserved Stack closure bytes failed verification.",
                ));
            }
        } else if exists(&body_path)? {
            return Err(error(
                "E_RECOVERY",
                "Absent Stack closure evidence contains unexpected bytes.",
            ));
        }
        Ok(r)
    }
    fn stack_resolution_result(&self, j: &Journal) -> Result<Value> {
        self.stack_load_resolution(j)?;
        Ok(
            json!({"id":j.id,"profile":j.profile,"state":"superseded","evidence_preserved":true,"active_resource_written":false,"original_backup_available":self.stack_load_backup(&j.id).is_ok(),"manual_reboot_required":false,"runtime_adoption":"unknown","warnings":["The current Stack file was kept. Closure does not restore configuration or establish runtime adoption or Wallet approval."]}),
        )
    }
    fn stack_resolve(&self, id: &str, confirmation: &str, submitted: &str) -> Result<Value> {
        if confirmation != RESOLVE_PHRASE {
            return Err(error(
                "E_CONFIRM",
                "Stack closure requires the exact KEEP CURRENT STACK FILE phrase and a current reviewed readback.",
            ));
        }
        if !valid_id(id) || !valid_hash(submitted) {
            return Err(error(
                "E_REQUEST",
                "Choose the current Stack operation ID and its closure review hash.",
            ));
        }
        let path = self.root.join("stack-journal.json");
        let mut j: Journal = read(&path).map_err(|_| {
            error(
                "E_RECOVERY",
                "The Stack journal is unreadable. Preserve it for inspection.",
            )
        })?;
        self.validate_stack_journal(&j)?;
        if j.id != id {
            return Err(error(
                "E_STALE",
                "The current Stack operation changed. Review closure again.",
            ));
        }
        if j.state == "superseded" {
            let r = self.stack_load_resolution(&j)?;
            let (current, _, parent) = self.stack_resolution_read(&j)?;
            if r.review_hash != submitted || current != r.current || parent != r.parent {
                return Err(error(
                    "E_STALE",
                    "Current Stack evidence changed after closure. No file was written.",
                ));
            }
            self.closure_history("stack-resolve", id, "superseded")?;
            return self.stack_resolution_result(&j);
        }
        let mut r = self.stack_resolution_review(&j)?;
        if r.review_hash != submitted {
            return Err(error(
                "E_STALE",
                "Stack closure review changed. Read current status again; no file was written.",
            ));
        }
        self.checkpoint("stack-before-resolve-evidence")?;
        let (current, body, parent) = self.stack_resolution_read(&j)?;
        let fresh: Journal = read(&path)?;
        if fresh != j || current != r.current || parent != r.parent {
            return Err(error(
                "E_STALE",
                "Stack closure evidence changed before preservation. No file was written.",
            ));
        }
        r.id = new_id()?;
        j.state = "superseded".into();
        j.resolution_id = r.id.clone();
        self.stack_init()?;
        let dir = self.stack_object("backups", id)?;
        safe_fs::private_dir(&dir)?;
        safe_fs::sync_dir(
            dir.parent()
                .ok_or_else(|| error("E_PATH", "Stack evidence parent is unavailable."))?,
        )?;
        if current.exists {
            safe_fs::atomic_write(
                &self.stack_resolution_path(&j, "bin")?,
                &body,
                &private_metadata(),
            )?;
        }
        safe_fs::write_json(&self.stack_resolution_path(&j, "json")?, &r)?;
        safe_fs::sync_dir(&dir)?;
        self.stack_load_resolution(&j)?;
        self.checkpoint("stack-before-resolve-commit")?;
        let (current, _, parent) = self.stack_resolution_read(&j)?;
        let fresh: Journal = read(&path)?;
        if fresh != r.prior || current != r.current || parent != r.parent {
            return Err(error(
                "E_STALE",
                "Stack closure evidence changed before recording. No file was written.",
            ));
        }
        self.stack_load_resolution(&j)?;
        self.closure_history_check()?;
        safe_fs::write_json(&path, &j)?;
        self.checkpoint("stack-after-resolve-commit")?;
        self.closure_history("stack-resolve", id, "superseded")?;
        let fresh: Journal = read(&path)?;
        let (current, _, parent) = self.stack_resolution_read(&j)?;
        if fresh != j || current != r.current || parent != r.parent {
            return Err(error(
                "E_STALE",
                "Stack evidence changed after closure was recorded. No active file was written; inspect fresh status.",
            ));
        }
        self.stack_resolution_result(&j)
    }
    fn validate_stack_journal(&self, j: &Journal) -> Result<()> {
        if j.schema != 1
            || !valid_id(&j.id)
            || resource(&j.profile) != j.resource
            || j.resource.is_empty()
            || !self.valid_state(&j.before)
            || !self.valid_state(&j.after)
            || j.before == j.after
            || timestamp(&j.time).is_err()
            || !self.valid_stack_parent(&j.parent, &j.resource)
            || !self.valid_stack_original(&j.before, &j.resource)
        {
            return Err(error(
                "E_RECOVERY",
                "Stack journal is corrupt or unsupported. Preserve private recovery evidence.",
            ));
        }
        if j.resource == "hma-config"
            && (!j.after.exists
                || j.after.metadata != j.before.metadata
                || !backend_name(&j.locator))
        {
            return Err(error(
                "E_RECOVERY",
                "HMA journal transition is unsupported.",
            ));
        }
        if j.resource == "brezygisk-unmount" {
            if !j.locator.is_empty() {
                return Err(error(
                    "E_RECOVERY",
                    "Stack journal resource binding is unsupported.",
                ));
            }
            if j.after.exists {
                let wanted = Metadata {
                    selinux: j.parent.selinux.clone(),
                    ..private_metadata()
                };
                if j.before.exists
                    || j.after.size != 0
                    || j.after.sha256 != hash(&[])
                    || j.after.metadata != wanted
                {
                    return Err(error(
                        "E_RECOVERY",
                        "Marker journal transition is unsupported.",
                    ));
                }
            } else if !j.before.exists {
                return Err(error(
                    "E_RECOVERY",
                    "Marker journal transition is unsupported.",
                ));
            }
        }
        if ![
            "applying",
            "writing",
            "committed",
            "restoring",
            "restored",
            "recovery-required",
            "superseded",
        ]
        .contains(&j.state.as_str())
        {
            return Err(error("E_RECOVERY", "Stack journal state is unsupported."));
        }
        if j.state == "superseded" {
            self.stack_load_resolution(j)?;
        } else if !j.resolution_id.is_empty() {
            return Err(error(
                "E_RECOVERY",
                "Stack journal resolution binding is unsupported.",
            ));
        }
        Ok(())
    }
    pub(crate) fn stack_unfinished(&self) -> bool {
        let path = self.root.join("stack-journal.json");
        if matches!(exists(&path), Ok(false)) {
            return false;
        }
        match read::<Journal>(&path) {
            Ok(j) => {
                self.validate_stack_journal(&j).is_err()
                    || !["committed", "restored", "superseded"].contains(&j.state.as_str())
            }
            Err(_) => true,
        }
    }
    pub(crate) fn stack_status(&self) -> Value {
        let pending = self.stack_unfinished() || self.require_foreign_recovered().is_err();
        let mut profiles = Vec::new();
        for profile in PROFILES {
            let (code, reason) = if pending {
                (
                    "recovery_pending",
                    "Recovery is required before another change.",
                )
            } else if self.stack_code(profile).is_err() {
                (
                    "unsupported_capability",
                    "The installed stack program is unsupported or unavailable.",
                )
            } else {
                match self.stack_read(resource(profile), "") {
                    Err(_) => (
                        "resource_unavailable",
                        "The supported stack resource is unavailable or unsafe.",
                    ),
                    Ok((_, body, _, _)) if profile == "hma-scope" && schema(&body).is_err() => (
                        "unsupported_configuration",
                        "The supported configuration schema could not be verified.",
                    ),
                    _ => ("available", "Available for explicit planning."),
                }
            };
            profiles.push(json!({"id":profile,"resource":resource(profile),"available":code=="available","reason_code":code,"reason":reason}));
        }
        let path = self.root.join("stack-journal.json");
        let operation = match read::<Journal>(&path) {
            Ok(j) if self.validate_stack_journal(&j).is_ok() => {
                let backup = self.stack_load_backup(&j.id).is_ok();
                let review = self.stack_resolution_review(&j).ok();
                let can_resolve =
                    !["restored", "superseded"].contains(&j.state.as_str()) && review.is_some();
                json!({"id":j.id,"profile":j.profile,"state":j.state,"can_verify":backup && ["committed","restored"].contains(&j.state.as_str()),"can_rollback":backup && !["restored","superseded"].contains(&j.state.as_str()),"can_resolve":can_resolve,"resolution_review_hash":if can_resolve {review.map(|r|r.review_hash)} else {None},"resolution_confirmation":if can_resolve {RESOLVE_PHRASE} else {""},"backup_available":backup})
            }
            _ if matches!(exists(&path), Ok(false)) => Value::Null,
            _ => {
                json!({"state":"unreadable","can_verify":false,"can_rollback":false,"can_resolve":false,"backup_available":false})
            }
        };
        json!({"profiles":profiles,"allowed_targets":TARGETS,"unfinished":pending,"stack_pending":self.stack_unfinished(),"operation":operation,"manual_reboot_required":true,"runtime_adoption":"unknown","warnings":warnings()})
    }
    pub fn stack(
        &self,
        action: &str,
        profile: &str,
        targets: &str,
        hide_packages: &str,
        enabled: &str,
        id: &str,
    ) -> Result<Value> {
        self.stack_confirmed(action, profile, targets, hide_packages, enabled, id, "", "")
    }
    #[allow(clippy::too_many_arguments)]
    pub fn stack_confirmed(
        &self,
        action: &str,
        profile: &str,
        targets: &str,
        hide_packages: &str,
        enabled: &str,
        id: &str,
        confirmation: &str,
        submitted_review: &str,
    ) -> Result<Value> {
        self.with_lock(|| {
            if action != "resolve" && (!confirmation.is_empty() || !submitted_review.is_empty()) {
                return Err(error(
                    "E_REQUEST",
                    "Only Stack resolve accepts closure confirmation and review.",
                ));
            }
            if action == "plan" {
                if !id.is_empty() {
                    return Err(error(
                        "E_REQUEST",
                        "Stack planning does not accept an operation ID.",
                    ));
                }
            } else if !profile.is_empty()
                || !targets.is_empty()
                || !hide_packages.is_empty()
                || !enabled.is_empty()
                || (action == "status" && !id.is_empty())
            {
                return Err(error(
                    "E_REQUEST",
                    "This stack action accepts only its documented operation ID.",
                ));
            }
            match action {
                "status" => Ok(self.stack_status()),
                "plan" => self.stack_plan(profile, targets, hide_packages, enabled),
                "apply" => self.stack_apply(id),
                "verify" => self.stack_verify(id),
                "rollback" => self.stack_rollback(id),
                "resolve" => self.stack_resolve(id, confirmation, submitted_review),
                _ => Err(error(
                    "E_REQUEST",
                    "Stack action must be status, plan, apply, verify, rollback or resolve.",
                )),
            }
        })
    }
    fn stack_plan(
        &self,
        profile: &str,
        targets: &str,
        hide_packages: &str,
        enabled: &str,
    ) -> Result<Value> {
        self.require_recovered()?;
        if self.stack_unfinished() {
            return Err(error(
                "E_RECOVERY",
                "Restore the unfinished stack transaction first.",
            ));
        }
        let res = resource(profile);
        if res.is_empty() {
            return Err(error(
                "E_SELECTION",
                "Choose an explicit supported stack profile.",
            ));
        }
        let capabilities = self.stack_capabilities(profile)?;
        let protected = self.snapshot()?;
        let (before, body, parent, locator) = self.stack_read(res, "")?;
        let evidence_before = self.stack_evidence_binding()?;
        let mut p = Plan {
            schema: 1,
            id: String::new(),
            time: self.time(),
            profile: profile.into(),
            resource: res.into(),
            locator,
            targets: Vec::new(),
            hide_packages: Vec::new(),
            enabled: false,
            before,
            after: absent(),
            parent,
            protected,
            capabilities,
            evidence_before,
            changes: Vec::new(),
        };
        let out = if profile == "hma-scope" {
            if !enabled.is_empty() {
                return Err(error(
                    "E_SELECTION",
                    "The HMA profile does not accept a global toggle.",
                ));
            }
            p.targets = list(targets, true)?;
            p.hide_packages = list(hide_packages, false)?;
            if p.hide_packages.iter().any(|p| forbidden(p)) {
                return Err(error(
                    "E_SELECTION",
                    "A selected package is protected or belongs to the helper or supported Google scopes.",
                ));
            }
            self.stack_installed(&p.targets, &p.hide_packages)?;
            let (out, changes) = hma(&body, &p.targets, &p.hide_packages)?;
            p.changes = changes;
            p.after = FileState {
                exists: true,
                sha256: hash(&out),
                size: out.len() as i64,
                metadata: p.before.metadata.clone(),
            };
            out
        } else {
            if !targets.is_empty()
                || !hide_packages.is_empty()
                || !["true", "false"].contains(&enabled)
            {
                return Err(error(
                    "E_SELECTION",
                    "Choose an explicit marker state without HMA selections.",
                ));
            }
            p.enabled = enabled == "true";
            if p.before.exists == p.enabled {
                return Err(error(
                    "E_SELECTION",
                    "The selected marker intent is already recorded.",
                ));
            }
            p.changes = vec![json!({"enabled_before":p.before.exists,"enabled_after":p.enabled})];
            if p.enabled {
                p.after = FileState {
                    exists: true,
                    sha256: hash(&[]),
                    size: 0,
                    metadata: Metadata {
                        selinux: p.parent.selinux.clone(),
                        ..private_metadata()
                    },
                };
            }
            Vec::new()
        };
        self.stack_init()?;
        p.id = new_id()?;
        let dir = self.stack_object("plans", &p.id)?;
        io(std::fs::create_dir(&dir))?;
        safe_fs::set_metadata(
            &dir,
            &Metadata {
                mode: 0o700,
                ..private_metadata()
            },
        )?;
        if p.after.exists {
            safe_fs::atomic_write(&dir.join("intent.bin"), &out, &private_metadata())?;
        }
        safe_fs::write_json(&dir.join("plan.json"), &p)?;
        safe_fs::sync_dir(&dir)?;
        safe_fs::sync_dir(dir.parent().unwrap())?;
        Ok(p.view())
    }
    fn stack_load_plan(&self, id: &str) -> Result<(Plan, PathBuf)> {
        let dir = self.stack_object("plans", id)?;
        let p: Plan = read(&dir.join("plan.json"))?;
        if p.id != id
            || self.validate_stack_journal(&p.journal("applying")).is_err()
            || !valid_hash(&p.evidence_before)
            || p.protected.len() != 3
            || p.capabilities.is_empty()
        {
            return Err(error("E_FORMAT", "Stack plan is corrupt or unsupported."));
        }
        if PROTECTED.iter().any(|n| {
            p.protected
                .get(*n)
                .map(|s| !self.valid_state(s))
                .unwrap_or(true)
        }) {
            return Err(error(
                "E_FORMAT",
                "Stack plan protected-file binding is incomplete.",
            ));
        }
        if p.profile == "hma-scope" {
            if list(&p.targets.join(","), true)
                .map(|v| v != p.targets)
                .unwrap_or(true)
                || list(&p.hide_packages.join(","), false)
                    .map(|v| v != p.hide_packages)
                    .unwrap_or(true)
                || p.hide_packages.iter().any(|n| forbidden(n))
                || !p.before.exists
                || !p.after.exists
                || p.before.metadata != p.after.metadata
            {
                return Err(error(
                    "E_FORMAT",
                    "Stack plan HMA selection or metadata is unsupported.",
                ));
            }
        } else if !p.targets.is_empty()
            || !p.hide_packages.is_empty()
            || p.after.exists != p.enabled
            || p.before.exists == p.enabled
        {
            return Err(error("E_FORMAT", "Marker plan selection is unsupported."));
        }
        Ok((p, dir))
    }
    fn stack_check_base(&self, p: &Plan, allow_new_boot: bool) -> Result<()> {
        let mut caps = self.stack_capabilities(&p.profile)?;
        let mut wanted = p.capabilities.clone();
        if allow_new_boot {
            caps.remove("boot");
            wanted.remove("boot");
        }
        if caps != wanted {
            return Err(error(
                "E_STALE",
                "Protected programs, PIF, user or module state changed. Review a new stack plan.",
            ));
        }
        if self.snapshot()? != p.protected {
            return Err(error(
                "E_STALE",
                "Protected configuration changed. No stack resource was overwritten.",
            ));
        }
        if p.profile == "hma-scope" {
            self.stack_installed(&p.targets, &p.hide_packages)?;
        }
        Ok(())
    }
    fn stack_check_resource(&self, p: &Plan, expected: &FileState) -> Result<()> {
        let (current, _, parent, _) = self.stack_read(&p.resource, &p.locator)?;
        if &current != expected || parent != p.parent {
            return Err(error(
                "E_STALE",
                "The stack resource or its metadata changed outside this plan.",
            ));
        }
        Ok(())
    }
    fn stack_load_backup(&self, id: &str) -> Result<StackBackup> {
        let dir = self.stack_object("backups", id)?;
        let b: StackBackup = read(&dir.join("backup.json"))?;
        if b.schema != 1
            || b.id != id
            || !["hma-config", "brezygisk-unmount"].contains(&b.resource.as_str())
            || !self.valid_stack_original(&b.before, &b.resource)
            || !self.valid_stack_parent(&b.parent, &b.resource)
            || (b.resource == "hma-config" && !backend_name(&b.locator))
            || (b.resource == "brezygisk-unmount" && !b.locator.is_empty())
            || timestamp(&b.time).is_err()
        {
            return Err(error(
                "E_BACKUP",
                "The private stack backup is corrupt or unsupported.",
            ));
        }
        if !valid_id(&b.protected_backup) || b.protected.len() != 3 {
            return Err(error(
                "E_BACKUP",
                "The protected configuration backup association is incomplete.",
            ));
        }
        let protected = self.load_backup(&b.protected_backup).map_err(|_| {
            error(
                "E_BACKUP",
                "The associated protected configuration backup failed verification.",
            )
        })?;
        if protected.kind != "stack-profile" || protected.files != b.protected {
            return Err(error(
                "E_BACKUP",
                "The associated protected configuration backup failed verification.",
            ));
        }
        let path = dir.join("resource.bin");
        if !b.before.exists {
            if exists(&path)? {
                return Err(error(
                    "E_BACKUP",
                    "The absent-resource backup contains unexpected data.",
                ));
            }
        } else {
            let body = safe_fs::bounded(&path, LIMIT).map_err(|_| {
                error(
                    "E_BACKUP",
                    "The private stack backup failed checksum verification.",
                )
            })?;
            if hash(&body) != b.before.sha256 || body.len() as i64 != b.before.size {
                return Err(error(
                    "E_BACKUP",
                    "The private stack backup failed checksum verification.",
                ));
            }
        }
        Ok(b)
    }
    fn stack_save_backup(&self, p: &Plan) -> Result<()> {
        self.checkpoint("stack-before-backup")?;
        safe_fs::enough_space(&self.root, (8 << 20) + p.before.size as u64 * 3)?;
        let (path, _) = self.stack_path(&p.resource, &p.locator)?;
        safe_fs::enough_space(path.parent().unwrap(), (8 << 20) + p.after.size as u64 * 2)?;
        self.stack_check_resource(p, &p.before)?;
        let protected = self.backup("stack-profile", &p.protected)?;
        let dir = self.stack_object("backups", &p.id)?;
        io(std::fs::create_dir(&dir))?;
        safe_fs::set_metadata(
            &dir,
            &Metadata {
                mode: 0o700,
                ..private_metadata()
            },
        )?;
        if p.before.exists {
            let body = safe_fs::bounded(&path, LIMIT)?;
            if hash(&body) != p.before.sha256 || body.len() as i64 != p.before.size {
                return Err(error("E_STALE", "Stack resource changed during backup."));
            }
            safe_fs::atomic_write(&dir.join("resource.bin"), &body, &private_metadata())?;
        }
        let b = StackBackup {
            schema: 1,
            id: p.id.clone(),
            resource: p.resource.clone(),
            locator: p.locator.clone(),
            time: self.time(),
            before: p.before.clone(),
            parent: p.parent.clone(),
            protected_backup: protected.id,
            protected: p.protected.clone(),
        };
        safe_fs::write_json(&dir.join("backup.json"), &b)?;
        safe_fs::sync_dir(&dir)?;
        safe_fs::sync_dir(dir.parent().unwrap())?;
        self.stack_load_backup(&p.id)?;
        self.stack_check_resource(p, &p.before)?;
        self.checkpoint("stack-after-backup")
    }
    fn stack_write(&self, p: &Plan, state: &FileState, body: &[u8]) -> Result<()> {
        self.stack_write_tracked(p, state, body, &mut false)
    }
    fn stack_write_tracked(
        &self,
        p: &Plan,
        state: &FileState,
        body: &[u8],
        started: &mut bool,
    ) -> Result<()> {
        let (path, _) = self.stack_path(&p.resource, &p.locator)?;
        if state.exists {
            if hash(body) != state.sha256 || body.len() as i64 != state.size {
                return Err(error(
                    "E_FORMAT",
                    "Stack write bytes do not match the reviewed state.",
                ));
            }
            *started = true;
            safe_fs::atomic_write(&path, body, &state.metadata)
        } else {
            *started = true;
            safe_fs::remove_file(&path)
        }
    }
    fn stack_apply(&self, id: &str) -> Result<Value> {
        self.require_recovered()?;
        if self.stack_unfinished() {
            return Err(error(
                "E_RECOVERY",
                "Restore the unfinished stack transaction first.",
            ));
        }
        let (p, dir) = self.stack_load_plan(id)?;
        let when = timestamp(&p.time)?;
        if self.now() < when || self.now().saturating_sub(when) > 1800 {
            return Err(error(
                "E_STALE",
                "The stack plan expired. Create a fresh review.",
            ));
        }
        if exists(&dir.join("submitted.json"))? {
            return Err(error(
                "E_DUPLICATE",
                "This stack plan was already submitted. Inspect its recorded outcome.",
            ));
        }
        self.stack_check_base(&p, false)?;
        self.stack_check_resource(&p, &p.before)?;
        if self.stack_evidence_binding()? != p.evidence_before {
            return Err(error(
                "E_STALE",
                "Stack evidence changed. Create a fresh review.",
            ));
        }
        let out = if p.after.exists {
            safe_fs::bounded(&dir.join("intent.bin"), LIMIT).map_err(|_| {
                error(
                    "E_STALE",
                    "Proposed stack bytes changed. Create a fresh review.",
                )
            })?
        } else {
            Vec::new()
        };
        if p.after.exists && (hash(&out) != p.after.sha256 || out.len() as i64 != p.after.size) {
            return Err(error(
                "E_STALE",
                "Proposed stack bytes changed. Create a fresh review.",
            ));
        }
        if p.profile == "hma-scope" {
            let (_, old, _, _) = self.stack_read(&p.resource, &p.locator)?;
            if hma(&old, &p.targets, &p.hide_packages)
                .map(|(expected, _)| expected != out)
                .unwrap_or(true)
            {
                return Err(error(
                    "E_FORMAT",
                    "Proposed HMA bytes do not match the explicit selection.",
                ));
            }
        } else if p.after.exists && !out.is_empty() {
            return Err(error(
                "E_FORMAT",
                "The marker intent contains unexpected bytes.",
            ));
        }
        safe_fs::write_json(&dir.join("submitted.json"), &json!({"time":self.time()}))?;
        self.stack_save_backup(&p)?;
        self.stack_check_base(&p, false)?;
        let mut j = p.journal("applying");
        j.time = self.time();
        let journal_path = self.root.join("stack-journal.json");
        safe_fs::write_json(&journal_path, &j)?;
        let run: Result<()> = (|| {
            self.checkpoint("stack-before-write")?;
            self.stack_check_base(&p, false)?;
            self.stack_check_resource(&p, &p.before)?;
            if self.stack_evidence_binding()? != p.evidence_before {
                return Err(error("E_STALE", "Stack evidence changed before writing."));
            }
            j.state = "writing".into();
            safe_fs::write_json(&journal_path, &j)?;
            self.stack_write(&p, &p.after, &out)?;
            self.checkpoint("stack-after-write")?;
            self.stack_check_resource(&p, &p.after)?;
            self.checkpoint("stack-before-commit")?;
            self.stack_check_base(&p, false)?;
            self.stack_check_resource(&p, &p.after)?;
            j.state = "committed".into();
            safe_fs::write_json(&journal_path, &j)?;
            self.checkpoint("stack-after-commit")?;
            self.stack_check_base(&p, false)?;
            self.stack_check_resource(&p, &p.after)?;
            self.stack_load_backup(&p.id)?;
            Ok(())
        })();
        if run.is_err() {
            let prior = j.clone();
            let mut started = false;
            if let Err(cause) = self.stack_restore(&p, &mut j, false, &mut started) {
                if started {
                    j.state = "recovery-required".into();
                    let _ = safe_fs::write_json(&journal_path, &j);
                } else {
                    return self.stack_prewrite_refusal(&mut j, &prior, cause);
                }
                return Err(error(
                    "E_RECOVERY",
                    "Stack application failed and restoration is pending. Preserve private recovery evidence.",
                ));
            }
            return Err(error("E_ROLLED_BACK", "Stack application failed. Original file state was restored; runtime remains unknown and manual reboot is required.").with_data(result(&j)));
        }
        Ok(result(&j))
    }
    fn stack_conflict(&self, p: &Plan, current: &FileState) -> Result<()> {
        let dir = self.stack_object("backups", &p.id)?;
        let (path, _) = self.stack_path(&p.resource, &p.locator)?;
        let name = if !exists(&dir.join("conflict.json"))? {
            "conflict".into()
        } else {
            format!("conflict-{}", new_id()?)
        };
        if current.exists {
            let body = safe_fs::bounded(&path, LIMIT)?;
            if hash(&body) != current.sha256 || body.len() as i64 != current.size {
                return Err(error(
                    "E_RECOVERY",
                    "Conflicting stack resource changed during preservation.",
                ));
            }
            // Keep the first conflict and every later distinct observation.
            safe_fs::atomic_write(&dir.join(format!("{name}.bin")), &body, &private_metadata())?;
        }
        safe_fs::write_json(
            &dir.join(format!("{name}.json")),
            &json!({"schema":1,"state":current,"parent":safe_fs::metadata(path.parent().ok_or_else(||error("E_PATH", "Stack parent is unavailable."))?)?,"time":self.time()}),
        )
    }
    fn stack_load_current(&self, p: &Plan, current: &FileState, dir: &Path) -> Result<()> {
        let r: StackBackup = read(&dir.join("rollback-current.json"))
            .map_err(|_| error("E_BACKUP", "Current stack rollback evidence is unreadable."))?;
        if r.schema != 1
            || r.id != p.id
            || r.resource != p.resource
            || r.locator != p.locator
            || &r.before != current
            || r.parent != p.parent
            || r.protected != p.protected
            || !valid_id(&r.protected_backup)
            || timestamp(&r.time).is_err()
        {
            return Err(error(
                "E_BACKUP",
                "Current stack rollback evidence has an invalid binding.",
            ));
        }
        let b = self.load_backup(&r.protected_backup).map_err(|_| {
            error(
                "E_BACKUP",
                "Current stack rollback protected backup failed verification.",
            )
        })?;
        if b.kind != "stack-profile" || b.files != p.protected {
            return Err(error(
                "E_BACKUP",
                "Current stack rollback protected backup failed verification.",
            ));
        }
        let path = dir.join("rollback-current.bin");
        if !current.exists {
            if exists(&path)? {
                return Err(error(
                    "E_BACKUP",
                    "Absent current stack rollback evidence contains unexpected bytes.",
                ));
            }
        } else {
            let body = safe_fs::bounded(&path, LIMIT).map_err(|_| {
                error(
                    "E_BACKUP",
                    "Current stack rollback evidence failed checksum verification.",
                )
            })?;
            if hash(&body) != current.sha256 || body.len() as i64 != current.size {
                return Err(error(
                    "E_BACKUP",
                    "Current stack rollback evidence failed checksum verification.",
                ));
            }
        }
        Ok(())
    }
    fn stack_rollback_current(&self, p: &Plan, current: &FileState) -> Result<()> {
        let dir = self.stack_object("backups", &p.id)?;
        if exists(&dir.join("rollback-current.json"))? {
            self.stack_load_current(p, current, &dir)?;
        }
        self.checkpoint("stack-before-rollback-backup")?;
        let protected = self.backup("stack-profile", &p.protected)?;
        if current.exists {
            let (path, _) = self.stack_path(&p.resource, &p.locator)?;
            let body = safe_fs::bounded(&path, LIMIT)?;
            if hash(&body) != current.sha256 || body.len() as i64 != current.size {
                return Err(error(
                    "E_STALE",
                    "Current stack resource changed during rollback backup.",
                ));
            }
            safe_fs::atomic_write(
                &dir.join("rollback-current.bin"),
                &body,
                &private_metadata(),
            )?;
        }
        let r = StackBackup {
            schema: 1,
            id: p.id.clone(),
            resource: p.resource.clone(),
            locator: p.locator.clone(),
            time: self.time(),
            before: current.clone(),
            parent: p.parent.clone(),
            protected_backup: protected.id,
            protected: p.protected.clone(),
        };
        safe_fs::write_json(&dir.join("rollback-current.json"), &r)?;
        safe_fs::sync_dir(&dir)?;
        self.stack_load_current(p, current, &dir)?;
        self.stack_check_resource(p, current)?;
        self.checkpoint("stack-after-rollback-backup")?;
        self.stack_load_current(p, current, &dir)
    }
    fn stack_prewrite_refusal<T>(
        &self,
        j: &mut Journal,
        prior: &Journal,
        cause: Error,
    ) -> Result<T> {
        let path = self.root.join("stack-journal.json");
        let current: Journal = read(&path).map_err(|_| {
            error(
                "E_RECOVERY",
                "Stack journal changed during a refused restoration. Preserve it.",
            )
        })?;
        if &current != prior {
            if current != *j {
                return Err(error(
                    "E_RECOVERY",
                    "Stack journal changed during a refused restoration. Preserve it.",
                ));
            }
            safe_fs::write_json(&path, prior)?;
        }
        *j = prior.clone();
        Err(cause)
    }
    fn stack_restore_resource(&self, p: &Plan, expected: &FileState) -> Result<()> {
        let (current, _, parent, _) = self.stack_read(&p.resource, &p.locator)?;
        if &current != expected || parent != p.parent {
            self.stack_conflict(p, &current)?;
            return Err(error(
                "E_STALE",
                "An external Stack resource change was preserved privately. Restoration refused before writing.",
            ));
        }
        Ok(())
    }
    fn stack_restore(
        &self,
        p: &Plan,
        j: &mut Journal,
        explicit: bool,
        started: &mut bool,
    ) -> Result<()> {
        let backup = self.stack_load_backup(&p.id)?;
        if backup.resource != p.resource
            || backup.locator != p.locator
            || backup.before != p.before
            || backup.parent != p.parent
            || backup.protected != p.protected
        {
            return Err(error(
                "E_BACKUP",
                "Stack backup binding does not match the reviewed resource.",
            ));
        }
        let (current, _, parent, _) = self.stack_read(&p.resource, &p.locator)?;
        if parent != p.parent {
            self.stack_conflict(p, &current)?;
            return Err(error(
                "E_STALE",
                "Stack parent metadata changed. No conflicting resource was overwritten.",
            ));
        }
        if current != p.before && current != p.after {
            self.stack_conflict(p, &current)?;
            return Err(error(
                "E_STALE",
                "An external stack writer conflict was preserved privately. Automatic restoration stopped.",
            ));
        }
        self.checkpoint("stack-before-restore")?;
        // Explicit rollback rechecks the reviewed context. Failed-Apply
        // compensation restores only its own resource despite other changes.
        if explicit {
            self.stack_check_base(p, true)?;
        }
        self.stack_restore_resource(p, &current)?;
        if current != p.before {
            if explicit {
                self.stack_rollback_current(p, &current)?;
                self.stack_check_base(p, true)?;
                self.stack_restore_resource(p, &current)?;
            }
            let body = if p.before.exists {
                let dir = self.stack_object("backups", &p.id)?;
                let body = safe_fs::bounded(&dir.join("resource.bin"), LIMIT)
                    .map_err(|_| error("E_BACKUP", "Stack backup changed before restoration."))?;
                if hash(&body) != p.before.sha256 || body.len() as i64 != p.before.size {
                    return Err(error(
                        "E_BACKUP",
                        "Stack backup changed before restoration.",
                    ));
                }
                body
            } else {
                Vec::new()
            };
            j.state = "restoring".into();
            safe_fs::write_json(&self.root.join("stack-journal.json"), j)?;
            self.stack_write_tracked(p, &p.before, &body, started)?;
        }
        self.checkpoint("stack-after-restore")?;
        self.stack_restore_resource(p, &p.before)?;
        self.stack_load_backup(&p.id)?;
        j.state = "restored".into();
        safe_fs::write_json(&self.root.join("stack-journal.json"), j)
    }
    fn stack_recorded_journal(&self, p: &Plan, id: &str) -> Result<Journal> {
        let j: Journal = read(&self.root.join("stack-journal.json")).map_err(|_| {
            error(
                "E_RECOVERY",
                "Choose the current valid stack transaction for restoration or verification.",
            )
        })?;
        if self.validate_stack_journal(&j).is_err()
            || j.id != id
            || j.resource != p.resource
            || j.locator != p.locator
            || j.before != p.before
            || j.after != p.after
            || j.parent != p.parent
            || j.profile != p.profile
        {
            return Err(error(
                "E_RECOVERY",
                "Choose the current valid stack transaction for restoration or verification.",
            ));
        }
        Ok(j)
    }
    fn stack_rollback(&self, id: &str) -> Result<Value> {
        self.require_foreign_recovered()?;
        let (p, _) = self.stack_load_plan(id)?;
        let mut j = self.stack_recorded_journal(&p, id)?;
        if j.state == "superseded" {
            return Err(error(
                "E_RECOVERY",
                "This Stack transaction was superseded by an explicit keep-current decision. Review a new plan.",
            ));
        }
        if j.state == "restored" {
            self.stack_load_backup(id)?;
            self.stack_check_resource(&p, &p.before)?;
            return Ok(result(&j));
        }
        self.stack_check_base(&p, true)?;
        let prior = j.clone();
        let mut started = false;
        if let Err(cause) = self.stack_restore(&p, &mut j, true, &mut started) {
            if !started {
                return self.stack_prewrite_refusal(&mut j, &prior, cause);
            }
            j.state = "recovery-required".into();
            let _ = safe_fs::write_json(&self.root.join("stack-journal.json"), &j);
            return Err(error(
                "E_RECOVERY",
                "Stack restoration is pending. Preserve the private backup and conflict evidence.",
            ));
        }
        Ok(result(&j))
    }
    fn stack_verify(&self, id: &str) -> Result<Value> {
        let (p, _) = self.stack_load_plan(id)?;
        let j = self.stack_recorded_journal(&p, id)?;
        let expected = match j.state.as_str() {
            "restored" => &p.before,
            "committed" => &p.after,
            _ => {
                return Err(error(
                    "E_RECOVERY",
                    "Stack restoration is pending; file verification cannot establish activation.",
                ));
            }
        };
        self.stack_check_base(&p, true)?;
        self.stack_check_resource(&p, expected)?;
        self.stack_load_backup(id)?;
        Ok(result(&j))
    }
}
