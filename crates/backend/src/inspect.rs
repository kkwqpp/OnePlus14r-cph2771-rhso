use crate::{
    App,
    error::{Error, Result},
    fs,
    store::{REQUIRED_PACKAGES, valid_patch, valid_stage},
    transaction::Journal,
    util,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
const FINGERPRINT: &str =
    "google/frankel_beta/frankel:CANARY/ZP11.260918.007/16484274:user/release-keys";
pub fn run(name: &str, args: &[&str]) -> Result<String> {
    let mut child = Command::new(name)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");
    let (out_tx, out_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let result = stdout.take((2 << 20) + 1).read_to_end(&mut b).map(|_| b);
        let _ = out_tx.send(result);
    });
    let (err_tx, err_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let result = stderr.take((64 << 10) + 1).read_to_end(&mut b).map(|_| b);
        let _ = err_tx.send(result);
    });
    let deadline = Instant::now() + Duration::from_secs(12);
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::new(
                "E_CAPABILITY",
                "The bounded diagnostic command timed out.",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let b = out_rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| Error::new("E_CAPABILITY", "Diagnostic output could not be read."))??;
    let e = err_rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| Error::new("E_CAPABILITY", "Diagnostic output could not be read."))??;
    if b.len() > 2 << 20 || e.len() > 64 << 10 {
        return Err(Error::new(
            "E_LIMIT",
            "Diagnostic command exceeded its output bound.",
        ));
    }
    if !status.success() {
        return Err(Error::new(
            "E_CAPABILITY",
            "Diagnostic command returned a non-success result.",
        ));
    }
    String::from_utf8(b)
        .map_err(|_| Error::new("E_CAPABILITY", "Diagnostic output is not supported text."))
}
pub fn patch_alignment(pif: &str, b: Option<&[u8]>) -> &'static str {
    let Some(b) = b.filter(|_| valid_patch(pif)) else {
        return "unknown";
    };
    let Ok(s) = std::str::from_utf8(b) else {
        return "ambiguous";
    };
    let mut global = None;
    for l in s.lines() {
        let v = l.trim();
        if v.is_empty() || v.starts_with('#') {
            continue;
        }
        let Some(date) = v.strip_prefix("all=") else {
            return "ambiguous";
        };
        if global.is_some() || !valid_patch(date) {
            return "ambiguous";
        }
        global = Some(date);
    }
    match global {
        Some(v) if v == pif => "aligned",
        Some(_) => "different",
        None => "unknown",
    }
}
pub fn target_states(b: &[u8]) -> BTreeMap<String, String> {
    let s = String::from_utf8_lossy(b);
    REQUIRED_PACKAGES
        .iter()
        .map(|pkg| {
            let mut n = 0;
            let mut state = "missing";
            for l in s.lines() {
                let v = l.trim();
                if v.is_empty() || v.starts_with('#') || v.trim_end_matches(['!', '?']) != *pkg {
                    continue;
                }
                n += 1;
                state = if v == format!("{pkg}!") {
                    "generate"
                } else if v == format!("{pkg}?") {
                    "leaf"
                } else if v == *pkg {
                    "unflagged"
                } else {
                    "invalid_flags"
                };
            }
            if n > 1 {
                state = "duplicate";
            }
            ((*pkg).into(), state.into())
        })
        .collect()
}
impl App {
    pub(crate) fn pif(&self) -> Result<BTreeMap<String, String>> {
        let b = fs::bounded(
            &self.modules.join("playintegrityfix/custom.pif.prop"),
            64 << 10,
        )?;
        let s = std::str::from_utf8(&b)
            .map_err(|_| Error::new("E_CAPABILITY", "PIF properties are not supported text."))?;
        let keys = [
            "FINGERPRINT",
            "SECURITY_PATCH",
            "spoofBuild",
            "spoofProps",
            "spoofProvider",
            "spoofSignature",
            "spoofVendingFinger",
            "spoofVendingSdk",
        ];
        let mut out = BTreeMap::new();
        for l in s.lines() {
            if let Some((k, v)) = l.trim().split_once('=')
                && keys.contains(&k)
                && out.insert(k.into(), v.into()).is_some()
            {
                return Err(Error::new(
                    "E_CAPABILITY",
                    "Duplicate PIF setting requires review.",
                ));
            }
        }
        Ok(out)
    }
    pub(crate) fn capabilities(&self) -> Result<BTreeMap<String, String>> {
        if self.fake {
            return Ok(BTreeMap::from([
                ("mode".into(), "offline-fake-engine".into()),
                ("xml_x509".into(), "bundled-rust".into()),
                ("reload".into(), "fake".into()),
            ]));
        }
        if util::owner_id() != 0 {
            return Err(Error::new(
                "E_ROOT",
                "KernelSU root permission is required.",
            ));
        }
        fs::no_links(&self.active)?;
        let m = fs::metadata(&self.active)?;
        if m.uid != 0 || m.mode & 0o77 != 0 || m.selinux.is_empty() {
            return Err(Error::new(
                "E_CAPABILITY",
                "Active directory ownership, private access or SELinux metadata is not verified.",
            ));
        }
        let mut out = BTreeMap::from([
            ("xml_x509".into(), "bundled-rust-validated-profile".into()),
            (
                "reload".into(),
                "installed-1.4.1-per-file-FileObserver".into(),
            ),
            ("filesystem".into(), "same-directory-rename-fsync".into()),
        ]);
        for (n, h) in [
            (
                "service.sh",
                "d1b1813d7bfe66ed58b357d2c6f247fe7e8d698a3aa79c722769ff0c0da6e508",
            ),
            (
                "daemon",
                "6ec6ec3f88c8b126d7935e5482d485ed8b37219ce26dbc16be5168ffd95658ed",
            ),
            (
                "service.apk",
                "75a78b56d7c6615cf49dfad8c7b3ed22b966ce506c99e4d664dacb4298c5e54d",
            ),
            (
                "libtricky_store.so",
                "6d729980d400d656e5f2908dc86c69104f49e7067961f3fc43dec4b30804cc91",
            ),
        ] {
            let b =
                fs::bounded(&self.modules.join("tricky_store").join(n), 8 << 20).map_err(|_| {
                    Error::new(
                        "E_CAPABILITY",
                        "The inspected TrickyStore installation is unavailable.",
                    )
                })?;
            if util::hash(&b) != h {
                return Err(Error::new(
                    "E_CAPABILITY",
                    "TrickyStore program files changed. Read-only diagnostics remain available; review compatibility before Apply.",
                ));
            }
            out.insert(format!("tricky_store/{n}"), h.into());
        }
        out.insert(
            "pif_hash".into(),
            util::hash(&fs::bounded(
                &self.modules.join("playintegrityfix/custom.pif.prop"),
                64 << 10,
            )?),
        );
        for n in ["target_from_denylist", "security_patch_auto_config"] {
            if self.active.join(n).try_exists()? {
                return Err(Error::new(
                    "E_WRITER",
                    "TA_utl has an enabled configuration writer marker. Review its behavior before Apply; no module was changed.",
                ));
            }
            out.insert(n.into(), "absent".into());
        }
        for n in ["TA_utl", ".TA_utl"] {
            let p = self.modules.join(n).join("service.sh");
            if p.try_exists()? {
                out.insert(
                    format!("{n}_script_hash"),
                    util::hash(&fs::bounded(&p, 1 << 20)?),
                );
            }
        }
        if self.engine_health()? != 1 {
            return Err(Error::new(
                "E_CAPABILITY",
                "Exactly one verified TrickyStore executable/argument instance is required. Inspect Diagnostics; no process was stopped.",
            ));
        }
        out.insert("engine_count".into(), "1".into());
        Ok(out)
    }
    pub(crate) fn engine_health(&self) -> Result<usize> {
        if self.fake {
            return Ok(1);
        }
        let mut count = 0;
        for e in std::fs::read_dir("/proc")? {
            let e = e?;
            if e.file_name().to_string_lossy().parse::<u32>().is_err() {
                continue;
            }
            let p = e.path();
            let Ok(b) = std::fs::read(p.join("cmdline")) else {
                continue;
            };
            if !b
                .split(|b| *b == 0)
                .any(|v| v == b"TrickyStore" || v == b"io.github.a13e300.tricky_store.MainKt")
            {
                continue;
            }
            let Ok(exe) = std::fs::read_link(p.join("exe")) else {
                continue;
            };
            if !matches!(
                exe.file_name().and_then(|n| n.to_str()),
                Some("app_process" | "app_process64")
            ) {
                continue;
            }
            let Ok(maps) = std::fs::read(p.join("maps")) else {
                continue;
            };
            if maps_contain(
                &maps,
                self.modules
                    .join("tricky_store/service.apk")
                    .to_string_lossy()
                    .as_ref(),
            ) || maps_contain(
                &maps,
                self.modules
                    .join("tricky_store/libtricky_store.so")
                    .to_string_lossy()
                    .as_ref(),
            ) {
                count += 1;
            }
        }
        Ok(count)
    }
    pub(crate) fn adoption(&self) -> Result<Value> {
        self.checkpoint("before-adoption")?;
        let n = self.engine_health()?;
        let v = json!({"verified_engine_instances":n,"health":if n==1{"healthy"}else{"failed"},"adoption":"pending","identity_evidence":"No freshly observed signer identity is available. Historical chain counts are insufficient.","wallet_acceptance":"unverified","manual_reboot_required":false});
        if n != 1 {
            return Err(Error::new("E_ADOPTION","Verified TrickyStore process health failed. Restore the configuration set; do not kill unrelated processes.").with_data(v));
        }
        Ok(v)
    }
    pub fn watch(&self, days: i64) -> Result<Value> {
        if !(1..=365).contains(&days) {
            return Err(Error::new(
                "E_INPUT",
                "Warning horizon must be between 1 and 365 days.",
            ));
        }
        let p = self.pif()?;
        let finger = p.get("FINGERPRINT").map(String::as_str).unwrap_or("");
        let state = if finger == FINGERPRINT {
            "estimate-valid-for-supplied-fingerprint"
        } else {
            "estimate-invalid-fingerprint-changed"
        };
        let until = time::macros::datetime!(2026-11-18 0:00 UTC).unix_timestamp();
        let remaining = (until - self.now()) / 86400;
        let patch = fs::bounded(&self.active.join("security_patch.txt"), 64 << 10);
        let alignment = patch_alignment(
            p.get("SECURITY_PATCH").map(String::as_str).unwrap_or(""),
            patch.as_deref().ok(),
        );
        let mut warnings = Vec::new();
        if state != "estimate-valid-for-supplied-fingerprint" {
            warnings.push("Fingerprint changed. Supply a newly justified expiry estimate.");
        } else if remaining <= days {
            warnings.push("Supplied estimated canary expiry is approaching or has passed; eligibility is not established.");
        }
        match alignment{"aligned"=>{},"ambiguous"=>warnings.push("Patch alignment is ambiguous: duplicate, invalid or overriding patch settings require explicit review."),"unknown"=>warnings.push("Patch alignment is unknown: a readable, valid PIF date and one supported global TrickyStore date are required."),_=>warnings.push("Global TrickyStore patch differs from the inspected PIF patch; review Diagnostics.")};
        let canonical = p
            .iter()
            .map(|(k, v)| format!("{k}={v}\n"))
            .collect::<String>();
        let mut v = json!({"estimate":"2026-11-18","estimate_source":"owner-supplied; not a Google guarantee","fingerprint_estimate_state":state,"fingerprint_hash":util::hash(finger.as_bytes()),"days_remaining":remaining,"warning_horizon_days":days,"patch_aligned":alignment=="aligned","patch_alignment_state":alignment,"pif_settings_hash":util::hash(canonical.as_bytes()),"warnings":warnings,"scheduled_watch":"disabled; no daemon or boot-time fetching"});
        if let Ok(b) = patch {
            v["patch_sha256"] = json!(util::hash(&b));
        }
        Ok(v)
    }
    pub fn status(&self) -> Result<Value> {
        let config = self.snapshot()?;
        let mut findings = Vec::new();
        let mut summaries = serde_json::Map::new();
        let mut algorithms = BTreeSet::new();
        let mut declared = BTreeSet::new();
        let mut validation = "missing";
        for n in ["keybox.xml", "keybox.xml.sw_default"] {
            let path = self.active.join(n);
            if !path.try_exists()? {
                if n == "keybox.xml" {
                    findings.push(self.finding(
                        "INPUT_keybox.xml",
                        "confirmed",
                        "The active keybox file is missing",
                        "Signing-key availability cannot be established.",
                        &config,
                    ));
                }
                continue;
            }
            let b = match fs::bounded(&path, rhso_keybox::MAX_INPUT) {
                Ok(b) => zeroize::Zeroizing::new(b),
                Err(_) => {
                    if n == "keybox.xml" {
                        validation = "unreadable";
                    }
                    findings.push(self.finding(
                        &format!("INPUT_{n}"),
                        "confirmed",
                        "Keybox input could not be read safely",
                        "Input oversized, symbolic or unreadable.",
                        &config,
                    ));
                    continue;
                }
            };
            if fs::metadata(&path).is_ok_and(|m| m.mode & 0o77 != 0) {
                findings.push(self.finding(&format!("PERMISSIONS_{n}"),"confirmed","Key material has broad file permissions","Group or other permission bits are present. Parent-directory access also matters.",&config));
            }
            match rhso_keybox::parse(&b, self.now()) {
                Ok(d) => {
                    let s = d.summary();
                    if n == "keybox.xml" {
                        validation = "validated";
                        for bx in &s.keyboxes {
                            for k in &bx.keys {
                                algorithms.insert(k.algorithm.clone());
                                declared.insert(k.algorithm.clone());
                            }
                        }
                    }
                    summaries.insert(n.into(), json!(s));
                }
                Err(_) => {
                    let audit = rhso_keybox::audit(&b, self.now());
                    if n == "keybox.xml" {
                        validation = "invalid";
                        if let Some(a) = audit["algorithms"].as_array() {
                            for v in a {
                                if let Some(s) = v.as_str()
                                    && matches!(s, "rsa" | "ecdsa" | "unsupported")
                                {
                                    declared.insert(s.into());
                                }
                            }
                        }
                    }
                    summaries.insert(n.into(), audit);
                    findings.push(self.finding(&format!("VALIDATION_{n}"),"confirmed","Keybox validation failed","Mandatory local XML/key/certificate checks rejected the input; secret content is withheld.",&config));
                }
            }
        }
        if !algorithms.contains("rsa") {
            findings.push(self.finding(
                if declared.contains("rsa") {
                    "RSA_UNVALIDATED"
                } else {
                    "RSA_MISSING"
                },
                if declared.contains("rsa") {
                    "confirmed"
                } else {
                    "hypothesis"
                },
                if declared.contains("rsa") {
                    "A declared RSA entry did not pass mandatory validation"
                } else {
                    "RSA absence does not establish a Wallet fault"
                },
                "An RSA label alone is not a requirement or success proof.",
                &config,
            ));
        }
        match fs::bounded(&self.active.join("target.txt"), 1 << 20) {
            Ok(b) => {
                for (pkg, state) in target_states(&b) {
                    if state != "generate" {
                        findings.push(self.finding(&format!("TARGET_{pkg}"),"confirmed","A required generate-mode target needs review","Required package has missing, duplicate or conflicting generate-mode entries.",&config));
                    }
                }
            }
            Err(_) => findings.push(self.finding(
                "INPUT_target.txt",
                "confirmed",
                "Required target configuration is unavailable",
                "Required package modes cannot be established.",
                &config,
            )),
        };
        let caps = self.capabilities();
        if let Err(e) = &caps {
            findings.push(self.finding(
                "CAPABILITY",
                "confirmed",
                "Apply is currently blocked",
                &e.message,
                &config,
            ));
        }
        let watch=self.watch(14).unwrap_or_else(|_|json!({"patch_aligned":false,"patch_alignment_state":"unknown","fingerprint_estimate_state":"unavailable","warnings":["PIF/watch inputs could not be evaluated safely."]}));
        if let Some(w) = watch["warnings"].as_array() {
            for s in w {
                if let Some(s) = s.as_str() {
                    findings.push(self.finding(
                        "WATCH",
                        "confirmed",
                        "Patch or canary warning",
                        s,
                        &config,
                    ));
                }
            }
        }
        let user = self.current_user();
        let mut device = json!({"real_bootloader":"owner-reported unlocked; spoofed properties are not evidence","wallet_error":"owner-reported security rejection after card-number submission","wallet_stage":"card provisioning","generic_integrity":"supplied BASIC/DEVICE/STRONG pass; not rechecked by this helper","wallet_acceptance":"unverified","current_android_user":user.as_deref().unwrap_or("unavailable"),"persistent_alias_warning":"Aliases were counted, never opened or removed. Stale app results remain a hypothesis.","certification":"Check Play Store Settings > About on the phone; unavailable through a trusted root API.","issuer_region_account":"Not inspected; user/provider action only if Wallet evidence indicates it."});
        let mut apps = Vec::new();
        if !self.fake {
            if let Ok(u) = &user {
                let role = run(
                    "/system/bin/cmd",
                    &[
                        "role",
                        "get-role-holders",
                        "--user",
                        u,
                        "android.app.role.WALLET",
                    ],
                )
                .unwrap_or_default();
                device["wallet_role"] = json!(match role.trim() {
                    "com.google.android.apps.walletnfcrel" => "Google Wallet",
                    "com.google.android.gms" => "Google Play services TapAndPay",
                    "" => "unset",
                    _ => "other holder; inspect settings",
                });
                let payment = run(
                    "/system/bin/settings",
                    &[
                        "--user",
                        u,
                        "get",
                        "secure",
                        "nfc_payment_default_component",
                    ],
                )
                .unwrap_or_default();
                device["default_payment"] = json!(if payment.trim()
                    == "com.google.android.gms/com.google.android.gms.tapandpay.hce.service.TpHceService"
                {
                    "Google TapAndPay"
                } else {
                    "other-or-unset; inspect phone settings"
                });
            }
            for pkg in REQUIRED_PACKAGES {
                let mut row = json!({"package":pkg,"uid":"unavailable","version":"unavailable"});
                if let Ok(u) = &user
                    && let Ok(s) = run(
                        "/system/bin/pm",
                        &["list", "packages", "--user", u, "-U", pkg],
                    )
                {
                    for l in s.lines() {
                        if l.starts_with(&format!("package:{pkg} "))
                            && let Some(uid) = l
                                .split_whitespace()
                                .find_map(|s| s.strip_prefix("uid:"))
                                .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
                        {
                            row["uid"] = json!(uid);
                        }
                    }
                }
                if let Ok(s) = run("/system/bin/dumpsys", &["package", pkg])
                    && let Some(v) = s
                        .lines()
                        .find_map(|l| l.trim().strip_prefix("versionName="))
                        .filter(|s| !s.is_empty() && s.len() <= 100)
                {
                    row["version"] = json!(v);
                }
                apps.push(row);
            }
            let nfc = run("/system/bin/cmd", &["nfc", "status"]);
            device["nfc"] = json!(match nfc {
                Ok(s) if s.contains("disabled") => "disabled",
                Ok(s) if s.contains("enabled") => "enabled",
                _ => "unavailable",
            });
            if let Ok(s) = run("/system/bin/settings", &["get", "global", "auto_time"]) {
                device["automatic_time"] = json!(s.trim() == "1");
            }
            device["device_time"] = json!(self.time());
            if let Ok(s) = run("/system/bin/dumpsys", &["connectivity"]) {
                device["validated_connectivity"] = json!(s.contains("IS_VALIDATED"));
            }
        }
        device["persistent_alias_count"] = json!(
            std::fs::read_dir(self.active.join("persistent_keys"))
                .map(|v| v.count())
                .unwrap_or(0)
        );
        device["network_checks"] = self.host_checks();
        let (hist, invalid) = self.public_history();
        if invalid > 0 {
            findings.push(self.finding(
                "HISTORY",
                "confirmed",
                "History metadata needs review",
                "Unsupported or corrupt history records were omitted from this redacted report.",
                &config,
            ));
        }
        let mut inventory = Vec::new();
        if let Ok(entries) = std::fs::read_dir(self.root.join("staged")) {
            for e in entries.flatten() {
                let id = e.file_name().to_string_lossy().into_owned();
                if e.file_type().is_ok_and(|f| f.is_dir())
                    && util::valid_id(&id)
                    && let Ok(st) =
                        fs::read_json::<crate::store::Stage>(&e.path().join("stage.json"))
                    && valid_stage(&st, &id)
                {
                    inventory.push(st);
                }
            }
        }
        let (reset, pending, next_reset) = self.reset_diagnostic();
        let public = self.public_trust_view();
        let binding = self.stack_evidence_binding();
        let stack_pending = self.stack_unfinished();
        let mut next = public["next_step"]
            .as_str()
            .unwrap_or("Check current Wallet readiness privately.")
            .to_owned();
        if caps.is_err() {
            next = "Resolve the stated capability blocker before reviewing an Apply plan.".into();
        }
        if validation != "validated" {
            next="Review the active keybox's mandatory validation failure or missing input before any replacement.".into();
        }
        if self.unfinished() {
            next = "Open Recovery and restore the interrupted transaction before other changes."
                .into();
        }
        if pending {
            next = next_reset;
        } else if stack_pending {
            next="Inspect the stack journal and restore its checked resource backup through Stack rollback.".into();
        }
        Ok(
            json!({"version":crate::VERSION,"public_attestation":public,"active":config,"algorithms":algorithms,"declared_algorithms":declared,"active_keybox_validation":validation,"keybox_summaries":summaries,"findings":findings,"evidence_time":self.time(),"freshness":"fresh snapshot; findings become stale after relevant hashes/settings change","last_operation":hist.last(),"rollback":self.backups().unwrap_or(Value::Null),"recovery":self.recovery("status").unwrap_or(Value::Null),"reset":reset,"next_step":next,"history":hist,"inventory":inventory,"device":device,"applications":apps,"watch":watch,"capabilities":caps.as_ref().ok(),"apply_available":caps.is_ok()&&binding.is_ok()&&!self.unfinished(),"api":self.api_source_status(),"stack":self.stack_status(),"stack_pending":stack_pending,"stack_evidence_binding":binding.unwrap_or_else(|_|"unavailable".into())}),
        )
    }
    fn finding(
        &self,
        id: &str,
        kind: &str,
        title: &str,
        evidence: &str,
        config: &BTreeMap<String, fs::FileState>,
    ) -> Value {
        json!({"id":id,"kind":kind,"title":title,"evidence":evidence,"time":self.time(),"stale":false,"configuration":config,"repair":"Review a scoped plan before any configuration change.","expected_effect":"A scoped repair can address this finding; it does not establish Wallet acceptance.","risk":"Review a plan; ordinary Apply never clears data or reboots.","rollback":"Complete three-file snapshot before change; named rollback available.","verification":"Recheck local configuration and obtain fresh independent evidence.","dependency":"User/external service evidence may still be required."})
    }
    fn host_checks(&self) -> Value {
        let mut v = json!({"failure_evidence":"not observed; static matches do not establish a network failure","blocked_service_domains":[]});
        if self.fake {
            return v;
        }
        match fs::bounded(std::path::Path::new("/system/etc/hosts"), 32 << 20) {
            Err(_) => {
                v["inventory"] = json!("unavailable (mount/symlink/size); no blocklist was changed")
            }
            Ok(b) => {
                let mut blocked = Vec::new();
                for l in String::from_utf8_lossy(&b).lines() {
                    let fields: Vec<_> = l.split_whitespace().collect();
                    if fields.len() < 2 || !matches!(fields[0], "0.0.0.0" | "127.0.0.1" | "::") {
                        continue;
                    }
                    for h in &fields[1..] {
                        if [
                            "wallet.google.com",
                            "payments.google.com",
                            "android.clients.google.com",
                            "play.googleapis.com",
                            "www.googleapis.com",
                            "mtalk.google.com",
                        ]
                        .contains(h)
                        {
                            blocked.push((*h).to_owned());
                        }
                    }
                }
                v["blocked_service_domains"] = json!(blocked);
                v["hosts_hash"] = json!(util::hash(&b));
            }
        }
        v
    }
    pub fn diagnose(&self) -> Result<Value> {
        self.with_lock(|| {
            let v = self.status()?;
            fs::write_json(&self.root.join("diagnosis.json"), &v)?;
            Ok(v)
        })
    }
    pub fn verify(&self, wallet_ready: bool, tap: bool, reviewed_user: &str) -> Result<Value> {
        self.with_lock(|| {
            self.require_recovered()?;
            let j: Journal = fs::read_json(&self.root.join("journal.json")).map_err(|_| Error::new("E_VERIFY", "No committed operation is recorded. Run Diagnostics first."))?;
            self.validate_journal(&j)?;
            if j.state != "committed" {
                return Err(Error::new("E_RECOVERY", "Complete recovery before verification."));
            }
            let state = self.snapshot()?;
            if state != j.intended {
                return Err(Error::new("E_STALE", "Active files changed after commit. Verification is stale."));
            }
            let binding = self.stack_evidence_binding()?;
            let user = self.checkpoint("verification-current-user").and_then(|_| self.current_user());
            if wallet_ready || tap {
                if !crate::reset::valid_user(reviewed_user) {
                    return Err(Error::new("E_CONFIRM", "Readiness declarations require the numeric Android user from a fresh reviewed status."));
                }
                if user.is_err() {
                    return Err(Error::new("E_CAPABILITY", "The current Android user could not be verified; readiness declarations were not recorded.").with_data(json!({"current_android_user":"unavailable","wallet_readiness":"unverified","tap_to_pay":"unverified"})));
                }
                if user.as_deref().ok() != Some(reviewed_user) {
                    return Err(Error::new("E_STALE", "The Android user changed since readiness review. Refresh status and confirm the current user's evidence again."));
                }
            }
            let mut v = self.adoption()?;
            v["files_committed"] = json!(true);
            v["configuration"] = json!(state);
            v["stack_evidence_binding"] = json!(binding);
            v["time"] = json!(self.time());
            v["current_android_user"] = json!(user.as_deref().unwrap_or("unavailable"));
            v["wallet_readiness"] = json!(if wallet_ready {"user-confirmed"} else {"unverified"});
            v["tap_to_pay"] = json!(if tap {"user-confirmed"} else {"unverified"});
            self.checkpoint("before-verification-persist")?;
            if self.snapshot()? != state || self.stack_evidence_binding()? != binding || user.as_ref().is_ok_and(|u| self.current_user().as_ref().ok() != Some(u)) {
                return Err(Error::new("E_STALE", "Configuration, stack or user changed during verification. No readiness report was recorded."));
            }
            fs::write_json(&self.root.join("verification.json"), &v)?;
            Ok(v)
        })
    }
}

fn maps_contain(maps: &[u8], path: &str) -> bool {
    !path.is_empty()
        && maps
            .windows(path.len())
            .any(|entry| entry == path.as_bytes())
}

#[cfg(test)]
mod proc_tests {
    #[test]
    fn maps_search_survives_non_utf8_unrelated_mappings() {
        let maps = b"unrelated-\xff\n/data/adb/modules/tricky_store/service.apk\n";
        assert!(super::maps_contain(
            maps,
            "/data/adb/modules/tricky_store/service.apk"
        ));
        assert!(!super::maps_contain(
            maps,
            "/data/adb/modules/tricky_store/libtricky_store.so"
        ));
        assert!(!super::maps_contain(maps, ""));
    }
}
