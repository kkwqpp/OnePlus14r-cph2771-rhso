//! Native-testable UI policy. No DOM, shell execution, storage or private key material.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const TARGETS: [&str; 4] = [
    "com.google.android.apps.walletnfcrel",
    "com.google.android.gms",
    "com.android.vending",
    "com.google.android.gsf",
];
pub const STATES: [&str; 8] = [
    "applying",
    "writing",
    "committed",
    "restoring",
    "restored",
    "recovery-required",
    "unreadable",
    "superseded",
];
pub const FILES: [&str; 3] = ["keybox.xml", "security_patch.txt", "target.txt"];
pub const RESET_PHRASE: &str = "CLEAR WALLET AND GOOGLE SERVICES";
pub const COMPLETE_PHRASE: &str = "PIF ACTION AND GMS FORCE-STOP COMPLETED";
pub const STACK_RESOLVE_PHRASE: &str = "KEEP CURRENT STACK FILE";
pub const RESET_CLOSE_PHRASE: &str = "CLOSE INCOMPLETE RESET WITHOUT REPEATING";
pub const OMITTED: &str = "Sensitive content omitted; use a redacted backend report.";
pub fn profile_name(id: &str) -> Option<&'static str> {
    match id {
        "hma-scope" => Some("HMA explicit blacklist scope"),
        "brezygisk-unmount" => Some("BreZygisk unmount marker"),
        _ => None,
    }
}
pub fn get<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&Value::Null)
}
pub fn string(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}
pub fn yes(v: &Value) -> bool {
    v == &Value::Bool(true)
}
pub fn list(v: &Value) -> &[Value] {
    let a = v.as_array().map(Vec::as_slice).unwrap_or(&[]);
    &a[..a.len().min(100)]
}
fn matches(pattern: &str, text: &str) -> bool {
    Regex::new(pattern).unwrap().is_match(text)
}
pub fn id(v: &Value) -> bool {
    matches(r"^[a-f0-9]{32}$", string(v))
}
pub fn hash(v: &Value) -> bool {
    matches(r"^[a-f0-9]{64}$", string(v))
}
pub fn integer(v: &Value) -> Option<u64> {
    v.as_u64().filter(|n| *n <= 9_007_199_254_740_991)
}
pub fn safe_text(v: &Value, fallback: &str) -> String {
    let text = match v {
        Value::String(s) if !s.is_empty() => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => return fallback.into(),
    };
    if matches(
        r"(?i)-----BEGIN|-----END|(?:authorization|api[_ -]?token|private[_ -]?key)\s*[:=]",
        &text,
    ) || matches(r"[A-Za-z0-9+/]{180,}={0,2}", &text)
    {
        return OMITTED.into();
    }
    text.chars()
        .filter(|c| !matches!(*c as u32, 0..=8 | 11 | 12 | 14..=31 | 127))
        .take(1400)
        .collect()
}
pub fn encode_request(command: &str, args: &Value) -> Result<String, String> {
    if ![
        "status", "diagnose", "ingest", "validate", "plan", "apply", "verify", "backups",
        "rollback", "api", "watch", "recovery", "reset", "trust", "stack",
    ]
    .contains(&command)
    {
        return Err("Unsupported command.".into());
    }
    let a = args.as_object().ok_or("Invalid arguments.")?;
    if command == "api" {
        let action = string(get(args, "action"));
        if !["status", "config", "import"].contains(&action)
            || a.keys().any(|k| !["action", "path"].contains(&k.as_str()))
            || (action != "config" && a.contains_key("path"))
        {
            return Err(
                "API requests accept only an action and a private configuration filepath.".into(),
            );
        }
        if action == "config" {
            private_api_path(string(get(args, "path")))?;
        }
    }
    if command == "stack" {
        let action = string(get(args, "action"));
        let fields: &[&str] = match action {
            "plan" => &["action", "profile", "targets", "hide-packages", "enabled"],
            "apply" | "verify" | "rollback" => &["action", "id"],
            "resolve" => &["action", "id", "confirmation", "review_hash"],
            "status" => &["action"],
            _ => return Err("Unsupported stack request fields.".into()),
        };
        if a.keys().any(|k| !fields.contains(&k.as_str())) {
            return Err("Unsupported stack request fields.".into());
        }
        if ["apply", "verify", "rollback", "resolve"].contains(&action) && !id(get(args, "id")) {
            return Err("Use a reviewed stack operation ID.".into());
        }
        if action == "resolve"
            && (string(get(args, "confirmation")) != STACK_RESOLVE_PHRASE
                || !hash(get(args, "review_hash")))
        {
            return Err(
                "Inspect the current stack file and confirm its reviewed close-out.".into(),
            );
        }
        if action == "plan" {
            match string(get(args, "profile")) {
                "hma-scope" => {
                    if a.contains_key("enabled")
                        || stack_package_list(string(get(args, "targets")))?
                            .iter()
                            .any(|p| !TARGETS.contains(&p.as_str()))
                    {
                        return Err("Choose only supported explicit stack targets.".into());
                    }
                    stack_package_list(string(get(args, "hide-packages")))?;
                }
                "brezygisk-unmount" => {
                    if !["true", "false"].contains(&string(get(args, "enabled")))
                        || a.contains_key("targets")
                        || a.contains_key("hide-packages")
                    {
                        return Err("Choose only an explicit marker value for this profile.".into());
                    }
                }
                _ => return Err("Choose a supported stack profile.".into()),
            }
        }
    }
    for (name, value) in a {
        if !matches(r"^[a-z_-]{1,40}$", name)
            || value
                .as_str()
                .is_none_or(|s| s.encode_utf16().count() > 4096)
        {
            return Err("Invalid argument.".into());
        }
    }
    let bytes = serde_json::to_vec(&json!({"command":command,"args":args}))
        .map_err(|_| "Invalid request.")?;
    if bytes.len() > 16384 {
        return Err("Request is too large.".into());
    }
    let payload = URL_SAFE_NO_PAD.encode(bytes);
    if payload.len() > 16384 {
        return Err("Encoded request is too large.".into());
    }
    Ok(payload)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub schema: u32,
    pub ok: bool,
    pub code: String,
    pub message: String,
    pub time: String,
    pub data: Value,
}
pub fn read_result(stdout: &str) -> Result<Response, String> {
    if stdout.encode_utf16().count() > 1_048_576 {
        return Err("Backend response is missing or too large.".into());
    }
    let v: Value = serde_json::from_str(stdout).map_err(
        |_| "Backend returned an invalid response. Use the CLI status/recovery commands.",
    )?;
    if get(&v, "schema") != &json!(1)
        || get(&v, "ok").as_bool().is_none()
        || get(&v, "code").as_str().is_none()
        || get(&v, "message").as_str().is_none()
    {
        return Err(
            "Backend schema is unsupported. Reinstall matching UI and backend versions.".into(),
        );
    }
    Ok(Response {
        schema: 1,
        ok: yes(get(&v, "ok")),
        code: safe_text(get(&v, "code"), "Not established"),
        message: safe_text(get(&v, "message"), "Not established"),
        time: safe_text(get(&v, "time"), "Not established"),
        data: if get(&v, "data").is_object() || get(&v, "data").is_array() {
            get(&v, "data").clone()
        } else {
            json!({})
        },
    })
}
pub fn selection_value(
    id: &str,
    box_index: f64,
    key_index: f64,
    algorithm: &str,
) -> Result<String, String> {
    if !matches(r"^[A-Za-z0-9_-]{1,96}$", id)
        || [box_index, key_index]
            .iter()
            .any(|n| !n.is_finite() || *n < 0.0 || n.fract() != 0.0 || *n > 9_007_199_254_740_991.0)
        || !["ecdsa", "rsa"].contains(&algorithm)
    {
        return Err("Backend returned an unsupported selection.".into());
    }
    Ok(format!(
        "{id}:{}:{}:{algorithm}",
        box_index as u64, key_index as u64
    ))
}
pub fn compaction_counts(v: &Value) -> Result<Value, String> {
    let err = "Target compaction review is missing or inconsistent. Apply is blocked.";
    let fields = [
        "entries_before",
        "entries_after",
        "removed_entries",
        "packages_before",
    ];
    let n: Vec<u64> = fields
        .iter()
        .map(|k| integer(get(v, k)).ok_or(err))
        .collect::<Result<_, _>>()?;
    if n[1] > n[0] || n[2] != n[0] - n[1] || n[3] > n[0] {
        return Err(err.into());
    }
    Ok(fields
        .into_iter()
        .zip(n)
        .map(|(k, n)| (k.to_string(), json!(n)))
        .collect())
}
pub fn private_api_path(path: &str) -> Result<&str, String> {
    if !matches(
        r"^/data/adb/wallet_diagnostic/inbox/[A-Za-z0-9_-][A-Za-z0-9._-]{0,95}\.json$",
        path,
    ) || path.contains("..")
    {
        return Err(
            "Use a JSON filename inside the root-private inbox. Never enter a URL or credential."
                .into(),
        );
    }
    Ok(path)
}
pub fn api_status_view(v: &Value) -> Option<Value> {
    if string(get(v, "api_status")) != "generic-https-raw-xml"
        || string(get(v, "supported_format")) != "raw-xml"
    {
        return None;
    }
    let state = match string(get(v, "state")) {
        "unconfigured" => "unconfigured",
        "configured" => "configured",
        _ => "invalid",
    };
    let generation = if id(get(v, "source_generation")) {
        get(v, "source_generation").clone()
    } else {
        Value::Null
    };
    let configured = yes(get(v, "configured")) && state == "configured" && !generation.is_null();
    Some(
        json!({"api_status":"generic-https-raw-xml","supported_format":"raw-xml","state":state,"configured":configured,"available":configured && yes(get(v,"available")) && get(v,"exact_endpoint_available")==&json!(false) && get(v,"provider_contract_verified")==&json!(false),"auth_configured":yes(get(v,"auth_configured")),"source_generation":generation,"exact_endpoint_available":false,"provider_contract_verified":false}),
    )
}
fn api_error(code: &str) -> Option<&'static str> {
    Some(match code {
        "E_API_UNAVAILABLE" => {
            "No configured generic raw-XML source is available. The exact supplied endpoint remains unverified."
        }
        "E_API_CONFIG" => {
            "Private API configuration is invalid or unsupported. Review the private JSON file locally."
        }
        "E_API_SSRF" => "The configured source or resolved address is not allowed.",
        "E_API_TLS" => "HTTPS verification failed. No staged input was accepted.",
        "E_API_DNS" => "The configured source could not be resolved. No staged input was accepted.",
        "E_API_HTTP" => "The source did not return an accepted HTTPS response.",
        "E_API_FORMAT" => "The source response is not an accepted raw-XML input.",
        "E_API_LIMIT" => "The source request exceeded a supported time, size or rate limit.",
        "E_API_STALE" => "The saved source changed. Inspect status and repeat the explicit import.",
        "E_RECOVERY" => {
            "An unfinished reset or transaction blocks this operation. Inspect its state; do not repeat app-data clears."
        }
        "E_BUSY" => "Another operation is running. Let it finish before retrying.",
        "E_PATH" => "The private configuration file path or ownership is not accepted.",
        "E_IO" => "A private file operation failed. Inspect the file locally.",
        "E_VALIDATION" => "Mandatory keybox validation did not pass.",
        "E_INPUT" => "The staged input is not accepted.",
        "E_REQUEST" => "API request arguments are unsupported.",
        "E_CAPABILITY" => "This backend cannot perform the requested API network operation.",
        _ => return None,
    })
}
pub fn redact_api_value(r: &Value) -> Value {
    let d = get(r, "data");
    let mut data = api_status_view(d).unwrap_or(json!({}));
    if id(get(d, "id")) {
        data["id"] = get(d, "id").clone();
    }
    if integer(get(d, "bytes")).is_some_and(|n| n <= 1_048_576) {
        data["bytes"] = get(d, "bytes").clone();
    }
    let ok = yes(get(r, "ok"));
    let original = string(get(r, "code"));
    let code = if ok {
        "OK"
    } else if api_error(original).is_some() {
        original
    } else {
        "E_API"
    };
    let time = string(get(r, "time"));
    let time = if matches(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$",
        time,
    ) {
        time
    } else {
        ""
    };
    json!({"schema":1,"ok":ok,"code":code,"message":if ok{"API operation completed. Review the redacted result before the next action."}else{api_error(code).unwrap_or("API operation stopped. Inspect redacted status or use the CLI; provider details are withheld.")},"time":time,"data":data})
}
pub fn redact_api(r: &Response) -> Response {
    serde_json::from_value(redact_api_value(&serde_json::to_value(r).unwrap())).unwrap()
}
fn stack_reason(code: &str) -> &'static str {
    match code {
        "available" => "Supported capability is available.",
        "recovery_pending" => "A pending operation must be recovered before another change.",
        "unsupported_capability" => {
            "The installed component does not match a supported capability."
        }
        "unsupported_configuration" => {
            "The existing configuration is unsupported; no change is available."
        }
        "resource_unavailable" => "The required private configuration resource is unavailable.",
        _ => "Capability status is unsupported; no change is available.",
    }
}
pub fn stack_status_view(v: &Value) -> Option<Value> {
    if !get(v, "profiles").is_array()
        || !get(v, "allowed_targets").is_array()
        || get(v, "unfinished").as_bool().is_none()
        || !yes(get(v, "manual_reboot_required"))
        || string(get(v, "runtime_adoption")) != "unknown"
    {
        return None;
    }
    let profiles:Vec<Value>=list(get(v,"profiles")).iter().filter(|p|profile_name(string(get(p,"id"))).is_some()).map(|p|json!({"id":get(p,"id"),"available":yes(get(p,"available")) && string(get(p,"reason_code"))=="available","reason":stack_reason(string(get(p,"reason_code")))})).collect();
    let mut names = std::collections::HashSet::new();
    if profiles.iter().any(|p| !names.insert(string(get(p, "id")))) {
        return None;
    }
    let op = get(v, "operation");
    let operation = if id(get(op, "id")) && profile_name(string(get(op, "profile"))).is_some() {
        json!({"id":get(op,"id"),"profile":get(op,"profile"),"state":if STATES.contains(&string(get(op,"state"))){string(get(op,"state"))}else{"unknown"},"can_verify":yes(get(op,"can_verify")),"can_rollback":yes(get(op,"can_rollback")),"backup_available":yes(get(op,"backup_available")),"can_resolve":yes(get(op,"can_resolve")) && hash(get(op,"resolution_review_hash")),"resolution_review_hash":if hash(get(op,"resolution_review_hash")){get(op,"resolution_review_hash")}else{&Value::Null}})
    } else {
        Value::Null
    };
    let targets: Vec<_> = TARGETS
        .into_iter()
        .filter(|p| list(get(v, "allowed_targets")).contains(&json!(p)))
        .collect();
    Some(
        json!({"profiles":profiles,"allowed_targets":targets,"unfinished":get(v,"unfinished"),"stack_pending":yes(get(v,"stack_pending")),"operation":operation}),
    )
}
pub fn stack_package_list(value: &str) -> Result<Vec<String>, String> {
    if value.encode_utf16().count() > 2048 {
        return Err("Enter a bounded comma-separated package list.".into());
    }
    let p: Vec<_> = value.split(',').map(str::trim).collect();
    if p.len() > 32
        || p.iter().any(|p| {
            p.len() > 255 || !matches(r"^([A-Za-z][A-Za-z0-9_]*\.)+[A-Za-z][A-Za-z0-9_]*$", p)
        })
    {
        return Err("Enter dotted package identifiers only, separated by commas.".into());
    }
    let mut out = Vec::new();
    for name in p {
        if !out.iter().any(|p| p == name) {
            out.push(name.to_owned());
        }
    }
    Ok(out)
}
pub fn stack_plan_view(v: &Value) -> Result<Value, String> {
    let profile = string(get(v, "profile"));
    let changes = list(get(v, "changes"));
    if !id(get(v, "id"))
        || profile_name(profile).is_none()
        || !yes(get(v, "manual_reboot_required"))
        || string(get(v, "runtime_adoption")) != "unknown"
        || string(get(v, "private_backup")) != "created-on-apply"
        || changes.is_empty()
        || changes.len() > 4
    {
        return Err(
            "Stack plan lacks a supported review and private backup policy. Apply is blocked."
                .into(),
        );
    }
    let mut rows = Vec::new();
    let mut targets = std::collections::HashSet::new();
    let mut positive = false;
    for c in changes {
        match profile {
        "hma-scope" if TARGETS.contains(&string(get(c,"target"))) && integer(get(c,"added_count")).is_some_and(|n|n<=32) && integer(get(c,"scopes_created")).is_some_and(|n|n<=1)=>{if !targets.insert(string(get(c,"target"))){return Err("Stack plan has duplicate, absent or ambiguous changes. Apply is blocked.".into());}positive |= integer(get(c,"added_count")).unwrap()>0;rows.push(json!({"target":get(c,"target"),"added_count":get(c,"added_count"),"scopes_created":get(c,"scopes_created")}));},
        "brezygisk-unmount" if get(c,"enabled_before").is_boolean() && get(c,"enabled_after").is_boolean() && get(c,"enabled_before")!=get(c,"enabled_after")=>rows.push(json!({"enabled_before":get(c,"enabled_before"),"enabled_after":get(c,"enabled_after")})),
        _=>return Err("Stack plan has unsupported change details. Apply is blocked.".into())
    }
    }
    if profile == "hma-scope" && !positive || profile == "brezygisk-unmount" && rows.len() != 1 {
        return Err(
            "Stack plan has duplicate, absent or ambiguous changes. Apply is blocked.".into(),
        );
    }
    Ok(json!({"id":get(v,"id"),"profile":profile,"changes":rows}))
}
fn stack_error(code: &str) -> Option<&'static str> {
    Some(match code {
        "E_RECOVERY" => {
            "A stack write needs recovery, or another reset/transaction is unfinished. Inspect status and restore only the matching private backup."
        }
        "E_ROLLED_BACK" => {
            "The stack write stopped and its previous files were restored. Inspect status before another change."
        }
        "E_STALE" => "Current stack files, code or review evidence changed. Build a fresh plan.",
        "E_CAPABILITY" => "The installed stack component or current Android user is unsupported.",
        "E_SELECTION" => "The explicit stack selections are not accepted.",
        "E_NO_CHANGES" => "The selected stack profile has no supported changes to apply.",
        "E_BUSY" => "Another operation is running. Let it finish; never remove its live lock.",
        "E_IO" => "A stack file operation stopped. Inspect the journal and private backup.",
        "E_REQUEST" => "Stack request arguments are unsupported.",
        "E_FORMAT" => "The stored stack plan or journal is unsupported or corrupt.",
        "E_BACKUP" => {
            "The private stack backup is unavailable or failed integrity checks. Preserve the recovery evidence."
        }
        "E_NOT_FOUND" => "The reviewed stack operation is unavailable.",
        _ => return None,
    })
}
pub fn redact_stack_value(r: &Value) -> Value {
    let original = string(get(r, "code"));
    let code = if stack_error(original).is_some() {
        original
    } else {
        "E_STACK"
    };
    json!({"schema":1,"ok":false,"code":code,"message":stack_error(code).unwrap_or("Stack operation stopped. Inspect redacted capabilities and recovery state; private details are withheld."),"time":"","data":{}})
}
pub fn redact_stack(r: &Response) -> Response {
    serde_json::from_value(redact_stack_value(&serde_json::to_value(r).unwrap())).unwrap()
}
pub fn evidence_binding(v: &Value) -> Option<String> {
    let config = v.get("active").or_else(|| v.get("configuration"))?;
    let user = v
        .get("device")
        .and_then(|d| d.get("current_android_user"))
        .or_else(|| v.get("current_android_user"))?;
    if !matches(r"^(0|[1-9][0-9]{0,5})$", string(user)) {
        return None;
    }
    let stack = v.get("stack_evidence_binding");
    if stack.is_some_and(|s| !hash(s)) {
        return None;
    }
    let mut files = Vec::new();
    for name in FILES {
        let f = config.get(name)?;
        let exists = get(f, "exists").as_bool()?;
        if !exists {
            files.push(json!([name, false]));
            continue;
        }
        let m = get(f, "metadata");
        if !hash(get(f, "sha256"))
            || integer(get(f, "size")).is_none()
            || integer(get(m, "uid")).is_none()
            || integer(get(m, "gid")).is_none()
            || integer(get(m, "mode")).is_none_or(|n| n > 511)
            || m.get("selinux").is_some_and(|v| !v.is_string())
        {
            return None;
        }
        files.push(json!([
            name,
            true,
            get(f, "sha256"),
            get(f, "size"),
            get(m, "uid"),
            get(m, "gid"),
            get(m, "mode"),
            string(get(m, "selinux"))
        ]));
    }
    Some(
        if let Some(stack) = stack {
            json!([user, files, stack])
        } else {
            json!([user, files])
        }
        .to_string(),
    )
}
pub fn needs_recovery(v: &Value) -> bool {
    yes(get(v, "pending"))
        || yes(get(v, "required"))
        || yes(get(v, "interrupted"))
        || get(v, "state")
            .as_str()
            .is_some_and(|s| !["none", "committed", "restored"].contains(&s))
}
