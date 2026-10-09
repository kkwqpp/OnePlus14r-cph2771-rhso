use crate::{
    App,
    error::{Error, Result},
    util,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub command: String,
    #[serde(default, deserialize_with = "null_map")]
    pub args: BTreeMap<String, String>,
}
fn null_map<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error> {
    Ok(Option::<BTreeMap<String, String>>::deserialize(d)?.unwrap_or_default())
}
#[derive(Serialize)]
pub struct Response {
    pub schema: u32,
    pub ok: bool,
    pub code: String,
    pub message: String,
    pub time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}
fn invalid() -> Error {
    Error::new(
        "E_REQUEST",
        "Invalid command request. Run help for exact options.",
    )
}
pub fn parse(args: &[String]) -> Result<Request> {
    let mut r = Request {
        command: args.first().cloned().unwrap_or_else(|| "help".into()),
        args: BTreeMap::new(),
    };
    if r.command == "request" {
        if args.len() != 2 || args[1].len() > 16384 {
            return Err(invalid());
        }
        let b = URL_SAFE_NO_PAD.decode(&args[1]).map_err(|_| invalid())?;
        util::strict_json(&b).map_err(|_| invalid())?;
        r = serde_json::from_slice(&b).map_err(|_| invalid())?;
    } else {
        let mut i = 1;
        while i < args.len() {
            if args[i] == "--json" {
                i += 1;
                continue;
            }
            let k = args[i]
                .strip_prefix("--")
                .filter(|s| !s.is_empty())
                .ok_or_else(invalid)?;
            if i + 1 >= args.len() || r.args.insert(k.into(), args[i + 1].clone()).is_some() {
                return Err(invalid());
            }
            i += 2;
        }
    }
    if let Some(v) = r.args.remove("review_hash")
        && r.args.insert("review-hash".into(), v).is_some()
    {
        return Err(invalid());
    }
    let options: &[&str] = match r.command.as_str() {
        "help" | "init" | "status" | "diagnose" | "export" | "backups" => &[],
        "ingest" => &["path"],
        "validate" | "apply" | "rollback" => &["id"],
        "plan" => &["selections", "targets", "compact-targets", "patch"],
        "verify" => &["wallet-ready", "tap-confirmed", "reviewed-user"],
        "trust" => &["action"],
        "api" => &["action", "path"],
        "stack" => &[
            "action",
            "profile",
            "targets",
            "hide-packages",
            "enabled",
            "id",
            "confirmation",
            "review-hash",
        ],
        "watch" => &["days"],
        "recovery" => &["action"],
        "reset" => &["action", "confirmation", "review-hash"],
        _ => return Err(invalid()),
    };
    for (k, v) in &r.args {
        if !options.contains(&k.as_str()) || v.len() > 8192 || v.contains('\0') {
            return Err(invalid());
        }
        if (k == "targets" && r.command == "plan"
            || matches!(
                k.as_str(),
                "compact-targets" | "enabled" | "wallet-ready" | "tap-confirmed"
            ))
            && !matches!(v.as_str(), "true" | "false")
        {
            return Err(invalid());
        }
    }
    Ok(r)
}
pub fn execute(a: &App, args: &[String]) -> Response {
    let result = parse(args).and_then(|r| {
        let get = |k: &str| r.args.get(k).map(String::as_str).unwrap_or("");
        let yes = |k: &str| get(k) == "true";
        match r.command.as_str() {
            "help" => Ok(json!({"help":HELP})),
            "init" => {
                a.init()?;
                Ok(json!({"state":"private-storage-ready"}))
            }
            "status" => a.status(),
            "diagnose" | "export" => a.diagnose(),
            "backups" => a.backups(),
            "ingest" => a.ingest(get("path")),
            "validate" => a.validate(get("id")),
            "plan" => a.plan(
                get("selections"),
                yes("targets"),
                get("patch"),
                yes("compact-targets"),
            ),
            "apply" => a.apply(get("id")),
            "verify" => a.verify(
                yes("wallet-ready"),
                yes("tap-confirmed"),
                get("reviewed-user"),
            ),
            "trust" => a.trust(get("action")),
            "rollback" => a.rollback(get("id")),
            "api" => a.api(get("action"), get("path")),
            "stack" => a.stack_confirmed(
                get("action"),
                get("profile"),
                get("targets"),
                get("hide-packages"),
                get("enabled"),
                get("id"),
                get("confirmation"),
                get("review-hash"),
            ),
            "watch" => a.watch(if get("days").is_empty() {
                14
            } else {
                get("days").parse().map_err(|_| invalid())?
            }),
            "recovery" => a.recovery(get("action")),
            "reset" => a.reset(get("action"), get("confirmation"), get("review-hash")),
            _ => Err(invalid()),
        }
    });
    match result {
        Ok(v) => Response {
            schema: 1,
            ok: true,
            code: "OK".into(),
            message: "Completed".into(),
            time: a.time(),
            data: Some(v),
        },
        Err(e) => Response {
            schema: 1,
            ok: false,
            code: e.code,
            message: e.message,
            time: a.time(),
            data: e.data,
        },
    }
}
pub fn human(r: &Response) {
    if let Some(v) = &r.data
        && let Some(s) = v["help"].as_str()
    {
        print!("{s}");
        return;
    }
    println!("{}: {}", r.code, r.message);
    if let Some(v) = &r.data {
        for k in [
            "id",
            "backup",
            "state",
            "adoption",
            "engine_health",
            "wallet_acceptance",
            "wallet_readiness",
            "tap_to_pay",
            "evidence_time",
            "message",
            "next_step",
        ] {
            if let Some(s) = v[k].as_str() {
                println!("{}: {s}", k.replace('_', " "));
            }
        }
        if v.get("preview").is_some() {
            println!("Review exact changes and warnings with --json before applying this plan.");
        }
        println!("Use --json for the complete redacted result.");
    }
}
pub const HELP: &str = r#"RHSO 0.3.0 — Rust backend and WebAssembly WebUI, no daemon
Persistent private state: /data/adb/wallet_diagnostic
Commands (optional --json; results are redacted):
  help | init | status | diagnose | export | backups
  ingest --path ROOT_PRIVATE_OR_ALLOWED_INBOX_XML
  validate --id INPUT_ID
  plan --selections INPUT_ID:0:0:ecdsa,OTHER_ID:0:0:rsa
       [--targets true] [--compact-targets true] [--patch YYYY-MM-DD]
  apply --id PLAN_ID
  verify [--wallet-ready true] [--tap-confirmed true] [--reviewed-user NUMERIC_USER]
  trust --action status|refresh
  rollback --id previous|last-verified|BACKUP_ID
  api --action status|config|import [--path ROOT_PRIVATE_JSON]
  stack --action status|plan|apply|verify|rollback
        [--profile hma-scope|brezygisk-unmount] [--id PLAN_ID]
        [--targets GOOGLE_PACKAGE_CSV] [--hide-packages PACKAGE_CSV]
        [--enabled true|false]
  stack --action resolve --id OPERATION_ID
        --confirmation 'KEEP CURRENT STACK FILE' --review-hash RESOLUTION_REVIEW_HASH
  watch [--days 14]
  recovery --action status|restore|release-lock
  reset --action preview|status|confirm|resume|complete
        --confirmation 'EXACT PHRASE FROM PREVIEW' --review-hash SHA256
  reset --action close --confirmation 'CLOSE INCOMPLETE RESET WITHOUT REPEATING'
        --review-hash CLOSE_REVIEW_HASH
Read close-out hashes from fresh stack/reset status. Close-outs preserve evidence;
they never restore resources, repeat clears or claim completed reset steps.
Use reviewed plans before Apply. No ordinary command clears data or reboots.
No bootloader, partition-writing or other attestation-engine functionality.
"#;
