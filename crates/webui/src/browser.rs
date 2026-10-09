//! Browser controller. Every project-owned workflow and validation runs in Rust.
use crate::core::{self, Response, get as g, list, string as s, yes};
use js_sys::{Function, Promise, Reflect};
use regex::Regex;
use serde_json::{Value, json};
use std::{cell::RefCell, rc::Rc};
use wasm_bindgen::{JsCast, prelude::*};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{Document, Element, Event, Window};

#[derive(Clone)]
struct Input {
    id: String,
    summary: Value,
    source: String,
}
#[derive(Default)]
struct State {
    busy: bool,
    bridge: bool,
    inputs: Vec<Input>,
    plan: Option<String>,
    reset: Option<String>,
    reset_close_review: Option<String>,
    reset_pending: bool,
    stack_pending: bool,
    recovery: bool,
    lock_present: bool,
    apply_available: bool,
    evidence: Option<String>,
    user: Option<String>,
    verification: Option<String>,
    verification_seen: bool,
    diagnostic: Option<String>,
    api_supported: bool,
    api_ready: bool,
    api_generation: Option<String>,
    api_stage: Option<String>,
    stack: Option<Value>,
    stack_plan: Option<Value>,
    stack_plan_binding: Option<String>,
    stack_rollback_binding: Option<String>,
}
struct App {
    document: Document,
    window: Window,
    bridge: Function,
    state: RefCell<State>,
}
#[derive(Debug)]
struct Failure {
    message: String,
    response: Option<Response>,
}
impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self {
            message,
            response: None,
        }
    }
}
impl From<&str> for Failure {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}
type Result<T> = std::result::Result<T, Failure>;
fn text(v: &Value) -> String {
    core::safe_text(v, "Not established")
}
fn fallback(v: &Value, default: &str) -> String {
    core::safe_text(v, default)
}
fn first<'a>(values: &[&'a Value]) -> &'a Value {
    values
        .iter()
        .find(|v| !v.is_null() && ***v != json!(""))
        .copied()
        .unwrap_or(&Value::Null)
}
fn valid(pattern: &str, value: &str) -> bool {
    Regex::new(pattern).unwrap().is_match(value)
}
fn prop(el: &Element, key: &str, value: &JsValue) {
    let _ = Reflect::set(el.as_ref(), &key.into(), value);
}
fn string_prop(el: &Element, key: &str) -> String {
    Reflect::get(el.as_ref(), &key.into())
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default()
}
fn bool_prop(el: &Element, key: &str) -> bool {
    Reflect::get(el.as_ref(), &key.into())
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

impl App {
    fn el(&self, id: &str) -> Element {
        self.document
            .get_element_by_id(id)
            .expect("declarative DOM contract")
    }
    fn all(&self, query: &str) -> Vec<Element> {
        self.document
            .query_selector_all(query)
            .ok()
            .map(|n| {
                (0..n.length())
                    .filter_map(|i| n.get(i)?.dyn_into().ok())
                    .collect()
            })
            .unwrap_or_default()
    }
    fn node(&self, tag: &str, content: Option<&str>, class: &str) -> Element {
        let el = self.document.create_element(tag).unwrap();
        if let Some(v) = content {
            el.set_text_content(Some(&text(&json!(v))));
        }
        if !class.is_empty() {
            el.set_class_name(class);
        }
        el
    }
    fn append(&self, parent: &Element, child: &Element) {
        let _ = parent.append_child(child);
    }
    fn p(&self, parent: &Element, value: &str) {
        self.append(parent, &self.node("p", Some(value), ""));
    }
    fn clear(&self, id: &str) -> Element {
        let el = self.el(id);
        el.set_text_content(None);
        el
    }
    fn set(&self, id: &str, value: &str) {
        self.el(id).set_text_content(Some(&text(&json!(value))));
    }
    fn hidden(&self, id: &str, value: bool) {
        prop(&self.el(id), "hidden", &value.into());
    }
    fn disabled(&self, id: &str, value: bool) {
        prop(&self.el(id), "disabled", &value.into());
    }
    fn checked(&self, id: &str) -> bool {
        bool_prop(&self.el(id), "checked")
    }
    fn check(&self, id: &str, value: bool) {
        prop(&self.el(id), "checked", &value.into());
    }
    fn value(&self, id: &str) -> String {
        string_prop(&self.el(id), "value")
    }
    fn set_value(&self, id: &str, value: &str) {
        prop(&self.el(id), "value", &value.into());
    }
    fn class(&self, id: &str, name: &str, value: bool) {
        let _ = self.el(id).class_list().toggle_with_force(name, value);
    }
    fn selected(&self, query: &str) -> Vec<String> {
        self.all(query)
            .iter()
            .map(|el| string_prop(el, "value"))
            .filter(|s| !s.is_empty())
            .collect()
    }
    fn notice(&self, message: &str, error: bool) {
        self.set("notice", message);
        self.class("notice", "error", error);
    }
    fn pairs(&self, id: &str, entries: Vec<(&str, String)>) {
        let el = self.clear(id);
        self.dl(&el, entries);
    }
    fn dl(&self, el: &Element, entries: Vec<(&str, String)>) {
        for (k, v) in entries {
            self.append(el, &self.node("dt", Some(k), ""));
            self.append(el, &self.node("dd", Some(&v), ""));
        }
    }
    fn items(&self, el: &Element, values: &Value) {
        let ul = self.node("ul", None, "");
        for v in list(values) {
            if let Some(v) = v.as_str() {
                self.append(&ul, &self.node("li", Some(warning(v)), ""));
            }
        }
        if ul.child_element_count() > 0 {
            self.append(el, &ul);
        }
    }
    fn show(&self, view: &str) {
        for el in self.all(".view") {
            prop(&el, "hidden", &(el.id() != view).into());
        }
        for el in self.all("nav [data-view]") {
            if el.get_attribute("data-view").as_deref() == Some(view) {
                let _ = el.set_attribute("aria-current", "page");
            } else {
                let _ = el.remove_attribute("aria-current");
            }
        }
        if let Ok(main) = self.el("main").dyn_into::<web_sys::HtmlElement>() {
            let opts = web_sys::FocusOptions::new();
            opts.set_prevent_scroll(true);
            let _ = main.focus_with_options(&opts);
        }
    }
    fn sync(&self) {
        let st = self.state.borrow();
        let base = st.busy || !st.bridge;
        for el in self.all("[data-action]") {
            prop(&el, "disabled", &base.into());
        }
        self.disabled(
            "apply-button",
            base || !st.apply_available || st.plan.is_none() || !self.checked("apply-confirm"),
        );
        self.disabled("plan-button", base || !st.apply_available);
        self.disabled("rollback-button", base || !self.checked("rollback-confirm"));
        self.disabled(
            "recovery-button",
            base || !st.recovery || !self.checked("recovery-confirm"),
        );
        self.disabled("release-lock-button", base || !st.lock_present);
        self.disabled(
            "reset-button",
            base || st.reset.is_none() || self.value("reset-phrase") != core::RESET_PHRASE,
        );
        self.disabled(
            "reset-complete-button",
            base || self.value("reset-complete-phrase") != core::COMPLETE_PHRASE,
        );
        self.disabled(
            "reset-close-button",
            base || st.reset_close_review.is_none()
                || self.value("reset-close-phrase") != core::RESET_CLOSE_PHRASE,
        );
        for el in self.all("input,select") {
            prop(&el, "disabled", &st.busy.into());
        }
        self.disabled("compact-targets", base || !st.apply_available);
        let blocked = base || st.reset_pending || st.recovery || st.stack_pending;
        self.disabled("api-config-button", blocked || !st.api_supported);
        self.disabled("api-config-path", blocked || !st.api_supported);
        self.disabled("api-import-button", blocked || !st.api_ready);
        self.disabled("api-validate-button", blocked || st.api_stage.is_none());
        let profile = self.value("stack-profile");
        let stack = st.stack.as_ref().unwrap_or(&Value::Null);
        let cap = list(g(stack, "profiles"))
            .iter()
            .find(|p| s(g(p, "id")) == profile)
            .unwrap_or(&Value::Null);
        self.disabled("stack-plan-button", blocked || !yes(g(cap, "available")));
        self.disabled(
            "stack-apply-button",
            blocked || st.stack_plan.is_none() || !self.checked("stack-apply-confirm"),
        );
        self.hidden("stack-hma-fields", profile != "hma-scope");
        self.hidden("stack-marker-fields", profile != "brezygisk-unmount");
        for el in self.all("[name='stack-target']") {
            prop(
                &el,
                "disabled",
                &(blocked
                    || !list(g(stack, "allowed_targets"))
                        .contains(&json!(string_prop(&el, "value"))))
                .into(),
            );
        }
        let op = g(stack, "operation");
        let operation_id = self.value("stack-operation-id");
        let matching = s(g(op, "id")) == operation_id;
        self.disabled(
            "stack-resolve-button",
            base || !matching
                || !yes(g(op, "can_resolve"))
                || self.value("stack-resolve-phrase") != core::STACK_RESOLVE_PHRASE,
        );
        self.disabled(
            "stack-verify-button",
            base || !core::id(&json!(operation_id)) || !matching || !yes(g(op, "can_verify")),
        );
        self.disabled(
            "stack-rollback-button",
            base || st.reset_pending
                || st.recovery
                || !matching
                || !yes(g(op, "can_rollback"))
                || st.stack_rollback_binding.is_none()
                || st.stack_rollback_binding != st.evidence
                || !self.checked("stack-rollback-confirm"),
        );
        self.set("stack-blocker",if st.reset_pending||st.recovery||st.stack_pending{"A pending reset or transaction blocks new stack changes. Inspect its state and use the matching explicit recovery action."}else if yes(g(cap,"available")){"Review every selected target and package; a manual reboot follows Apply and rollback."}else{g(cap,"reason").as_str().unwrap_or("Inspect capabilities and choose a supported profile. Nothing is selected automatically.")});
        self.class("notice", "busy", st.busy);
        let _ = self
            .el("main")
            .set_attribute("aria-busy", if st.busy { "true" } else { "false" });
        for el in self.all("[data-view]") {
            prop(&el, "disabled", &st.busy.into());
        }
    }
    async fn request(
        self: &Rc<Self>,
        command: &str,
        args: Value,
        progress: &str,
        private_result: bool,
    ) -> Result<Response> {
        {
            let st = self.state.borrow();
            if st.busy {
                return Err("An operation is already running.".into());
            }
            if !st.bridge {
                return Err(
                    "WebUI root bridge unavailable. Use the exact CLI entry point in Advanced."
                        .into(),
                );
            }
        }
        let payload = core::encode_request(command, &args)?;
        self.state.borrow_mut().busy = true;
        self.sync();
        self.notice(progress, false);
        let outcome=async {
            let called=self.bridge.call1(&JsValue::NULL,&format!("/data/adb/modules/wallet_diagnostic/bin/walletdiag request {payload}").into()).map_err(|_|Failure::from("The root bridge did not return a result. Inspect recovery before another write."))?;
            let output=JsFuture::from(Promise::resolve(&called)).await.map_err(|_|Failure::from("The root bridge stopped before a backend result. Inspect recovery before another write."))?;
            let stdout=Reflect::get(&output,&"stdout".into()).ok().and_then(|v|v.as_string()).unwrap_or_default();
            let mut r=core::read_result(&stdout)?;
            if command=="api"{r=core::redact_api(&r);}else if command=="stack"&&!r.ok{r=core::redact_stack(&r);}else if private_result{let redacted=core::redact_api(&r);r.code=redacted.code;r.message=redacted.message;if !r.ok{r.data=redacted.data;}}
            let errno=Reflect::get(&output,&"errno".into()).ok().and_then(|v|v.as_f64()).unwrap_or(0.0);
            if errno!=0.0&&r.ok{return Err("Backend ended unexpectedly despite a success-shaped response. Inspect recovery before another write.".into());}
            let notice = if r.ok {
                format!("Complete. {}", r.message)
            } else {
                format!("Stopped · {}: {}", r.code, r.message)
            };
            self.notice(&notice, !r.ok);
            if !r.ok{return Err(Failure{message:r.message.clone(),response:Some(r)});}Ok(r)
        }.await;
        self.state.borrow_mut().busy = false;
        self.sync();
        outcome
    }
    async fn req(self: &Rc<Self>, command: &str, args: Value, progress: &str) -> Result<Response> {
        self.request(command, args, progress, false).await
    }
    fn invalidate_verification(&self, reason: &str) {
        self.check("wallet-ready", false);
        self.check("tap-confirmed", false);
        let mut st = self.state.borrow_mut();
        if st.verification_seen || self.el("verification-result").child_element_count() > 0 {
            let el = self.clear("verification-result");
            self.p(&el,&format!("Previous verification is no longer current. {reason} Collect fresh verification and repeat any user checks after the relevant change."));
            self.set("apply-result", "");
        }
        st.verification_seen = false;
        st.verification = None;
    }
    fn record_verification(&self, r: &Response) {
        self.describe("verification-result", r);
        self.p(&self.el("verification-result"), "Saving files does not prove the engine loaded them. Local checks do not establish Wallet approval; check setup and a real tap privately.");
        let binding = core::evidence_binding(&r.data);
        {
            let mut st = self.state.borrow_mut();
            st.verification_seen = true;
            st.verification = binding.clone();
            if binding.is_some() {
                st.evidence = binding.clone();
                st.user = g(&r.data, "current_android_user")
                    .as_str()
                    .map(str::to_owned);
            }
        }
        if binding.is_none() {
            self.p(&self.el("verification-result"),"Configuration/user binding is unavailable. This result is historical evidence; collect current status and repeat user checks before relying on readiness.");
        }
    }
    fn finding(&self, el: &Element, f: &Value) {
        if !f.is_object() {
            return;
        }
        let card = self.node("article", None, "card");
        self.append(
            &card,
            &self.node(
                "h3",
                Some(&fallback(first(&[g(f, "title"), g(f, "code")]), "Finding")),
                "",
            ),
        );
        self.p(
            &card,
            &text(first(&[g(f, "message"), g(f, "summary"), g(f, "evidence")])),
        );
        let dl = self.node("dl", None, "");
        self.dl(
            &dl,
            vec![
                (
                    "Evidence type",
                    fallback(
                        first(&[g(f, "kind"), g(f, "certainty")]),
                        "Hypothesis / evidence limits unspecified",
                    ),
                ),
                (
                    "Collected",
                    text(first(&[g(f, "collected_at"), g(f, "time")])),
                ),
                (
                    "Freshness",
                    if yes(g(f, "stale")) {
                        "Stale — collect again".into()
                    } else {
                        fallback(g(f, "freshness"), "Recheck after relevant changes")
                    },
                ),
            ],
        );
        self.append(&card, &dl);
        let detail = self.node("details", None, "");
        self.append(
            &detail,
            &self.node("summary", Some("Evidence, repair and verification"), ""),
        );
        for (k, v) in [
            ("Evidence", g(f, "evidence")),
            ("Expected effect", g(f, "expected_effect")),
            (
                "Proposed repair",
                first(&[g(f, "repair"), g(f, "proposed_repair")]),
            ),
            ("Risk", g(f, "risk")),
            ("Rollback", g(f, "rollback")),
            ("Verify with", g(f, "verification")),
            (
                "Dependencies / uncertainty",
                first(&[
                    g(f, "dependency"),
                    g(f, "dependencies"),
                    g(f, "uncertainty"),
                ]),
            ),
        ] {
            if v.is_string() {
                self.p(&detail, &format!("{k}: {}", text(v)));
            } else if v.is_array() {
                self.p(&detail, k);
                self.items(&detail, v);
            }
        }
        self.append(&card, &detail);
        self.append(el, &card);
    }
    fn findings(&self, id: &str, values: &Value) {
        let el = self.clear(id);
        for f in list(values) {
            self.finding(&el, f);
        }
        if el.child_element_count() == 0 {
            self.p(
                &el,
                "No findings in this response. This does not establish Wallet acceptance.",
            );
        }
    }
    fn describe(&self, id: &str, r: &Response) {
        let d = &r.data;
        let el = self.clear(id);
        self.p(&el, &fallback(g(d, "message"), &r.message));
        let dl = self.node("dl", None, "");
        if d.get("user").is_some() {
            self.dl(
                &dl,
                vec![("Reviewed numeric Android user", text(g(d, "user")))],
            );
        }
        let reboot = first(&[g(d, "manual_reboot_required"), g(d, "reboot_required")]);
        self.dl(
            &dl,
            vec![
                (
                    "Files saved",
                    text(first(&[g(d, "files_committed"), g(d, "committed")])),
                ),
                (
                    "Engine health",
                    text(first(&[
                        g(d, "engine_health"),
                        g(d, "health"),
                        g(g(d, "engine"), "health"),
                    ])),
                ),
                (
                    "Engine using this configuration",
                    text(first(&[g(d, "adoption"), g(d, "engine_adoption")])),
                ),
                (
                    "Wallet readiness",
                    fallback(g(d, "wallet_readiness"), "User test required"),
                ),
                (
                    "Tap-to-Pay",
                    fallback(g(d, "tap_to_pay"), "User test required"),
                ),
                (
                    "Wallet acceptance",
                    fallback(g(d, "wallet_acceptance"), "User test required"),
                ),
                ("Operation / journal state", text(g(d, "state"))),
                ("Lock present", text(g(d, "lock_present"))),
                (
                    "Manual reboot",
                    match reboot.as_bool() {
                        Some(true) => "Required by reviewed procedure; never automatic",
                        Some(false) => "Not required by this result",
                        None => "Not established",
                    }
                    .into(),
                ),
                ("Evidence collected", r.time.clone()),
            ],
        );
        self.append(&el, &dl);
        for k in ["identity_evidence", "next_step"] {
            if g(d, k).is_string() {
                self.p(&el, &text(g(d, k)));
            }
        }
        self.items(&el, g(d, "warnings"));
        for f in list(g(d, "findings")) {
            self.finding(&el, f);
        }
    }
    fn diagnostic_context(&self, d: &Value) {
        let el = self.clear("diagnostic-context");
        let device = g(d, "device");
        let dl = self.node("dl", None, "");
        self.dl(
            &dl,
            [
                ("Wallet stage", "wallet_stage"),
                ("Generic integrity", "generic_integrity"),
                ("Real bootloader", "real_bootloader"),
                ("Current numeric Android user", "current_android_user"),
                ("Wallet role", "wallet_role"),
                ("NFC", "nfc"),
                ("Default contactless payment", "default_payment"),
                ("Automatic time", "automatic_time"),
                ("Device time", "device_time"),
                ("Validated connectivity", "validated_connectivity"),
                ("Persistent aliases counted", "persistent_alias_count"),
                ("Alias limits", "persistent_alias_warning"),
                ("Certification", "certification"),
                ("Issuer / region / account limits", "issuer_region_account"),
            ]
            .into_iter()
            .map(|(label, key)| (label, text(g(device, key))))
            .collect(),
        );
        self.append(&el, &dl);
        for app in list(g(d, "applications")) {
            if app.is_object() {
                self.p(
                    &el,
                    &format!(
                        "{} · Version {} · Current UID {}",
                        text(g(app, "package")),
                        text(g(app, "version")),
                        text(g(app, "uid"))
                    ),
                );
            }
        }
        let network = g(device, "network_checks");
        if network.is_object() {
            self.p(&el, &text(g(network, "failure_evidence")));
            self.items(&el, g(network, "blocked_service_domains"));
        }
    }
    fn status(&self, r: &Response) {
        let d = &r.data;
        let active = g(d, "active");
        let last = g(d, "last_operation");
        let binding = core::evidence_binding(d);
        let (changed, stale_verify, stale_diagnostic, stale_stack) = {
            let st = self.state.borrow();
            (
                st.evidence.is_some() && st.evidence != binding,
                st.verification_seen && (binding.is_none() || st.verification != binding),
                st.diagnostic.is_some() && st.diagnostic != binding,
                st.stack_plan.is_some() && st.stack_plan_binding != binding,
            )
        };
        if changed {
            self.check("stack-rollback-confirm", false);
            self.state.borrow_mut().stack_rollback_binding = None;
        }
        if stale_stack {
            self.discard_stack_plan("Current configuration, stack evidence or numeric Android user changed. Build a fresh stack plan.");
        }
        if changed || stale_verify {
            self.invalidate_verification("Current configuration or Android user changed, or its binding could not be established.");
        }
        if stale_diagnostic {
            self.set("diagnostics-time","Previous diagnostic view is stale: configuration or Android user changed. Collect diagnostics again.");
            self.p(
                &self.clear("diagnostic-context"),
                "Collect diagnostics again for current device evidence.",
            );
            self.p(
                &self.clear("diagnostic-findings"),
                "Previous findings were invalidated by a relevant configuration/user change.",
            );
            self.state.borrow_mut().diagnostic = None;
        }
        {
            let mut st = self.state.borrow_mut();
            st.evidence = binding.clone();
            st.user = if binding.is_some() {
                first(&[
                    g(g(d, "device"), "current_android_user"),
                    g(d, "current_android_user"),
                ])
                .as_str()
                .map(str::to_owned)
            } else {
                None
            };
        }
        let inventory = first(&[g(d, "algorithms"), g(active, "algorithms")]);
        let mut algorithms = if inventory.is_array() {
            list(inventory)
                .iter()
                .map(text)
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            s(inventory).into()
        };
        let keybox = g(g(d, "keybox_summaries"), "keybox.xml");
        let validated =
            yes(g(keybox, "structural_valid")) && yes(g(keybox, "cryptographic_consistent"));
        if !validated {
            algorithms = if algorithms.is_empty() {
                "No validated signing-key inventory established".into()
            } else {
                format!(
                    "{algorithms} (declared inventory only; mandatory validation not established)"
                )
            };
        }
        let configuration = first(&[g(active, "summary"), g(d, "configuration_summary")]);
        let config = if configuration.is_string() {
            text(configuration)
        } else if active.get("keybox.xml").is_some() {
            core::FILES
                .iter()
                .map(|n| {
                    format!(
                        "{n}: {}",
                        if yes(g(g(active, n), "exists")) {
                            "present"
                        } else {
                            "absent"
                        }
                    )
                })
                .collect::<Vec<_>>()
                .join(" · ")
        } else {
            "See fresh diagnostics for configuration validation".into()
        };
        let rollback = g(d, "rollback");
        let backup_count = list(g(rollback, "backups")).len();
        self.pairs(
            "current-summary",
            vec![
                ("Signing-key types", algorithms),
                (
                    "Local keybox checks",
                    if validated {
                        "Structure and cryptographic consistency passed"
                    } else {
                        "Not established; inspect current findings"
                    }
                    .into(),
                ),
                (
                    "Public trust / revocation",
                    format!(
                        "{} / {}",
                        fallback(g(keybox, "trust"), "unknown"),
                        fallback(g(keybox, "revocation"), "unknown")
                    ),
                ),
                ("Saved configuration", config),
                (
                    "What these checks mean",
                    "Saved files and key consistency. Engine use and Wallet approval are separate checks."
                        .into(),
                ),
                (
                    "Current numeric Android user",
                    text(g(g(d, "device"), "current_android_user")),
                ),
                (
                    "Evidence collected",
                    fallback(g(d, "evidence_time"), &r.time),
                ),
                (
                    "Freshness",
                    fallback(g(d, "freshness"), "Recollect after configuration changes"),
                ),
                (
                    "Last operation",
                    if last.is_string() {
                        text(last)
                    } else if first(&[g(last, "type"), g(last, "command")]).is_string() {
                        format!(
                            "{} · {} · {}",
                            text(first(&[g(last, "type"), g(last, "command")])),
                            text(first(&[g(last, "state"), g(last, "status")])),
                            text(first(&[g(last, "time"), g(last, "timestamp")]))
                        )
                    } else {
                        "No recorded operation".into()
                    },
                ),
                (
                    "Rollback available",
                    if rollback.is_string() {
                        text(rollback)
                    } else if yes(g(rollback, "available")) || backup_count > 0 {
                        "Yes; inspect backups".into()
                    } else if g(rollback, "available") == &json!(false)
                        || g(rollback, "backups").is_array()
                    {
                        "No recorded backup".into()
                    } else {
                        "Inspect backups".into()
                    },
                ),
            ],
        );
        self.set(
            "next-step",
            &fallback(
                g(d, "next_step"),
                "Collect fresh diagnostics before selecting a repair.",
            ),
        );
        self.findings("dashboard-findings", g(d, "findings"));
        let recovery = core::needs_recovery(g(d, "recovery"));
        self.hidden("recovery-card", !recovery);
        self.set(
            "recovery-summary",
            &fallback(
                first(&[
                    g(g(d, "recovery"), "message"),
                    g(g(d, "recovery"), "next_step"),
                ]),
                "A journal needs review. Inspect recovery before starting another write.",
            ),
        );
        let reset_pending = g(g(d, "reset"), "state")
            .as_str()
            .is_some_and(|v| !["none", "completed", "closed-incomplete"].contains(&v));
        let stack_pending = yes(g(d, "stack_pending")) || yes(g(g(d, "stack"), "stack_pending"));
        let apply = g(d, "apply_available") != &json!(false) && !reset_pending && !stack_pending;
        {
            let mut st = self.state.borrow_mut();
            st.recovery = recovery;
            st.reset_pending = reset_pending;
            st.stack_pending = stack_pending;
            st.apply_available = apply;
        }
        self.set("plan-blocker",if reset_pending{"A one-shot reset is unfinished. Inspect reset state and complete its reviewed manual steps before another plan. Do not repeat app-data clears."}else if stack_pending{"An unfinished stack transaction blocks new configuration changes. Inspect the stack operation and explicitly restore its private backup."}else if apply{""}else{"Apply is unavailable: inspect the capability finding in Diagnostics, then refresh status after the supported resolution."});
        let history = self.clear("history-list");
        for op in list(g(d, "history")) {
            if op.is_object() {
                self.p(
                    &history,
                    &format!(
                        "{} · {} · {}{}",
                        text(first(&[g(op, "time"), g(op, "timestamp")])),
                        text(first(&[g(op, "command"), g(op, "type")])),
                        text(first(&[g(op, "code"), g(op, "status"), g(op, "state")])),
                        if yes(g(op, "verified")) {
                            " · Recorded verification"
                        } else {
                            ""
                        }
                    ),
                );
            }
        }
        if history.child_element_count() == 0 {
            self.p(&history, "No operation history returned.");
        }
        self.public_trust(g(d, "public_attestation"));
        self.api(g(d, "api"));
        if d.get("stack").is_some() {
            self.stack_status(g(d, "stack"));
        }
        let drop_api = {
            let st = self.state.borrow();
            (reset_pending || recovery || stack_pending)
                && (st.api_stage.is_some() || st.inputs.iter().any(|i| i.source == "api"))
        };
        if drop_api {
            self.discard_api("A pending reset or transaction invalidated this API review. Complete the reviewed recovery steps, then explicitly import again.",true);
        }
        self.sync();
    }
    fn discard_api(&self, reason: &str, drop_inputs: bool) {
        {
            let mut st = self.state.borrow_mut();
            st.api_stage = None;
            st.plan = None;
            if drop_inputs {
                st.inputs.retain(|i| i.source != "api");
            }
        }
        self.check("apply-confirm", false);
        self.hidden("plan-card", true);
        self.hidden("selection-card", false);
        self.hidden("import-input", false);
        self.set("api-stage-result", reason);
        self.selections();
        self.sync();
    }
    fn api(&self, value: &Value) {
        let data = core::api_status_view(value);
        let generation = data
            .as_ref()
            .filter(|v| yes(g(v, "configured")))
            .and_then(|v| g(v, "source_generation").as_str())
            .map(str::to_owned);
        let changed = {
            let st = self.state.borrow();
            st.api_generation.is_some() && st.api_generation != generation
        };
        if changed {
            self.discard_api("The configured source changed or became unavailable. Previous API inputs were removed from this review; private staged files are retained. Explicitly import and validate again.",true);
        }
        let ready = data.as_ref().is_some_and(|d| yes(g(d, "available")));
        {
            let mut st = self.state.borrow_mut();
            st.api_generation = generation;
            st.api_supported = data.is_some();
            st.api_ready = ready;
        }
        let el = self.clear("api-result");
        if let Some(ref d) = data {
            let dl = self.node("dl", None, "");
            self.dl(
                &dl,
                vec![
                    ("Generic adapter", "Configured HTTPS raw XML".into()),
                    ("Configuration state", text(g(d, "state"))),
                    ("Configured source ready", text(g(d, "available"))),
                    ("Authentication configured", text(g(d, "auth_configured"))),
                    ("Exact supplied endpoint available", "No".into()),
                    ("Provider contract verified", "No".into()),
                ],
            );
            self.append(&el, &dl);
        } else {
            self.p(&el,"This backend does not expose the configured generic raw-XML adapter. The exact supplied endpoint remains unverified and unavailable. Local import remains available.");
        }
        let st = self.state.borrow();
        self.set("api-reason",if st.reset_pending||st.recovery||st.stack_pending{"An unfinished reset or transaction blocks configuration, fetch and API validation. Inspect its state; do not repeat app-data clears."}else if data.is_some(){"Only an explicit Fetch reads the configured feed. Imported material stays staged until you validate and review it; no key selection, Plan or Apply is automatic."}else{"Install a matching backend to use private-file configuration. Never enter credentials or a URL here."});
        drop(st);
        self.sync();
    }
    fn discard_stack_plan(&self, reason: &str) {
        {
            let mut st = self.state.borrow_mut();
            st.stack_plan = None;
            st.stack_plan_binding = None;
        }
        self.check("stack-apply-confirm", false);
        self.hidden("stack-plan-card", true);
        if !reason.is_empty() {
            self.set("stack-operation-result", reason);
        }
    }
    fn invalidate_stack(&self, reason: &str) {
        self.invalidate_verification(reason);
        {
            let mut st = self.state.borrow_mut();
            st.evidence = None;
            st.diagnostic = None;
            st.plan = None;
        }
        self.set("diagnostics-time","Previous diagnostics are stale after a submitted stack change. Collect diagnostics again.");
        self.p(
            &self.clear("diagnostic-context"),
            "Collect fresh device and stack evidence.",
        );
        self.p(&self.clear("diagnostic-findings"), reason);
        self.check("apply-confirm", false);
        self.hidden("plan-card", true);
        self.hidden("selection-card", false);
        self.hidden("import-input", false);
    }
    fn stack_status(&self, value: &Value) {
        let data = core::stack_status_view(value);
        let (previous, invalid) = {
            let st = self.state.borrow();
            let previous = st
                .stack
                .as_ref()
                .map(|v| g(g(v, "operation"), "id").clone())
                .unwrap_or(Value::Null);
            let invalid = st.stack_plan.as_ref().is_some_and(|plan| {
                data.as_ref().is_none_or(|d| {
                    yes(g(d, "unfinished"))
                        || !list(g(d, "profiles"))
                            .iter()
                            .any(|p| g(p, "id") == g(plan, "profile") && yes(g(p, "available")))
                        || (g(g(d, "operation"), "id") != g(plan, "operationBefore")
                            && g(g(d, "operation"), "id") != g(plan, "id"))
                })
            });
            (previous, invalid)
        };
        if invalid {
            self.discard_stack_plan(
                "Stack capability or operation changed. Build a fresh review before another Apply.",
            );
        }
        {
            let mut st = self.state.borrow_mut();
            st.stack = data.clone();
            if data.as_ref().is_some_and(|d| yes(g(d, "unfinished"))) {
                if data.as_ref().is_some_and(|d| yes(g(d, "stack_pending"))) {
                    st.stack_pending = true;
                }
                st.apply_available = false;
            }
        }
        if data.as_ref().is_some_and(|d| yes(g(d, "unfinished"))) {
            self.discard_stack_plan("An unfinished configuration operation blocks new stack changes. Inspect its matching recovery action.");
        }
        let el = self.clear("stack-status-result");
        if let Some(d) = data {
            for p in list(g(&d, "profiles")) {
                self.p(
                    &el,
                    &format!(
                        "{}: {}. {}",
                        core::profile_name(s(g(p, "id"))).unwrap_or("Unknown profile"),
                        if yes(g(p, "available")) {
                            "available"
                        } else {
                            "unavailable"
                        },
                        text(g(p, "reason"))
                    ),
                );
            }
            self.p(&el,&format!("Unfinished configuration operation: {}. Runtime adoption: unknown. Manual reboot is required after Apply and rollback.",if yes(g(&d,"unfinished")){"yes"}else{"no"}));
            let op = g(&d, "operation");
            if op.is_object() {
                self.p(
                    &el,
                    &format!(
                        "Operation {} · {} · {} · Private backup {}.",
                        text(g(op, "id")),
                        core::profile_name(s(g(op, "profile"))).unwrap_or("Unknown profile"),
                        text(g(op, "state")),
                        if yes(g(op, "backup_available")) {
                            "available"
                        } else {
                            "not established"
                        }
                    ),
                );
                let current = self.value("stack-operation-id");
                if current.is_empty() || current == s(&previous) {
                    self.set_value("stack-operation-id", s(g(op, "id")));
                }
            }
        } else {
            self.p(&el,"This backend does not expose a supported stack interface. Install a matching module; no stack changes are available.");
        }
        self.sync();
    }
    fn stack_plan(&self, value: &Value, choices: Value) -> Result<()> {
        let mut plan = core::stack_plan_view(value)?;
        let profile = s(g(&plan, "profile"));
        if g(&plan, "profile") != g(&choices, "profile")
            || (profile == "hma-scope"
                && list(g(&plan, "changes")).iter().any(|c| {
                    !list(g(&choices, "targets")).contains(g(c, "target"))
                        || core::integer(g(c, "added_count")).unwrap_or(u64::MAX)
                            > list(g(&choices, "packages")).len() as u64
                }))
            || (profile == "brezygisk-unmount"
                && g(&list(g(&plan, "changes"))[0], "enabled_after")
                    != &json!(s(g(&choices, "enabled")) == "true"))
        {
            return Err(
                "Stack preview differs from the explicit selections. Apply is blocked.".into(),
            );
        }
        let el = self.clear("stack-plan-result");
        self.p(
            &el,
            &format!(
                "{} · Plan {}",
                core::profile_name(profile).unwrap(),
                text(g(&plan, "id"))
            ),
        );
        self.p(&el,"Apply creates and verifies a private full backup before writing. Apply and rollback require a manual reboot. Runtime adoption and Wallet acceptance remain unknown.");
        if profile == "hma-scope" {
            self.p(
                &el,
                &format!(
                    "Explicit packages selected in this review: {}",
                    list(g(&choices, "packages"))
                        .iter()
                        .map(text)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
            for c in list(g(&plan, "changes")) {
                self.p(
                    &el,
                    &format!(
                        "{}: {}add {} blacklist entries. Existing private lists are withheld.",
                        text(g(c, "target")),
                        if core::integer(g(c, "scopes_created")) == Some(1) {
                            "create the selected scope and "
                        } else {
                            ""
                        },
                        text(g(c, "added_count"))
                    ),
                );
            }
        } else {
            let c = &list(g(&plan, "changes"))[0];
            self.p(
                &el,
                &format!(
                    "Unmount marker: {} → {}.",
                    if yes(g(c, "enabled_before")) {
                        "enabled"
                    } else {
                        "disabled"
                    },
                    if yes(g(c, "enabled_after")) {
                        "enabled"
                    } else {
                        "disabled"
                    }
                ),
            );
        }
        {
            let mut st = self.state.borrow_mut();
            plan["operationBefore"] = st
                .stack
                .as_ref()
                .map(|v| g(g(v, "operation"), "id").clone())
                .unwrap_or(Value::Null);
            plan["choices"] = choices;
            st.stack_plan = Some(plan);
            st.stack_plan_binding = st.evidence.clone();
        }
        self.hidden("stack-plan-card", false);
        self.check("stack-apply-confirm", false);
        self.sync();
        Ok(())
    }
    fn stack_outcome(&self, r: &Response) {
        let d = &r.data;
        let el = self.clear("stack-operation-result");
        if s(g(d, "state")) == "superseded" {
            self.p(&el, "Stack operation closed. Current resource preserved as evidence; no stack file was written. Runtime adoption and Wallet acceptance remain unknown.");
            return;
        }
        if core::id(g(d, "id")) {
            self.set_value("stack-operation-id", s(g(d, "id")));
        }
        self.p(
            &el,
            &format!(
                "Stack operation state: {}. Persisted file readback {}. Private backup {}.",
                if core::STATES.contains(&s(g(d, "state"))) {
                    s(g(d, "state"))
                } else {
                    "not established"
                },
                if yes(g(d, "readback_verified")) {
                    "verified"
                } else {
                    "not established"
                },
                if s(g(d, "private_backup")) == "verified" {
                    "verified"
                } else {
                    "not established"
                }
            ),
        );
        self.p(&el,"Runtime adoption: unknown. Wallet acceptance is not established by a file check. Reboot manually after Apply or rollback; the helper never reboots automatically.");
    }
    fn init_trust(&self) {
        let card = self.node("div", None, "card");
        card.set_id("public-trust-card");
        prop(&card, "hidden", &true.into());
        self.append(
            &card,
            &self.node("h3", Some("Google public attestation evidence"), ""),
        );
        self.p(&card,"An explicit refresh downloads Google public attestation roots and status feeds over HTTPS GET. No keybox, private key, certificate or certificate serial is uploaded. Root matching and feed flags do not establish Wallet acceptance.");
        for (action, label) in [
            ("trust-status", "Inspect cached public evidence"),
            ("trust-refresh", "Fetch Google public feeds (GET)"),
        ] {
            let button = self.node("button", Some(label), "");
            let _ = button.set_attribute("type", "button");
            let _ = button.set_attribute("data-action", action);
            self.append(&card, &button);
        }
        let result = self.node("div", None, "");
        result.set_id("public-trust-result");
        self.append(&card, &result);
        if let Ok(Some(watch)) = self.el("watch-result").closest(".card") {
            if let Some(parent) = watch.parent_node() {
                let _ = parent.insert_before(&card, Some(&watch));
            }
        }
    }
    fn public_trust(&self, d: &Value) {
        if g(d, "available").as_bool().is_none() {
            self.hidden("public-trust-card", true);
            return;
        }
        self.hidden("public-trust-card", false);
        let el = self.clear("public-trust-result");
        let dl = self.node("dl", None, "");
        self.dl(
            &dl,
            vec![
                ("Cache state", text(g(d, "state"))),
                ("Public evidence available", text(g(d, "available"))),
                ("Checked", text(g(d, "checked_at"))),
                ("Expires", text(g(d, "expires_at"))),
            ],
        );
        self.append(&el, &dl);
        for key in list(g(d, "keys")) {
            let (Some(b), Some(k)) = (
                core::integer(g(key, "keybox_index")),
                core::integer(g(key, "key_index")),
            ) else {
                continue;
            };
            let algorithm = s(g(key, "algorithm"));
            if !["ecdsa", "rsa"].contains(&algorithm) {
                continue;
            }
            let root = match g(key, "google_root_key").as_bool() {
                Some(true) => "matches",
                Some(false) => "does not match",
                None => "unknown",
            };
            let revoke = s(g(key, "revocation"));
            let revoke = if [
                "listed-revoked",
                "listed-suspended",
                "not-listed-as-of-feed",
                "unknown",
            ]
            .contains(&revoke)
            {
                revoke
            } else {
                "unknown"
            };
            self.p(&el,&format!("Keybox {} · Key {} · {} · Google root public key {root} · Public status {revoke}.",b+1,k+1,algorithm.to_uppercase()));
        }
        self.items(&el, g(d, "limitations"));
        if g(d, "next_step").is_string() {
            self.p(&el, &text(g(d, "next_step")));
        }
    }
    fn selections(&self) {
        self.hidden("selection-card", false);
        let inputs = self.clear("input-list");
        let choices = self.clear("selection-list");
        let state_inputs = self.state.borrow().inputs.clone();
        for (ordinal, i) in state_inputs.iter().enumerate() {
            self.p(&inputs,&format!("Input {} · File structure: {}; key and certificate checks: {}. Trust: {}; revocation: {}.",ordinal+1,if yes(g(&i.summary,"structural_valid")){"passed"}else{"unknown"},if yes(g(&i.summary,"cryptographic_consistent")){"passed"}else{"unknown"},fallback(g(&i.summary,"trust"),"unknown"),fallback(g(&i.summary,"revocation"),"unknown")));
        }
        self.p(&choices, "Choose one signing key per type for a new merged keybox. Plans that change only targets or patches keep the current keybox.");
        for algorithm in ["ecdsa", "rsa"] {
            let signing_key = match algorithm {
                "ecdsa" => "ECDSA signing key (elliptic curve)",
                _ => "RSA signing key",
            };
            let field = self.node("fieldset", None, "");
            self.append(&field, &self.node("legend", Some(signing_key), ""));
            let label = self.node("label", None, "choice");
            let radio = self.node("input", None, "");
            for (k, v) in [
                ("type", "radio"),
                ("name", &format!("key-{algorithm}")),
                ("value", ""),
            ] {
                prop(&radio, k, &v.into());
            }
            prop(&radio, "checked", &true.into());
            self.append(&label, &radio);
            self.append(
                &label,
                &self.node(
                    "span",
                    Some(&format!(
                        "Leave {} out of a new merged keybox",
                        algorithm.to_uppercase()
                    )),
                    "",
                ),
            );
            self.append(&field, &label);
            let mut count = 0;
            for (ordinal, i) in state_inputs.iter().enumerate() {
                for b in list(g(&i.summary, "keyboxes")) {
                    for k in list(g(b, "keys")) {
                        if s(g(k, "algorithm")).to_lowercase() != algorithm {
                            continue;
                        }
                        let (Some(bi), Some(ki)) = (g(b, "index").as_f64(), g(k, "index").as_f64())
                        else {
                            continue;
                        };
                        let Ok(value) = core::selection_value(&i.id, bi, ki, algorithm) else {
                            continue;
                        };
                        let label = self.node("label", None, "choice");
                        let radio = self.node("input", None, "");
                        prop(&radio, "type", &"radio".into());
                        prop(&radio, "name", &format!("key-{algorithm}").into());
                        prop(&radio, "value", &value.into());
                        let desc=self.node("span",Some(&format!("Input {} · Keybox {} · Key {} · {} · {} certificates · Key format: {} · Valid until {}.",ordinal+1,bi as u64+1,ki as u64+1,text(g(k,"parameter")),text(g(k,"certificate_count")),text(g(k,"private_key_format")),text(g(k,"valid_until")))),"");
                        self.items(&desc, g(k, "warnings"));
                        self.append(&label, &radio);
                        self.append(&label, &desc);
                        self.append(&field, &label);
                        count += 1;
                    }
                }
            }
            if count == 0 {
                self.p(&field, "No validated entry for this algorithm.");
            }
            self.append(&choices, &field);
        }
        self.class("step-review", "active", !state_inputs.is_empty());
        self.class("step-import", "active", state_inputs.is_empty());
        self.sync();
    }
    fn plan(&self, r: &Response) -> Result<()> {
        let d = &r.data;
        self.state.borrow_mut().plan = None;
        let id = s(g(d, "id"));
        if !valid(r"^[A-Za-z0-9_-]{1,96}$", id) {
            return Err("Backend did not return a usable plan ID. Apply is blocked.".into());
        }
        let previews = list(g(d, "preview"));
        let changes = list(g(d, "changes"));
        if changes.is_empty()
            || changes.iter().any(|name| {
                !core::FILES.contains(&s(name)) || !previews.iter().any(|p| g(p, "file") == name)
            })
        {
            return Err("Plan lacks a complete redacted change preview. Apply is blocked; reinstall matching UI/backend.".into());
        }
        let compaction = if d.get("target_compaction").is_some() || self.checked("compact-targets")
        {
            Some(core::compaction_counts(g(d, "target_compaction"))?)
        } else {
            None
        };
        if compaction
            .as_ref()
            .is_some_and(|c| core::integer(g(c, "removed_entries")).unwrap_or(0) > 0)
            && !changes.contains(&json!("target.txt"))
        {
            return Err(
                "Target compaction review has no target.txt change. Apply is blocked.".into(),
            );
        }
        self.state.borrow_mut().plan = Some(id.into());
        let output: Vec<_> = list(g(g(d, "summary"), "keyboxes"))
            .iter()
            .flat_map(|b| list(g(b, "keys")))
            .collect();
        let algorithms = if g(d, "algorithms").is_array() {
            list(g(d, "algorithms"))
                .iter()
                .map(text)
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            fallback(
                g(d, "algorithms"),
                &output
                    .iter()
                    .map(|k| text(g(k, "algorithm")))
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        };
        self.pairs(
            "plan-summary",
            vec![
                ("Plan", id.into()),
                ("Created", r.time.clone()),
                (
                    "Selected algorithms",
                    if algorithms.is_empty() {
                        "Only explicitly selected entries enter a merged keybox".into()
                    } else {
                        algorithms
                    },
                ),
                (
                    "Output metadata",
                    fallback(
                        first(&[
                            g(d, "device_id_policy"),
                            if g(d, "metadata").is_string() {
                                g(d, "metadata")
                            } else {
                                g(g(d, "metadata"), "device_id_policy")
                            },
                        ]),
                        "Source identity is not recreated",
                    ),
                ),
                (
                    "Engine activation steps",
                    fallback(g(d, "adoption"), "Evidence collection; no automatic reboot"),
                ),
                (
                    "Recovery policy",
                    fallback(
                        g(d, "recovery_policy"),
                        "Restore the previous snapshot if a configuration write fails",
                    ),
                ),
            ],
        );
        let el = self.clear("plan-changes");
        self.append(&el, &self.node("h4", Some("Configuration changes"), ""));
        if let Some(c) = compaction {
            self.p(&el,&format!("Target compaction: {} entries → {}; {} repeated entries removed. Reviewed input contains {} packages. These counts describe compaction before any separately selected required-target repair. Review the final target.txt changes below.",text(g(&c,"entries_before")),text(g(&c,"entries_after")),text(g(&c,"removed_entries")),text(g(&c,"packages_before"))));
        }
        for change in changes {
            let name = s(change);
            let old = g(g(d, "active"), name);
            let intended = g(g(d, "intended"), name);
            self.p(
                &el,
                &format!(
                    "{name}: {}",
                    if yes(g(old, "exists")) {
                        "replace existing file"
                    } else {
                        "create previously absent file"
                    }
                ),
            );
            if g(old, "sha256").is_string() {
                self.p(&el, &format!("Before SHA-256: {}", text(g(old, "sha256"))));
            }
            if g(intended, "sha256").is_string() {
                self.p(
                    &el,
                    &format!("After SHA-256: {}", text(g(intended, "sha256"))),
                );
            }
        }
        for key in output {
            self.p(
                &el,
                &format!(
                    "Output {}: {} · {} certificates · PEM {} · Valid until {}.",
                    text(g(key, "algorithm")).to_uppercase(),
                    text(g(key, "parameter")),
                    text(g(key, "certificate_count")),
                    text(g(key, "private_key_format")),
                    text(g(key, "valid_until"))
                ),
            );
            self.items(&el, g(key, "warnings"));
        }
        for p in previews {
            if !core::FILES.contains(&s(g(p, "file"))) {
                continue;
            }
            let detail = self.node("details", None, "");
            self.append(
                &detail,
                &self.node(
                    "summary",
                    Some(&format!(
                        "{}: exact redacted changes and metadata",
                        text(g(p, "file"))
                    )),
                    "",
                ),
            );
            self.p(
                &detail,
                &format!(
                    "Original file {}. Before SHA-256: {}. After SHA-256: {}.",
                    if yes(g(p, "old_exists")) {
                        "present"
                    } else {
                        "absent"
                    },
                    fallback(g(p, "old_sha256"), "Absent"),
                    text(g(p, "new_sha256"))
                ),
            );
            let m = g(p, "metadata");
            self.p(
                &detail,
                &format!(
                    "Owner {}:{} · Mode {} · SELinux {}.",
                    text(g(m, "uid")),
                    text(g(m, "gid")),
                    core::integer(g(m, "mode"))
                        .map(|n| format!("{n:o}"))
                        .unwrap_or("unknown".into()),
                    text(g(m, "selinux"))
                ),
            );
            for (key, title) in [
                ("added_lines", "Added lines"),
                ("removed_lines", "Removed lines"),
            ] {
                if p.get(key).is_some() {
                    self.append(&detail, &self.node("h4", Some(title), ""));
                    self.items(&detail, g(p, key));
                }
            }
            self.append(&el, &detail);
        }
        self.items(&el, g(g(d, "summary"), "warnings"));
        let warnings = self.clear("plan-warnings");
        self.items(&warnings, g(d, "warnings"));
        self.items(&warnings, g(d, "required_capabilities"));
        if let Some(caps) = g(d, "required_capabilities").as_object() {
            for (name, value) in caps {
                self.p(&warnings, &format!("{name}: {}", text(value)));
            }
        }
        self.hidden("plan-card", false);
        self.hidden("selection-card", true);
        self.hidden("import-input", true);
        self.check("apply-confirm", false);
        self.class("step-apply", "active", true);
        self.sync();
        let options = web_sys::ScrollIntoViewOptions::new();
        options.set_block(web_sys::ScrollLogicalPosition::Start);
        self.el("plan-card")
            .scroll_into_view_with_scroll_into_view_options(&options);
        Ok(())
    }
    fn backups(&self, r: &Response) {
        let d = &r.data;
        let backups = list(if d.is_array() { d } else { g(d, "backups") });
        let select = self.clear("backup-choice");
        for (id, label) in [
            ("previous", "Previous configuration"),
            (
                "last-verified",
                "Last configuration with recorded verification",
            ),
        ] {
            let option = self.node("option", Some(label), "");
            prop(&option, "value", &id.into());
            self.append(&select, &option);
        }
        let el = self.clear("backup-list");
        for backup in backups {
            let id = s(g(backup, "id"));
            if !valid(r"^[A-Za-z0-9_-]{1,96}$", id) {
                continue;
            }
            let failed = s(g(backup, "integrity")) == "failed";
            let label = format!(
                "{} · {} · {} · {id}{}",
                text(first(&[g(backup, "time"), g(backup, "created_at")])),
                text(first(&[g(backup, "type"), g(backup, "operation")])),
                if yes(g(backup, "verified")) {
                    "Verification recorded"
                } else {
                    "No recorded verification"
                },
                if failed {
                    " · Corrupt/unavailable; restore blocked"
                } else {
                    ""
                }
            );
            let option = self.node("option", Some(&label), "");
            prop(&option, "value", &id.into());
            prop(&option, "disabled", &failed.into());
            self.append(&select, &option);
            let card = self.node("article", None, "card");
            self.append(&card, &self.node("h3", Some(id), ""));
            self.p(&card, &label);
            let changes = g(backup, "changes");
            self.items(&card, changes);
            if changes.is_object() {
                for name in core::FILES {
                    if let Some(file) = changes.get(name) {
                        self.p(
                            &card,
                            &format!(
                                "{name}: {}",
                                if yes(g(file, "exists")) {
                                    format!("present · SHA-256 {}", text(g(file, "sha256")))
                                } else {
                                    "originally absent".into()
                                }
                            ),
                        );
                    }
                }
            }
            self.items(&card, g(backup, "warnings"));
            self.append(&el, &card);
        }
        if el.child_element_count() == 0 {
            self.p(&el,"No named backups returned. The backend checks symbolic rollback availability before writing.");
        }
        self.check("rollback-confirm", false);
        self.sync();
    }
    async fn validate(self: &Rc<Self>, id: &str, source: &str) -> Result<()> {
        let r = self
            .request(
                "validate",
                json!({"id":id}),
                "Validating XML, private key, and complete certificate chain…",
                source == "api",
            )
            .await?;
        let summary = r.data.get("summary").unwrap_or(&r.data);
        if !yes(g(summary, "structural_valid")) || !yes(g(summary, "cryptographic_consistent")) {
            return Err(
                "Mandatory validation did not pass. Apply remains blocked for this input.".into(),
            );
        }
        {
            let mut st = self.state.borrow_mut();
            st.inputs.retain(|i| i.id != id);
            st.inputs.push(Input {
                id: id.into(),
                summary: summary.clone(),
                source: source.into(),
            });
            st.plan = None;
        }
        self.check("apply-confirm", false);
        self.hidden("plan-card", true);
        self.hidden("selection-card", false);
        self.hidden("import-input", false);
        self.selections();
        Ok(())
    }
    async fn ingest(self: &Rc<Self>, path: &str, active: bool) -> Result<()> {
        if !active
            && (!valid(
                r"^/(?:data/adb/wallet_diagnostic/inbox|sdcard/keybox_inbox)/[A-Za-z0-9._ /-]+\.xml$",
                path,
            ) || path.contains("..")
                || path.len() > 1024)
        {
            return Err("Use an absolute XML path inside the private inbox or optional shared inbox. Use a simple filename.".into());
        }
        let r = self
            .req(
                "ingest",
                json!({"path":path}),
                "Copying the input into private staging…",
            )
            .await?;
        let id = s(g(&r.data, "id"));
        if !valid(r"^[A-Za-z0-9_-]{1,96}$", id) {
            return Err("Backend did not return a staged input ID.".into());
        }
        self.validate(id, "local").await
    }
    async fn collect_status(self: &Rc<Self>, progress: &str) -> Result<()> {
        let r = self.req("status", json!({}), progress).await?;
        self.status(&r);
        Ok(())
    }
    async fn collect_stack(self: &Rc<Self>) -> Result<()> {
        let r = self
            .req(
                "stack",
                json!({"action":"status"}),
                "Inspecting redacted stack capabilities and operation…",
            )
            .await?;
        self.stack_status(&r.data);
        Ok(())
    }
    async fn action(self: &Rc<Self>, action: &str) -> Result<()> {
        match action {
            "status" => self.collect_status("Collecting evidence…").await?,
            "diagnose" => {
                let r = self
                    .req("diagnose", json!({}), "Collecting targeted diagnostics…")
                    .await?;
                self.status(&r);
                self.diagnostic_context(&r.data);
                self.findings("diagnostic-findings", g(&r.data, "findings"));
                self.state.borrow_mut().diagnostic = core::evidence_binding(&r.data);
                self.set(
                    "diagnostics-time",
                    &format!("Collected {}; recheck after relevant changes.", r.time),
                );
                self.show("diagnostics");
            }
            "ingest" => {
                self.ingest(&self.value("input-path").trim().to_owned(), false)
                    .await?
            }
            "ingest-active" => {
                self.ingest("/data/adb/tricky_store/keybox.xml", true)
                    .await?
            }
            "plan" => {
                let selections = self.selected("#selection-list input:checked").join(",");
                let targets = if self.checked("repair-targets") {
                    "true"
                } else {
                    "false"
                };
                let compact = self.checked("compact-targets");
                let patch = self.value("patch").trim().to_owned();
                if !patch.is_empty() && !valid(r"^\d{4}-\d{2}-\d{2}$", &patch) {
                    return Err("Patch must be YYYY-MM-DD or empty.".into());
                }
                if selections.is_empty() && targets == "false" && !compact && patch.is_empty() {
                    return Err("Select validated key material, target compaction or an evidence-supported target/patch repair.".into());
                }
                let mut args = json!({"selections":selections,"targets":targets,"patch":patch});
                if compact {
                    args["compact-targets"] = json!("true");
                }
                let r = self
                    .req(
                        "plan",
                        args,
                        "Building a plan bound to current input and configuration hashes…",
                    )
                    .await?;
                self.plan(&r)?;
            }
            "apply" => {
                let id = self
                    .state
                    .borrow()
                    .plan
                    .clone()
                    .ok_or("Review and confirm the plan first.")?;
                if !self.checked("apply-confirm") {
                    return Err("Review and confirm the plan first.".into());
                }
                self.state.borrow_mut().plan = None;
                self.check("apply-confirm", false);
                self.invalidate_verification("A new Apply was submitted.");
                self.state.borrow_mut().evidence = None;
                self.sync();
                let r=self.req("apply",json!({"id":id}),"Backing up and committing. Let the backend finish safe recovery if needed…").await?;
                self.hidden("plan-card", true);
                self.hidden("verify-card", false);
                self.class("step-verify", "active", true);
                let warning = self
                    .collect_status(
                        "Collecting current configuration and Android user after Apply…",
                    )
                    .await
                    .err()
                    .map(|e| {
                        format!(
                            "Apply completed, but fresh status could not be collected. {}",
                            e.message
                        )
                    });
                self.set("apply-result", &fallback(g(&r.data, "message"), &r.message));
                self.describe("verification-result", &r);
                {
                    let mut st = self.state.borrow_mut();
                    st.verification_seen = true;
                    st.verification = core::evidence_binding(&r.data).or(st.evidence.clone());
                }
                if let Some(w) = warning {
                    self.notice(&w, true);
                    self.p(&self.el("verification-result"), &w);
                }
                self.hidden("import-input", false);
                self.selections();
            }
            "verify" => {
                let had = self.checked("wallet-ready") || self.checked("tap-confirmed");
                if had {
                    let binding = self.state.borrow().evidence.clone();
                    self.collect_status("Rechecking the configuration and Android user reviewed by your personal checks…").await?;
                    let current = self.state.borrow().evidence.clone();
                    if binding.is_none()
                        || current.is_none()
                        || binding != current
                        || (!self.checked("wallet-ready") && !self.checked("tap-confirmed"))
                    {
                        return Err("Current configuration/user evidence changed or was unavailable. Repeat your personal checks before recording them.".into());
                    }
                }
                let mut args = json!({"wallet-ready":if self.checked("wallet-ready"){"true"}else{"false"},"tap-confirmed":if self.checked("tap-confirmed"){"true"}else{"false"}});
                if had {
                    args["reviewed-user"] = json!(
                        self.state
                            .borrow()
                            .user
                            .clone()
                            .ok_or("Current numeric Android user is unavailable.")?
                    );
                }
                let r = self
                    .req(
                        "verify",
                        args,
                        "Checking files, engine health, and fresh adoption evidence…",
                    )
                    .await?;
                if had && core::evidence_binding(&r.data) != self.state.borrow().evidence {
                    return Err("Verification returned a different or unavailable configuration/user binding. Repeat personal checks against fresh status.".into());
                }
                self.record_verification(&r);
                self.hidden("verify-card", false);
                self.show("import");
            }
            "back-review" => {
                self.state.borrow_mut().plan = None;
                self.hidden("plan-card", true);
                self.hidden("selection-card", false);
                self.hidden("import-input", false);
                self.check("apply-confirm", false);
            }
            "cancel-import" => {
                {
                    let mut st = self.state.borrow_mut();
                    st.plan = None;
                    st.inputs.clear();
                    st.api_stage = None;
                }
                self.set("api-stage-result","API review cancelled. Private staged files are retained; a new explicit import is required.");
                self.hidden("plan-card", true);
                self.hidden("import-input", false);
                for id in ["apply-confirm", "repair-targets", "compact-targets"] {
                    self.check(id, false);
                }
                self.set_value("patch", "");
                self.invalidate_verification("The review was cancelled.");
                self.selections();
                self.notice("Review cancelled. Private staged files are retained; active configuration unchanged.",false);
            }
            "backups" => {
                let r = self
                    .req("backups", json!({}), "Collecting evidence…")
                    .await?;
                self.backups(&r);
            }
            "rollback" => {
                if !self.checked("rollback-confirm") {
                    return Err("Confirm the selected rollback first.".into());
                }
                self.check("rollback-confirm", false);
                self.invalidate_verification("A rollback was submitted.");
                self.state.borrow_mut().evidence = None;
                let r = self
                    .req(
                        "rollback",
                        json!({"id":self.value("backup-choice")}),
                        "Backing up the current set and restoring the selected configuration…",
                    )
                    .await?;
                self.describe("backup-preview", &r);
            }
            "api" => {
                let r = self
                    .req(
                        "api",
                        json!({"action":"status"}),
                        "Reading redacted API status; no feed is fetched…",
                    )
                    .await?;
                self.api(&r.data);
            }
            "api-config" => {
                let path = self.value("api-config-path").trim().to_owned();
                core::private_api_path(&path)?;
                self.discard_api("The source is being reconfigured. Previous API inputs were removed from this review; private staged files are retained.",true);
                let r = self
                    .req(
                        "api",
                        json!({"action":"config","path":path}),
                        "Saving the private-file configuration; no feed is fetched…",
                    )
                    .await?;
                self.api(&r.data);
            }
            "api-import" => {
                let allowed = {
                    let st = self.state.borrow();
                    st.api_ready && !st.reset_pending && !st.recovery && !st.stack_pending
                };
                if !allowed {
                    return Err(
                        "Inspect a ready source and complete pending recovery before importing."
                            .into(),
                    );
                }
                self.discard_api("Fetching one staged input. Any previous plan was discarded; active configuration is unchanged.",false);
                let r = self
                    .req(
                        "api",
                        json!({"action":"import"}),
                        "Fetching the configured HTTPS raw-XML feed once into private staging…",
                    )
                    .await?;
                if !core::id(g(&r.data, "id")) {
                    return Err("API import returned no usable staged input ID. Validation and Apply are blocked.".into());
                }
                self.state.borrow_mut().api_stage = Some(s(g(&r.data, "id")).into());
                self.set("api-stage-result",&format!("API input staged{}. Validate it next, then review and choose its signing keys.",core::integer(g(&r.data,"bytes")).map(|n|format!(" · {n} bytes")).unwrap_or_default()));
            }
            "api-validate" => {
                let (id, generation) = {
                    let st = self.state.borrow();
                    if st.reset_pending || st.recovery || st.stack_pending {
                        return Err(
                            "Import a staged API input after pending recovery is complete.".into(),
                        );
                    }
                    (
                        st.api_stage.clone().ok_or(
                            "Import a staged API input after pending recovery is complete.",
                        )?,
                        st.api_generation.clone(),
                    )
                };
                self.collect_status(
                    "Rechecking source generation and pending recovery before API validation…",
                )
                .await?;
                let allow = {
                    let st = self.state.borrow();
                    st.api_stage.as_deref() == Some(&id)
                        && st.api_generation == generation
                        && st.api_ready
                        && !st.reset_pending
                        && !st.recovery
                        && !st.stack_pending
                };
                if !allow {
                    return Err("The API source or recovery state changed. Inspect status and explicitly import again; validation was not submitted.".into());
                }
                self.validate(&id, "api").await?;
                self.state.borrow_mut().api_stage = None;
                self.set("api-stage-result","API input validated and listed for deliberate selection. No algorithm was selected and no plan or active change was made.");
                self.show("import");
            }
            "stack-status" => {
                self.collect_status("Collecting current user, configuration and stack evidence…")
                    .await?;
                self.collect_stack().await?;
            }
            "stack-candidates" => {
                let packages = core::stack_package_list(&self.value("stack-package-input"))?;
                let existing = self.selected("[name='stack-package']");
                let mut union = existing.clone();
                for name in &packages {
                    if !union.contains(name) {
                        union.push(name.clone());
                    }
                }
                if union.len() > 32 {
                    return Err("Offer at most 32 package choices in one review. Cancel to start a different list.".into());
                }
                for name in packages {
                    if existing.contains(&name) {
                        continue;
                    }
                    let label = self.node("label", None, "check");
                    let input = self.node("input", None, "");
                    prop(&input, "type", &"checkbox".into());
                    prop(&input, "name", &"stack-package".into());
                    prop(&input, "value", &name.clone().into());
                    self.append(&label, &input);
                    self.append(&label, &self.node("span", Some(&name), ""));
                    self.append(&self.el("stack-package-choices"), &label);
                }
                self.discard_stack_plan("Package choices changed. Select the desired packages explicitly, then build a new plan.");
            }
            "stack-plan" => {
                self.discard_stack_plan("");
                let profile = self.value("stack-profile");
                let mut choices = json!({"profile":profile});
                let mut args = json!({"action":"plan","profile":profile});
                if profile == "hma-scope" {
                    let targets = self.selected("[name='stack-target']:checked");
                    let packages = self.selected("[name='stack-package']:checked");
                    if targets.is_empty() || packages.is_empty() {
                        return Err(
                            "Choose at least one target and one package checkbox explicitly."
                                .into(),
                        );
                    }
                    args["targets"] = json!(targets.join(","));
                    args["hide-packages"] = json!(packages.join(","));
                    choices["targets"] = json!(targets);
                    choices["packages"] = json!(packages);
                } else if profile == "brezygisk-unmount" {
                    let enabled = self
                        .selected("[name='stack-enabled']:checked")
                        .first()
                        .cloned()
                        .unwrap_or_default();
                    if !["true", "false"].contains(&enabled.as_str()) {
                        return Err("Choose the intended unmount marker value explicitly.".into());
                    }
                    args["enabled"] = json!(enabled);
                    choices["enabled"] = args["enabled"].clone();
                } else {
                    return Err("Choose a supported stack profile explicitly.".into());
                }
                self.collect_status("Rechecking current configuration and numeric Android user before stack planning…").await?;
                self.collect_stack().await?;
                let allow = {
                    let st = self.state.borrow();
                    let stack = st.stack.as_ref().unwrap_or(&Value::Null);
                    st.evidence.is_some()
                        && !st.reset_pending
                        && !st.recovery
                        && !st.stack_pending
                        && list(g(stack, "profiles"))
                            .iter()
                            .any(|p| s(g(p, "id")) == profile && yes(g(p, "available")))
                        && list(g(&choices, "targets"))
                            .iter()
                            .all(|t| list(g(stack, "allowed_targets")).contains(t))
                };
                if !allow {
                    return Err("Fresh stack capability, user or recovery evidence does not allow this plan.".into());
                }
                let r = self
                    .req(
                        "stack",
                        args,
                        "Building only the explicitly selected stack profile plan…",
                    )
                    .await?;
                self.stack_plan(&r.data, choices)?;
            }
            "stack-apply" => {
                let plan = self
                    .state
                    .borrow()
                    .stack_plan
                    .clone()
                    .ok_or("Review and confirm the stack plan first.")?;
                if !self.checked("stack-apply-confirm") {
                    return Err("Review and confirm the stack plan first.".into());
                }
                self.collect_status("Rechecking configuration, stack evidence and numeric Android user before Apply…").await?;
                self.collect_stack().await?;
                let allow = {
                    let st = self.state.borrow();
                    st.stack_plan.as_ref() == Some(&plan)
                        && st.stack_plan_binding == st.evidence
                        && !st.reset_pending
                        && !st.recovery
                        && !st.stack_pending
                };
                if !allow {
                    return Err("Stack review is stale or recovery is pending. Build a fresh plan; Apply was not submitted.".into());
                }
                self.discard_stack_plan("");
                self.invalidate_stack("A separately confirmed stack Apply was submitted.");
                let r=self.req("stack",json!({"action":"apply","id":g(&plan,"id")}),"Creating the private full backup and committing the reviewed stack change…").await?;
                self.stack_outcome(&r);
                self.collect_status("Collecting status after the stack file change…")
                    .await?;
                self.collect_stack().await?;
            }
            "stack-verify" => {
                let id = self.value("stack-operation-id");
                if !core::id(&json!(id)) {
                    return Err("Use the reviewed 32-character stack operation ID.".into());
                }
                self.collect_stack().await?;
                let allowed = {
                    let st = self.state.borrow();
                    let op = st
                        .stack
                        .as_ref()
                        .map(|v| g(v, "operation"))
                        .unwrap_or(&Value::Null);
                    s(g(op, "id")) == id && yes(g(op, "can_verify"))
                };
                if !allowed {
                    return Err(
                        "Inspect an operation with available file verification first.".into(),
                    );
                }
                let r=self.req("stack",json!({"action":"verify","id":id}),"Verifying persisted stack bytes and metadata; runtime adoption remains unknown…").await?;
                self.stack_outcome(&r);
            }
            "stack-rollback" => {
                let id = self.value("stack-operation-id");
                let binding = self.state.borrow().stack_rollback_binding.clone();
                if !core::id(&json!(id))
                    || !self.checked("stack-rollback-confirm")
                    || binding.is_none()
                {
                    return Err("Inspect the matching operation and confirm private-backup restoration first.".into());
                }
                self.collect_status("Checking pending reset and stack recovery state…")
                    .await?;
                self.collect_stack().await?;
                let allow = {
                    let st = self.state.borrow();
                    let op = st
                        .stack
                        .as_ref()
                        .map(|v| g(v, "operation"))
                        .unwrap_or(&Value::Null);
                    binding == st.evidence
                        && self.checked("stack-rollback-confirm")
                        && !st.reset_pending
                        && !st.recovery
                        && s(g(op, "id")) == id
                        && yes(g(op, "can_rollback"))
                };
                if !allow {
                    return Err("The matching private stack backup is unavailable, review is stale or another recovery is pending.".into());
                }
                self.check("stack-rollback-confirm", false);
                self.state.borrow_mut().stack_rollback_binding = None;
                self.discard_stack_plan("");
                self.invalidate_stack("A separately confirmed stack rollback was submitted.");
                let r = self
                    .req(
                        "stack",
                        json!({"action":"rollback","id":id}),
                        "Restoring the matching verified private stack backup…",
                    )
                    .await?;
                self.stack_outcome(&r);
                self.collect_status("Collecting status after stack backup restoration…")
                    .await?;
                self.collect_stack().await?;
            }
            "stack-resolve" => {
                let id = self.value("stack-operation-id");
                let review = self
                    .state
                    .borrow()
                    .stack
                    .as_ref()
                    .map(|v| s(g(g(v, "operation"), "resolution_review_hash")).to_owned())
                    .unwrap_or_default();
                if !core::id(&json!(id))
                    || !core::hash(&json!(review))
                    || self.value("stack-resolve-phrase") != core::STACK_RESOLVE_PHRASE
                {
                    return Err(
                        "Inspect the stack operation and type the exact keep-current phrase first."
                            .into(),
                    );
                }
                self.collect_stack().await?;
                let unchanged = self.state.borrow().stack.as_ref().is_some_and(|v| {
                    s(g(g(v, "operation"), "id")) == id
                        && s(g(g(v, "operation"), "resolution_review_hash")) == review
                        && yes(g(g(v, "operation"), "can_resolve"))
                });
                if !unchanged {
                    self.set_value("stack-resolve-phrase", "");
                    return Err("Stack evidence changed. Inspect and confirm the current file again; close-out was not submitted.".into());
                }
                self.set_value("stack-resolve-phrase", "");
                self.discard_stack_plan("");
                self.invalidate_verification(
                    "A stack close-out was recorded; prior workflow evidence is stale.",
                );
                let r=self.req("stack",json!({"action":"resolve","id":id,"confirmation":core::STACK_RESOLVE_PHRASE,"review_hash":review}),"Preserving the current stack resource and closing its operation without writing that resource…").await?;
                self.stack_outcome(&r);
                self.collect_status("Refreshing status after stack close-out…")
                    .await?;
                self.collect_stack().await?;
            }
            "stack-cancel" => {
                self.discard_stack_plan("");
                self.check("stack-rollback-confirm", false);
                self.state.borrow_mut().stack_rollback_binding = None;
                self.set_value("stack-profile", "");
                self.set_value("stack-package-input", "");
                self.clear("stack-package-choices");
                for el in self.all("[name='stack-target'],[name='stack-enabled']") {
                    prop(&el, "checked", &false.into());
                }
                self.set("stack-operation-result","Stack review cancelled. Private staged plans are retained; active stack configuration is unchanged.");
            }
            "trust-status" | "trust-refresh" => {
                let refresh = action == "trust-refresh";
                let r=self.req("trust",json!({"action":if refresh{"refresh"}else{"status"}}),if refresh{"Fetching full Google public roots and status feeds over HTTPS GET; no private material is uploaded…"}else{"Reading cached redacted public attestation evidence…"}).await?;
                self.public_trust(&r.data);
            }
            "watch" => {
                let days = self.value("watch-days");
                if !valid(r"^\d{1,3}$", &days)
                    || days
                        .parse::<u16>()
                        .map_or(true, |n| !(1..=365).contains(&n))
                {
                    return Err("Use 1–365 days.".into());
                }
                let r = self
                    .req("watch", json!({"days":days}), "Collecting evidence…")
                    .await?;
                let alignment = match g(&r.data, "patch_aligned").as_bool() {
                    Some(true) => "aligned".into(),
                    Some(false) => "mismatch".into(),
                    None => fallback(g(&r.data, "patch_aligned"), "unknown"),
                };
                let el = self.clear("watch-result");
                self.p(&el,&format!("Estimated expiry {} · {} days remaining · Fingerprint estimate: {} · Patch alignment {alignment}.",text(g(&r.data,"estimate")),text(g(&r.data,"days_remaining")),text(g(&r.data,"fingerprint_estimate_state"))));
                self.items(&el, g(&r.data, "warnings"));
            }
            "recovery-status" => {
                let r = self
                    .req(
                        "recovery",
                        json!({"action":"status"}),
                        "Collecting evidence…",
                    )
                    .await?;
                {
                    let mut st = self.state.borrow_mut();
                    st.recovery = core::needs_recovery(&r.data);
                    st.lock_present = yes(g(&r.data, "lock_present"));
                }
                self.describe("recovery-result", &r);
            }
            "recovery-restore" => {
                if !self.state.borrow().recovery || !self.checked("recovery-confirm") {
                    return Err("Inspect the journal and confirm restoration first.".into());
                }
                self.check("recovery-confirm", false);
                self.invalidate_verification("Recovery restoration was submitted.");
                self.state.borrow_mut().evidence = None;
                let r = self
                    .req(
                        "recovery",
                        json!({"action":"restore"}),
                        "Restoring the interrupted transaction’s previous configuration…",
                    )
                    .await?;
                self.describe("recovery-result", &r);
                self.state.borrow_mut().recovery = false;
            }
            "recovery-release" => {
                if !self.state.borrow().lock_present {
                    return Err("Inspect the recovery lock first.".into());
                }
                let r = self
                    .req(
                        "recovery",
                        json!({"action":"release-lock"}),
                        "Checking that the lock-owning process ended before release…",
                    )
                    .await?;
                self.describe("recovery-result", &r);
                self.state.borrow_mut().lock_present = false;
            }
            "reset-status" | "reset-resume" => {
                let r=self.req("reset",json!({"action":if action=="reset-resume"{"resume"}else{"status"}}),if action=="reset-resume"{"Checking the one-shot reset journal; PIF execution remains a manual action…"}else{"Collecting evidence…"}).await?;
                self.describe("reset-result", &r);
                self.state.borrow_mut().reset_close_review = if yes(g(&r.data, "can_close"))
                    && core::hash(g(&r.data, "close_review_hash"))
                {
                    Some(s(g(&r.data, "close_review_hash")).into())
                } else {
                    None
                };
            }
            "reset-close" => {
                let review = self
                    .state
                    .borrow()
                    .reset_close_review
                    .clone()
                    .ok_or("Inspect an incomplete reset before closing it.")?;
                if self.value("reset-close-phrase") != core::RESET_CLOSE_PHRASE {
                    return Err("Type the exact incomplete-reset close-out phrase.".into());
                }
                let status = self
                    .req(
                        "reset",
                        json!({"action":"status"}),
                        "Rechecking the incomplete reset ledger…",
                    )
                    .await?;
                if !yes(g(&status.data, "can_close"))
                    || s(g(&status.data, "close_review_hash")) != review
                {
                    self.state.borrow_mut().reset_close_review = None;
                    self.set_value("reset-close-phrase", "");
                    return Err("Reset evidence changed. Inspect its current state again; no close-out was submitted.".into());
                }
                self.state.borrow_mut().reset_close_review = None;
                self.set_value("reset-close-phrase", "");
                self.invalidate_verification(
                    "An incomplete reset was closed; cleared data is not restored.",
                );
                let r=self.req("reset",json!({"action":"close","confirmation":core::RESET_CLOSE_PHRASE,"review_hash":review}),"Recording close-out without repeating any clear or changing app data…").await?;
                self.describe("reset-result", &r);
                self.collect_status("Refreshing status after incomplete reset close-out…")
                    .await?;
            }
            "reset-preview" => {
                self.state.borrow_mut().reset = None;
                self.set_value("reset-phrase", "");
                let r = self
                    .req("reset", json!({"action":"preview"}), "Collecting evidence…")
                    .await?;
                let el = self.clear("reset-preview");
                self.p(&el, &r.message);
                self.p(&el,&format!("Reviewed numeric Android user: {}. All clears are bound to this user; a profile change blocks continuation.",text(g(&r.data,"user"))));
                self.items(&el, g(&r.data, "steps"));
                self.items(&el, g(&r.data, "consequences"));
                let hash = s(g(&r.data, "review_hash"));
                if hash.is_empty() {
                    return Err("Reviewed reset hash unavailable. Reset is blocked.".into());
                }
                self.state.borrow_mut().reset = Some(hash.into());
                self.hidden("reset-confirm-fields", false);
            }
            "reset-confirm" => {
                let hash =
                    self.state.borrow().reset.clone().ok_or(
                        "Review the reset sequence and type the full confirmation phrase.",
                    )?;
                if self.value("reset-phrase") != core::RESET_PHRASE {
                    return Err(
                        "Review the reset sequence and type the full confirmation phrase.".into(),
                    );
                }
                self.state.borrow_mut().reset = None;
                self.set_value("reset-phrase", "");
                self.hidden("reset-confirm-fields", true);
                self.invalidate_verification(
                    "A separately confirmed app-data reset was submitted.",
                );
                let r=self.req("reset",json!({"action":"confirm","confirmation":core::RESET_PHRASE,"review_hash":hash}),"Executing only the separately confirmed, reviewed app-data steps…").await?;
                self.describe("reset-result", &r);
            }
            "reset-complete" => {
                if self.value("reset-complete-phrase") != core::COMPLETE_PHRASE {
                    return Err("Confirm the successful manual post-reboot commands first.".into());
                }
                self.set_value("reset-complete-phrase", "");
                self.invalidate_verification("Manual PIF/GMS completion was recorded.");
                let r = self
                    .req(
                        "reset",
                        json!({"action":"complete","confirmation":core::COMPLETE_PHRASE}),
                        "Recording your separately confirmed manual completion…",
                    )
                    .await?;
                self.describe("reset-result", &r);
            }
            _ => return Ok(()),
        }
        self.sync();
        Ok(())
    }
    async fn handle(self: &Rc<Self>, action: String) {
        if let Err(error) = self.action(&action).await {
            let failure = error
                .response
                .as_ref()
                .map(|r| format!("{}: {}", r.code, r.message))
                .unwrap_or(error.message);
            self.notice(&failure, true);
            if action == "verify" {
                self.invalidate_verification(
                    "The latest Verify did not establish current evidence.",
                );
            }
            if let Some(r) = error.response {
                if r.data.get("findings").is_some() {
                    self.findings("diagnostic-findings", g(&r.data, "findings"));
                }
                if action.starts_with("reset-") {
                    self.describe("reset-result", &r);
                }
                if action.starts_with("trust-") {
                    self.public_trust(&r.data);
                }
                if action == "apply" {
                    self.hidden("plan-card", true);
                    self.hidden("verify-card", false);
                    self.describe("verification-result", &r);
                }
            }
            if ["stack-apply", "stack-rollback", "stack-resolve"].contains(&action.as_str()) {
                if self
                    .collect_status("Inspecting recovery state after the stopped stack operation…")
                    .await
                    .is_err()
                    || self.collect_stack().await.is_err()
                {
                    {
                        let mut st = self.state.borrow_mut();
                        st.stack_pending = true;
                        st.apply_available = false;
                    }
                    self.discard_stack_plan(
                        "Fresh stack state is unavailable. Inspect recovery before another write.",
                    );
                }
                self.notice(&failure, true);
            }
            self.sync();
        }
    }
}

fn warning(value: &str) -> &str {
    match value {
        "trust_not_established" => "Public trust is not established by local chain validation.",
        "revocation_unknown" => "Revocation status is unknown.",
        "engine_compatibility_requires_verification" => {
            "Engine compatibility and actual adoption require separate verification."
        }
        "pkcs8_requires_traditional_pem_for_installed_engine" => {
            "Source private key uses PKCS#8. A reviewed merge converts it to the traditional PEM required by the inspected engine."
        }
        "private_key_encoding_normalized_for_installed_engine" => {
            "Output private-key encoding is converted to SEC1 for ECDSA or PKCS#1 for RSA. The mathematical key and complete chain stay together."
        }
        "metadata_placeholder_indicator" => {
            "Source metadata has a placeholder indicator; source identity is withheld."
        }
        "certificate_placeholder_indicator" => {
            "A certificate has a placeholder indicator; review provenance and trust."
        }
        "single_self_signed_certificate_placeholder_possible" => {
            "A single self-signed certificate may be placeholder material."
        }
        "self_signed_anchor_does_not_establish_trust" => {
            "A self-signed chain anchor does not establish public trust."
        }
        "duplicate_algorithm_explicit_selection_required" => {
            "Duplicate algorithm entries require explicit selection."
        }
        _ => value,
    }
}

/// Called once by the small loader after explicit-byte WASM initialization.
#[wasm_bindgen]
pub fn start_ui(bridge: Function) -> std::result::Result<(), JsValue> {
    let window = web_sys::window().ok_or("Browser window unavailable")?;
    let document = window.document().ok_or("Browser document unavailable")?;
    let native = Reflect::get(window.as_ref(), &"ksu".into())
        .ok()
        .and_then(|v| Reflect::get(&v, &"exec".into()).ok())
        .is_some_and(|v| v.is_function());
    let app = Rc::new(App {
        window,
        document,
        bridge,
        state: RefCell::new(State {
            bridge: native,
            apply_available: true,
            ..State::default()
        }),
    });
    app.init_trust();
    let a = app.clone();
    let click = Closure::<dyn FnMut(Event)>::new(move |event: Event| {
        let Some(target) = event.target().and_then(|t| t.dyn_into::<Element>().ok()) else {
            return;
        };
        let Ok(Some(button)) = target.closest("button") else {
            return;
        };
        if bool_prop(&button, "disabled") {
            return;
        }
        if let Some(view) = button.get_attribute("data-view") {
            a.show(&view);
            return;
        }
        if let Some(action) = button.get_attribute("data-action") {
            let a = a.clone();
            spawn_local(async move {
                a.handle(action).await;
            });
        }
    });
    app.document
        .add_event_listener_with_callback("click", click.as_ref().unchecked_ref())?;
    click.forget();
    let a = app.clone();
    let change = Closure::<dyn FnMut(Event)>::new(move |event: Event| {
        if let Some(el) = event.target().and_then(|t| t.dyn_into::<Element>().ok()) {
            let id = el.id();
            let name = string_prop(&el, "name");
            if id == "stack-rollback-confirm" {
                let mut st = a.state.borrow_mut();
                st.stack_rollback_binding = if bool_prop(&el, "checked") {
                    st.evidence.clone()
                } else {
                    None
                };
            }
            if id == "stack-profile" {
                a.discard_stack_plan("The selected stack profile changed. Build a fresh review.");
            }
            if ["stack-target", "stack-package", "stack-enabled"].contains(&name.as_str()) {
                a.discard_stack_plan("Stack selections changed. Build a fresh review.");
            }
            if id == "backup-choice" {
                a.check("rollback-confirm", false);
            }
            a.sync();
        }
    });
    app.document
        .add_event_listener_with_callback("change", change.as_ref().unchecked_ref())?;
    change.forget();
    let a = app.clone();
    let input = Closure::<dyn FnMut(Event)>::new(move |event: Event| {
        if let Some(el) = event.target().and_then(|t| t.dyn_into::<Element>().ok()) {
            if el.id() == "stack-operation-id" {
                a.check("stack-rollback-confirm", false);
                a.state.borrow_mut().stack_rollback_binding = None;
            }
            a.sync();
        }
    });
    app.document
        .add_event_listener_with_callback("input", input.as_ref().unchecked_ref())?;
    input.forget();
    let a = app.clone();
    let unload = Closure::<dyn FnMut(Event)>::new(move |event: Event| {
        if a.state.borrow().busy {
            event.prevent_default();
            let _ = Reflect::set(
                event.as_ref(),
                &"returnValue".into(),
                &"An operation is still running. Inspect recovery if interrupted.".into(),
            );
        }
    });
    app.window
        .add_event_listener_with_callback("beforeunload", unload.as_ref().unchecked_ref())?;
    unload.forget();
    app.selections();
    app.sync();
    if native {
        let a = app.clone();
        spawn_local(async move {
            a.handle("status".into()).await;
        });
    } else {
        app.notice("WebUI root bridge unavailable. Open this module in KSU WebUI, or run /data/adb/modules/wallet_diagnostic/bin/walletdiag help through a root shell.",true);
    }
    Ok(())
}
