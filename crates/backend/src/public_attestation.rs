use crate::{
    App,
    error::{Error, Result},
    fs, network, util,
};
use rhso_keybox::{self as keybox, Document, PublicFeeds};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
const ROOTS: &str = "https://android.googleapis.com/attestation/root";
const STATUS: &str = "https://android.googleapis.com/attestation/status";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    #[serde(with = "byte_codec")]
    body: Vec<u8>,
    sha256: String,
    expires_at: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cache {
    schema: u32,
    checked_at: String,
    roots: Snapshot,
    status: Snapshot,
}
mod byte_codec {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(b))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}
const LIMITATIONS: [&str; 4] = [
    "The complete Google public feeds are fetched over verified HTTPS; no private key, local certificate, serial or keybox is uploaded.",
    "The feeds have no documented detached signature. Cached bytes and timestamps are locally checked, not a signed offline CRL.",
    "A recognized Google root key and absence from this status snapshot do not establish genuine hardware, fresh attestation, issuer approval or Wallet acceptance.",
    "Private-input validation uses the helper's conservative date/chain profile. Historical factory-attestation exceptions are not silently applied to imported signer keys.",
];
pub fn expiry(h: &BTreeMap<String, Vec<String>>, now: i64) -> i64 {
    let field = |k: &str| {
        h.get(k).and_then(|v| {
            if v.len() == 1 {
                Some(v[0].as_str())
            } else {
                None
            }
        })
    };
    let Some(date) = field("date").and_then(http_time) else {
        return now;
    };
    if date > now + 300
        || h.get("age").is_some_and(|v| v.len() > 1)
        || h.get("expires").is_some_and(|v| v.len() > 1)
    {
        return now;
    }
    let mut max_age = None;
    for part in h
        .get("cache-control")
        .into_iter()
        .flatten()
        .flat_map(|s| s.split(','))
    {
        let p = part.trim().to_ascii_lowercase();
        if p == "no-store" || p == "no-cache" || p.starts_with("no-cache=") {
            return now;
        }
        if let Some(raw) = p.strip_prefix("max-age=") {
            let raw = if raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2 {
                &raw[1..raw.len() - 1]
            } else {
                raw
            };
            if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) || max_age.is_some() {
                return now;
            }
            let Ok(v) = raw.parse::<i64>() else {
                return now;
            };
            max_age = Some(v);
        }
    }
    let mut age = 0;
    if let Some(raw) = field("age") {
        if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
            return now;
        }
        let Ok(v) = raw.parse::<i64>() else {
            return now;
        };
        age = v;
    }
    age = age.max(now.saturating_sub(date));
    let mut lifetime = max_age.unwrap_or(-1);
    if let Some(until) = field("expires").and_then(http_time) {
        let value = until.saturating_sub(date);
        if lifetime < 0 || value < lifetime {
            lifetime = value;
        }
    }
    now.saturating_add(lifetime.min(86400).saturating_sub(age).max(0))
}
fn http_time(s: &str) -> Option<i64> {
    httpdate::parse_http_date(s)
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|v| i64::try_from(v.as_secs()).ok())
}
fn fetch(url: &str, max: usize, now: i64) -> Result<Snapshot> {
    if url != ROOTS && url != STATUS {
        return Err(Error::new(
            "E_PUBLIC_FEED",
            "Only the verified Google public-feed endpoints are supported.",
        ));
    }
    let u = url::Url::parse(url).expect("fixed URL");
    let r=network::get(&u,&[("Accept".into(),"application/json".into()),("User-Agent".into(),"WalletDiagnostic-public-check/0.1".into())],max,false).map_err(|e|match e.code.as_str(){"E_API_DNS"=>Error::new("E_PUBLIC_DNS","Android could not resolve the Google public-feed hostname. Cached evidence was preserved."),"E_API_TLS"=>Error::new("E_PUBLIC_TLS","Google public-feed TLS certificate verification failed. Check device time and the system trust store; verification was not bypassed."),_=>Error::new("E_PUBLIC_FEED","Google public-feed request failed or returned an unsupported response. Existing cached evidence was preserved; no local material was uploaded.")})?;
    if r.headers
        .get("cache-control")
        .into_iter()
        .flatten()
        .flat_map(|s| s.split(','))
        .any(|v| v.trim().eq_ignore_ascii_case("no-store"))
    {
        return Err(Error::new(
            "E_PUBLIC_FEED",
            "Public response forbids caching. Existing evidence was preserved without storing the new response.",
        ));
    }
    if !crate::media_type::json_headers(&r.headers) {
        return Err(Error::new(
            "E_PUBLIC_FEED",
            "Google public-feed response was not the verified JSON format.",
        ));
    }
    Ok(Snapshot {
        body: r.body.to_vec(),
        sha256: util::hash(&r.body),
        expires_at: util::time(expiry(&r.headers, now)),
    })
}
impl App {
    fn load_public_cache(&self) -> Result<(Cache, PublicFeeds, i64)> {
        let c: Cache = fs::read_json(&self.root.join("public-attestation.json"))?;
        let checked = util::parse_time(&c.checked_at)?;
        if c.schema != 1 || checked > self.now() + 60 {
            return Err(Error::new(
                "E_PUBLIC_FEED",
                "Public-feed cache metadata is invalid; refresh it explicitly.",
            ));
        }
        let mut until = i64::MAX;
        for s in [&c.roots, &c.status] {
            let expiry = util::parse_time(&s.expires_at)?;
            if !util::valid_hash(&s.sha256)
                || util::hash(&s.body) != s.sha256
                || expiry > checked + 86400
            {
                return Err(Error::new(
                    "E_PUBLIC_FEED",
                    "Public-feed cache failed metadata or checksum checks; refresh it explicitly.",
                ));
            }
            until = until.min(expiry);
        }
        let f=keybox::parse_public_feeds(&c.roots.body,&c.status.body).map_err(|_|Error::new("E_PUBLIC_FEED","Public-feed cache format is invalid or unsupported; no public trust verdict was issued."))?;
        Ok((c, f, until))
    }
    pub(crate) fn public_trust_view(&self) -> Value {
        let p = self.root.join("public-attestation.json");
        let mut out = json!({"available":false,"state":"no-cache","sources":"Google public attestation roots and status over verified HTTPS","keys":[],"limitations":LIMITATIONS,"next_step":"Run an explicit Google public-feed refresh, then recheck the current chain locally."});
        let Ok((c, f, until)) = self.load_public_cache() else {
            if std::fs::symlink_metadata(&p).is_ok() {
                out["state"] = json!("invalid");
                out["next_step"] = json!(
                    "Public evidence is invalid or unsupported. Refresh explicitly; current files were not changed."
                );
            }
            return out;
        };
        out["checked_at"] = json!(c.checked_at);
        out["expires_at"] = json!(util::time(until));
        out["roots_sha256"] = json!(c.roots.sha256);
        out["status_sha256"] = json!(c.status.sha256);
        if self.now() >= until {
            out["state"] = json!("stale");
            out["next_step"] =
                json!("Refresh the expired public-feed snapshot before interpreting status.");
            return out;
        }
        out["state"] = json!("fresh");
        let Ok(b) = fs::bounded(&self.active.join("keybox.xml"), keybox::MAX_INPUT) else {
            out["next_step"] =
                json!("Current keybox is unavailable; no public chain assessment was possible.");
            return out;
        };
        let b = zeroize::Zeroizing::new(b);
        out["keybox_sha256"] = json!(util::hash(&b));
        let Ok(d) = keybox::parse(&b, self.now()) else {
            out["next_step"] = json!(
                "Current input failed conservative local validation. Review its diagnostic before a public-chain assessment."
            );
            return out;
        };
        let Ok(checks) = d.check_public(&f) else {
            out["state"] = json!("invalid");
            return out;
        };
        out["available"] = json!(true);
        out["next_step"] = json!(
            "Check current Wallet setup/security guidance and Play certification; public-chain checks do not prove payment readiness."
        );
        for c in &checks {
            if matches!(c.revocation, "listed-revoked" | "listed-suspended") {
                out["next_step"] = json!(
                    "A local chain certificate is listed by Google. Preserve it and obtain authorized non-listed material before considering a replacement."
                );
                break;
            }
            if !c.google_root_key {
                out["next_step"] = json!(
                    "The chain anchor does not match Google's published root keys. Local consistency does not establish Google trust."
                );
            }
        }
        out["keys"] = json!(checks);
        out
    }
    pub fn trust(&self, action: &str) -> Result<Value> {
        self.with_lock(||{if action.is_empty()||action=="status"{return Ok(self.public_trust_view());}
if action!="refresh"{return Err(Error::new("E_REQUEST","Trust actions are status or refresh."));}
if self.fake{return Err(Error::new("E_CAPABILITY","Network refresh is disabled in the fake-engine test backend.").with_data(self.public_trust_view()));}let roots=fetch(ROOTS,keybox::MAX_PUBLIC_ROOTS,self.now()).map_err(|e|e.with_data(self.public_trust_view()))?;let status=fetch(STATUS,keybox::MAX_PUBLIC_STATUS,self.now()).map_err(|e|e.with_data(self.public_trust_view()))?;keybox::parse_public_feeds(&roots.body,&status.body).map_err(|_|Error::new("E_PUBLIC_FEED","Public JSON did not pass the verified schema. Existing evidence was preserved."))?;fs::write_json(&self.root.join("public-attestation.json"),&Cache{schema:1,checked_at:self.time(),roots,status})?;Ok(self.public_trust_view())})
    }
    pub(crate) fn reject_public_listed(&self, d: &Document) -> Result<()> {
        let Ok((_, f, until)) = self.load_public_cache() else {
            return Ok(());
        };
        if self.now() >= until {
            return Ok(());
        }
        let checks = d.check_public(&f).map_err(|_| {
            Error::new(
                "E_VALIDATION",
                "Public-chain assessment failed; inspect diagnostics before Apply.",
            )
        })?;
        if checks
            .iter()
            .any(|c| matches!(c.revocation, "listed-revoked" | "listed-suspended"))
        {
            return Err(Error::new(
                "E_VALIDATION",
                "Selected or retained chain includes a certificate listed by Google's fresh public status feed. No configuration was changed.",
            ));
        }
        Ok(())
    }
    pub(crate) fn plan_capabilities(&self) -> Result<BTreeMap<String, String>> {
        let mut out = self.capabilities()?;
        out.insert(
            "stack_evidence_binding".into(),
            self.stack_evidence_binding()?,
        );
        let p = self.root.join("public-attestation.json");
        let snapshot = if std::fs::symlink_metadata(&p).is_err() {
            "absent".into()
        } else {
            fs::bounded(&p, 4 << 20)
                .map(|b| util::hash(&b))
                .unwrap_or_else(|_| "unreadable".into())
        };
        out.insert("public_feed_snapshot".into(), snapshot);
        let state = match self.load_public_cache() {
            Ok((_, _, until)) if self.now() < until => "fresh",
            Ok(_) => "stale",
            Err(_) => "unknown",
        };
        out.insert("public_feed_state".into(), state.into());
        Ok(out)
    }
}
