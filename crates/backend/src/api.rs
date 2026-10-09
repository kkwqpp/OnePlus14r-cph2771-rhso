//! Private HTTPS raw-XML staging. This never validates, selects or applies keys.
use crate::{
    App,
    error::{Error, Result},
    fs, network, util,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;
use zeroize::Zeroize;
#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Authentication {
    mode: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    token: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    header: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    key: String,
}
impl Drop for Authentication {
    fn drop(&mut self) {
        self.token.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.key.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: u32,
    url: String,
    provenance_declaration: String,
    auth: Authentication,
}
impl Drop for Configuration {
    fn drop(&mut self) {
        self.url.zeroize();
        self.provenance_declaration.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateState {
    schema: u32,
    generation: String,
    config: Configuration,
}
fn config_error() -> Error {
    Error::new(
        "E_API_CONFIG",
        "Private source configuration is invalid or unsupported; no credential details are displayed.",
    )
}
fn text_ok(s: &str, max: usize, empty: bool) -> bool {
    (empty || !s.is_empty()) && s.len() <= max && !s.chars().any(|c| c < ' ' || c == '\u{7f}')
}
impl Configuration {
    fn validate(&self) -> Result<url::Url> {
        if self.schema != 1
            || !text_ok(&self.url, 2048, false)
            || !text_ok(&self.provenance_declaration, 512, false)
            || self.provenance_declaration.trim().is_empty()
            || self.url.contains('#')
        {
            return Err(config_error());
        }
        let u = url::Url::parse(&self.url).map_err(|_| config_error())?;
        if u.scheme() != "https"
            || u.port() == Some(0)
            || !u.username().is_empty()
            || u.password().is_some()
            || u.fragment().is_some()
            || u.host().is_none()
        {
            return Err(config_error());
        }
        let authority = self
            .url
            .split_once("://")
            .map(|(_, v)| v.split('/').next().unwrap_or(""))
            .unwrap_or("");
        if !authority.is_ascii() || authority.split('?').next().unwrap_or("").ends_with(':') {
            return Err(config_error());
        }
        let host = u.host_str().ok_or_else(config_error)?;
        if let Ok(ip) = host.trim_matches(['[', ']']).parse() {
            if !network::public_address(ip) {
                return Err(config_error());
            }
        } else {
            let re = regex::Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$").unwrap();
            if host.len() > 253
                || host
                    .trim_end_matches('.')
                    .split('.')
                    .any(|s| !re.is_match(s))
            {
                return Err(config_error());
            }
        }
        let a = &self.auth;
        for s in [&a.token, &a.username, &a.password, &a.header, &a.key] {
            if !text_ok(s, 8192, true) {
                return Err(config_error());
            }
        }
        let ok = match a.mode.as_str() {
            "NONE" => {
                a.token.is_empty()
                    && a.username.is_empty()
                    && a.password.is_empty()
                    && a.header.is_empty()
                    && a.key.is_empty()
            }
            "BEARER" => {
                !a.token.is_empty()
                    && !a.token.contains([' ', '\t'])
                    && a.username.is_empty()
                    && a.password.is_empty()
                    && a.header.is_empty()
                    && a.key.is_empty()
            }
            "BASIC" => {
                !a.username.is_empty()
                    && !a.password.is_empty()
                    && a.username.len() <= 256
                    && !a.username.contains(':')
                    && a.token.is_empty()
                    && a.header.is_empty()
                    && a.key.is_empty()
            }
            "API_KEY" => {
                let header = a.header.to_ascii_lowercase();
                !a.key.is_empty()
                    && a.key.trim() == a.key
                    && a.token.is_empty()
                    && a.username.is_empty()
                    && a.password.is_empty()
                    && regex::Regex::new(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
                        .unwrap()
                        .is_match(&a.header)
                    && !header.starts_with("proxy-")
                    && ![
                        "authorization",
                        "cookie",
                        "cookie2",
                        "host",
                        "connection",
                        "content-length",
                        "transfer-encoding",
                        "accept",
                        "accept-encoding",
                        "user-agent",
                        "referer",
                        "origin",
                        "te",
                        "trailer",
                        "upgrade",
                    ]
                    .contains(&header.as_str())
            }
            _ => false,
        };
        if !ok {
            return Err(config_error());
        }
        Ok(u)
    }
}
fn decode<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T> {
    if b.is_empty() || b.len() > 16 << 10 {
        return Err(config_error());
    }
    let v = util::strict_json(b).map_err(|_| config_error())?;
    fn inspect(v: &Value, depth: usize, n: &mut usize) -> bool {
        *n += 1;
        if depth > 6 || *n > 256 {
            return false;
        }
        match v {
            Value::Null | Value::Array(_) => false,
            Value::Object(o) => o.values().all(|v| inspect(v, depth + 1, n)),
            _ => true,
        }
    }
    if !inspect(&v, 0, &mut 0) {
        return Err(config_error());
    }
    serde_json::from_slice(b).map_err(|_| config_error())
}
fn private_file(p: &Path) -> Result<()> {
    fs::no_links(p).map_err(|_| config_error())?;
    let m = fs::metadata(p).map_err(|_| config_error())?;
    if m.mode != 0o600 || m.uid != util::owner_id() || m.gid != util::owner_id() {
        return Err(config_error());
    }
    Ok(())
}
fn private_directory(p: &Path) -> Result<()> {
    fs::no_links(p).map_err(|_| config_error())?;
    if !std::fs::metadata(p).is_ok_and(|m| m.is_dir()) {
        return Err(config_error());
    }
    let m = fs::metadata(p).map_err(|_| config_error())?;
    if m.mode != 0o700 || m.uid != util::owner_id() || m.gid != util::owner_id() {
        return Err(config_error());
    }
    Ok(())
}
pub fn raw_xml(b: &[u8]) -> Result<()> {
    use quick_xml::events::Event;
    if b.is_empty() || b.len() > rhso_keybox::MAX_INPUT {
        return Err(Error::new(
            "E_API_LIMIT",
            "Source response is empty or exceeds the private XML bound.",
        ));
    }
    let format_error = || {
        Error::new(
            "E_API_FORMAT",
            "Source response is not complete supported raw UTF-8 XML.",
        )
    };
    let text = std::str::from_utf8(b).map_err(|_| format_error())?;
    if b.contains(&b'&')
        || !text.chars().all(|c| {
            matches!(c, '\t' | '\r' | '\n') || c >= '\u{20}' && c != '\u{fffe}' && c != '\u{ffff}'
        })
    {
        return Err(Error::new(
            "E_API_FORMAT",
            "Only raw UTF-8 keybox XML is supported; encrypted, archive and HTML formats are rejected.",
        ));
    }
    let mut reader = quick_xml::Reader::from_reader(b);
    reader.config_mut().expand_empty_elements = true;
    reader.config_mut().check_comments = true;
    let mut elements = Vec::<Vec<u8>>::new();
    let mut roots = 0;
    let mut tokens = 0;
    let mut declaration = false;
    static DECLARATION: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let declaration_pattern = DECLARATION.get_or_init(|| regex::Regex::new(r#"^xml[ \t\r\n]+version[ \t\r\n]*=[ \t\r\n]*(?:"1\.0"|'1\.0')(?:[ \t\r\n]+encoding[ \t\r\n]*=[ \t\r\n]*(?:"(?:UTF-8|utf-8)"|'(?:UTF-8|utf-8)'))?(?:[ \t\r\n]+standalone[ \t\r\n]*=[ \t\r\n]*(?:"(?:yes|no)"|'(?:yes|no)'))?[ \t\r\n]*$"#).expect("fixed XML declaration pattern"));
    loop {
        tokens += 1;
        if tokens > 4096 {
            return Err(Error::new(
                "E_API_LIMIT",
                "Source XML exceeds the structural inspection bound.",
            ));
        }
        let ev = reader.read_event().map_err(|_| format_error())?;
        match ev {
            Event::Eof => break,
            Event::Start(e) => {
                if elements.len() >= 32 {
                    return Err(Error::new(
                        "E_API_LIMIT",
                        "Source XML exceeds the structural inspection bound.",
                    ));
                }
                let name = e.name();
                if !supported_xml_name(name.as_ref()) {
                    return Err(format_error());
                }
                // Inspect every element's attributes, including nested elements.
                // Namespaces, malformed/duplicate attributes and entity syntax
                // are rejected before any private staging file is created.
                for attribute in e.attributes() {
                    let attribute = attribute.map_err(|_| format_error())?;
                    if !supported_xml_name(attribute.key.as_ref())
                        || attribute.key.as_ref() == b"xmlns"
                        || attribute.value.contains(&b'<')
                    {
                        return Err(format_error());
                    }
                }
                if elements.is_empty() {
                    roots += 1;
                    if roots != 1 || !matches!(e.name().as_ref(), b"AndroidAttestation" | b"Keybox")
                    {
                        return Err(Error::new(
                            "E_API_FORMAT",
                            "Source XML has an unsupported wrapper.",
                        ));
                    }
                }
                elements.push(name.as_ref().to_vec());
            }
            Event::End(e) => {
                if elements.pop().is_none_or(|name| name != e.name().as_ref()) {
                    return Err(format_error());
                }
            }
            Event::DocType(_) | Event::PI(_) | Event::GeneralRef(_) | Event::Empty(_) => {
                return Err(Error::new(
                    "E_API_FORMAT",
                    "XML directives and processing instructions are not supported.",
                ));
            }
            Event::Decl(value) => {
                if roots > 0
                    || !elements.is_empty()
                    || declaration
                    || !declaration_pattern
                        .is_match(std::str::from_utf8(value.as_ref()).map_err(|_| format_error())?)
                {
                    return Err(format_error());
                }
                declaration = true;
            }
            Event::Comment(value) => {
                if value.len() > 4096 {
                    return Err(Error::new(
                        "E_API_LIMIT",
                        "Source XML exceeds the structural inspection bound.",
                    ));
                }
            }
            Event::Text(t) if elements.is_empty() => {
                if !xml_space(t.as_ref()) {
                    return Err(Error::new(
                        "E_API_FORMAT",
                        "Unexpected data outside the XML wrapper.",
                    ));
                }
            }
            Event::CData(t) if elements.is_empty() => {
                if !xml_space(t.as_ref()) {
                    return Err(format_error());
                }
            }
            _ => {}
        }
    }
    if roots != 1 || !elements.is_empty() {
        return Err(Error::new(
            "E_API_FORMAT",
            "Source response does not contain a complete keybox XML wrapper.",
        ));
    }
    Ok(())
}
fn xml_space(b: &[u8]) -> bool {
    b.iter().all(|c| matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
}
fn supported_xml_name(b: &[u8]) -> bool {
    // The supported raw-keybox schema has unqualified ASCII element/attribute
    // names. General XML namespaces and alternate name grammars are unsupported.
    b.first()
        .is_some_and(|v| v.is_ascii_alphabetic() || *v == b'_')
        && b.iter()
            .skip(1)
            .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'_' | b'-' | b'.'))
}
pub fn xml_headers(h: &std::collections::BTreeMap<String, Vec<String>>) -> bool {
    let Some(media) =
        crate::media_type::single(h, "content-type").and_then(crate::media_type::parse)
    else {
        return false;
    };
    if !matches!(media.essence.as_str(), "application/xml" | "text/xml") {
        return false;
    }
    if media
        .parameters
        .get("charset")
        .is_some_and(|v| !matches!(v.to_ascii_lowercase().as_str(), "" | "utf-8" | "us-ascii"))
    {
        return false;
    }
    crate::media_type::uncompressed(h)
}
impl App {
    fn load_api_source(&self) -> Result<(PrivateState, String)> {
        let p = self.root.join("api-source.json");
        let b = zeroize::Zeroizing::new(fs::bounded(&p, 16 << 10)?);
        private_directory(&self.root)?;
        private_file(&p)?;
        let s: PrivateState = decode(&b)?;
        if s.schema != 1 || !util::valid_id(&s.generation) {
            return Err(config_error());
        }
        s.config.validate()?;
        Ok((s, util::hash(&b)))
    }
    pub(crate) fn api_source_status(&self) -> Value {
        let mut out = json!({"api_status":"generic-https-raw-xml","state":"unconfigured","configured":false,"available":false,"auth_configured":false,"exact_endpoint_available":false,"provider_contract_verified":false,"supported_format":"raw-xml","message":"The original supplied endpoint remains unverified and unavailable. A separately configured HTTPS raw-XML source requires an operator provenance declaration; no provider identity or hardware trust is inferred."});
        match self.load_api_source() {
            Ok((s, _)) => {
                out["state"] = json!("configured");
                out["configured"] = json!(true);
                out["available"] = json!(!self.fake && !self.unfinished());
                out["auth_configured"] = json!(s.config.auth.mode != "NONE");
                out["source_generation"] = json!(s.generation);
            }
            Err(_) => {
                if std::fs::symlink_metadata(self.root.join("api-source.json")).is_ok() {
                    out["state"] = json!("invalid");
                }
            }
        }
        out
    }
    pub fn api(&self, action: &str, path: &str) -> Result<Value> {
        if action.is_empty() || action == "status" {
            if !path.is_empty() {
                return Err(Error::new(
                    "E_REQUEST",
                    "A configuration path is accepted only for API config.",
                ));
            }
            return Ok(self.api_source_status());
        }
        if action != "config" && action != "import" {
            return Err(Error::new(
                "E_REQUEST",
                "API actions are status, config or import.",
            ));
        }
        self.with_lock(||{self.require_recovered()?;if action=="config"{let p=Path::new(path);let base=self.root.join("inbox");let filename=p.file_name().and_then(|v|v.to_str()).unwrap_or("");if !p.is_absolute()||p.parent()!=Some(base.as_path())||path.contains(['\0','\r','\n'])||filename.contains("..")||!regex::Regex::new(r"^[A-Za-z0-9_-][A-Za-z0-9._-]{0,95}\.json$").unwrap().is_match(filename){return Err(Error::new("E_PATH","API configuration is accepted only from a clean root-private inbox JSON path."));}private_directory(&self.root)?;private_directory(&base)?;private_file(p)?;let b=zeroize::Zeroizing::new(fs::bounded(p,16<<10)?);let config:Configuration=decode(&b)?;config.validate()?;fs::write_json(&self.root.join("api-source.json"),&PrivateState{schema:1,generation:util::new_id()?,config})?;return Ok(self.api_source_status());}
if !path.is_empty(){return Err(Error::new("E_REQUEST","A configuration path is accepted only for API config."));}
if self.fake{return Err(Error::new("E_CAPABILITY","Network import is disabled in the fake-engine test backend."));}
if !self.root.join("api-source.json").try_exists()?{fs::no_links(&self.root.join("api-source.json"))?;return Err(Error::new("E_API_UNAVAILABLE","No private generic source is configured; the original endpoint remains unverified and unavailable."));}let(s,digest)=self.load_api_source().map_err(|_|config_error())?;let url=s.config.validate()?;let a=&s.config.auth;let mut headers=vec![("Accept".into(),"application/xml, text/xml".into()),("User-Agent".into(),"WalletDiagnostic-configured-source/1".into())];match a.mode.as_str(){"BEARER"=>headers.push(("Authorization".into(),format!("Bearer {}",a.token))),"BASIC"=>headers.push(("Authorization".into(),format!("Basic {}",STANDARD.encode(format!("{}:{}",a.username,a.password))))),"API_KEY"=>headers.push((a.header.clone(),a.key.clone())),_=>{}}let fetched=network::get(&url,&headers,rhso_keybox::MAX_INPUT,true);for(_,v)in &mut headers{v.zeroize();}let r=fetched?;if !xml_headers(&r.headers){return Err(Error::new("E_API_FORMAT","Configured source must return uncompressed raw XML with a supported content type."));}raw_xml(&r.body)?;self.checkpoint("before-api-stage")?;let(fresh,now_digest)=self.load_api_source()?;if fresh.generation!=s.generation||now_digest!=digest{return Err(Error::new("E_API_STALE","Private source configuration changed during import; no input was staged."));}self.require_recovered()?;Ok(json!(self.stage_bytes(&r.body)?))})
    }
}
