use crate::{crypto, fail, placeholder, Document, Key, Keybox, Result, MAX_INPUT};
use quick_xml::{events::Event, Reader};
use regex::Regex;
use std::{
    collections::{BTreeMap, HashSet},
    sync::OnceLock,
};
use zeroize::{Zeroize, Zeroizing};

fn declaration_pattern() -> &'static Regex {
    static DECL: OnceLock<Regex> = OnceLock::new();
    DECL.get_or_init(||Regex::new(r#"^xml\s+version\s*=\s*[\"']1\.0[\"'](?:\s+encoding\s*=\s*[\"'](?:UTF-8|utf-8)[\"'])?(?:\s+standalone\s*=\s*[\"'](?:yes|no)[\"'])?\s*$"#).expect("fixed declaration regex"))
}

pub(crate) struct Element {
    pub name: String,
    pub attrs: BTreeMap<String, String>,
    pub children: Vec<Element>,
    pub text: Zeroizing<String>,
}
impl Drop for Element {
    fn drop(&mut self) {
        for value in self.attrs.values_mut() {
            value.zeroize();
        }
    }
}
fn element(name: &[u8]) -> Result<Element> {
    let name = std::str::from_utf8(name).map_err(|_| fail("E_XML"))?;
    if name.contains(':') || name.is_empty() {
        return Err(fail("E_SCHEMA"));
    }
    Ok(Element {
        name: name.into(),
        attrs: BTreeMap::new(),
        children: Vec::new(),
        text: Zeroizing::new(String::new()),
    })
}
pub(crate) fn parse(data: &[u8]) -> Result<Element> {
    if data.is_empty() || data.len() > MAX_INPUT {
        return Err(fail("E_SIZE"));
    }
    if data.contains(&b'&') {
        return Err(fail("E_XML_ENTITY"));
    }
    let text = std::str::from_utf8(data).map_err(|_| fail("E_XML"))?;
    if !text.chars().all(|c| {
        matches!(c, '\t' | '\r' | '\n') || c >= '\u{20}' && c != '\u{fffe}' && c != '\u{ffff}'
    }) {
        return Err(fail("E_XML"));
    }
    let mut reader = Reader::from_reader(data);
    reader.config_mut().expand_empty_elements = true;
    reader.config_mut().check_comments = true;
    let mut root = None;
    let mut stack: Vec<Element> = Vec::new();
    let mut tokens = 0usize;
    let mut declaration = false;
    loop {
        let event = reader.read_event().map_err(|_| fail("E_XML"))?;
        if matches!(event, Event::Eof) {
            break;
        }
        tokens += 1;
        if tokens > 4096 {
            return Err(fail("E_LIMIT"));
        }
        match event {
            Event::DocType(_) => return Err(fail("E_XML_DIRECTIVE")),
            Event::PI(_) => return Err(fail("E_XML_PROCESSING")),
            Event::Decl(value) => {
                let regex = declaration_pattern();
                let text = std::str::from_utf8(value.as_ref()).map_err(|_| fail("E_XML"))?;
                if text.contains("encoding") && !text.contains("UTF-8") && !text.contains("utf-8") {
                    return Err(fail("E_XML"));
                }
                if root.is_some() || !stack.is_empty() || declaration || !regex.is_match(text) {
                    return Err(fail("E_XML_PROCESSING"));
                }
                declaration = true;
            }
            Event::Comment(value) => {
                if value.len() > 4096 {
                    return Err(fail("E_LIMIT"));
                }
            }
            Event::Start(value) => {
                if stack.len() >= 8 {
                    return Err(fail("E_SCHEMA"));
                }
                let mut node = element(value.name().as_ref())?;
                for attr in value.attributes().with_checks(false) {
                    let attr = attr.map_err(|_| fail("E_SCHEMA"))?;
                    let name = std::str::from_utf8(attr.key.as_ref()).map_err(|_| fail("E_XML"))?;
                    if name.contains(':') || name == "xmlns" || node.attrs.contains_key(name) {
                        return Err(fail("E_SCHEMA"));
                    }
                    let value =
                        std::str::from_utf8(attr.value.as_ref()).map_err(|_| fail("E_XML"))?;
                    if value.contains('<') {
                        return Err(fail("E_XML"));
                    }
                    node.attrs.insert(name.into(), value.into());
                }
                if stack.is_empty() && root.is_some() {
                    return Err(fail("E_SCHEMA"));
                }
                stack.push(node);
            }
            Event::End(value) => {
                let node = stack.pop().ok_or(fail("E_XML"))?;
                if node.name.as_bytes() != value.name().as_ref() {
                    return Err(fail("E_XML"));
                }
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else {
                    root = Some(node);
                }
            }
            Event::Text(value) => {
                let value = std::str::from_utf8(value.as_ref()).map_err(|_| fail("E_XML"))?;
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(value);
                } else if !value.trim().is_empty() {
                    return Err(fail("E_XML"));
                }
            }
            Event::CData(value) => {
                let value = std::str::from_utf8(value.as_ref()).map_err(|_| fail("E_XML"))?;
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(value);
                } else if !value.trim().is_empty() {
                    return Err(fail("E_XML"));
                }
            }
            Event::GeneralRef(_) => return Err(fail("E_XML_ENTITY")),
            Event::Empty(_) => return Err(fail("E_XML")),
            Event::Eof => unreachable!(),
        }
    }
    if !stack.is_empty() {
        return Err(fail("E_XML"));
    }
    root.ok_or(fail("E_XML"))
}
fn shape(e: &Element, name: &str, attrs: &[&str]) -> bool {
    e.name == name && e.attrs.len() == attrs.len() && attrs.iter().all(|a| e.attrs.contains_key(*a))
}
fn container(e: &Element) -> bool {
    e.text.trim().is_empty()
}
fn count(e: &Element, name: &str, max: usize) -> Result<usize> {
    if !shape(e, name, &[]) || !e.children.is_empty() {
        return Err(fail("E_SCHEMA"));
    }
    let text = e.text.trim();
    if text.is_empty() || text.len() > 3 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(fail("E_COUNT"));
    }
    let n = text.parse::<usize>().map_err(|_| fail("E_COUNT"))?;
    if n < 1 || n > max {
        return Err(fail("E_COUNT"));
    }
    Ok(n)
}
pub(crate) fn document(root: Element, now: i64) -> Result<Document> {
    if !shape(&root, "AndroidAttestation", &[]) || !container(&root) || root.children.len() < 2 {
        return Err(fail("E_SCHEMA"));
    }
    let count_boxes = count(&root.children[0], "NumberOfKeyboxes", 16)?;
    if root.children.len() != count_boxes + 1 {
        return Err(fail("E_COUNT"));
    }
    let mut doc = Document {
        boxes: Vec::new(),
        validated_at: now,
        merged: false,
    };
    for b in root.children.iter().skip(1) {
        if !shape(b, "Keybox", &["DeviceID"])
            || !container(b)
            || b.children.is_empty()
            || b.children.len() > 8
        {
            return Err(fail("E_SCHEMA"));
        }
        let id = &b.attrs["DeviceID"];
        if id.is_empty() || id.len() > 256 {
            return Err(fail("E_SCHEMA"));
        }
        let mut output = Keybox {
            device_id: Zeroizing::new(id.clone()),
            keys: Vec::new(),
            warnings: Vec::new(),
        };
        if placeholder(id) {
            output
                .warnings
                .push("metadata_placeholder_indicator".into());
        }
        let mut seen = HashSet::new();
        for k in &b.children {
            if !shape(k, "Key", &["algorithm"]) || !container(k) || k.children.len() != 2 {
                return Err(fail("E_SCHEMA"));
            }
            let alg = &k.attrs["algorithm"];
            if alg != "rsa" && alg != "ecdsa" {
                return Err(fail("E_ALGORITHM"));
            }
            let (private, chain) = (&k.children[0], &k.children[1]);
            if !shape(private, "PrivateKey", &["format"])
                || private.attrs["format"] != "pem"
                || !private.children.is_empty()
                || !shape(chain, "CertificateChain", &[])
                || !container(chain)
                || chain.children.len() < 2
            {
                return Err(fail("E_SCHEMA"));
            }
            let n = count(&chain.children[0], "NumberOfCertificates", 8)?;
            if chain.children.len() != n + 1 {
                return Err(fail("E_COUNT"));
            }
            let mut key = Key {
                algorithm: alg.clone(),
                private_pem: Zeroizing::new(
                    private.text.trim_matches([' ', '\t', '\r', '\n']).into(),
                ),
                certificates: Vec::new(),
                parameter: String::new(),
                private_format: String::new(),
                valid_until: 0,
                warnings: Vec::new(),
            };
            for cert in chain.children.iter().skip(1) {
                if !shape(cert, "Certificate", &["format"])
                    || cert.attrs["format"] != "pem"
                    || !cert.children.is_empty()
                {
                    return Err(fail("E_SCHEMA"));
                }
                key.certificates
                    .push(cert.text.trim_matches([' ', '\t', '\r', '\n']).into());
            }
            crypto::validate(&mut key, now)?;
            if !seen.insert(alg.clone()) {
                crate::warn(
                    &mut output.warnings,
                    "duplicate_algorithm_explicit_selection_required",
                );
            }
            output.keys.push(key);
        }
        doc.boxes.push(output);
    }
    Ok(doc)
}
fn escaped(out: &mut Vec<u8>, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '>' => out.extend_from_slice(b"&gt;"),
            '"' => out.extend_from_slice(b"&#34;"),
            '\'' => out.extend_from_slice(b"&#39;"),
            _ => {
                let mut bytes = [0; 4];
                out.extend_from_slice(ch.encode_utf8(&mut bytes).as_bytes());
            }
        }
    }
}
pub(crate) fn encode(d: &Document) -> Result<Zeroizing<Vec<u8>>> {
    if d.boxes.is_empty() {
        return Err(fail("E_SCHEMA"));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(8192));
    out.extend_from_slice(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<AndroidAttestation>\n  <NumberOfKeyboxes>{}</NumberOfKeyboxes>",d.boxes.len()).as_bytes());
    for b in &d.boxes {
        out.extend_from_slice(b"\n  <Keybox DeviceID=\"");
        escaped(&mut out, &b.device_id);
        out.extend_from_slice(b"\">");
        for k in &b.keys {
            out.extend_from_slice(
                format!(
                    "\n    <Key algorithm=\"{}\">\n      <PrivateKey format=\"pem\">\n",
                    k.algorithm
                )
                .as_bytes(),
            );
            escaped(&mut out, &k.private_pem);
            out.extend_from_slice(format!("\n</PrivateKey>\n      <CertificateChain>\n        <NumberOfCertificates>{}</NumberOfCertificates>",k.certificates.len()).as_bytes());
            for c in &k.certificates {
                out.extend_from_slice(b"\n        <Certificate format=\"pem\">\n");
                escaped(&mut out, c);
                out.extend_from_slice(b"\n</Certificate>");
            }
            out.extend_from_slice(b"\n      </CertificateChain>\n    </Key>");
        }
        out.extend_from_slice(b"\n  </Keybox>");
    }
    out.extend_from_slice(b"\n</AndroidAttestation>");
    if out.len() > MAX_INPUT {
        return Err(fail("E_SIZE"));
    }
    Ok(out)
}
