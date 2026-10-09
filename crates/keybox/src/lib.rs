//! Validates bounded local keybox XML and merges explicit selections.
//! This crate does no I/O or network access. All ordinary formatting is redacted.
//! Mathematical consistency never establishes hardware, trust, or payment approval.
#![forbid(unsafe_code)]

mod audit;
mod crypto;
mod public;
mod xml;

use serde::{Deserialize, Serialize, Serializer};
use std::fmt;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::{Zeroize, Zeroizing};

pub use audit::audit;
pub use public::{parse_public_feeds, PublicFeeds, PublicKeyCheck};
pub const MAX_INPUT: usize = 1 << 20;
pub const MAX_PUBLIC_ROOTS: usize = 128 << 10;
pub const MAX_PUBLIC_STATUS: usize = 2 << 20;
pub const OUTPUT_DEVICE_ID: &str = "WalletDiagnosticHelper";
pub type Result<T> = std::result::Result<T, Error>;

/// Fixed code only: parser errors and certificate/input identities stay private.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Error {
    pub code: &'static str,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "keybox validation failed ({})", self.code)
    }
}
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for Error {}
pub(crate) fn fail(code: &'static str) -> Error {
    Error { code }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub source: i64,
    pub keybox: i64,
    pub key: i64,
    pub algorithm: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct KeySummary {
    pub index: usize,
    pub algorithm: String,
    pub parameter: String,
    pub private_key_format: String,
    pub certificate_count: usize,
    pub valid_until: String,
    pub warnings: Vec<String>,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BoxSummary {
    pub index: usize,
    pub keys: Vec<KeySummary>,
    pub warnings: Vec<String>,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RedactedSummary {
    pub structural_valid: bool,
    pub cryptographic_consistent: bool,
    pub trust: &'static str,
    pub revocation: &'static str,
    pub engine_adoption: &'static str,
    pub wallet_acceptance: &'static str,
    pub validated_at: String,
    pub helper_parameter_policy: &'static str,
    pub engine_parameter_compatibility: &'static str,
    pub keyboxes: Vec<BoxSummary>,
    pub warnings: Vec<String>,
    pub device_id_policy: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_device_id: Option<&'static str>,
}

#[derive(Clone)]
pub(crate) struct Key {
    pub algorithm: String,
    pub private_pem: Zeroizing<String>,
    pub certificates: Vec<String>,
    pub parameter: String,
    pub private_format: String,
    pub valid_until: i64,
    pub warnings: Vec<String>,
}
impl Drop for Key {
    fn drop(&mut self) {
        self.certificates.zeroize();
    }
}
#[derive(Clone)]
pub(crate) struct Keybox {
    pub device_id: Zeroizing<String>,
    pub keys: Vec<Key>,
    pub warnings: Vec<String>,
}
/// Secret fields are private, zeroized at drop, and excluded from all formatting.
#[derive(Clone)]
pub struct Document {
    pub(crate) boxes: Vec<Keybox>,
    pub(crate) validated_at: i64,
    pub(crate) merged: bool,
}

pub(crate) fn timestamp(value: i64) -> String {
    OffsetDateTime::from_unix_timestamp(value)
        .ok()
        .and_then(|x| x.format(&Rfc3339).ok())
        .unwrap_or_default()
}
pub(crate) fn valid_time(now: i64) -> Result<()> {
    // Match Go's invalid zero time (0001-01-01), while epoch is a valid caller time.
    if now == -62_135_596_800 || OffsetDateTime::from_unix_timestamp(now).is_err() {
        return Err(fail("E_TIME"));
    }
    Ok(())
}
pub(crate) fn warn(warnings: &mut Vec<String>, value: &str) {
    if !warnings.iter().any(|x| x == value) {
        warnings.push(value.to_owned());
    }
}
pub(crate) fn placeholder(value: &str) -> bool {
    let value = value.trim().to_lowercase();
    [
        "placeholder",
        "default",
        "software",
        "test",
        "dummy",
        "example",
    ]
    .iter()
    .any(|x| value.contains(x))
}

impl Document {
    pub fn summary(&self) -> RedactedSummary {
        let mut summary = RedactedSummary {
            structural_valid: true,
            cryptographic_consistent: true,
            trust: "unknown",
            revocation: "unknown",
            engine_adoption: "not_assessed",
            wallet_acceptance: "not_assessed",
            validated_at: timestamp(self.validated_at),
            helper_parameter_policy: "RSA 2048–4096; EC P-256/P-384",
            engine_parameter_compatibility: "unverified",
            keyboxes: Vec::new(),
            warnings: vec![
                "trust_not_established".into(),
                "revocation_unknown".into(),
                "engine_compatibility_requires_verification".into(),
            ],
            device_id_policy: if self.merged {
                "fixed_helper_metadata_no_hardware_identity"
            } else {
                "source_metadata_redacted"
            },
            metadata_device_id: if self.merged {
                Some(OUTPUT_DEVICE_ID)
            } else {
                None
            },
        };
        if self.boxes.len() > 1 {
            summary
                .warnings
                .push("multiple_keyboxes_explicit_selection_required".into());
        }
        for (index, b) in self.boxes.iter().enumerate() {
            summary.keyboxes.push(BoxSummary {
                index,
                warnings: b.warnings.clone(),
                keys: b
                    .keys
                    .iter()
                    .enumerate()
                    .map(|(index, k)| KeySummary {
                        index,
                        algorithm: k.algorithm.clone(),
                        parameter: k.parameter.clone(),
                        private_key_format: k.private_format.clone(),
                        certificate_count: k.certificates.len(),
                        valid_until: timestamp(k.valid_until),
                        warnings: k.warnings.clone(),
                    })
                    .collect(),
            });
        }
        summary
    }
    /// Returns secret material for private staging only. Never log or expose it.
    pub fn xml(&self) -> Result<Zeroizing<Vec<u8>>> {
        xml::encode(self)
    }
}
impl Serialize for Document {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        self.summary().serialize(s)
    }
}
impl fmt::Display for Document {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = serde_json::to_string(&self.summary()).map_err(|_| fmt::Error)?;
        f.write_str(&value)
    }
}
impl fmt::Debug for Document {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub fn parse(data: &[u8], now_unix: i64) -> Result<Document> {
    valid_time(now_unix)?;
    let root = xml::parse(data)?;
    xml::document(root, now_unix)
}
pub fn merge(inputs: &[&Document], selected: &[Selection], now_unix: i64) -> Result<Document> {
    valid_time(now_unix)?;
    if selected.is_empty() || selected.len() > 2 {
        return Err(fail("E_SELECTION"));
    }
    let mut result = Document {
        boxes: vec![Keybox {
            device_id: Zeroizing::new(OUTPUT_DEVICE_ID.to_owned()),
            keys: Vec::new(),
            warnings: Vec::new(),
        }],
        validated_at: now_unix,
        merged: true,
    };
    let mut seen = std::collections::HashSet::new();
    for selection in selected {
        if selection.algorithm != "ecdsa" && selection.algorithm != "rsa" {
            return Err(fail("E_SELECTION"));
        }
        if !seen.insert(selection.algorithm.clone()) {
            return Err(fail("E_SELECTION_CONFLICT"));
        }
        let source = usize::try_from(selection.source)
            .ok()
            .and_then(|i| inputs.get(i))
            .ok_or(fail("E_SELECTION"))?;
        let b = usize::try_from(selection.keybox)
            .ok()
            .and_then(|i| source.boxes.get(i))
            .ok_or(fail("E_SELECTION"))?;
        let mut key = usize::try_from(selection.key)
            .ok()
            .and_then(|i| b.keys.get(i))
            .ok_or(fail("E_SELECTION"))?
            .clone();
        if key.algorithm != selection.algorithm {
            return Err(fail("E_SELECTION_ALGORITHM"));
        }
        crypto::validate(&mut key, now_unix)?;
        crypto::normalize_traditional(&mut key)?;
        result.boxes[0].keys.push(key);
    }
    result.boxes[0]
        .keys
        .sort_by(|a, b| a.algorithm.cmp(&b.algorithm));
    Ok(result)
}
