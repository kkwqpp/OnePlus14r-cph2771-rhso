use crate::{fail, placeholder, warn, Key, Result};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use pkcs8::{
    der::{Decode, Encode},
    DecodePrivateKey, EncodePublicKey,
};
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey},
    traits::{PrivateKeyParts, PublicKeyParts},
    Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_parser::{
    extensions::{GeneralName, ParsedExtension},
    prelude::*,
};
use zeroize::{Zeroize, Zeroizing};

pub(crate) struct Pem {
    pub tag: String,
    pub contents: Zeroizing<Vec<u8>>,
}
pub(crate) fn normalize_whitespace(value: &str) -> String {
    value
        .trim_matches([' ', '\t', '\r', '\n'])
        .split('\n')
        .map(|x| x.trim_matches([' ', '\t']))
        .collect::<Vec<_>>()
        .join("\n")
        .trim_matches([' ', '\t', '\r', '\n'])
        .into()
}
pub(crate) fn complete_pem(value: &str, private: bool) -> Result<Pem> {
    let code = if private {
        "E_PRIVATE_PEM"
    } else {
        "E_CERT_PEM"
    };
    let normalized = Zeroizing::new(normalize_whitespace(value));
    if !normalized.starts_with("-----BEGIN ")
        || normalized.matches("-----BEGIN ").count() != 1
        || normalized.matches("-----END ").count() != 1
    {
        return Err(fail(code));
    }
    // Header-bearing/encrypted PEM is intentionally not part of the input contract.
    if normalized.lines().skip(1).any(|x| x.contains(':')) {
        return Err(fail(code));
    }
    let pem = ::pem::parse(normalized.as_bytes()).map_err(|_| fail(code))?;
    let tag = pem.tag().to_owned();
    if !normalized.starts_with(&format!("-----BEGIN {tag}-----"))
        || !normalized.ends_with(&format!("-----END {tag}-----"))
    {
        return Err(fail(code));
    }
    Ok(Pem {
        tag,
        contents: Zeroizing::new(pem.into_contents()),
    })
}
enum Private {
    Rsa(Box<RsaPrivateKey>),
    Ec256(p256::SecretKey),
    Ec384(p384::SecretKey),
}
fn rsa_private(der: &[u8]) -> Result<Private> {
    let encoded = rsa::pkcs1::RsaPrivateKey::from_der(der).map_err(|_| fail("E_PRIVATE_KEY"))?;
    if encoded.other_prime_infos.is_some() {
        return Err(fail("E_PARAMETERS"));
    }
    let pk = RsaPrivateKey::from_pkcs1_der(der).map_err(|_| fail("E_PRIVATE_KEY"))?;
    let e1 = rsa::BigUint::from_bytes_be(encoded.exponent1.as_bytes());
    let e2 = rsa::BigUint::from_bytes_be(encoded.exponent2.as_bytes());
    let coefficient = rsa::BigUint::from_bytes_be(encoded.coefficient.as_bytes());
    if pk.dp().is_none_or(|x| x != &e1)
        || pk.dq().is_none_or(|x| x != &e2)
        || coefficient >= pk.primes()[0]
        || pk
            .crt_coefficient()
            .as_ref()
            .is_none_or(|x| x != &coefficient)
    {
        return Err(fail("E_PRIVATE_KEY"));
    }
    Ok(Private::Rsa(Box::new(pk)))
}
fn ec(der: &[u8], pkcs8: bool) -> Result<Private> {
    let oid = if pkcs8 {
        let info = pkcs8::PrivateKeyInfo::from_der(der).map_err(|_| fail("E_PRIVATE_KEY"))?;
        info.algorithm
            .parameters_oid()
            .map_err(|_| fail("E_PRIVATE_KEY"))?
            .to_string()
    } else {
        let info = sec1::EcPrivateKey::from_der(der).map_err(|_| fail("E_PRIVATE_KEY"))?;
        match info.parameters {
            Some(sec1::EcParameters::NamedCurve(oid)) => oid.to_string(),
            _ => return Err(fail("E_PRIVATE_KEY")),
        }
    };
    match oid.as_str() {
        "1.2.840.10045.3.1.7" => Ok(Private::Ec256(if pkcs8 {
            p256::SecretKey::from_pkcs8_der(der).map_err(|_| fail("E_PRIVATE_KEY"))?
        } else {
            p256::SecretKey::from_sec1_der(der).map_err(|_| fail("E_PRIVATE_KEY"))?
        })),
        "1.3.132.0.34" => Ok(Private::Ec384(if pkcs8 {
            p384::SecretKey::from_pkcs8_der(der).map_err(|_| fail("E_PRIVATE_KEY"))?
        } else {
            p384::SecretKey::from_sec1_der(der).map_err(|_| fail("E_PRIVATE_KEY"))?
        })),
        _ => Err(fail("E_PARAMETERS")),
    }
}
fn private(pem: &Pem) -> Result<Private> {
    match pem.tag.as_str() {
        "RSA PRIVATE KEY" => rsa_private(&pem.contents),
        "EC PRIVATE KEY" => ec(&pem.contents, false),
        "PRIVATE KEY" => {
            let info = pkcs8::PrivateKeyInfo::from_der(&pem.contents)
                .map_err(|_| fail("E_PRIVATE_KEY"))?;
            match info.algorithm.oid.to_string().as_str() {
                "1.2.840.113549.1.1.1" => rsa_private(info.private_key),
                "1.2.840.10045.2.1" => ec(&pem.contents, true),
                _ => Err(fail("E_PARAMETERS")),
            }
        }
        _ => Err(fail("E_PRIVATE_KEY")),
    }
}
pub(crate) fn certificate(der: &[u8]) -> Result<X509Certificate<'_>> {
    let (remainder, cert) = X509Certificate::from_der(der).map_err(|_| fail("E_CERTIFICATE"))?;
    if !remainder.is_empty()
        || cert.tbs_certificate.signature != cert.signature_algorithm
        || cert.version().0 > 2
        || cert.raw_serial().first().is_some_and(|x| x & 0x80 != 0)
    {
        return Err(fail("E_CERTIFICATE"));
    }
    let mut seen = std::collections::HashSet::new();
    for ext in cert.extensions() {
        if !seen.insert(ext.oid.to_id_string())
            || matches!(ext.parsed_extension(), ParsedExtension::ParseError { .. })
        {
            return Err(fail("E_CERTIFICATE"));
        }
        if ext.critical
            && matches!(
                ext.oid.to_id_string().as_str(),
                "2.5.29.14" | "2.5.29.35" | "1.3.6.1.5.5.7.1.1"
            )
        {
            return Err(fail("E_CERTIFICATE"));
        }
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            if !san
                .general_names
                .iter()
                .all(|name| general_name_valid(name, false))
            {
                return Err(fail("E_CERTIFICATE"));
            }
        }
        if let ParsedExtension::NameConstraints(nc) = ext.parsed_extension() {
            let mut names = nc
                .permitted_subtrees
                .iter()
                .chain(nc.excluded_subtrees.iter())
                .flat_map(|x| x.iter())
                .peekable();
            if names.peek().is_none() || !names.all(|n| general_name_valid(&n.base, true)) {
                return Err(fail("E_CERTIFICATE"));
            }
        }
    }
    Ok(cert)
}
fn ip_address_valid(bytes: &[u8]) -> bool {
    matches!(bytes.len(), 4 | 16)
        && !(bytes.len() == 16
            && bytes[..10].iter().all(|byte| *byte == 0)
            && bytes[10..12] == [255, 255])
}
fn general_name_valid(name: &GeneralName<'_>, constraint: bool) -> bool {
    // x509-parser permits UTF-8 IA5Strings, malformed known names and arbitrary
    // IP lengths. Check their encoding even in noncritical extensions.
    match name {
        GeneralName::RFC822Name(s) | GeneralName::DNSName(s) | GeneralName::URI(s) => s.is_ascii(),
        GeneralName::IPAddress(bytes) if !constraint => ip_address_valid(bytes),
        GeneralName::IPAddress(bytes) => {
            if !matches!(bytes.len(), 8 | 32) {
                return false;
            }
            let (address, mask) = bytes.split_at(bytes.len() / 2);
            ip_address_valid(address)
                && mask
                    .iter()
                    .flat_map(|byte| (0..8).rev().map(move |bit| byte & (1 << bit) != 0))
                    .skip_while(|set| *set)
                    .all(|set| !set)
        }
        GeneralName::Invalid(tag, _) if matches!(tag.0, 1 | 2 | 6 | 7) => false,
        _ => true,
    }
}
fn critical(cert: &X509Certificate<'_>) -> Result<()> {
    for ext in cert.extensions().iter().filter(|x| x.critical) {
        let supported = match ext.oid.to_id_string().as_str() {
            "2.5.29.15" | "2.5.29.19" | "2.5.29.31" | "2.5.29.32" | "2.5.29.33" | "2.5.29.36"
            | "2.5.29.37" | "2.5.29.54" => true,
            "2.5.29.17" => match ext.parsed_extension() {
                ParsedExtension::SubjectAlternativeName(san) => san.general_names.iter().any(|n| {
                    matches!(
                        n,
                        GeneralName::RFC822Name(_)
                            | GeneralName::DNSName(_)
                            | GeneralName::URI(_)
                            | GeneralName::IPAddress(_)
                    )
                }),
                _ => false,
            },
            "2.5.29.30" => match ext.parsed_extension() {
                ParsedExtension::NameConstraints(nc) => nc
                    .permitted_subtrees
                    .iter()
                    .chain(nc.excluded_subtrees.iter())
                    .flat_map(|x| x.iter())
                    .all(|n| {
                        matches!(
                            n.base,
                            GeneralName::RFC822Name(_)
                                | GeneralName::DNSName(_)
                                | GeneralName::URI(_)
                                | GeneralName::IPAddress(_)
                        )
                    }),
                _ => false,
            },
            _ => false,
        };
        if !supported {
            return Err(fail("E_CERT_CRITICAL"));
        }
    }
    Ok(())
}
fn signature_from(cert: &X509Certificate<'_>, parent: &X509Certificate<'_>) -> Result<()> {
    let bc = parent
        .basic_constraints()
        .map_err(|_| fail("E_CHAIN_SIGNATURE"))?;
    if (parent.version().0 == 2 && bc.is_none()) || bc.as_ref().is_some_and(|x| !x.value.ca) {
        return Err(fail("E_CHAIN_SIGNATURE"));
    }
    if parent
        .key_usage()
        .map_err(|_| fail("E_CHAIN_SIGNATURE"))?
        .is_some_and(|x| x.value.flags != 0 && !x.value.key_cert_sign())
    {
        return Err(fail("E_CHAIN_SIGNATURE"));
    }
    verify_signature(cert, parent, false)
}
fn rsa_issuer_size(key: &SubjectPublicKeyInfo<'_>) -> Result<()> {
    let public = rsa::pkcs1::RsaPublicKey::from_der(&key.subject_public_key.data)
        .map_err(|_| fail("E_CHAIN_SIGNATURE"))?;
    if rsa::BigUint::from_bytes_be(public.modulus.as_bytes()).bits() < 1024 {
        return Err(fail("E_CHAIN_SIGNATURE"));
    }
    // Do not apply the private-import maximum here. ring still verifies its
    // historical public-issuer profile through 8192 bits; the fallback retains
    // RustCrypto's own public-key maximum when ring rejects the signature.
    Ok(())
}
/// Private imports reject SHA-1; public catalogs use the historical low-level
/// signature policy. Extra RustCrypto paths cover SHA-512 ECDSA and RSA issuer
/// sizes outside ring's default verification profile without accepting new keys.
pub(crate) fn verify_signature(
    cert: &X509Certificate<'_>,
    parent: &X509Certificate<'_>,
    allow_sha1: bool,
) -> Result<()> {
    let oid = cert.signature_algorithm.algorithm.to_id_string();
    let data = cert.tbs_certificate.as_ref();
    let signature = cert.signature_value.data.as_ref();
    let key = parent.public_key();
    if cert.signature_value.unused_bits != 0 || key.subject_public_key.unused_bits != 0 {
        return Err(fail("E_CHAIN_SIGNATURE"));
    }
    match oid.as_str() {
        "1.2.840.113549.1.1.5"
        | "1.3.14.3.2.29"
        | "1.2.840.113549.1.1.11"
        | "1.2.840.113549.1.1.12"
        | "1.2.840.113549.1.1.13" => {
            if key.algorithm.algorithm.to_id_string() != "1.2.840.113549.1.1.1" {
                return Err(fail("E_CHAIN_SIGNATURE"));
            }
            rsa_issuer_size(key)?;
            let (scheme, digest) = match oid.as_str() {
                "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" => {
                    if !allow_sha1 {
                        return Err(fail("E_CHAIN_SIGNATURE"));
                    }
                    (
                        Pkcs1v15Sign::new::<sha1::Sha1>(),
                        sha1::Sha1::digest(data).to_vec(),
                    )
                }
                "1.2.840.113549.1.1.11" => {
                    (Pkcs1v15Sign::new::<Sha256>(), Sha256::digest(data).to_vec())
                }
                "1.2.840.113549.1.1.12" => {
                    (Pkcs1v15Sign::new::<Sha384>(), Sha384::digest(data).to_vec())
                }
                _ => (Pkcs1v15Sign::new::<Sha512>(), Sha512::digest(data).to_vec()),
            };
            // ring permits a wider maximum public modulus than rsa's decoder.
            // The fallback deliberately runs only after standard verification.
            if cert.verify_signature(Some(key)).is_ok() {
                return Ok(());
            }
            let public = RsaPublicKey::from_pkcs1_der(&key.subject_public_key.data)
                .map_err(|_| fail("E_CHAIN_SIGNATURE"))?;
            public
                .verify(scheme, &digest, signature)
                .map_err(|_| fail("E_CHAIN_SIGNATURE"))
        }
        "1.2.840.113549.1.1.10" => {
            if key.algorithm.algorithm.to_id_string() != "1.2.840.113549.1.1.1" {
                return Err(fail("E_CHAIN_SIGNATURE"));
            }
            rsa_issuer_size(key)?;
            let raw = cert
                .signature_algorithm
                .parameters
                .as_ref()
                .ok_or(fail("E_CHAIN_SIGNATURE"))?;
            pss_parameters_shape(raw.data)?;
            let params = x509_parser::signature_algorithm::RsaSsaPssParams::try_from(raw)
                .map_err(|_| fail("E_CHAIN_SIGNATURE"))?;
            if params
                .hash_algorithm()
                .and_then(|x| x.parameters.as_ref())
                .is_some_and(|x| x.as_null().is_err())
            {
                return Err(fail("E_CHAIN_SIGNATURE"));
            }
            let mask = params
                .mask_gen_algorithm()
                .map_err(|_| fail("E_CHAIN_SIGNATURE"))?;
            let hash = params.hash_algorithm_oid().to_id_string();
            if mask.mgf.to_id_string() != "1.2.840.113549.1.1.8"
                || mask.hash.to_id_string() != hash
                || params.trailer_field() != 1
            {
                return Err(fail("E_CHAIN_SIGNATURE"));
            }
            let (scheme, digest, size) = match hash.as_str() {
                "2.16.840.1.101.3.4.2.1" => {
                    (Pss::new::<Sha256>(), Sha256::digest(data).to_vec(), 32)
                }
                "2.16.840.1.101.3.4.2.2" => {
                    (Pss::new::<Sha384>(), Sha384::digest(data).to_vec(), 48)
                }
                "2.16.840.1.101.3.4.2.3" => {
                    (Pss::new::<Sha512>(), Sha512::digest(data).to_vec(), 64)
                }
                _ => return Err(fail("E_CHAIN_SIGNATURE")),
            };
            if params.salt_length() != size {
                return Err(fail("E_CHAIN_SIGNATURE"));
            }
            if cert.verify_signature(Some(key)).is_ok() {
                return Ok(());
            }
            let public = RsaPublicKey::from_pkcs1_der(&key.subject_public_key.data)
                .map_err(|_| fail("E_CHAIN_SIGNATURE"))?;
            public
                .verify(scheme, &digest, signature)
                .map_err(|_| fail("E_CHAIN_SIGNATURE"))
        }
        "1.2.840.10045.4.1"
        | "1.2.840.10045.4.3.2"
        | "1.2.840.10045.4.3.3"
        | "1.2.840.10045.4.3.4" => {
            if key.algorithm.algorithm.to_id_string() != "1.2.840.10045.2.1" {
                return Err(fail("E_CHAIN_SIGNATURE"));
            }
            let digest = match oid.as_str() {
                "1.2.840.10045.4.1" => {
                    if !allow_sha1 {
                        return Err(fail("E_CHAIN_SIGNATURE"));
                    }
                    sha1::Sha1::digest(data).to_vec()
                }
                "1.2.840.10045.4.3.2" => Sha256::digest(data).to_vec(),
                "1.2.840.10045.4.3.3" => Sha384::digest(data).to_vec(),
                _ => Sha512::digest(data).to_vec(),
            };
            let curve = key
                .algorithm
                .parameters
                .as_ref()
                .and_then(|x| x.as_oid().ok())
                .ok_or(fail("E_CHAIN_SIGNATURE"))?
                .to_id_string();
            let width = match curve.as_str() {
                "1.2.840.10045.3.1.7" => 32,
                "1.3.132.0.34" => 48,
                "1.3.132.0.35" => 66,
                _ => return Err(fail("E_CHAIN_SIGNATURE")),
            };
            // A short digest is the same positive scalar after left zero padding.
            let digest = if digest.len() < width {
                let mut padded = vec![0; width - digest.len()];
                padded.extend(digest);
                padded
            } else {
                digest
            };
            match width {
                32 => p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.subject_public_key.data)
                    .map_err(|_| fail("E_CHAIN_SIGNATURE"))?
                    .verify_prehash(
                        &digest,
                        &p256::ecdsa::Signature::from_der(signature)
                            .map_err(|_| fail("E_CHAIN_SIGNATURE"))?,
                    )
                    .map_err(|_| fail("E_CHAIN_SIGNATURE")),
                48 => p384::ecdsa::VerifyingKey::from_sec1_bytes(&key.subject_public_key.data)
                    .map_err(|_| fail("E_CHAIN_SIGNATURE"))?
                    .verify_prehash(
                        &digest,
                        &p384::ecdsa::Signature::from_der(signature)
                            .map_err(|_| fail("E_CHAIN_SIGNATURE"))?,
                    )
                    .map_err(|_| fail("E_CHAIN_SIGNATURE")),
                _ => p521::ecdsa::VerifyingKey::from_sec1_bytes(&key.subject_public_key.data)
                    .map_err(|_| fail("E_CHAIN_SIGNATURE"))?
                    .verify_prehash(
                        &digest,
                        &p521::ecdsa::Signature::from_der(signature)
                            .map_err(|_| fail("E_CHAIN_SIGNATURE"))?,
                    )
                    .map_err(|_| fail("E_CHAIN_SIGNATURE")),
            }
        }
        "1.3.101.112" => {
            if cert.signature_algorithm.parameters.is_some() {
                return Err(fail("E_CHAIN_SIGNATURE"));
            }
            cert.verify_signature(Some(key))
                .map_err(|_| fail("E_CHAIN_SIGNATURE"))
        }
        _ => Err(fail("E_CHAIN_SIGNATURE")),
    }
}
fn pss_parameters_shape(mut input: &[u8]) -> Result<()> {
    // The dependency's PSS parser ignores trailing fields. Every declared field
    // must be a single DER item, unique, ordered, and completely consumed.
    let mut previous = None;
    while !input.is_empty() {
        let tag = *input.first().ok_or(fail("E_CHAIN_SIGNATURE"))?;
        if !(0xa0..=0xa3).contains(&tag) || previous.is_some_and(|old| tag <= old) {
            return Err(fail("E_CHAIN_SIGNATURE"));
        }
        previous = Some(tag);
        let (outer, rest) = der_item(input)?;
        let (inner, trailing) = der_item(outer)?;
        if !trailing.is_empty() || inner.is_empty() {
            return Err(fail("E_CHAIN_SIGNATURE"));
        }
        input = rest;
    }
    Ok(())
}
fn der_item(input: &[u8]) -> Result<(&[u8], &[u8])> {
    if input.len() < 2 {
        return Err(fail("E_CHAIN_SIGNATURE"));
    }
    let first = input[1];
    let (offset, len) = if first < 128 {
        (2, first as usize)
    } else {
        let width = (first & 0x7f) as usize;
        if width == 0 || width > 4 || input.len() < 2 + width || input[2] == 0 {
            return Err(fail("E_CHAIN_SIGNATURE"));
        }
        let mut len = 0usize;
        for byte in &input[2..2 + width] {
            len = (len << 8) | *byte as usize;
        }
        if len < 128 {
            return Err(fail("E_CHAIN_SIGNATURE"));
        }
        (2 + width, len)
    };
    let end = offset.checked_add(len).ok_or(fail("E_CHAIN_SIGNATURE"))?;
    if end > input.len() {
        return Err(fail("E_CHAIN_SIGNATURE"));
    }
    Ok((&input[offset..end], &input[end..]))
}
pub(crate) fn cert_placeholder(cert: &X509Certificate<'_>) -> bool {
    cert.subject()
        .iter_common_name()
        .chain(cert.issuer().iter_common_name())
        .filter_map(|x| x.as_str().ok())
        .any(placeholder)
}
pub(crate) fn validate(key: &mut Key, now: i64) -> Result<()> {
    let canonical = Zeroizing::new(normalize_whitespace(&key.private_pem));
    if *canonical != *key.private_pem {
        warn(&mut key.warnings, "private_key_pem_whitespace_normalized");
    }
    key.private_pem = canonical;
    let pem = complete_pem(&key.private_pem, true)?;
    key.private_format = match pem.tag.as_str() {
        "EC PRIVATE KEY" => "sec1",
        "RSA PRIVATE KEY" => "pkcs1",
        "PRIVATE KEY" => "pkcs8",
        _ => return Err(fail("E_PRIVATE_KEY")),
    }
    .into();
    if key.private_format == "pkcs8" {
        warn(
            &mut key.warnings,
            "pkcs8_requires_traditional_pem_for_installed_engine",
        );
    }
    let pk = private(&pem)?;
    let spki = match &pk {
        Private::Rsa(pk) => {
            if key.algorithm != "rsa" {
                return Err(fail("E_ALGORITHM_MISMATCH"));
            }
            let bits = pk.n().bits();
            if !(2048..=4096).contains(&bits)
                || pk.e() < &rsa::BigUint::from(3u8)
                || pk.e().to_bytes_be().last().is_none_or(|x| x & 1 == 0)
                || pk.primes().len() != 2
            {
                return Err(fail("E_PARAMETERS"));
            }
            pk.validate().map_err(|_| fail("E_PRIVATE_KEY"))?;
            key.parameter = bits.to_string();
            pk.to_public_key()
                .to_public_key_der()
                .map_err(|_| fail("E_PRIVATE_KEY"))?
                .as_bytes()
                .to_vec()
        }
        Private::Ec256(pk) => {
            if key.algorithm != "ecdsa" {
                return Err(fail("E_ALGORITHM_MISMATCH"));
            }
            key.parameter = "P-256".into();
            pk.public_key()
                .to_public_key_der()
                .map_err(|_| fail("E_PRIVATE_KEY"))?
                .as_bytes()
                .to_vec()
        }
        Private::Ec384(pk) => {
            if key.algorithm != "ecdsa" {
                return Err(fail("E_ALGORITHM_MISMATCH"));
            }
            key.parameter = "P-384".into();
            pk.public_key()
                .to_public_key_der()
                .map_err(|_| fail("E_PRIVATE_KEY"))?
                .as_bytes()
                .to_vec()
        }
    };
    let mut ders = Vec::new();
    for value in &mut key.certificates {
        let canonical = normalize_whitespace(value);
        if canonical != *value {
            warn(&mut key.warnings, "certificate_pem_whitespace_normalized");
        }
        *value = canonical;
        let pem = complete_pem(value, false)?;
        if pem.tag != "CERTIFICATE" {
            return Err(fail("E_CERT_PEM"));
        }
        ders.push(pem.contents);
    }
    let mut certs = Vec::new();
    let mut until = None;
    for der in &ders {
        let cert = certificate(der)?;
        if now < cert.validity().not_before.timestamp()
            || now > cert.validity().not_after.timestamp()
        {
            return Err(fail("E_CERT_TIME"));
        }
        critical(&cert)?;
        until = Some(
            until.map_or(cert.validity().not_after.timestamp(), |x: i64| {
                x.min(cert.validity().not_after.timestamp())
            }),
        );
        if cert_placeholder(&cert) {
            warn(&mut key.warnings, "certificate_placeholder_indicator");
        }
        certs.push(cert);
    }
    if certs.is_empty() {
        return Err(fail("E_COUNT"));
    }
    key.valid_until = until.ok_or(fail("E_COUNT"))?;
    if spki != certs[0].public_key().raw {
        return Err(fail("E_KEY_MISMATCH"));
    }
    let mut seen = std::collections::HashSet::new();
    for (index, cert) in certs.iter().enumerate() {
        if !seen.insert(cert.as_raw()) {
            return Err(fail("E_CHAIN_DUPLICATE"));
        }
        if let Some(parent) = certs.get(index + 1) {
            if cert.issuer().as_raw() != parent.subject().as_raw() {
                return Err(fail("E_CHAIN_ORDER"));
            }
            signature_from(cert, parent)?;
            if parent
                .basic_constraints()
                .map_err(|_| fail("E_CHAIN_CONSTRAINT"))?
                .is_some_and(|x| {
                    x.value
                        .path_len_constraint
                        .is_some_and(|max| index > max as usize)
                })
            {
                return Err(fail("E_CHAIN_CONSTRAINT"));
            }
        }
    }
    let last = certs.last().ok_or(fail("E_COUNT"))?;
    if last.subject().as_raw() != last.issuer().as_raw() {
        return Err(fail("E_CHAIN_INCOMPLETE"));
    }
    signature_from(last, last)?;
    if certs.len() == 1 {
        warn(
            &mut key.warnings,
            "single_self_signed_certificate_placeholder_possible",
        );
    }
    warn(
        &mut key.warnings,
        "self_signed_anchor_does_not_establish_trust",
    );
    Ok(())
}
pub(crate) fn normalize_traditional(key: &mut Key) -> Result<()> {
    if key.private_format != "pkcs8" {
        return Ok(());
    }
    let pem = complete_pem(&key.private_pem, true)?;
    let (tag, der) = match private(&pem)? {
        Private::Rsa(pk) => (
            "RSA PRIVATE KEY",
            Zeroizing::new(
                pk.to_pkcs1_der()
                    .map_err(|_| fail("E_PRIVATE_KEY"))?
                    .as_bytes()
                    .to_vec(),
            ),
        ),
        Private::Ec256(pk) => (
            "EC PRIVATE KEY",
            sec1_with_curve(
                pk.to_sec1_der().map_err(|_| fail("E_PRIVATE_KEY"))?,
                "1.2.840.10045.3.1.7",
            )?,
        ),
        Private::Ec384(pk) => (
            "EC PRIVATE KEY",
            sec1_with_curve(
                pk.to_sec1_der().map_err(|_| fail("E_PRIVATE_KEY"))?,
                "1.3.132.0.34",
            )?,
        ),
    };
    key.private_format = if tag == "RSA PRIVATE KEY" {
        "pkcs1"
    } else {
        "sec1"
    }
    .into();
    let output = ::pem::Pem::new(tag, der.as_slice());
    key.private_pem = Zeroizing::new(
        ::pem::encode_config(
            &output,
            ::pem::EncodeConfig::new().set_line_ending(::pem::LineEnding::LF),
        )
        .trim()
        .into(),
    );
    output.into_contents().zeroize();
    key.warnings
        .retain(|x| x != "pkcs8_requires_traditional_pem_for_installed_engine");
    warn(
        &mut key.warnings,
        "private_key_encoding_normalized_for_installed_engine",
    );
    Ok(())
}
fn sec1_with_curve(der: Zeroizing<Vec<u8>>, oid: &str) -> Result<Zeroizing<Vec<u8>>> {
    // RustCrypto's generic SecretKey SEC1 writer deliberately omits parameters;
    // standalone traditional PEM requires the named curve for TrickyStore/Go.
    let mut encoded = sec1::EcPrivateKey::from_der(&der).map_err(|_| fail("E_PRIVATE_KEY"))?;
    encoded.parameters = Some(sec1::EcParameters::NamedCurve(
        pkcs8::ObjectIdentifier::new(oid).map_err(|_| fail("E_PRIVATE_KEY"))?,
    ));
    Ok(Zeroizing::new(
        encoded.to_der().map_err(|_| fail("E_PRIVATE_KEY"))?,
    ))
}
