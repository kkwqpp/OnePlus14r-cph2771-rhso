# RHSO keybox library

This independently implemented Rust crate handles bounded local validation and
explicit selection. It performs no file access, network request, installation,
credential retrieval, attestation generation, or engine modification.

`parse(bytes, unix_seconds)` returns a `Document`. `summary()`, ordinary
`Debug`/`Display`, and serialization expose only redacted DTOs. Source metadata,
PEM, subjects, and serials remain private. `xml()` deliberately returns secret
bytes in a `Zeroizing<Vec<u8>>` for the private transaction layer only.

`merge(&[&Document], &[Selection], unix_seconds)` requires source/box/key indexes
and the declared algorithm. It preserves complete selected certificate chains,
normalizes PKCS8 encoding to traditional SEC1/PKCS1, and uses fixed helper
metadata. No hardware identity is inferred and no duplicate is selected silently.

`parse_public_feeds(roots_json, status_json)` parses a complete public catalog.
`Document::check_public()` checks it locally and returns indexes and flags only.
Unknown root keys retain an unknown revocation result even when their serials
collide with a recognized issuer. Acquisition authentication and freshness belong
to the caller. A matching root or absence from a list does not prove hardware,
attestation freshness, engine adoption, or payment acceptance.

Validation bounds are 1 MiB XML, 16 boxes, 8 keys per box, 8 certificates per key,
4,096 XML tokens, and depth 8. Entities, DTDs, namespaces, directives and extra
processing instructions are rejected. Private keys are RSA 2048–4096 (two primes)
or EC P-256/P-384. Checks cover PEM/DER shape, canonical RSA CRT consistency, certificate
time, unhandled critical extensions, key matching, chain order, duplicate
certificates, CA/key usage, path length, completeness, and cryptographic signatures.
Known SAN and name-constraint encodings require ASCII IA5 strings, correctly sized
IP addresses and contiguous constraint masks; IPv4-mapped IPv6 values are rejected.
Complete domain, mailbox and URI semantic parity with Go remains unverified.

The RustCrypto signature paths support RSA PKCS1/PSS, ECDSA SHA-256/384/512 with
P-256/P-384/P-521 issuer keys, and Ed25519. SHA-1 is accepted only for the public
catalog's lower-level historical signature policy. Legacy DSA/P-224 and new
post-quantum issuer algorithms are outside this release's tested profile and fail
closed; they must be added with independent fixtures before being advertised.
RSA issuer keys below 1024 bits fail before ring or RustCrypto verification. The
private-key limit does not narrow ring's supported issuer maximum of 8192 bits.
No OpenSSL or Android platform crypto service is required.

Synthetic tests generate all keys and certificates in memory. They cover
successful algorithms, exact selection, encoding round trips, hostile inputs,
signature and path failures, redaction, catalog schema/context collisions and
resource bounds. They read no phone or real keybox data.
