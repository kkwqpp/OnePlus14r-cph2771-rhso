# Keybox validation and explicit merge

This component consumes already privately staged XML bytes. It has no filesystem,
network, TrickyStore reload, transaction, or presentation dependency. It cannot
write active configuration. Go 1.25 and the Go standard library are sufficient;
the module bundles the compiled backend rather than requiring OpenSSL or Python
on Android.

`Parse(data []byte, now time.Time) (*Document, error)` validates every supplied
record. Inputs are limited to 1 MiB, 16 Keyboxes, 8 keys per Keybox, 8 certificates
per key, 4,096 XML tokens and 8 levels. A zero time, unsupported schema, ambiguous
encoding, malformed XML, directive, processing instruction other than a UTF-8 XML
declaration, entity, namespace or unknown field fails closed. The published
`AndroidAttestation` wrapper must contain `NumberOfKeyboxes` followed by nested
`Keybox DeviceID="..."` entries. A bare Keybox is not evidenced by the pinned
documentation and is rejected. Key entries require exact lowercase `ecdsa` or
`rsa`; PEM is parsed without encrypted blocks, headers, extra blocks or garbage.
ASCII spaces/tabs at individual PEM line edges are normalized, accommodating the
installed keybox's XML indentation. This preserves all base64 bytes and still
rejects truncated framing, multiple blocks, unrelated data and Unicode framing
whitespace. Output PEM framing and payload lines are emitted without indentation.

The helper currently accepts RSA keys with two primes and 2,048–4,096 bits, and
ECDSA keys on P-256 or P-384. These are deliberately conservative helper limits,
not confirmed claims about all engine-supported parameters. Traditional RSA/EC
private PEM and unencrypted PKCS#8 are supported for import. A private key must match the
first certificate. Every certificate must be current and have no unsupported
critical extension. The supplied chain must end in a self-signed CA certificate;
its issuer ordering, signatures, CA requirements, basic path-length constraints,
and absence of duplicate certificates are checked. These checks do not establish
that a Google-trusted anchor, device identity or unrevoked key has been supplied.

`Merge(inputs []*Document, selections []Selection, now time.Time)` accepts one or
two explicit selections. `Selection{Source, Keybox, Key, Algorithm}` uses
zero-based indices and the exact declared algorithm. Repeated algorithms,
out-of-range indices, algorithm mismatches and expired selections are rejected.
Duplicate source algorithms and multiple Keyboxes remain visible in inventory;
the package never silently picks one. Merge preserves the selected mathematical
private key and complete chain, retaining traditional PEM or normalizing PKCS#8
to EC SEC1/RSA PKCS1 as required by the inspected installed engine parser. Source
and output formats and normalization warnings appear in redacted summaries. It
produces a single Keybox with one key per selected algorithm,
and deliberately uses `DeviceID="WalletDiagnosticHelper"`. This fixed value is
helper metadata and carries no claim of a hardware identity. `XML()` returns
secret material for private staging only. It must never be put into a response,
report, log or WebUI preview.

`Summary()` and JSON/string formatting expose only the redacted inventory,
parameter limits, chain counts, expiry, explicit selection indices, warnings and
metadata policy. Original DeviceIDs, certificate subjects/serials, private keys,
and full certificate/keybox content remain private fields. Placeholder warnings
are local text indicators only and can have false positives; absence of a
warning does not establish provenance. Structural and cryptographic validity
are separate from `trust:"unknown"`, `revocation:"unknown"`, engine adoption and
Wallet acceptance. All errors are typed `*Error` with fixed `E_*` codes and no
underlying library error or untrusted value, preventing input leakage through
ordinary failures.

The schema source is the official [TrickyStore v1.4.1 README](https://github.com/5ec1cff/TrickyStore/blob/1.4.1/README.md).
Its keybox section documents the wrapper, counts, algorithms and PEM fields.
The [v1.4.1 release](https://github.com/5ec1cff/TrickyStore/releases/tag/1.4.1)
does not publish parser source; the README states that versions since 1.1.0 are
closed source. Static inspection of the development installation's service APK found its
`Ca.p` parser casts the parsed object to BouncyCastle `PEMKeyPair`; its `Kc`/`Ic`
map yields this type for traditional RSA/EC and a different `PrivateKeyInfo`
object for generic PKCS#8. Private decompiler reports and copied APK code are
excluded from this public snapshot; inspected program code was not executed by
analysis tooling. See [public validation limits](../../docs/validation.md). Other engine
parameter compatibility and runtime adoption must be verified independently.
Configuration serialization and cryptographic tests
provide no evidence of Wallet Tap-to-Pay readiness.

Tests generate ephemeral synthetic RSA/ECDSA keys and chains in memory. No real
keybox or private credential is present in the source tree. Run:

```text
go test ./internal/keybox
go vet ./internal/keybox
go test ./internal/keybox -run=^$ -fuzz=FuzzParseNeverLeaks -fuzztime=5s
```

Coverage includes ECDSA-only/RSA-only/combined round trips, duplicate and multiple
records, explicit conflict rejection, XML/XXE/resource limits, malformed and
incomplete PEM, unsupported parameters, key mismatch, certificate validity,
chain ordering/signatures/completeness, safe formatting and parser fuzz seeds.
