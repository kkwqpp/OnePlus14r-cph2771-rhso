# Public trust, revocation and Wallet diagnosis

Reviewed 2026-10-09. This research used primary documentation, pinned public source and bounded public HTTPS GETs on the PC. No phone probe, private keybox inspection, certificate-specific request, account action or configuration write was performed for this research.

The helper can determine whether an already cryptographically consistent public signer chain reaches a verified Google anchor and whether its public certificate identifiers occur in a fresh Google status snapshot. Report those limited facts separately. Neither result proves hardware custody, engine adoption, device certification, card eligibility or Wallet acceptance.

## Exact public contracts and observed responses

These two fixed, unauthenticated URLs are linked by [Android's official attestation guidance](https://developer.android.com/privacy-and-security/security-key-attestation):

| Purpose | Exact HTTPS URL | Public payload |
|---|---|---|
| Google trust anchors | `https://android.googleapis.com/attestation/root` | JSON array of PEM X.509 certificate strings |
| Certificate status | `https://android.googleapis.com/attestation/status` | JSON object containing an `entries` dictionary |

GET the complete feed. Do not add a certificate serial, device identifier, private key, credential, query parameter or guessed authentication header. Do not follow certificate-supplied URLs. These responses were HTTP 200 without credentials; this establishes the observed public GET contract, not an undocumented keybox provider contract.

At **2026-10-09T16:17:56Z**, a .NET HttpClient used normal TLS verification, redirects disabled, a 20-second timeout, streamed 8 MiB bounds and strict UTF-8 parsing. It retained payloads in memory and printed only public-feed metadata, aggregate counts and public-root fingerprints.

| Response | Root feed | Status feed |
|---|---|---|
| Content-Type | `application/json` | `application/json` |
| Bytes | 2,690 | 179,422 |
| Payload SHA-256 | `b79beef96dd68073f1975bab90970ae85d1ae56d451a819ece6bff3d4e253ab4` | `e39321c886afde01dfdb47ec0dca3ce770f2819fee1d7fb0398aeb5181427df5` |
| Cache-Control | `public, max-age=86400` | `public, max-age=86400` |
| Date | `2026-10-09T16:17:55Z` | `2026-10-09T03:20:32Z` |
| Age | Absent | `46644` seconds |
| Expires | `2026-10-10T16:17:55Z` | `2026-10-10T03:20:32Z` |
| Last-Modified | `2025-07-29T17:38:00Z` | `2026-09-29T15:58:00Z` |
| ETag | Absent | Absent |
| Contents | Two public anchors | 1,759 entries; all `REVOKED` |

Status entries contained only `status` and `reason`; observed reasons were `KEY_COMPROMISE` and `SOFTWARE_FLAW`. Every dictionary key matched the documented format. Counts, hashes and headers are a dated observation, not constants for the implementation. The two feeds have independent response ages and authentication evidence.

### Status schema

The published [JSON schema](https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status) requires top-level `entries`, forbids other top-level properties, and uses lowercase unpadded hexadecimal serial dictionary keys matching `^[a-f1-9][a-f0-9]*$`. Each entry allows only:

| Field | Requirement |
|---|---|
| `status` | Required string: `REVOKED` or `SUSPENDED` |
| `expires` | Optional UTC calendar date `YYYY-MM-DD`; certificate expiry, not feed freshness |
| `reason` | Optional: `UNSPECIFIED`, `KEY_COMPROMISE`, `CA_COMPROMISE`, `SUPERSEDED`, `SOFTWARE_FLAW` |
| `comment` | Optional string, maximum 140 characters |

Treat a future field/status, wrong type, duplicate JSON key, invalid serial/date, missing field or oversized document as unsupported evidence. This fail-closed parser policy is a helper recommendation. Do not silently ignore unsupported data and report a clean result. Do not discard a matched entry because its optional `expires` date has passed; that date permits Google's list maintenance and is not a local acceptance exception.

Google describes `REVOKED` as permanent and `SUSPENDED` as temporary nonacceptance. The feed lists abnormal statuses, not every issued certificate. Absence can therefore mean only **not listed in this fresh snapshot**. The [official explanation of the TLS-secured status service](https://android-developers.googleblog.com/2019/09/trust-but-verify-attestation-with.html) distinguishes it from traditional CRL/OCSP delivery.

The current [official Kotlin reader](https://github.com/android/keyattestation/blob/3f550f94a9e3c010dda7cdcad8bca764cd76d4f4/src/main/kotlin/GoogleRevocationList.kt) filters only `REVOKED`. A new helper must deliberately retain and report `SUSPENDED` according to the documented schema. Its [revocation checker](https://github.com/android/keyattestation/blob/3f550f94a9e3c010dda7cdcad8bca764cd76d4f4/src/main/kotlin/provider/RevocationChecker.kt) demonstrates internal unpadded hexadecimal matching; exceptions containing raw serials must be translated into redacted errors.

## Freshness, cache provenance and offline limits

The feeds are HTTPS JSON. No detached signature, signed JSON envelope, offline verification key or signed-CRL format was documented or observed for these endpoints. A local SHA-256 detects accidental changes relative to saved metadata; it does not independently authenticate Google or an attacker-modified cache. Preserve verified acquisition evidence and protect cache files. An offline copy imported from an arbitrary file is not equivalent to a verified TLS acquisition.

[RFC 9111, sections 4.2–4.2.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.3) requires incorporating response age rather than restarting the full lifetime at download. For a private helper cache using `max-age`, retain request/response time, Date, Age, lifetime and payload hash; calculate:

```text
apparent_age = max(0, response_time - Date)
corrected_initial_age = max(apparent_age, Age + response_delay)
current_age = corrected_initial_age + (now - response_time)
fresh = current_age < max_age
```

Absent Age has value zero for this calculation. At acquisition the observed status response had approximately **39,756 seconds remaining**, about 11 hours, not a new 24-hour lifetime. Last-Modified describes content modification and does not replace cache freshness.

Recommended helper policy, distinct from Google's documented contract:

- Use fixed allowlisted HTTPS endpoints, normal certificate verification, no redirects, bounded reads/timeouts, strict parse before atomic cache replacement and an independent root/status cache record.
- Honor `no-store`, `no-cache`, zero lifetime and explicit expiration. Implement unambiguous `max-age` and, if supported, Expires relative to Date. Invalid or conflicting freshness fields produce unknown freshness.
- If there is no usable explicit freshness information, the default accepted freshness lifetime is **zero**. Google documents no fallback TTL. Do not silently assume 24 hours or derive a security lifetime from Last-Modified.
- Failed HTTP/TLS, truncated/schema-invalid data, cache corruption or clock rollback must not overwrite a valid previous snapshot or restart its lifetime. Previously valid cached data can remain usable until its established deadline; after that, negative status is unknown. A stale positive match remains visible as a historical warning with its age.
- Persist bytes/hash/fetch metadata privately with strict ownership/modes. An untrusted caller must not inject a feed/cache path or substitute a root store. Same-device root tampering cannot be excluded by a hash stored alongside the cache; PC verification gives a stronger independent diagnostic.

Expose source URL, payload digest, acquired time, freshness deadline/remaining lifetime and redacted errors. Keep certificate serials internal. A public result may identify certificate index or digest and matched status/reason. Do not emit comments, subjects, serials, device IDs, accounts, keys or raw upstream/crypto exceptions.

## Anchor identity and certificate checks

A second bounded public-root GET at **2026-10-09T16:24:15Z** verified algorithms and sizes. Public-root metadata:

| Anchor | RSA | EC |
|---|---|---|
| Public key | RSA 4096 | ECDSA P-384; curve OID `1.3.132.0.34` |
| Certificate validity UTC | 2022-03-20 to 2042-03-15 | 2025-07-17 to 2035-07-15 |
| DER SHA-256 | `cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc` | `6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0` |
| SPKI SHA-256 | `feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae` | `3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec` |
| Basic constraints | CA=true | CA=true |
| Key usage | Certificate signing | Certificate signing, CRL signing |

The current official [rotation guidance](https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate) says the new root started signing on **2026-02-01** and requires both anchors. March 31/April 10 deadlines were not corroborated on the currently available primary pages and are not implementation assumptions. Devices launching with Android 16 use RKP; older factory chains remain relevant.

For the limited label **Google-rooted**, use independently authenticated Google anchor keys/subjects, verify issuer/subject chaining and every child signature to that anchor, and require the claimed final root to agree with the trusted key/identity. Self-signature, a Google-looking name or a root contained in the user's input is insufficient. Historical RSA root certificate reissues share the canonical key; exact whole-certificate DER equality alone rejects legitimate old chains. Do not automatically grant trust to new keys downloaded from a configurable URL. Reviewed/bundled anchor SPKI identity plus verified endpoint refresh makes root-store changes auditable.

The pinned [official path validator](https://github.com/android/keyattestation/blob/3f550f94a9e3c010dda7cdcad8bca764cd76d4f4/src/main/kotlin/provider/KeyAttestationCertPathValidator.kt) explicitly accommodates older chains that fail ordinary RFC 5280 validation. It verifies names/signatures and attestation placement; its BasicChecker does not impose generic CA/keyCertSign constraints. The live anchors' CA/key-usage properties above are observations, not proof that every historical Android signer must have those properties. A stricter helper import rule must be described as its own conservative policy.

Keep dates equally explicit. Google's old-factory guidance permits expired factory certificates while requiring RKP validity. The pinned validator additionally skips the generated target's date, checks NotBefore on other certificates and exempts factory-provisioned expiry. Its [chain model](https://github.com/android/keyattestation/blob/3f550f94a9e3c010dda7cdcad8bca764cd76d4f4/src/main/kotlin/provider/KeyAttestationCertPath.kt) expects a full generated attestation chain and uses provisioning heuristics. A private signer keybox is not that full fresh chain. Do not relax the helper's import-date rejection merely because a subject string resembles factory provisioning; import-date failures remain failures under that policy.

## What a locally valid signer cannot establish

The official [attestation verifier](https://github.com/android/keyattestation/blob/3f550f94a9e3c010dda7cdcad8bca764cd76d4f4/src/main/kotlin/Verifier.kt) goes beyond signatures: it validates a full generated chain, expected challenge/application identity, parsed extensions and selected security constraints. Its [README](https://github.com/android/keyattestation/tree/3f550f94a9e3c010dda7cdcad8bca764cd76d4f4) explains challenge/replay/relay limits. Do not copy its raw chain/serial/device-identity logging into the diagnostic.

[AOSP's attestation schema](https://source.android.com/docs/security/features/keystore/attestation) distinguishes software, TEE and StrongBox security levels and records boot lock/verified-boot state. A consistent imported signer chain lacks a fresh generated target bound to a verifier's challenge. Its exposed/shared private signer cannot establish that new signatures were produced in this phone's secure hardware. Passing the public-root/status checks therefore must never become `hardware_valid`, `device_certified` or `wallet_passed`.

The [official RKP architecture](https://android-developers.googleblog.com/2022/03/upgrading-android-attestation-remote.html) uses ECDSA attestation signing even for generated keys with other algorithms. Thus absent RSA is not by itself evidence of a modern attestation failure. Software roots with public source signing keys provide no secure-hardware assurance; unknown vendor roots require independent vendor evidence. Check status only in the context of an authenticated anchored chain, so an arbitrary synthetic serial collision cannot be presented as a Google rejection of this device.

## Evidence-supported next diagnosis

Obtain current user-visible Wallet and certification evidence before proposing further configuration changes. The symptom's timing after card entry does not identify the failing policy.

| Evidence | Supported implication and next step |
|---|---|
| Wallet profile → Tap-to-pay setup | Record only readiness flags and exact nonprivate message. Google's [setup-status guidance](https://support.google.com/wallet/answer/14220596?hl=en) identifies this UI. |
| “Couldn't finish card setup for tap to pay” | Google's [card-setup guidance](https://support.google.com/wallet/answer/12058983?hl=en) identifies issuer refusal; the user asks the bank about digital provisioning. |
| “Phone can't be set up for tap and pay” | Check current security/certification status and NFC. Root/modified OS/unlocked bootloader are named unsupported configurations in [Wallet security troubleshooting](https://support.google.com/wallet/answer/12200245?hl=en). |
| Play Store profile → Settings → About → certification | Record certified/not-certified and any current remediation message. [Google Play guidance](https://support.google.com/googleplay/answer/7165974?hl=en) distinguishes certification from Play Protect malware scanning; disabling scanning does not fix certification. |
| NFC/default app/screen lock/card readiness | Check [contactless setup requirements](https://support.google.com/wallet/answer/12060043?hl=en). NFC off affects tapping and does not alone explain an explicit security provisioning rejection. |
| Authentication method | Check [payment-verification requirements](https://support.google.com/wallet/answer/12059519?hl=en): PIN/pattern/password or supported strong biometric; weaker face/Smart Unlock can be insufficient. |
| Fresh public local diagnostic | Display Google-rooted/not-rooted, each matched status, snapshot freshness and unknowns. Retain active configuration; no result authorizes fetching another keybox or resetting app data. |

This helper preserves the existing rooted stack and bootloader state. Official unroot/relock/factory-reset suggestions are outside its scope; report the compatibility limitation without performing them. Wallet/issuer success requires successful card provisioning and a user-confirmed contactless payment, independently of helper success. No verified universal reset/wait period or private Wallet support API was found; use the actual UI and current primary guidance.
