# Public interface research

Collected 2026-10-09. This document records public primary-source evidence. Private installed-code reports and copied program inputs are excluded from this repository; [validation and limits](validation.md) gives the public development summary. Public documentation, static code, runtime adoption, Play Integrity and successful Wallet Tap-to-Pay are separate evidence levels.

## TrickyStore 1.4.1

The [pinned 1.4.1 README](https://github.com/5ec1cff/TrickyStore/blob/1.4.1/README.md) documents:

- Android 10+; certificate-chain modification for Android key attestation.
- Configuration under `/data/adb/tricky_store/`: `keybox.xml`, `target.txt`, `security_patch.txt`.
- Immediate configuration updates: “All configuration files will take effect immediately.”
- An `AndroidAttestation` wrapper, `NumberOfKeyboxes`, `Keybox DeviceID`, `Key algorithm="ecdsa|rsa"`, PEM `PrivateKey`, `CertificateChain`, declared count, and PEM `Certificate` elements.
- Package suffix `!` forces certificate generation; `?` forces leaf modification. Broken TEE falls back to generation.
- Patch formats include simple numeric dates and advanced `system`, `boot`, `vendor`, `all`, `no`, and `prop` values. Patch configuration changes attestation results, not Android properties.
- The implementation became closed source from 1.1.0.

The [1.4.1 release](https://github.com/5ec1cff/TrickyStore/releases/tag/1.4.1) provides a release SHA-256 of `2f5e73fcba0e4e43b6e96b38f333cbe394873e3a81cf8fe1b831c2fbd6c46ea9`. No release archive or bundled keybox was fetched in this research.

The README is an example, not a complete parser specification. It does not publish EC curve/RSA size limits, every accepted PEM encoding, duplicate or multi-Keybox selection behavior, reload ordering, restart commands, or a strong adoption-proof API. The helper must label its supported validation profile explicitly and block unsupported parameters. It must never infer those constraints merely from Android's generic key APIs.

Immediate updates are the documented default. A launcher restart is not justified by a historical “startup cache” note alone. Compare installed code and launcher, committed file hashes, and fresh attestation evidence. Absence of fresh requests means adoption pending. A healthy process or a historical chain count proves neither selected-key identity nor Wallet acceptance.

## Module and WebUI contract

The [KernelSU WebUI guide](https://kernelsu.org/guide/module-webui.html) requires a module `webroot/index.html` and locally placed associated assets. The manager hosts the page in Android WebView and exposes shell APIs. Module installation manages webroot permissions and SELinux labeling. The [module guide](https://kernelsu.org/guide/module.html) describes module scripts, including manually invoked `action.sh`, and KernelSU BusyBox standalone shell behavior.

The [KernelSU Next API documentation](https://github.com/KernelSU-Next/KernelSU-Next/blob/dev/docs/WebUi_Next/API_DOC.md) documents native `ksu.exec(command)`, callback forms `ksu.exec(command, callbackName)` and `ksu.exec(command, JSONoptions, callbackName)`, plus `spawn`, `toast`, `fullScreen` and `moduleInfo`. An exec callback receives exit code, stdout and stderr; options include cwd and environment. `moduleInfo()` returns JSON including moduleDir/id. This development-branch documentation does not itself prove every API exists in the installed randomized manager. Probe a harmless backend status call and provide CLI fallback.

The official [KsuWebUIStandalone repository](https://github.com/5ec1cff/KsuWebUIStandalone) is archived. Its [manifest](https://github.com/5ec1cff/KsuWebUIStandalone/blob/master/app/src/main/AndroidManifest.xml) exports `.WebUIActivity`. Its [activity](https://github.com/5ec1cff/KsuWebUIStandalone/blob/master/app/src/main/java/io/github/a13e300/ksuwebui/WebUIActivity.kt) reads the `id` string extra and optional `name`, serves module webroot, and binds the native interface as `ksu`. That archived activity has no WebChromeClient file-picker implementation. Other host builds may implement a picker, so archived source is not a capability guarantee for every version. A usable private-path/inbox import remains required because static picker support does not verify its full import round trip.

For that documented package, the action launcher can resolve the installed activity, then invoke:

```sh
am start -n io.github.a13e300.ksuwebui/.WebUIActivity --es id wallet_diagnostic --es name 'Wallet Diagnostic'
```

Use the module's actual ID; the manager package must be discovered rather than hardcoded. Resolve failure must show status and the exact CLI command.

The standalone [bridge source](https://github.com/5ec1cff/KsuWebUIStandalone/blob/master/app/src/main/java/io/github/a13e300/ksuwebui/WebViewInterface.kt) concatenates command, spawn arguments, cwd and environment into shell text. JSON spawn arguments are not an argv safety boundary. The helper must centrally quote every shell argument, constrain request sizes and command names, and keep private material and credentials out of bridge requests. Never pass untrusted text as callback names, cwd or environment assignments. Feature availability must also be checked against the installed APK.

## Play Integrity Fork action and the reset boundary

The pinned [PIF v18 action](https://github.com/osm0sis/PlayIntegrityFork/blob/v18/module/action.sh) disables BusyBox standalone mode, then invokes `autopif4.sh -m`. The [v18 generator](https://github.com/osm0sis/PlayIntegrityFork/blob/v18/module/autopif4.sh) obtains a Canary configuration, writes/replaces PIF configuration, preserves selected advanced values through migration, estimates expiry from release date plus six weeks, updates TrickyStore patch configuration when present, and invokes `killpi.sh` when installed. This is a configuration-changing action, not a harmless refresh. The generator also contains upstream downloads with certificate verification disabled; the helper's own API importer must not copy that behavior.

Consequently, a separately confirmed reset must show PIF action effects, inspect installed script hashes, back up every affected file, and stop if those scripts change. Ordinary Apply must not run PIF action. The helper retains a legacy double GMS clear in its separately confirmed workflow; no verified primary rationale for the repetition was found. It is not an established Wallet remedy.

The [PIF README](https://github.com/osm0sis/PlayIntegrityFork/blob/v18/README.md) distinguishes Android <13 and Android 13+ verdicts and describes Wallet-related behavior. Its troubleshooting advice includes clearing cache/data or waiting for app-side results; it is community module guidance, not a Google acceptance guarantee. Its warning about GMS data affecting paired WearOS devices must appear before an explicitly confirmed reset if relevant.

## Wallet and attestation evidence

[Google Wallet setup guidance](https://support.google.com/wallet/answer/12060043) requires NFC, a default payment application, a supported payment method/country, screen lock, and security requirements. [Google troubleshooting guidance](https://support.google.com/wallet/answer/12200245?hl=en) also identifies certification/security failures and issuer/card problems. It states that rooted/custom-modified devices and unlocked bootloaders may be unsupported. This helper preserves existing bootloader state; it must report that policy limitation without offering relock or partition-writing functionality.

[Android attestation documentation](https://source.android.com/docs/security/features/keystore/attestation) distinguishes the generated attested key from its certified signing key and defines attestation certificate chains. [Android verification guidance](https://developer.android.com/privacy-and-security/security-key-attestation) requires trusted-root, signature, extension, and revocation checks. A locally consistent chain does not establish Google trust. The helper must keep trust and revocation unknown when no independently verified trust store or fresh public revocation evidence exists; it must never upload a local keybox for checking.

[Play Integrity verdict documentation](https://developer.android.com/google/play/integrity/verdicts) describes device verdict signals. Those results cannot prove issuer provisioning or successful NFC payment. The helper therefore reports structural validity, crypto consistency, trust, revocation, engine adoption, Wallet readiness and user-confirmed Tap-to-Pay separately.

## Configured remote provider: unavailable

Endpoint, preserved exactly: `https://keybox.tryigit.dev/api/cleverestrikcy/`.

On 2026-10-09, a single bounded HTTPS HEAD request with normal platform certificate validation, no credentials and redirects disabled returned HTTP 404, `text/html; charset=UTF-8`, no redirect. Only response headers were requested; no response body/keybox was retrieved. Public indexed search did not establish a provider contract. HEAD does not establish whether another method would be valid, and 404 does not authorize changing the spelling.

The adapter is unavailable. Missing information:

- Provider-authored endpoint/method and parameter documentation.
- Authentication placement, token format/scopes, and supported credential handling.
- Success payload format/content type, schema/wrappers, size limits and selection semantics.
- Documented error/auth/rate-limit/retry/redirect behavior.
- Distribution authorization, provenance, provider capabilities and permitted use.

Do not invent routes, append trial paths, guess authorization headers, fetch a keybox to infer its structure, or fall back to another service. The current unavailable adapter provides no credential-entry or storage command. A future verified adapter would require private credential handling before enabling network import. Local imports remain usable without this provider.

## Analysis tools

Static compatibility research used [official JADX v1.5.6](https://github.com/skylot/jadx/releases/tag/v1.5.6) with Temurin Java 21.0.12.1+1. The public release API lists portable `jadx-1.5.6.zip`, 72,646,741 bytes, SHA-256 `545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974`; the acquired archive matched that public digest. These tools are optional research dependencies, not backend build prerequisites. Keep tools, copied code and decompiler output outside module source and package. Decompiled output is an analysis aid, not recovered original source; Android native/kernel code requires separate analysis.
