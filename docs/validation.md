# Validation and limits

This records development checks for Wallet Diagnostic v0.1.1. It is separate from production signer adoption, Wallet approval and a real payment. The development phone still rejects Tap-to-Pay setup.

## Completed checks

| Check | Recorded result |
|---|---|
| Windows `go test ./... -count=1 -json` | All three packages passed; 415 passed tests/subtests, three documented skips, no failures. Package completion events are excluded from this test count. |
| `go vet ./...` | Passed. |
| Node WebUI core tests | 5/5 passed. |
| Offline headless Chrome integration | Passed import/review/confirmation flows, inert untrusted HTML, mobile/reflow fixtures, unavailable API/bridge, stale configuration and numeric-user binding. The bridge and data were synthetic. |
| Module shell/install/uninstall fixtures | Passed with inert Android command stubs. |
| Actual Android native synthetic executables | Core 274, keybox 109 and CLI 34 passed: 417 total, one intentional subprocess-helper skip, no failures; all executables exited zero. |
| Repeated packaging | Byte-identical ZIPs for unchanged backend/assets and the same compression runtime. |
| Packaging from a fresh source checkout | Creates the otherwise untracked backend directory; reproduced the delivered ZIP SHA-256. |

Windows skips comprise an intentional child-helper test and two symlink cases requiring Windows privileges; Android exercised the POSIX/symlink paths. Synthetic tests cover injected failures, process interruption and journal recovery checkpoints. They do not certify every possible power loss, disk/controller failure or arbitrary concurrent root writer.

## Device observations

The v0.1.1 helper was installed and activated through the existing KernelSU/NoMount stack. Root CLI initialization, local staging/validation, diagnostics, status and explicit public Google-feed refresh worked. Native Android DNS and normal TLS verification were exercised. Protected active configuration and PIF settings were preserved, with one observed TrickyStore engine instance.

The standalone WebUI host previously required root permission. A working real-phone dashboard/picker session has not been demonstrated; offline WebUI tests and CLI success do not substitute for that check.

No real configuration Apply/rollback, confirmed signer adoption, app-data reset or successful Tap-to-Pay transaction was demonstrated. Passing external integrity-checker labels do not establish the payment system's policy result.

## Release identity

Module version: `v0.1.1`, version code `2`, module ID `wallet_diagnostic`.

ZIP: `releases/wallet-diagnostic-v0.1.1.zip`, 3,098,949 bytes.

```text
039581ad774fd66702cfaef92bb835821088cdf698941c73f9c46c9f28828328
```

Backend SHA-256:

```text
80674b104140fd9777ae535bc1c6051c0db0457cbeec93563e5a90ff9a2c8acf
```

The backend uses Go 1.27.2 and Android NDK r30, cgo and an API 28 AArch64 target. The inspected ELF is PIE with `/system/bin/linker64`, 16 KiB load alignment and dependencies on Android system libraries. Those shared libraries are not bundled. A fully rebuilt binary may differ with toolchain or environment changes; deterministic packaging does not promise universal binary reproducibility.

Copied/decompiled OS, kernel and application code used for bounded compatibility research remains outside this public repository. Original-source recovery, opaque TEE/secure-element firmware, Google server policy and issuer decisions remain unresolved.
