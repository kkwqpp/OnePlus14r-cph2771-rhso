# RHSO v0.2.0 validation and limits

2026-10-09. The release adds selected HMA schema-93 blacklist additions, the BreZygisk 548 unmount marker, duplicate target compaction, private configured HTTPS raw-XML staging, and PIF/stack-aware verification freshness. These results are separate from runtime activation, signer adoption, Google Wallet approval and an actual payment. **Tap-to-Pay remains unproved.**

## Completed checks

| Check | Recorded result |
|---|---|
| Windows `go test ./... -count=1 -json` | All three packages passed; 668 tests/subtests passed, five skipped, zero failures. Package-completion events are excluded. |
| `go vet ./...` | Passed. |
| Node syntax and WebUI core tests | Passed; 10/10 unit tests. |
| Offline headless Chrome integration | Passed explicit import/selection/review/confirmation, API privacy/generation guards, selected Stack controls, stale user/PIF/stack evidence, pending recovery, inert HTML and 390px/320px enlarged-text fixtures. Mock bridge and synthetic data. |
| Module shell/install/uninstall fixtures | Passed using inert Android command stubs. |
| Native Android synthetic executables | Core 521, keybox 109, CLI 42 passed: 672 total, one intentional child-helper skip, zero failures; all three exited zero. |
| ELF inspection | AArch64 PIE, `/system/bin/linker64`, 16 KiB load alignment; system liblog/libdl/libc dependencies. |
| Native public-feed transport | Explicit Google whole-feed refresh succeeded at 20:14:21 UTC with native DNS and verified TLS; no private material uploaded. |
| Repeated package and curated public assets | Both reproduced the delivered ZIP SHA-256. |
| Fresh Git checkout packaging | Passed: fresh source native build and package reproduced exact backend/ZIP hashes; relative output follows the PowerShell working directory. |
| Real helper update | Installed through existing KernelSU/NoMount; v0.2.0 staged for manual reboot. Pending CLI and five software-asset hashes matched release. Three active files including metadata, PIF and combined hiding-state evidence remained unchanged. |

Windows skips are the intentional child helper plus four symlink cases requiring Windows privileges. Android exercised those POSIX/symlink paths. Synthetic cases cover malformed/ambiguous metadata, unsupported selections, private feed TLS/address/format/redaction boundaries, stale context, verified backups, faults, process interruption and recovery. New directory entries are synced before Stack writes. Arbitrary power loss, disk/controller faults and every concurrent root syscall race are not certified; another root writer remains outside the helper lock.

## Live evidence and limits

The temporary v0.2.0 read-only CLI recognized both installed HMA and BreZygisk profiles as available. No hiding setting, target compaction or provider import was applied on the real phone. Both Stack Apply and rollback report runtime adoption unknown and require manual reboot review. File readback cannot establish activation.

The prior v0.1.1 helper applied the owner's ECDSA material at 18:51 UTC. The separately confirmed ritual made five user-0 app clears at 18:54, followed by an owner reboot and reviewed manual PIF/GMS continuation; completion was recorded at 19:29:54. The PIF fingerprint/patch changed under that separate authorization; advanced flags, keybox/target bytes and protected metadata/properties were checked. See the [live trial](live-keybox-trial.md). App clears cannot be restored by configuration backups. Earlier integrity-checker passes predate this reset.

Current active material is ECDSA-only. A fresh private Wallet retry and terminal payment remain outstanding. No production Stack Apply/rollback, real WebUI dashboard/picker session, fresh selected-signer adoption or successful payment was demonstrated. No additional attestation engine, boot/partition write, relock, automatic reboot, generic trace deletion or background process was introduced.

The exact original Cleveres endpoint remains unavailable/unverified. Generic raw-XML transport tests do not prove a provider contract, material provenance or hardware trust. No production keybox provider request was made. CBOX/ZIP/CUSTOM authentication remain unsupported.

## Release identity

Module ID `wallet_diagnostic`, name RHSO - Root Hiding Stack Optimizer, version `v0.2.0`, version code `3`. Existing CLI/private directory names remain for update continuity.

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `releases/rhso-v0.2.0.zip` | 3,177,094 | `1ed5da036ff2d02cf3d19f5e456565c5a0cca1a5ab78b6da9489ac03adf2328d` |
| Native backend | 7,357,480 | `2e93f7bc81eb7e9c4338f092db643d6aa461aff01b8a8a35feea4223f7c8129c` |

The archive has 17 reviewed entries: original backend/assets, lifecycle scripts, module metadata and complete licenses. No real keybox, credential, copied APK/firmware, test executable, decompiler or toolchain is included. Synthetic phone executables, temporary check binary and transfer ZIP were removed; private staging/backups/journals remain. No own daemon, watcher or test process runs.

Build: Go 1.27.2, NDK r30, API 28 Android arm64, cgo and external linking for native DNS. Android system shared libraries are not bundled. Deterministic ZIP packaging assumes unchanged binary/assets/compression runtime; universal reproducible compilation is not claimed.

Historical v0.1.1: Windows 415 pass/3 skip, Android 417 pass/1 skip, five UI unit tests; module ZIP SHA-256 `039581ad774fd66702cfaef92bb835821088cdf698941c73f9c46c9f28828328`. Those are historical counts, not the expanded current suite.

Copied/decompiled OS/kernel/application code remains outside public Git. Bounded pseudocode does not recover complete original source; TEE/secure-element firmware, active opaque DroidGuard behavior, Google server policy and issuer decisions remain unresolved. Hardcoded development annotations are not fresh observations of another phone.
