# RHSO — Root Hiding Stack Optimizer

RHSO is an explicitly invoked configuration and diagnostic helper for supported rooted Android installations. Keybox management follows **Import → Review → Apply → Verify**. Supported HMA/BreZygisk settings use separately selected plans and private resource backups.

The current **unfinished 0.3.0 Rust migration** targets project-owned backend, keybox validation, browser policy/workflows and packaging in Rust. The browser controller runs as WASM; its small loader, generated wasm-bindgen glue, vendored KernelSU SDK and minimal Android lifecycle scripts provide interoperability. The critical audit of checkpoint `6647086` is complete and its [corrections](docs/rust-audit-fixes.md) are implemented locally. Full behavior parity, Android execution, installed host compatibility and installation/update checks remain pending in [validation](docs/validation.md). Go source is retained as the comparison baseline; earlier Go results are historical evidence. This candidate is not a completed release.

RHSO does not establish Google Wallet acceptance from keybox validation, an integrity-check result or a successful file write. Readiness, signer adoption, public trust and a successful terminal payment remain separate evidence. **Tap-to-Pay remains unproved.** Changing implementation language cannot guarantee a Wallet fix.

## Local-test candidate download

- [RHSO 0.3.0 audit candidate ZIP](releases/rhso-v0.3.0-audit-candidate.zip)
- [Candidate SHA-256](releases/rhso-v0.3.0-audit-candidate.zip.sha256)

This candidate has passed the offline checks recorded below. Android execution, installed WebUI, HTTPS and update preservation are still pending. It is not a completed release, and Wallet/payment acceptance remains unproved. The historical [0.2.0 ZIP](releases/rhso-v0.2.0.zip) remains separate; downgrading state created by Rust requires compatibility review.

## Start here

1. Read [first use](docs/first-use.md) and the [supported RHSO controls](docs/rhso.md).
2. Build and review the current candidate with [Rust build](docs/rust-build.md). The audit candidate is `dist/rhso-v0.3.0-audit-candidate.zip` with a `.sha256` sidecar; see its record in [validation](docs/validation.md). It has not been installed. Historical checksums describe older releases.
3. For a reviewed installation, collect status and diagnostics before choosing changes. If the WebUI host is unavailable, use `/data/adb/modules/wallet_diagnostic/bin/walletdiag help` through a root shell.
4. Import only authorized material, select each Keybox/key/algorithm deliberately, review the full change preview, then apply and verify when the evidence supports it.

Module ID `wallet_diagnostic`, CLI name `walletdiag` and private directory `/data/adb/wallet_diagnostic` remain stable for update/recovery continuity. Inputs enter private staging before validation. Configuration writes take verified backups, reject stale reviews and retain recovery journals. Individual file writes do not make an entire configuration set atomic. Updates and uninstall preserve private recovery data. Uninstall leaves an applied configuration in effect unless it was explicitly rolled back.

## Scope and limits

- The Rust helper validates bounded XML/private-key/X.509 inputs and preserves each selected key with its complete certificate chain. Source identity is withheld, and required private-key encoding changes are disclosed. Trust, revocation, engine adoption and Wallet acceptance stay separate.
- Explicit Google public-feed requests use full public feeds and normal HTTPS verification. No local keybox, private key or certificate serial is uploaded. Rust native DNS/TLS behavior requires its own real-device check; earlier Go transport results do not substitute for it.
- The exact supplied Cleveres endpoint remains unavailable/unverified. The separate generic HTTPS raw-XML adapter takes a root-private JSON configuration file and performs one separately requested staging-only GET. Credentials and provider bodies never enter the UI, request arguments or reports. Validation and key selection remain manual.
- Supported HMA schema-93 blacklist additions and the BreZygisk 548 unmount marker have typed, capability-pinned plans, private backups, file verification and explicit rollback. Both write directions require manual reboot review and keep runtime adoption unknown. Target compaction preserves retained entries and rejects mixed modes.
- Wallet reset is a separate destructive workflow with a preview, full confirmation phrase and numeric-user-bound journal. Configuration rollback cannot recover deleted app data. Reboot and reviewed PIF execution remain manual; nothing resumes the ritual automatically.
- The helper starts no daemon, extra attestation engine, boot-time rotation or automatic reboot. Its only mount is one static ODM overlay that hides the StrongBox keystore feature (see [RHSO controls](docs/rhso.md#strongbox-feature-overlay)). It does not write bootloader/partitions or relock the device. Existing engines remain external components.
- The WebUI bundles its assets, renders untrusted values as text and stores no keys or credentials in browser storage. Never put real keyboxes, private keys, credentials, account/card data or copied firmware/APKs into source control or support reports.

The [Rust component map](docs/rust-component-map.md) distinguishes independently authored helper logic from external engines, applications, Android/OS code, kernel code and hardware/server decisions. Decompilation does not recover complete original source or turn those components into a reproducible Rust implementation. Their existing code and behavior remain external to this rewrite. Runtime activation and payment acceptance need direct evidence.

## Documentation and source

| Item | Location |
| --- | --- |
| Current build, WASM assets and deterministic package | [Rust build](docs/rust-build.md); [portable build entry point](docs/portable-build.md) |
| Current validation and historical baseline | [Validation](docs/validation.md); [Rust subsystem matrix](docs/rust-validation.md) |
| Audit fixes and reviewed recovery close-outs | [Rust audit corrections](docs/rust-audit-fixes.md) |
| Guided WebUI and plain-language controls | [Rust WebUI guide](docs/rust-ui.md) |
| Rewrite feasibility and external boundaries | [Rust component map](docs/rust-component-map.md) |
| Installation/import/recovery guide | [First use](docs/first-use.md) |
| CLI, ADB, API boundaries and reset | [Advanced](docs/advanced.md) |
| Stack controls, target compaction and private source import | [RHSO controls](docs/rhso.md) |
| Storage/interface architecture | [Architecture](docs/architecture.md) |
| Public-source research and trust-feed limits | [Research](docs/research.md); [trust research](docs/trust-research.md) |
| Prior authorized keybox/reset trial | [Historical live trial](docs/live-keybox-trial.md) |
| Prior host and installed-component inspection | See the [component map](docs/rust-component-map.md) and current [validation](docs/validation.md) |
| Kernel/native and Wallet evidence limits | See the [component map](docs/rust-component-map.md) |
| Earlier Go release validation | [Historical baseline in validation](docs/validation.md) |
| Rust backend/keybox | `crates/backend/`, `crates/keybox/` |
| Rust browser/packager | `crates/webui/`, `crates/packager/` |
| Declarative assets, bridge glue and lifecycle adapters | `module/` |

Copied/decompiled device code, SDKs and external build tools remain outside the repository and module ZIP. Tests use synthetic fixtures and mock responses; those are distinct from active inspection, production configuration changes and actual payments.

## License

Original helper source is [MIT](LICENSE). Rust standard-library/dependency code and the unchanged Apache-2.0 KernelSU SDK retain their own notices. NDK/LLVM notice collections cover incorporated native startup/compiler/runtime components without redistributing a full toolchain. Required notices are bundled under `module/licenses/`. Inspected device/vendor/APK/kernel code is not relicensed or redistributed by this project.
