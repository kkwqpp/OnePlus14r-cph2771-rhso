# RHSO — Root Hiding Stack Optimizer

RHSO provides explicitly reviewed configuration profiles for a supported root hiding stack, alongside Wallet diagnostics and keybox management. It includes a local KernelSU WebUI, native Android arm64 CLI, private staging, backups and interrupted-operation recovery. Every change requires a deliberate review; the module starts no boot writer or background optimizer.

**Google Wallet Tap-to-Pay has not been demonstrated.** Keybox validation, public certificate evidence, configuration readback and passing integrity-checker labels do not establish Wallet eligibility or runtime adoption.

## Download and installation

- [RHSO v0.2.0 module ZIP](releases/rhso-v0.2.0.zip)
- [SHA-256 file](releases/rhso-v0.2.0.zip.sha256)

The release passed Windows and isolated native Android tests. It is staged on the development phone for a manual reboot, with protected configuration unchanged. ZIP SHA-256:

```text
1ed5da036ff2d02cf3d19f5e456565c5a0cca1a5ab78b6da9489ac03adf2328d
```

Read [first use](docs/first-use.md) and the [RHSO profile guide](docs/rhso.md). Compare the archive hash and install through the existing KernelSU manager. The root CLI remains `/data/adb/modules/wallet_diagnostic/bin/walletdiag help`. The module ID `wallet_diagnostic` and private state directory `/data/adb/wallet_diagnostic` are retained for update and recovery continuity.

The historical v0.1.1 baseline was exercised on a rooted OnePlus 15R with an existing TrickyStore stack. Broad device compatibility is unproved. Keybox Apply is gated by the inspected TrickyStore 1.4.1 component hashes. HMA and BreZygisk profiles have separate code, schema, resource and current-user guards; unsupported installations expose a reason and refuse writes.

## What it does

- Builds explicit HMA blacklist scope plans for selected supported targets and package names, or a separately selected BreZygisk unmount-marker plan. Neither profile preselects Google targets, hidden packages or an enabled marker.
- Creates a verified private full backup before stack Apply, records a recovery journal, verifies persisted bytes and metadata, and supports explicit restoration of the matching backup. Apply and rollback require a manual reboot; runtime adoption remains unknown.
- Copies authorized local inputs into private staging, validates bounded XML/private keys/X.509 chains, and supports deliberate ECDSA/RSA selection and merging.
- Previews supported `keybox.xml`, `security_patch.txt` and `target.txt` changes. Optional target compaction removes later repeated package-and-mode entries while retaining first entries, comments and blank lines; conflicting modes or unsupported syntax stop the plan.
- Supports a generic configured HTTPS raw-XML feed through a root-private JSON file. Status and configuration do not fetch. An explicit Fetch stages one input, followed by separate validation, selection, Plan and Apply. URLs and credentials stay outside the WebUI, request arguments, status and support exports.
- Downloads complete Google public root/status feeds on explicit request and compares local chains on the phone. Keyboxes, private keys and certificate serials are not uploaded. Public-feed flags remain distinct from engine adoption and Wallet acceptance.
- Reports redacted prerequisites, capabilities, backups and history through one backend. Configuration, stack evidence and the numeric Android user participate in UI freshness checks. All UI assets are bundled locally.

## Boundaries and recorded history

RHSO ships no attestation engine, root hiding hooks, property-spoofing code, mounts, daemon, automatic rotation, reboot, bootloader or partition operations. It configures supported existing components only through explicitly reviewed profiles. An unlisted certificate or successful file readback is not a Wallet approval.

The exact supplied Cleveres endpoint remains unavailable and its provider contract is unverified. The generic raw-XML adapter does not establish a provider contract, authorized key provenance or hardware trust, and does not support an encrypted CBOX format. HTTPS certificate verification remains enabled. No remote script or downloaded code is executed. See the [advanced guide](docs/advanced.md) for private-file configuration and supported input boundaries.

A separately previewed and confirmed app-data reset can destroy application data; configuration rollback cannot restore that data. Reboot and the reviewed PIF action remain manual. The [live keybox trial](docs/live-keybox-trial.md) records an explicit ECDSA configuration Apply and the completed reset/PIF workflow. These observations do not prove signing-key adoption or payment acceptance. **No RHSO stack-profile Apply has been demonstrated on a live device.**

Diagnostic fields describing an unlocked development bootloader, a reported card-setup security rejection and supplied integrity passes are historical baseline annotations, not fresh observations of another phone. Current-user, file, engine, NFC and public-feed checks have their own evidence and limits. The manual fingerprint watch estimate is tied to one built-in public fingerprint and is not a Google eligibility deadline.

Private state lives outside the replaceable module folder. Updates and uninstall preserve staging, backups and recovery data. Uninstall leaves previously applied component configuration in effect; explicitly restore the appropriate backup first if desired.

## Source and documentation

| Item | Location |
|---|---|
| Installation, import and recovery | [First use](docs/first-use.md) |
| Reviewed stack profiles and runtime limits | [RHSO guide](docs/rhso.md) |
| CLI, private feed configuration and reset boundaries | [Advanced guide](docs/advanced.md) |
| Components, commands and state model | [Architecture](docs/architecture.md) |
| Portable build and fixture commands | [Build guide](docs/build.md) |
| Recorded checks and release verification status | [Validation](docs/validation.md) |
| Explicit live trial and remaining uncertainty | [Live keybox trial](docs/live-keybox-trial.md) |
| Primary-source references | [Research](docs/research.md), [public-feed contracts](docs/trust-research.md) |
| Backend and synthetic tests | `cmd/walletdiag/`, `internal/core/`, `internal/keybox/` |
| Local WebUI and lifecycle scripts | `module/` |
| Packaging and browser/shell fixtures | `scripts/`, `tests/` |

This public source snapshot excludes private device evidence, original private Git history, copied firmware/APKs, decompiler output, build tools, credentials, keyboxes and recovery data. Tests generate synthetic material; never commit real private keys or account/card data.

## License

Original code is [MIT](LICENSE). The vendored KernelSU JavaScript SDK retains Apache-2.0, and the linked Go runtime retains its BSD notice. NDK/LLVM notices cover native startup/runtime components. Full notices and provenance are in `module/licenses/` and the ZIP. Inspected device/vendor code is not redistributed or relicensed.
