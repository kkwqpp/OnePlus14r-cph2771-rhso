# Wallet Diagnostic

Wallet Diagnostic is an explicitly invoked diagnostic and keybox configuration helper for an existing TrickyStore installation. It provides a local KernelSU WebUI, native Android arm64 CLI, module action, reviewed configuration plans, backups and interrupted-operation recovery.

This repository was named **RHSO — Root Hiding Stack Optimizer** by its owner. The implemented module is called **Wallet Diagnostic** because it diagnoses prerequisites and manages configuration; it does not optimize root hiding. **It has not made Google Wallet Tap-to-Pay work on the development phone.** Local validation, a public certificate check or passing integrity-checker labels do not establish Wallet eligibility.

## Download and installation

- [Installable v0.1.1 module ZIP](releases/wallet-diagnostic-v0.1.1.zip)
- [SHA-256 file](releases/wallet-diagnostic-v0.1.1.zip.sha256)

Expected ZIP SHA-256:

```text
039581ad774fd66702cfaef92bb835821088cdf698941c73f9c46c9f28828328
```

Read [first use](docs/first-use.md), compare the downloaded ZIP's hash, then install through the existing KernelSU manager. Open the module WebUI and collect diagnostics. The root CLI fallback is `/data/adb/modules/wallet_diagnostic/bin/walletdiag help`.

The release was tested on a rooted OnePlus 15R with an existing TrickyStore stack. Broad device compatibility is unproved. The GitHub repository's existing name is not a model compatibility claim.

Apply is gated by the inspected TrickyStore 1.4.1 component hashes. Other installations require a compatibility review before writes. The manual watch estimate is tied to one built-in public fingerprint and is not a Google eligibility deadline.

Diagnostic fields describing the owner's unlocked bootloader, Wallet error and supplied integrity passes are hardcoded development-baseline annotations. They are not fresh observations of another phone. Current-user, file, engine, NFC and public-feed checks have their own runtime evidence and limits.

## What it does

- Copies authorized local inputs into private phone staging; validates bounded XML, private keys and X.509 chains; supports explicit ECDSA/RSA selection and merging.
- Previews supported changes to `keybox.xml`, `security_patch.txt` and `target.txt`, with stale-input and external-change checks.
- Backs up bytes and metadata, journals each write, attempts restoration on failure, and preserves pending recovery when restoration cannot finish. Multiple files are recoverable; they are not replaced atomically as a set.
- Downloads complete Google public root/status feeds on explicit request and compares the local chain on the phone. Private keyboxes and serials are not uploaded. Results remain distinct from engine adoption and Wallet acceptance.
- Reports targeted prerequisites, redacted status, backups and history through one backend. All UI assets are bundled locally.

## Boundaries

The module includes no attestation engine, root-hiding hooks, property spoofing, mounts, daemon, boot writer, automatic rotation, reboot, bootloader or partition operations. It preserves the existing stack outside explicitly reviewed supported configuration changes.

Public-feed evidence has freshness and issuer-context limits; an unlisted certificate is not a Wallet approval. Actual signer adoption and payment acceptance remain unproved. An optional provider adapter is unavailable because its supplied endpoint has no verified contract. Credentials are not accepted and no provider material is fetched.

An app-data reset workflow exists behind a separate preview and explicit confirmation. It can destroy application data; configuration rollback cannot restore that data. Reboot and the separately reviewed PIF action remain manual. No real reset, production configuration Apply/rollback or successful payment was demonstrated during development.

Private state lives in `/data/adb/wallet_diagnostic`, outside the replaceable module folder. Updates and uninstall preserve staging, backups and recovery data. Uninstall also leaves any previously applied TrickyStore configuration in effect; roll back explicitly first if desired.

## Source and documentation

| Item | Location |
|---|---|
| Installation, import and recovery | [First use](docs/first-use.md) |
| CLI, ADB and explicit reset boundaries | [Advanced guide](docs/advanced.md) |
| Components, commands and state model | [Architecture](docs/architecture.md) |
| Portable build and fixture commands | [Build guide](docs/build.md) |
| Recorded checks and remaining limits | [Validation](docs/validation.md) |
| Primary-source references | [Research](docs/research.md), [public-feed contracts](docs/trust-research.md) |
| Backend and synthetic tests | `cmd/walletdiag/`, `internal/core/`, `internal/keybox/` |
| Local WebUI and lifecycle scripts | `module/` |
| Packaging and browser/shell fixtures | `scripts/`, `tests/` |

This is a fresh public source snapshot. Private device evidence, original private Git history, copied firmware/APKs, decompiler output, build tools, credentials, keyboxes and recovery data are excluded. Tests generate synthetic material; never commit real private keys or account/card data.

## License

Original code is [MIT](LICENSE). The vendored KernelSU JavaScript SDK retains Apache-2.0, and the linked Go runtime retains its BSD notice. NDK/LLVM notices cover native startup/runtime components. Full notices and provenance are in `module/licenses/` and the ZIP. Inspected device/vendor code is not redistributed or relicensed.
