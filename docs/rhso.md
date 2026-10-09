# RHSO controls and source imports

RHSO is an explicitly invoked configuration helper for the existing stack. The module ID remains `wallet_diagnostic` so updates retain existing private staging, backups and recovery. TrickyStore remains the only attestation engine. The helper contains no kernel/boot writer, automatic rotation, daemon, reboot command or downloaded-code executor.

Every setting change follows **Status → selected profile → Plan → review → Apply → file verification**. A complete private resource backup and journal precede a write. Profile activation and Wallet acceptance are separate results. The installed versions are pinned; unsupported versions remain diagnostic-only until reviewed.

## Target compaction

Select **Compact duplicate target rules** independently of required-target repair. A compaction-only plan retains the existing keybox and patch without regenerating either. It removes repeated rules only when each package has one consistent mode. Mixed modes and unsupported syntax stop the plan. Comments, order and the retained lines keep their original bytes. The preview counts individual duplicate occurrences and shows their removed lines.

```powershell
& adb shell "su -c '/data/adb/modules/wallet_diagnostic/bin/walletdiag plan --compact-targets true --json'"
# Review the returned plan ID and exact diff before a separate Apply.
```

This tidies a supported target file; it does not change conflicting modes or establish a payment fix. It uses the existing three-file backup/transaction workflow.

## Selected HMA blacklist additions

The inspected HMA oss-173 manager and module use configuration schema 93. RHSO discovers one verified backend configuration, rather than overwriting the manager's obsolete file path or writing to every matching directory. Select Google app scopes explicitly and enter only the packages you intend those apps to hide. It adds selected packages to blacklist `extraAppList`, preserving other scopes, global settings, templates and per-app fields. Whitelist modes, conflicting selections, unsafe files and unsupported schemas are blocked.

Review newly created scopes and each addition. A selected package must actually be installed for the reviewed Android user. The helper does not assume that hiding a package solves Wallet's rejection. Existing runtime configuration resides in the service's memory; file replacement alone cannot prove activation. A manual reboot and subsequent file review are required; runtime adoption remains unknown until independently demonstrated.

```powershell
& adb shell "su -c '/data/adb/modules/wallet_diagnostic/bin/walletdiag stack --action status --json'"
# Replace the fictional hide package with your deliberately selected installed package.
& adb shell "su -c '/data/adb/modules/wallet_diagnostic/bin/walletdiag stack --action plan --profile hma-scope --targets com.google.android.gms --hide-packages org.example.rootapp --json'"
# Review the preview and returned ID before any separate write.
& adb shell "su -c '/data/adb/modules/wallet_diagnostic/bin/walletdiag stack --action apply --id REVIEWED_PLAN_ID --json'"
& adb shell "su -c '/data/adb/modules/wallet_diagnostic/bin/walletdiag stack --action verify --id REVIEWED_PLAN_ID --json'"
# Explicitly chosen rollback restores only this profile's resource.
& adb shell "su -c '/data/adb/modules/wallet_diagnostic/bin/walletdiag stack --action rollback --id REVIEWED_PLAN_ID --json'"
```

## BreZygisk unmount intent

The inspected BreZygisk 548 setting is its own persistent unmount marker. It is different from Specter's Zygisk Next denylist setting. RHSO can review a deliberate enable/disable plan and restore the previous marker's exact contents, metadata or absence.

The native daemon reads this marker while creating namespaces and then caches those namespaces. The setting affects broad module mounts; compatibility with every app or NoMount/BRENE interaction is not established. RHSO does not recommend enabling it automatically. Apply and rollback both require manual activation review after reboot. No monitor stop/exit, daemon restart or zygote termination is included.

HMA and BreZygisk use a separate typed resource registry, private backups and stack journal. They do not expand the keybox transaction's three-file allowlist. An unfinished stack transaction blocks keybox, API and other stack writes. Inspect **Stack status**, then use the recorded plan's **Stack rollback** to restore its checked resource. If an interrupted host process left a lock, use the existing verified **Recovery → release lock** first; never delete a lock manually or repeat app-data clearing.

Before a setting write, RHSO also verifies a protected three-file TrickyStore backup. Stack rollback verifies that association but restores only its selected setting resource. The setting's existing bytes, ownership, permissions, SELinux context or original absence are preserved. Neither ordinary Apply nor rollback clears caches or application data.

## Configured raw-XML HTTPS sources

The original supplied spelling `https://keybox.tryigit.dev/api/cleverestrikcy/` remains unverified and unavailable. Analysis of CleveresTricky 2.8.7 established a generic configurable feed client, not a confirmed provider endpoint. RHSO supports a deliberately narrower configured raw-XML source; it does not install Cleveres or call its native keybox engine.

Provision a JSON file directly inside the root-private inbox, root-owned and mode 0600. Insert credentials privately in that file. The request bridge accepts only its path, never a URL, token or password. A nonempty provenance declaration records your authority to use that source; it is not cryptographic provider authentication or a hardware-trust claim.

Example private file structure, with a documentation-only placeholder URL:

```json
{
  "schema": 1,
  "url": "https://your-authorized-feed.example/input.xml",
  "provenance_declaration": "I am authorized to obtain and use this material.",
  "auth": { "mode": "NONE" }
}
```

Supported authentication configurations are `NONE`, `BEARER` with `token`, `BASIC` with `username` and `password`, or `API_KEY` with `header` and `key`. These fields stay in root-private storage and are not displayed or exported. CUSTOM headers, CBOX envelopes and ZIP archives are unsupported. Do not put a real private configuration in Git, browser storage, screenshots, chats or support exports.

```powershell
& adb shell "su -c '/data/adb/modules/wallet_diagnostic/bin/walletdiag api --action config --path /data/adb/wallet_diagnostic/inbox/source.json --json'"
& adb shell "su -c '/data/adb/modules/wallet_diagnostic/bin/walletdiag api --action status --json'"
# Import performs one explicit request, only after private configuration/review.
& adb shell "su -c '/data/adb/modules/wallet_diagnostic/bin/walletdiag api --action import --json'"
```

Each import performs one bounded GET with normal certificate verification, no redirects/proxy/retries and checked public destination addresses. It accepts uncompressed UTF-8 raw XML with an XML content type within the existing 1 MiB staging limit. HTML, archives, encrypted payloads, XML directives/external entities, unsupported wrappers and incomplete responses are rejected. Timeout, DNS, TLS, HTTP and input failures display fixed redacted errors. Provider URLs, query parameters, authentication and raw responses never enter the UI or support export.

Success returns an immutable staged input ID. **Validate** is separate, followed by deliberate algorithm/key selection, Plan and Apply. Import never automatically selects, applies, clears data, rotates material, reboots or changes active settings. A failed import leaves the active configuration untouched. Status/configuration never fetch a keybox. No production provider request or provider-format interoperability is inferred from synthetic client tests.

## Cleanup and payment limits

Specter's broad cleanup removes app/shared/system state and clears log buffers without recoverable backups. Those operations do not meet this module's recovery contract and are not implemented as a generic trace-wipe button. Staging, credentials, backup/journal/history data and persistent signing aliases remain preserved.

RHSO can verify files and report activation pending. A passing integrity checker, Google-root match, unlisted certificate, completed reset or applied hiding setting is not a successful card setup or terminal payment. The [live trial record](live-keybox-trial.md) separates the owner-authorized phone operations from those still unverified.
