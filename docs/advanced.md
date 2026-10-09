Historical Go 0.2.0 guide. Current implementation/build and audit corrections are in [Rust build](rust-build.md), [validation](validation.md) and [audit corrections](rust-audit-fixes.md). Historical examples are preserved for comparison and do not authorize phone operations.

# Advanced, CLI and ADB guide

The single backend is `/data/adb/modules/wallet_diagnostic/bin/walletdiag`. Persistent private state is `/data/adb/wallet_diagnostic`; active configuration remains `/data/adb/tricky_store`. The backend bundles Go’s XML, private-key and X.509 validation and does not require phone Python, curl or OpenSSL. Missing mandatory permissions or validation capabilities block writes with a stable result code.

## Access and stable interface

Use `walletdiag help` for native CLI forms and exit codes. Every WebUI action calls the same command dispatcher using a bounded base64url UTF-8 JSON request. The request and response schema is version 1:

```json
{"command":"status","args":{}}
```

```json
{"schema":1,"ok":true,"code":"OK","message":"Redacted result","time":"RFC3339","data":{}}
```

Argument values are strings. The UI never interpolates a filename, token, XML body or API response into a shell command. It calls only a fixed backend path followed by `request` and a base64url alphabet. Both native `exec` and `spawn` are shell boundaries; do not build your own unquoted shell command from supplied material.

For reliable Windows PowerShell quoting, use this helper. It passes only a fixed remote command and an encoded alphabet; filenames containing spaces remain JSON data. It sends no secret content or credentials on the command line.

```powershell
function Invoke-WalletDiagnostic {
    param([Parameter(Mandatory)][string]$Command, [hashtable]$Arguments = @{})
    $request = @{ command = $Command; args = $Arguments } | ConvertTo-Json -Compress -Depth 8
    $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($request)).TrimEnd('=').Replace('+','-').Replace('/','_')
    if ($payload -notmatch '^[A-Za-z0-9_-]+$') { throw 'Request encoding failed' }
    & adb shell "su -c '/data/adb/modules/wallet_diagnostic/bin/walletdiag request $payload'"
    if ($LASTEXITCODE -ne 0) { throw "Backend stopped with exit code $LASTEXITCODE; read the redacted result above" }
}
Invoke-WalletDiagnostic status
Invoke-WalletDiagnostic diagnose
Invoke-WalletDiagnostic watch @{ days = '14' }
Invoke-WalletDiagnostic recovery @{ action = 'status' }
Invoke-WalletDiagnostic trust @{ action = 'status' }
# Explicit network check: fetch Google's complete public roots/status, then
# compare the local chain on the phone. Nothing private is uploaded.
Invoke-WalletDiagnostic trust @{ action = 'refresh' }
```

Do not log private filenames or identifiers beyond what the redacted support report needs. Raw keyboxes, private keys, credentials, card/account data, app databases and unrelated log dumps must not enter support exports. The backend’s read-only evidence is still timestamped: recollect after relevant changes.

## Private import, selection, plan and apply

The first-use guide gives the simple temporary-copy procedure. To avoid a phone-side intermediate XML file, transfer from the PC directly into a reviewed root-owned inbox path through binary stdin. This PowerShell 7 example does not pass file contents in command arguments or print them. Run `init` first so the inbox exists; status itself does not initialize private state:

```powershell
$localInput = 'C:\Private\input.xml'
& adb shell "su -c '/data/adb/modules/wallet_diagnostic/bin/walletdiag init'"
if ($LASTEXITCODE -ne 0) { throw 'Inspect the backend status error before continuing' }
$transfer = [Diagnostics.ProcessStartInfo]::new()
$transfer.FileName = (Get-Command adb).Source
$transfer.UseShellExecute = $false
$transfer.RedirectStandardInput = $true
$transfer.RedirectStandardOutput = $true
$transfer.RedirectStandardError = $true
$transfer.ArgumentList.Add('shell')
$transfer.ArgumentList.Add("su -c 'umask 077; test ! -L /data/adb/wallet_diagnostic/inbox/input.xml && cat > /data/adb/wallet_diagnostic/inbox/input.xml'")
$process = [Diagnostics.Process]::Start($transfer)
$source = [IO.File]::OpenRead($localInput)
try { $source.CopyTo($process.StandardInput.BaseStream) } finally { $source.Dispose(); $process.StandardInput.Close() }
$transferError = $process.StandardError.ReadToEnd()
$process.WaitForExit()
if ($process.ExitCode -ne 0) { throw 'Private transfer failed. Inspect the inbox permissions and ADB root authorization.' }
$process.Dispose()
```

The backend initializes a restrictive inbox on explicitly invoked init/ingest. Do not overwrite an inbox path that is a symlink, and do not manually loosen private directory permissions. The backend rejects unsafe staging sources; stdin transfer is only a convenience for the device owner and is not itself the validation gate. ADB connections and the PC source still need appropriate privacy.

```powershell
Invoke-WalletDiagnostic ingest @{ path = '/data/adb/wallet_diagnostic/inbox/input.xml' }
Invoke-WalletDiagnostic validate @{ id = 'STAGED_ID_FROM_INGEST' }
Invoke-WalletDiagnostic plan @{ selections = 'STAGED_ID:0:0:ecdsa,OTHER_STAGED_ID:0:0:rsa'; targets = 'false'; patch = '' }
# Read the plan first. IDs and indices below are placeholders, never automatic selections.
Invoke-WalletDiagnostic apply @{ id = 'REVIEWED_PLAN_ID' }
Invoke-WalletDiagnostic verify
# Only to record checks you personally completed after the change:
Invoke-WalletDiagnostic verify @{ 'wallet-ready' = 'true'; 'tap-confirmed' = 'true'; 'reviewed-user' = 'NUMERIC_USER_FROM_FRESH_STATUS' }
```

Selection tuples are `staged_id:keybox_index:key_index:algorithm`; indexes start at zero and must match the validation summary. Select at most one complete key per supported algorithm. Do not silently replace a duplicate or choose a Keybox. The helper uses deliberately fixed output metadata and does not recreate source hardware identity.

Structural validity, cryptographic consistency, established trust, revocation, adoption and Wallet acceptance are separate results. Certificate validity/signature checks cannot prove public trust or non-revocation. The helper’s RSA 2048–4096 / EC P-256/P-384 parameter policy is distinct from installed-engine compatibility evidence; unsupported mandatory capabilities block Apply.

`trust refresh` uses only the two documented Google HTTPS feeds, with native Android DNS, normal TLS verification, no credentials, no redirects and bounded reads. Root-key matching and certificate serial comparisons happen locally. Unknown anchors retain unknown revocation status; an absent entry is only “not listed in this fresh snapshot.” The private cache is not a signed offline CRL. Plan/Apply bind its bytes and freshness, reject a known listed Google-anchored chain, and require a new plan after a refresh or expiry. Rollback can restore original bytes even when their status is listed. See [trust research](trust-research.md).

Readiness/tap declarations must identify the numeric Android user you just reviewed. If the active configuration or user changes before recording, verification stops rather than attaching your result to another configuration or profile. An unchecked or historical declaration is never promoted to a current successful payment result.

`targets='true'` requests required generate-mode target repair while retaining unrelated lines and comments. A nonempty `patch='YYYY-MM-DD'` requests a backed-up TrickyStore patch change. Justify both from fresh diagnosis. PIF fingerprints/flags, spoofed boot properties, unfamiliar modules, caches, blocklists and account/payment state are preserved.

## Backups, rollback and recovery

```powershell
Invoke-WalletDiagnostic backups
Invoke-WalletDiagnostic rollback @{ id = 'previous' }
Invoke-WalletDiagnostic rollback @{ id = 'last-verified' }
Invoke-WalletDiagnostic rollback @{ id = 'REVIEWED_BACKUP_ID' }
Invoke-WalletDiagnostic recovery @{ action = 'status' }
Invoke-WalletDiagnostic recovery @{ action = 'restore' }
Invoke-WalletDiagnostic recovery @{ action = 'release-lock' }
```

Rollback snapshots the current set, verifies the chosen backup, restores original absence when a file did not exist, then reports engine/adoption evidence. `last-verified` requires a checked checkpoint created only by a trusted internal identity-adoption verification result. The production adapter currently reports adoption pending, so this choice is unavailable until such a checkpoint exists; Wallet/Tap-to-Pay declarations alone do not create one. It never substitutes for a user-confirmed payment test. Recovery snapshots the current, possibly partial file set before restoring the journal’s previous set. No silent pruning is performed. `release-lock` checks that the lock owner ended or the boot changed and refuses a live owner; it does not restore an interrupted configuration, so inspect the journal separately.

Each active write has an exclusive helper operation lock and a persistent journal. That lock cannot control TA_utl or another external writer. Inputs and active hashes are rechecked before commit. Same-filesystem temporary files and individual renames reduce partial-file exposure, but several renames are not an atomic set. If a process or reboot interrupts the set, the journal’s old snapshots permit recovery. Inspect pending recovery before writing again. If restore fails, stop and retain the journal/backups for diagnosis.

Do not kill keystore2 or guess process names to force adoption. The helper does not broadly restart engines. Fresh post-commit identity evidence is needed; absent traffic is pending evidence. Manual reboot, if ever required by verified installed behavior, remains a user action.

## API configuration

The supplied endpoint remains `https://keybox.tryigit.dev/api/cleverestrikcy/`, including its exact spelling. A HEAD response and a guessed route are insufficient to establish its provider contract; that endpoint remains unavailable. Analysis of CleveresTricky's configurable feed client supports a separate generic HTTPS raw-XML adapter. Private configuration and credentials are read only from a root-owned mode-0600 JSON file directly inside the private inbox. No token, URL or password argument is accepted. See [RHSO controls](rhso.md) for the schema, authentication modes, import limits and explicit staging workflow.

```powershell
Invoke-WalletDiagnostic api @{ action = 'status' }
```

Generic import uses one bounded GET, verified TLS, checked public DNS addresses, no proxy, redirect or retry, and private staging only. It never uploads existing material or executes downloaded code. A failed import preserves active configuration. Local ingest needs no provider account; a source provenance declaration does not establish hardware trust or authenticate a provider contract.

## Selected stack settings and target compaction

Use `stack --action status --json` for installed-version and resource availability. Select `hma-scope` targets and hide packages explicitly, or a deliberate `brezygisk-unmount` enable/disable intent. Separate `plan`, `apply`, `verify` and `rollback` actions all use the same backend. The redacted preview and plan ID must be reviewed before Apply. Stack recovery uses its typed resource backup and journal; the keybox transaction's three-file allowlist is unchanged. Both setting Apply and rollback report runtime adoption unknown and require manual reboot review. See [RHSO controls](rhso.md) for the verified contracts and limitations.

`plan --compact-targets true` independently removes duplicate target occurrences when their modes agree, retaining comments and original kept lines. Mixed modes or unsupported syntax stop the plan. Use the ordinary keybox plan preview, backup, Apply and recovery workflow; compaction alone preserves keybox and patch bytes.

## Manual watch

`watch` compares TrickyStore/PIF patches and warns about the supplied estimated 2026-11-18 fingerprint expiry within configurable days. The estimate is meaningful only for the supplied fingerprint and is invalidated by a fingerprint change. This module installs no scheduler or daemon. Watch does not change patches, fingerprints or configuration.

## Separately confirmed reset

Ordinary Apply, installation, module action and diagnosis never clear app data or reboot. Reset is an Advanced workflow only after diagnosis supports trying it. The review and journal bind a numeric Android user as well as the installed PIF action/dependency hashes, current three-file configuration and PIF settings. The backend checks the same user before confirmation and across reboot/resume/completion. It passes that fixed numeric user to every clear, rather than resolving `current` independently at each destructive step. A profile switch or changed scripts/settings blocks continuation and needs review; no failed clear is repeated automatically. The configured sequence is Wallet clear, Play Store clear, GSF clear, GMS clear twice, a manual reboot, the separately reviewed PIF action, GMS force-stop for the bound user, then user sign-in/card re-provisioning and Wallet checks. There is no established reason for the repeated GMS clear; it is retained because the owner explicitly requested that sequence.

Automatic post-reboot PIF execution is unavailable. Inspection showed the installed action can fetch network material, modify PIF/TrickyStore patch settings and stop processes. Its network mutation contract is not verified; the helper cannot treat a script hash as an audit of fetched content. `resume` checks the journal/reboot/scripts and returns a precise capability blocker plus manual next steps. It does not run the action. Do not execute these commands merely to test the helper. The device owner must separately review and choose the installed action before running it manually; it is outside ordinary configuration Apply.

```powershell
$resetReview = Invoke-WalletDiagnostic reset @{ action = 'preview' } | Out-String | ConvertFrom-Json
$resetUser = [string]$resetReview.data.user
if (-not $resetReview.ok -or $resetUser -notmatch '^[0-9]+$') { throw 'Reset user/review unavailable; stop' }
# Read steps, consequences and the numeric user from this redacted review.
$resetReview.data
# Only after separately reviewing the effects and deciding to clear app data:
Invoke-WalletDiagnostic reset @{ action = 'confirm'; confirmation = 'CLEAR WALLET AND GOOGLE SERVICES'; review_hash = [string]$resetReview.data.review_hash }
# Reboot manually as directed by the journal, then explicitly continue:
Invoke-WalletDiagnostic reset @{ action = 'resume' }
# Only after separately choosing and reviewing the installed PIF action:
$resetStatus = Invoke-WalletDiagnostic reset @{ action = 'status' } | Out-String | ConvertFrom-Json
$resetUser = [string]$resetStatus.data.user
if (-not $resetStatus.ok -or $resetUser -notmatch '^[0-9]+$') { throw 'Bound reset user unavailable; stop' }
$currentUser = ((& adb shell "su -c '/system/bin/am get-current-user'") | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $currentUser -ne $resetUser) { throw 'Android user changed; stop before PIF action' }
& adb shell "su -c '/system/bin/sh /data/adb/modules/playintegrityfix/action.sh'"
if ($LASTEXITCODE -ne 0) { throw 'PIF action failed; stop and inspect without repeating app clears' }
$currentUser = ((& adb shell "su -c '/system/bin/am get-current-user'") | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $currentUser -ne $resetUser) { throw 'Android user changed; stop before force-stop' }
& adb shell "su -c '/system/bin/am force-stop --user $resetUser com.google.android.gms'"
if ($LASTEXITCODE -ne 0) { throw 'GMS force-stop failed; stop and inspect' }
Invoke-WalletDiagnostic reset @{ action = 'complete'; confirmation = 'PIF ACTION AND GMS FORCE-STOP COMPLETED' }
```

`resume` intentionally returns an unavailable capability result instead of executing PIF, so the PowerShell helper stops that invocation. Inspect the result and perform the later manual commands as a separate, reviewed choice. Recheck the journal’s numeric user before the PIF action too; the action has global side effects outside the helper’s per-user clear boundary. If the PC shell is reopened, recover the bound user from reset status rather than guessing user 0 or using `current` in the force-stop command.

The confirmation irreversibly clears the listed apps’ local data for the reviewed numeric user; configuration backups do not restore it. Wallet/card setup may be lost; GSF state and Android-ID behavior may change; Google sign-in and card provisioning may be required. The journal is one-shot and never resumes automatically at boot or repeats failed clears. Manual completion is an owner declaration, not proof that the helper executed or independently verified PIF behavior. The authorized development-phone trial completed the requested ritual with separately guarded PIF execution; see the [live trial record](live-keybox-trial.md). No successful Wallet setup or payment was established by completing it.

## Compatibility and UI limitations

Locally bundled KernelSU JavaScript SDK 3.0.2 uses `ksu.exec(command, JSON.stringify(options), callbackName)`. KSU Next and standalone WebUI are shell execution bridges, not safe argument-vector APIs. The installed standalone APK statically exposes the expected three-argument overload, the exported WebUI activity and a file-picker callback. Picker runtime behavior, returned content-URI handling and root staging are not proven by static decompilation, so the module uses an absolute inbox path with ADB fallback. It does not guess the randomized manager package or load scripts from a CDN. All displayed values use text nodes; API-provided HTML is never rendered.

No secrets are saved in WebUI localStorage/sessionStorage. The UI retains only redacted summaries and selected IDs in memory, blocks repeat taps while a command runs, and removes the plan after submission. Back/cancel is available before commit; cancellation during commit must be handled by the backend’s finish/recovery policy. If the host closes, inspect the persistent journal before another write.

## Build

`go.mod` declares a Go 1.25 minimum; the tested compiler is the official Go 1.27.2 toolchain. The production Android build uses `CGO_ENABLED=1`, `GOOS=android`, `GOARCH=arm64` and Android NDK r30 API-28 clang with `-trimpath` to support native Android DNS. It links the platform runtime and does not ship a separate resolver daemon. Run the backend tests and UI contract tests listed in the test report before packaging. Build/decompiler tools are separate development dependencies and do not belong on the phone.

```powershell
& .\scripts\package.ps1 -BackendPath '.\dist\walletdiag' -OutputPath '.\dist\rhso-v0.2.0.zip'
Get-FileHash -LiteralPath '.\dist\rhso-v0.2.0.zip' -Algorithm SHA256
```

Packaging checks an AArch64 ELF header, required local assets/licenses, LF shell/property files, and rejects symlinks. ZIP entries are ordered and have fixed timestamps; repeated packaging with unchanged source and toolchain should yield the same hash. KernelSU installation is supported; no recovery-flashing instructions are included. Updates preserve private state. Uninstall keeps active TrickyStore changes and recovery data; roll back deliberately before uninstall if needed.
