# First use

This helper is for a rooted Android device you own or are authorized to manage, with an existing compatible KernelSU and TrickyStore installation. It preserves bootloader state and has no partition writer, attestation engine, automatic rotation, reboot, or boot-time configuration changes. A Wallet security rejection during card setup does not identify its cause. Wallet acceptance and Tap-to-Pay require separate user checks; see [validation and limits](validation.md) for development results.

1. Keep the module ZIP and its SHA-256 file on the PC. Verify the download against the supplied package hash. Install the ZIP through the existing KernelSU manager; no custom recovery installation is supported. Fresh installation preserves the active TrickyStore/PIF files. Do not change other modules to make the helper run.
2. Open **Wallet Diagnostic → WebUI**, or use the module action. The action opens the installed standalone WebUI when the verified activity is available; otherwise it prints status and the exact CLI entry point. A randomized manager package is never assumed.
   If the host shows **Please grant root** or keeps loading, grant KernelSU root to **KsuWebUI** (`io.github.a13e300.ksuwebui`), open its main screen, then reopen the helper. A launched activity alone does not confirm a working dashboard; the harmless Status result must display **Complete · OK**. CLI remains available while the host permission is missing.
3. Tap **Collect diagnostics** before importing anything. Separate confirmed findings from hypotheses. Missing RSA is a hypothesis to test, not a proven explanation of the Wallet failure. The API adapter is unavailable until its exact contract is verified; local import works independently.
   Use **Google public attestation evidence → Fetch Google public feeds (GET)** for an explicit network check. It downloads whole public feeds and compares the chain locally; no keybox or serial is uploaded. An unlisted Google-anchored chain is a limited result, not proof that Wallet accepts the phone.
4. Copy material you own or are authorized to use into the private inbox using the example below. Enter `/data/adb/wallet_diagnostic/inbox/input.xml` in **Import & review**. Keys and complete keyboxes must remain private; do not paste them into the UI, chats, screenshots or issue reports.
5. Import and validate each needed input. Select the exact Keybox and key for each chosen algorithm. A merged replacement contains only the algorithms you select; use **Import current active keybox** and select its entry to retain an existing algorithm. The helper keeps the selected private key with its whole associated certificate chain. Conflicting entries require a deliberate choice. If validation fails, Apply stays blocked for that input.
6. Build the plan. Review algorithms, certificate counts, metadata decisions, warnings and the exact configuration changes. Choose target/patch repairs only when the findings justify them. Apply checks for stale inputs or external edits and snapshots `keybox.xml`, `security_patch.txt` and `target.txt` before committing.
7. Confirm **Back up & apply**, then wait for completion. During a commit, let the backend finish or recover. Use **Verify** and distinguish committed files, engine health, adoption evidence and actual Wallet acceptance. Fresh attestation traffic may be needed; historical log chains do not prove adoption.
8. Test Wallet readiness and, when practical, Tap-to-Pay yourself. Local files and public-feed checks cannot establish Google acceptance, global non-revocation, issuer approval, region eligibility or successful card provisioning.

## Windows PowerShell: private import

Run `adb devices` first and confirm that the intended owned phone is the only connected device. If multiple devices are connected, add `-s YOUR_DEVICE_SERIAL` to every `adb` call. Do not post the serial in support exports.

```powershell
$localInput = Read-Host 'Absolute path to your private input XML'
& adb push $localInput '/data/local/tmp/walletdiag-input.xml'
if ($LASTEXITCODE -ne 0) { throw 'ADB push failed' }
& adb shell "su -c '/data/adb/modules/wallet_diagnostic/bin/walletdiag init'"
if ($LASTEXITCODE -ne 0) { throw 'Private state initialization failed; inspect the error first' }
& adb shell "su -c 'umask 077; test ! -L /data/adb/wallet_diagnostic/inbox/input.xml && cp /data/local/tmp/walletdiag-input.xml /data/adb/wallet_diagnostic/inbox/input.xml && chmod 600 /data/adb/wallet_diagnostic/inbox/input.xml'"
if ($LASTEXITCODE -ne 0) { throw 'Private copy failed' }
& adb shell "su -c 'rm -f /data/local/tmp/walletdiag-input.xml'"
```

The intermediate `/data/local/tmp` copy is accessible to the ADB shell user. For stricter handling, use the direct root-shell transfer described in the [advanced guide](advanced.md). The optional `/sdcard/keybox_inbox/` handoff location is less private; copying to private staging does not delete your original. Remove only the copies you explicitly intend to remove.

## If anything is interrupted

Open **Advanced → Interrupted-operation recovery → Inspect recovery journal** before starting another write. Restore the previous set through the recovery control when the journal requires it. If WebUI cannot open, use the same backend through ADB:

```powershell
& adb shell "su -c '/data/adb/modules/wallet_diagnostic/bin/walletdiag recovery'"
& adb shell "su -c '/data/adb/modules/wallet_diagnostic/bin/walletdiag help'"
```

For a completed change you want to undo, use **Backups & history** and select **Previous configuration**, a named backup, or **Last configuration with recorded verification**. Rollback first backs up the current set. App-data reset is separate, cannot be reversed by restoring configuration, and requires its own reviewed confirmation bound to a numeric Android user. Profile changes block continuation; clears and the manual GMS force-stop must target that fixed user. Its reboot and PIF action are manual; automatic PIF execution is unavailable because the installed action has unverified network mutations. See the [advanced guide](advanced.md) before choosing that workflow.

## Update and uninstall

Updates replace the installation folder and preserve private state in `/data/adb/wallet_diagnostic`. Inspect any pending recovery before updating. Uninstall preserves staged material, backups, credentials/settings if added in a future verified adapter, and journals. Previously applied TrickyStore configuration remains in effect. Explicitly roll back before uninstall if you want the previous configuration. No sensitive-state deletion or automatic backup pruning is included.

[Validation and limits](validation.md) separates offline fixtures, isolated Android tests and development device observations. An isolated test does not establish production adoption or recovery. Real configuration mutation, SELinux writes, host WebUI execution and Wallet/Tap-to-Pay require separate evidence. [Build and test](build.md) lists reproducible development commands.
