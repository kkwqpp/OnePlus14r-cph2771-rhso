# First use

The steps below preserve the earlier Go interface and installation guidance. The current Rust candidate uses a guided overview and simpler labels; start with the [Rust WebUI guide](rust-ui.md) and [current validation](validation.md). Real Android installation and host compatibility remain pending for Rust.

This helper is for the owned rooted OnePlus 15R and the existing TrickyStore stack. The real bootloader remains unlocked. The module has no partition writer, attestation engine, automatic rotation, reboot, or boot-time configuration changes. A reported “device doesn’t meet security requirements” immediately after entering the card number is a card-setup rejection; Wallet acceptance and Tap-to-Pay still require an actual user check.

1. Keep the module ZIP and its SHA-256 file on the PC. Verify the download against the supplied package hash. Install the ZIP through the existing KernelSU manager; no custom recovery installation is supported. Fresh installation preserves the active TrickyStore/PIF files. Do not change other modules to make the helper run.
2. Open **RHSO → WebUI**, or use the module action. The module ID remains `wallet_diagnostic` for updates. The action opens the installed standalone WebUI when the verified activity is available; otherwise it prints status and the exact CLI entry point. A randomized manager package is never assumed.
   If the host shows **Please grant root** or keeps loading, grant KernelSU root to **KsuWebUI** (`io.github.a13e300.ksuwebui`), open its main screen, then reopen the helper. A launched activity alone does not confirm a working dashboard; the harmless Status result must display **Complete · OK**. CLI remains available while the host permission is missing.
3. Tap **Collect diagnostics** before importing anything. Separate confirmed findings from hypotheses. Missing RSA is a hypothesis to test, not a proven explanation of the Wallet failure. The original API endpoint remains unavailable; a separately configured generic raw-XML source can stage authorized material. See [RHSO controls](rhso.md) for private configuration and selected HMA/BreZygisk settings.
   Use **Google public attestation evidence → Fetch Google public feeds (GET)** for an explicit network check. It downloads whole public feeds and compares the chain locally; no keybox or serial is uploaded. An unlisted Google-anchored chain is a limited result, not proof that Wallet accepts the phone.
4. Copy material you own or are authorized to use into the private inbox using the example below. Enter `/data/adb/wallet_diagnostic/inbox/input.xml` in **Import & review**. Keys and complete keyboxes must remain private; do not paste them into the UI, chats, screenshots or issue reports.
5. Import and validate each needed input. Select the exact Keybox and key for each chosen algorithm. A merged replacement contains only the algorithms you select; use **Import current active keybox** and select its entry to retain an existing algorithm. The helper keeps the selected private key with its whole associated certificate chain. Conflicting entries require a deliberate choice. If validation fails, Apply stays blocked for that input.
6. Build the plan. Review algorithms, certificate counts, metadata decisions, warnings and the exact configuration changes. Choose target/patch repairs only when the findings justify them. Apply checks for stale inputs or external edits and snapshots `keybox.xml`, `security_patch.txt` and `target.txt` before committing.
7. Confirm **Back up & apply**, then wait for completion. During a commit, let the backend finish or recover. Use **Verify** and distinguish committed files, engine health, adoption evidence and actual Wallet acceptance. Fresh attestation traffic may be needed; historical log chains do not prove adoption.
8. Test Wallet readiness and, when practical, Tap-to-Pay yourself. The helper cannot establish Google acceptance, remote revocation status, issuer approval, region eligibility or card provisioning merely from local files.

## Windows PowerShell: private import

Run `adb devices` first and confirm that the intended owned phone is the only connected device. If multiple devices are connected, add `-s YOUR_DEVICE_SERIAL` to every `adb` call. Do not post the serial in support exports.

```powershell
$localInput = 'C:\Private\input.xml'
& adb push $localInput '/data/local/tmp/walletdiag-input.xml'
if ($LASTEXITCODE -ne 0) { throw 'ADB push failed' }
& adb shell "su -c '/data/adb/modules/wallet_diagnostic/bin/walletdiag init'"
if ($LASTEXITCODE -ne 0) { throw 'Private state initialization failed; inspect the error first' }
& adb shell "su -c 'umask 077; test ! -L /data/adb/wallet_diagnostic/inbox/input.xml && cp /data/local/tmp/walletdiag-input.xml /data/adb/wallet_diagnostic/inbox/input.xml && chmod 600 /data/adb/wallet_diagnostic/inbox/input.xml'"
if ($LASTEXITCODE -ne 0) { throw 'Private copy failed' }
& adb shell "su -c 'rm -f /data/local/tmp/walletdiag-input.xml'"
```

The intermediate `/data/local/tmp` copy is accessible to the ADB shell user. For stricter handling, use the direct root-shell transfer described in the advanced guide. The optional `/sdcard/keybox_inbox/` handoff location is less private; copying to private staging does not delete your original. Remove only the copies you explicitly intend to remove.

## If anything is interrupted

Open **Advanced → Interrupted-operation recovery → Inspect recovery journal** before starting another write. Restore the previous set through the recovery control when the journal requires it. If WebUI cannot open, use the same backend through ADB:

```powershell
& adb shell "su -c '/data/adb/modules/wallet_diagnostic/bin/walletdiag recovery'"
& adb shell "su -c '/data/adb/modules/wallet_diagnostic/bin/walletdiag help'"
```

For a completed change you want to undo, use **Backups & history** and select **Previous configuration**, a named backup, or **Last configuration with recorded verification**. Rollback first backs up the current set. App-data reset is separate, cannot be reversed by restoring configuration, and requires its own reviewed confirmation bound to a numeric Android user. Profile changes block continuation; clears and the manual GMS force-stop must target that fixed user. Its reboot and PIF action are manual; automatic PIF execution is unavailable because the installed action has unverified network mutations. See the advanced guide before choosing that workflow.

## Update and uninstall

Updates replace the installation folder and preserve private state in `/data/adb/wallet_diagnostic`. Inspect any pending keybox or stack recovery before updating. Uninstall preserves staged material, backups, private source credentials/settings and journals. Previously applied TrickyStore and hiding settings remain in effect. Explicitly roll back each relevant transaction before uninstall if you want its previous configuration. No sensitive-state deletion or automatic backup pruning is included.

The test report separates PC offline checks, isolated Android sandbox tests, read-only active configuration inspection, installed-code compatibility evidence and any real WebUI test. A phone sandbox test does not establish production adoption or recovery. Real active-set mutation, SELinux writes, host WebUI execution and Wallet/Tap-to-Pay must be identified separately; consult the report for the actual completed checks and remaining limitations.
