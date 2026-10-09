# Owner-authorized keybox and Wallet reset trial

This record supersedes earlier statements that no live Apply or reset occurred. Times are UTC on 2026-10-09. Private keys, keyboxes, certificate identifiers, configuration digests and recovery IDs are omitted.

The owner explicitly supplied an owned ECDSA keybox and authorized using it through the helper. At 18:51, the module's existing validation, public-feed review, Plan and Apply workflow replaced only active `keybox.xml`. The original configuration set has a named private backup on the phone. Byte and metadata readback passed, and one verified TrickyStore engine remained healthy. Signer adoption and payment acceptance were not established.

The owner subsequently requested the reset ritual. At 18:54, the module completed five successful clears for numeric Android user 0: Wallet, Play Store, Google Services Framework, then Google Play services twice. The repeated GMS clear follows the requested sequence; its technical rationale remains unverified. App-data clearing is irreversible and is not restored by configuration backups.

The owner rebooted manually. Resume verified a new boot, the same numeric user and the reviewed scripts, then stopped at the deliberate manual PIF boundary. No clears were repeated when USB debugging was restored.

At 19:29, the installed PIF action and its transitive shell dependencies were reviewed and hash checked. A separate root-private snapshot saved affected PIF files, existing backup files, scratch data and active TrickyStore configuration. The operator ran the installed action once with a bounded timeout. Its exit status and actual output were checked separately: required PIF fields existed, the TrickyStore patch matched PIF, all seven advanced flags remained unchanged, keybox and target bytes were unchanged, and TrickyStore ownership, modes, SELinux contexts and the two protected boot properties were preserved. GMS was then force-stopped explicitly for user 0. The module recorded reset completion at 19:29:54.

The active material still validated as ECDSA-only after this trial. A later owner reference to RSA does not establish an observed RSA selection. Earlier BASIC/DEVICE/STRONG passes predate this reset and must not be treated as fresh post-reset evidence.

The PIF fingerprint and patch changed as part of the separately authorized ritual. That invalidates earlier configuration-bound verification. Fresh Status and Diagnose succeeded after completion; a fresh private card-setup attempt and an actual terminal payment remain required. Neither successful file adoption nor a completed ritual proves Wallet eligibility.

Keep both the named original keybox backup and the later reset-preparation backup. The latter contains the newly applied keybox, so `previous` is not a reliable synonym for the original keybox backup. Do not repeat app-data clearing automatically or remove recovery data.

Google's current [Wallet security guidance](https://support.google.com/wallet/answer/12200245?hl=en) lists rooted, modified and unlocked devices among unsupported configurations. This explains why a separate checker pass cannot establish Wallet acceptance; it does not identify the precise failing signal on this phone. The owner's bootloader and partition safety boundaries remain in force.
