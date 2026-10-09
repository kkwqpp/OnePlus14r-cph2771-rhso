#!/system/bin/sh
# Keep private inputs, journals and backups; uninstall is not an implicit rollback.
echo 'Wallet Diagnostic removed. Previously applied TrickyStore configuration remains.'
echo 'Recovery data retained at /data/adb/wallet_diagnostic.'
echo 'Reinstall the helper to inspect backups and explicitly roll back before any state deletion.'
