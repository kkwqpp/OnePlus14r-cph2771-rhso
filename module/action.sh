#!/system/bin/sh
# Verified upstream standalone WebUI activity. Never guess the randomized manager package.
MODDIR=${0%/*}
ACTIVITY=io.github.a13e300.ksuwebui/.WebUIActivity
if command -v cmd >/dev/null 2>&1; then
  resolved=$(cmd package resolve-activity --brief -n "$ACTIVITY" 2>/dev/null)
  case "$resolved" in
    *io.github.a13e300.ksuwebui/*WebUIActivity*)
      if am start -n "$ACTIVITY" --es id wallet_diagnostic --es name 'RHSO' >/dev/null 2>&1; then
        echo 'Opened RHSO WebUI.'
        exit 0
      fi
      ;;
  esac
fi
echo 'WebUI could not be opened. Open the module WebUI from your installed manager.'
echo 'Read-only status follows; this action does not import, apply, reset or reboot.'
if [ -x "$MODDIR/bin/walletdiag" ]; then
  "$MODDIR/bin/walletdiag" status
else
  echo 'Backend missing. Reinstall the complete module ZIP; Apply is unavailable.'
fi
echo 'Exact CLI entry point: /data/adb/modules/wallet_diagnostic/bin/walletdiag help'
