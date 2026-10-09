#!/system/bin/sh
# KernelSU sources this installer after extraction. No active configuration writes.
[ "$ARCH" = "arm64" ] || abort "RHSO requires an arm64 device."
[ -f "$MODPATH/bin/walletdiag" ] || abort "Required validation backend is missing."
set_perm "$MODPATH/bin/walletdiag" 0 0 0755
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
# KernelSU sets WebUI permissions and contexts; do not override them.
# Private state is initialized and checked by the backend when explicitly invoked.
ui_print "RHSO installed. Active TrickyStore/PIF and hiding settings unchanged."
ui_print "Open WebUI or run /data/adb/modules/wallet_diagnostic/bin/walletdiag help"
ui_print "Updates preserve /data/adb/wallet_diagnostic. Recovery data is retained on uninstall."
