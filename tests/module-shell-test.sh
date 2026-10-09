#!/usr/bin/env bash
set -euo pipefail
# Offline installer/action preservation test. Every Android command is an inert stub.
cd "$(dirname "$0")/.."
for script in module/customize.sh module/action.sh module/uninstall.sh; do bash -n "$script"; done
mkdir -p build
fixture_root=$(cd build && pwd -P)
fixture=$(mktemp -d "$fixture_root/module-shell-fixture-XXXXXX")
fixture=$(cd "$fixture" && pwd -P)
case "$fixture" in "$fixture_root"/module-shell-fixture-*) ;; *) echo 'Unsafe fixture cleanup path' >&2; exit 1 ;; esac
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/module/bin" "$fixture/stubs" "$fixture/private/backups"
cp module/customize.sh module/action.sh module/uninstall.sh "$fixture/module/"
printf 'keep\n' > "$fixture/private/backups/retained"
cat > "$fixture/module/bin/walletdiag" <<'SH'
#!/usr/bin/env bash
[ "$*" = 'status' ] || exit 90
echo STATUS_BACKEND_REACHED
SH
cat > "$fixture/stubs/cmd" <<'SH'
#!/usr/bin/env bash
[ "$*" = 'package resolve-activity --brief -n io.github.a13e300.ksuwebui/.WebUIActivity' ] || exit 91
if [ "${MOCK_WEBUI_AVAILABLE:-no}" = yes ]; then
  echo io.github.a13e300.ksuwebui/io.github.a13e300.ksuwebui.WebUIActivity
else
  exit 1
fi
SH
cat > "$fixture/stubs/am" <<'SH'
#!/usr/bin/env bash
[ "$*" = 'start -n io.github.a13e300.ksuwebui/.WebUIActivity --es id wallet_diagnostic --es name RHSO' ] || exit 92
printf '%s\n' "$*" > "$MOCK_ACTION_LOG"
SH
chmod +x "$fixture/module/bin/walletdiag" "$fixture/stubs/cmd" "$fixture/stubs/am"
export PATH="$fixture/stubs:$PATH" MOCK_ACTION_LOG="$fixture/launched"
output=$(MOCK_WEBUI_AVAILABLE=no bash "$fixture/module/action.sh")
[[ "$output" == *STATUS_BACKEND_REACHED* ]]
[[ "$output" == *'/data/adb/modules/wallet_diagnostic/bin/walletdiag help'* ]]
[[ ! -f "$fixture/launched" ]]
MOCK_WEBUI_AVAILABLE=yes bash "$fixture/module/action.sh" >/dev/null
[[ -f "$fixture/launched" ]]
# Installer sourcing only sets executable module paths; no private/active state operation.
export ARCH=arm64 MODPATH="$fixture/module"
ui_print(){ :; }
abort(){ echo "unexpected installer abort: $*" >&2; return 1; }
set_perm(){ [[ "$1" == "$MODPATH/"* ]] || return 1; printf '%s\n' "$1" >> "$fixture/permissions"; }
export -f ui_print abort set_perm
source "$fixture/module/customize.sh"
[[ $(wc -l < "$fixture/permissions") -eq 3 ]]
bash "$fixture/module/uninstall.sh" >/dev/null
[[ $(cat "$fixture/private/backups/retained") == keep ]]
echo 'PASS: shell syntax, fixed standalone launch, status/CLI fallback, module-only installer permissions, uninstall retention.'
