#!/bin/bash
# Deploy the stack to the device over SSH (rootless jailbreak layout).
# Usage: DEVICE=192.168.x.x ./deploy.sh
set -euo pipefail
DEVICE="${DEVICE:-192.168.191.130}"
SUDO_PASS="${SUDO_PASS:?set SUDO_PASS to the device's sudo password}"
SSH="ssh -o StrictHostKeyChecking=no mobile@$DEVICE"
SCP="scp -o StrictHostKeyChecking=no"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LDID="${LDID:-/var/containers/Bundle/Application/*/TrollStore.app/ldid}" # pick yours
ENT="$ROOT/src/wda_entitlements.plist"

echo "== 1. shim =="
$SCP "$ROOT/src/objc_shim.dylib" "mobile@$DEVICE:/var/mobile/objc_shim.dylib"
$SSH "echo "$SUDO_PASS" | sudo -S mv /var/mobile/objc_shim.dylib /var/jb/objc_shim.dylib \
  && sudo chown root:wheel /var/jb/objc_shim.dylib && sudo chmod 755 /var/jb/objc_shim.dylib \
  && sudo $LDID -S$ENT /var/jb/objc_shim.dylib"

echo "== 2. automation support bundle (preferredBackendPath target) =="
$SSH "sudo mkdir -p /var/jb/usr/lib/xctfw && sudo cp -R /var/mobile/XCTAutomationSupport.framework /var/jb/usr/lib/xctfw/"

echo "== 3. testmanagerd (from your DDI; re-sign with docs/testmanagerd_entitlements.plist) =="
$SSH "sudo mv /var/mobile/testmanagerd /var/jb/usr/libexec/testmanagerd \
  && sudo chown root:wheel /var/jb/usr/libexec/testmanagerd && sudo chmod 755 /var/jb/usr/libexec/testmanagerd \
  && sudo $LDID -S/var/mobile/tmd_ent.plist /var/jb/usr/libexec/testmanagerd \
  && sudo launchctl kickstart -k system/com.apple.testmanagerd || true"

echo "== 4. Accessibility prefs (write, flush, verify) =="
$SSH 'python3 - <<PYEOF
import plistlib
p = "/var/mobile/Library/Preferences/com.apple.Accessibility.plist"
d = plistlib.load(open(p, "rb"))
for k in ("AutomationEnabled", "IgnoreAXServerEntitlements",
          "AccessibilityEnabled", "ApplicationAccessibilityEnabled"):
    d[k] = 1
plistlib.dump(d, open(p, "wb"))
print("prefs:", {k: d[k] for k in ("AutomationEnabled", "ApplicationAccessibilityEnabled")})
PYEOF
echo "$SUDO_PASS" | sudo -S killall -9 cfprefsd; sleep 2
python3 -c "
import plistlib
d = plistlib.load(open(\"/var/mobile/Library/Preferences/com.apple.Accessibility.plist\",\"rb\"))
assert d.get(\"AutomationEnabled\") == 1, \"cfprefsd clobbered AutomationEnabled — rerun\"
print(\"verified\")"'

echo "== 5. launch runner =="
$SSH 'uiopen --bundleid com.facebook.WebDriverAgentRunner.xctrunner'
sleep 30
echo "== verify =="
$SSH 'curl -s --max-time 90 http://127.0.0.1:8100/source -o /tmp/wda_check.xml -w "HTTP %{http_code}, %{size_download} bytes\n"; head -c 300 /tmp/wda_check.xml'

cat <<'NOTE'

NOTE: the runner app itself must be installed with TrollStore (persistent
spawn) and signed with the same entitlements. SpringBoard's pid is NOT
stable across boots — the shim resolves it via the process table; if you
hardcode it anywhere, re-check after every reboot (see docs/TECHNICAL.md §2).
NOTE
