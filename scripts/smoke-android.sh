#!/usr/bin/env bash
set -euo pipefail
adb wait-for-device
timeout 240 bash -c 'until [[ $(adb shell getprop sys.boot_completed | tr -d "\r") == 1 ]]; do sleep 3; done'
# Android may report boot completed while system_server is restarting.
timeout 120 bash -c '
  until adb shell cmd package path android 2>/dev/null | grep -q "^package:" &&
        adb shell input keyevent 82 >/dev/null 2>&1; do
    sleep 3
  done
'
adb shell wm dismiss-keyguard || true
echo 'Android framework is ready'
adb shell getprop ro.build.id
adb shell getprop ro.product.cpu.abilist
test "$(adb shell getprop ro.build.version.sdk | tr -d '\r')" = 37
page_size=$(adb shell getconf PAGE_SIZE | tr -d '\r')
echo "Page size: $page_size"
test "$page_size" = "${EMULATOR_PAGE:-4096}"
installed=false
for attempt in 1 2 3; do
  if adb install --no-streaming -r "$1"; then
    installed=true
    break
  fi
  sleep 10
done
test "$installed" = true
adb shell pm grant com.spstan.tgwsproxy android.permission.POST_NOTIFICATIONS

activity=com.spstan.tgwsproxy/com.amurcanov.tgwsproxy.MainActivity
adb logcat -c
adb shell am start -W -n "$activity"

tap_labeled() {
  python3 - "$1" <<'PY'
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

def adb(*args):
    return subprocess.check_output(["adb", "shell", *args], timeout=18)

for _ in range(8):
    try:
        adb("uiautomator", "dump", "/sdcard/proxy-smoke.xml")
        root = ET.fromstring(adb("cat", "/sdcard/proxy-smoke.xml"))
    except (subprocess.SubprocessError, ET.ParseError):
        continue
    for node in root.iter("node"):
        if node.get("clickable") != "true":
            continue
        if any(re.fullmatch(sys.argv[1], value, re.I)
               for candidate in node.iter("node")
               for value in [candidate.get("text", ""), candidate.get("content-desc", "")]):
            x1, y1, x2, y2 = map(int, re.findall(r"\d+", node.get("bounds", "")))
            adb("input", "tap", str((x1+x2)//2), str((y1+y2)//2))
            quit()
    time.sleep(2)
raise SystemExit("UI control not found: " + sys.argv[1])
PY
}

wait_log() {
  local tag=$1 needle=$2
  for _ in {1..20}; do
    if adb logcat -d -s "$tag" | grep -F "$needle" >/dev/null; then return; fi
    sleep 2
  done
  adb logcat -d -s ProxyService TgWsProxy AndroidRuntime
  return 1
}

tap_labeled 'Start proxy|Запустить прокси'
wait_log ProxyService 'Proxy ready: listening on port 1443'
wait_log TgWsProxy 'CF WebSocket transport: WSS :443'
adb shell dumpsys activity services com.spstan.tgwsproxy | grep -F 'isForeground=true'
tap_labeled 'Stop proxy|Остановить прокси'
wait_log TgWsProxy 'StopProxy: done'

echo 'Started and stopped with default WSS'
tap_labeled 'Settings|Настройки'
tap_labeled 'Disable TLS for CF proxy and CF Worker|Выключить TLS для CF-прокси и CF-worker'
sleep 2
adb shell am force-stop com.spstan.tgwsproxy
adb logcat -c
adb shell am start -W -n "$activity"
tap_labeled 'Start proxy|Запустить прокси'
wait_log ProxyService 'Proxy ready: listening on port 1443'
wait_log TgWsProxy 'CF WebSocket transport: WS :80'
tap_labeled 'Stop proxy|Остановить прокси'
wait_log TgWsProxy 'StopProxy: done'
echo 'Cleartext WS preference survived a process restart'
