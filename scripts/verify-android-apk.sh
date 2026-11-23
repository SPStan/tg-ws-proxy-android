#!/usr/bin/env bash
set -euo pipefail

apk=$1
tools="$ANDROID_HOME/build-tools/36.0.0"
"$tools/apksigner" verify --print-certs "$apk"
"$tools/zipalign" -c -P 16 4 "$apk"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
unzip -q "$apk" 'lib/arm64-v8a/*.so' -d "$tmp"
test -f "$tmp/lib/arm64-v8a/libtgwsproxy.so"
test -f "$tmp/lib/arm64-v8a/libjnidispatch.so"
objdump="$ANDROID_HOME/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objdump"
for so in "$tmp"/lib/arm64-v8a/*.so; do
  echo "${so##*/}"
  "$objdump" -p "$so" | awk '/LOAD/ {
    print
    n++
    if (substr($NF,1,3) != "2**" || substr($NF,4)+0 < 14) bad=1
  } END { exit (!n || bad) }'
done
(cd "$(dirname "$apk")"; sha256sum "$(basename "$apk")") | tee "$apk.sha256"
