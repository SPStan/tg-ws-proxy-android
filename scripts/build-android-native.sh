#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

case "${1:-arm64-v8a}" in
  arm64-v8a)
    abi=arm64-v8a; target=aarch64-linux-android; clang=aarch64-linux-android24-clang
    ;;
  armeabi-v7a)
    abi=armeabi-v7a; target=armv7-linux-androideabi; clang=armv7a-linux-androideabi21-clang
    ;;
  x86_64)
    abi=x86_64; target=x86_64-linux-android; clang=x86_64-linux-android24-clang
    ;;
  *) echo "Supported ABIs: arm64-v8a, armeabi-v7a, x86_64" >&2; exit 2 ;;
esac

sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:?Set ANDROID_HOME or ANDROID_SDK_ROOT}}
ndk="$sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/bin"
cargo_target=${target//-/_}
env "CARGO_TARGET_${cargo_target^^}_LINKER=$ndk/$clang" \
    "CC_${cargo_target}=$ndk/$clang" "AR_${cargo_target}=$ndk/llvm-ar" \
    RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384" \
    cargo +1.95.0 build --locked --release --target "$target"
install -D "target/$target/release/libtgwsproxy.so" "app/src/main/jniLibs/$abi/libtgwsproxy.so"
