#!/bin/bash

set -euo pipefail

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_directory/../.." && pwd)"
headers="$repository_root/macos/Core/include"
output="${HUSHWIRE_IOS_CORE_OUTPUT:-$repository_root/dist/HushWireCore-iOS.xcframework}"

if [[ "$output" != /* ]]; then
  output="$repository_root/$output"
fi

case "$output" in
  "$repository_root/dist/"*) ;;
  *)
    echo "HUSHWIRE_IOS_CORE_OUTPUT must stay below $repository_root/dist" >&2
    exit 64
    ;;
esac

if [[ "$output" == *"/../"* || "$output" == */.. ]]; then
  echo "HUSHWIRE_IOS_CORE_OUTPUT must not contain parent-directory traversal" >&2
  exit 64
fi

required_targets=(
  aarch64-apple-ios
  aarch64-apple-ios-sim
  x86_64-apple-ios
)
installed_targets="$(rustup target list --installed)"
for target in "${required_targets[@]}"; do
  if ! grep -qx "$target" <<<"$installed_targets"; then
    echo "Missing Rust target $target; install it with: rustup target add $target" >&2
    exit 69
  fi
done

cd "$repository_root"
for target in "${required_targets[@]}"; do
  cargo build --release --lib --target "$target"
done

device_library="$repository_root/target/aarch64-apple-ios/release/libhushwire.a"
simulator_arm64_library="$repository_root/target/aarch64-apple-ios-sim/release/libhushwire.a"
simulator_x86_64_library="$repository_root/target/x86_64-apple-ios/release/libhushwire.a"

mkdir -p "$repository_root/dist"
build_directory="$(mktemp -d "$repository_root/dist/hushwire-ios-core.XXXXXX")"
trap 'rm -rf "$build_directory"' EXIT
simulator_library="$build_directory/libhushwire.a"

lipo -create \
  "$simulator_arm64_library" \
  "$simulator_x86_64_library" \
  -output "$simulator_library"

if [[ -e "$output" ]]; then
  rm -rf "$output"
fi
mkdir -p "$(dirname "$output")"
xcodebuild -create-xcframework \
  -library "$device_library" -headers "$headers" \
  -library "$simulator_library" -headers "$headers" \
  -output "$output"

echo "Created $output"
