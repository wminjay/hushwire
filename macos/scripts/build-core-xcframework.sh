#!/bin/bash

set -euo pipefail

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_directory/../.." && pwd)"
headers="$repository_root/macos/Core/include"
output="${HUSHWIRE_CORE_OUTPUT:-$repository_root/dist/HushWireCore.xcframework}"

if [[ "$output" != /* ]]; then
  output="$repository_root/$output"
fi

case "$output" in
  "$repository_root/dist/"*) ;;
  *)
    echo "HUSHWIRE_CORE_OUTPUT must stay below $repository_root/dist" >&2
    exit 64
    ;;
esac

if [[ "$output" == *"/../"* || "$output" == */.. ]]; then
  echo "HUSHWIRE_CORE_OUTPUT must not contain parent-directory traversal" >&2
  exit 64
fi

required_targets=(aarch64-apple-darwin x86_64-apple-darwin)
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

arm64_library="$repository_root/target/aarch64-apple-darwin/release/libhushwire.a"
x86_64_library="$repository_root/target/x86_64-apple-darwin/release/libhushwire.a"
mkdir -p "$repository_root/dist"
build_directory="$(mktemp -d "$repository_root/dist/hushwire-core.XXXXXX")"
trap 'rm -rf "$build_directory"' EXIT
universal_library="$build_directory/libhushwire.a"

lipo -create "$arm64_library" "$x86_64_library" -output "$universal_library"

rm -rf "$output"
mkdir -p "$(dirname "$output")"
xcodebuild -create-xcframework \
  -library "$universal_library" -headers "$headers" \
  -output "$output"

echo "Created $output"
