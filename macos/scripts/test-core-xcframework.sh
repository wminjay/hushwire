#!/bin/bash

set -euo pipefail

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_directory/../.." && pwd)"
framework="$repository_root/dist/HushWireCore.xcframework"
slice="$framework/macos-arm64_x86_64"

"$script_directory/build-core-xcframework.sh"

test_directory="$(mktemp -d "$repository_root/dist/hushwire-core-test.XXXXXX")"
trap 'rm -rf "$test_directory"' EXIT

swiftc \
  -I "$slice/Headers" \
  -L "$slice" \
  -lhushwire \
  -o "$test_directory/HushWireCoreSmoke" \
  "$repository_root/macos/Core/Tests/CoreABISmoke.swift"

"$test_directory/HushWireCoreSmoke"

swiftc \
  -I "$slice/Headers" \
  -L "$slice" \
  -lhushwire \
  -framework Network \
  -o "$test_directory/HushWireSystemExtensionCoreSmoke" \
  "$repository_root/macos/SystemExtension/Shared/HushWireCoreRuntime.swift" \
  "$repository_root/macos/SystemExtension/Shared/HushWireConfigurationPolicy.swift" \
  "$repository_root/macos/Core/Tests/SystemExtensionCoreSmoke.swift"

"$test_directory/HushWireSystemExtensionCoreSmoke"
