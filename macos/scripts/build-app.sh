#!/bin/zsh

set -euo pipefail

script_directory="${0:A:h}"
macos_directory="${script_directory:h}"
repository_root="${macos_directory:h}"
output_directory="${repository_root}/dist"
application_path="${output_directory}/HushWire.app"
rust_target="${HUSHWIRE_RUST_TARGET:-}"
swift_architecture="${HUSHWIRE_SWIFT_ARCH:-}"

if [[ -n "$rust_target" && -z "$swift_architecture" ]] \
    || [[ -z "$rust_target" && -n "$swift_architecture" ]]; then
    print -u2 -- "HUSHWIRE_RUST_TARGET and HUSHWIRE_SWIFT_ARCH must be set together"
    exit 2
fi

case "$application_path" in
    "${repository_root}/dist/HushWire.app") ;;
    *)
        print -u2 -- "Refusing to replace unexpected application path: $application_path"
        exit 1
        ;;
esac

print -- "Building the Rust tunnel core…"
if [[ -n "$rust_target" ]]; then
    cargo build --manifest-path "${repository_root}/Cargo.toml" --release --target "$rust_target"
    rust_binary_path="${repository_root}/target/${rust_target}/release/hushwire"
else
    cargo build --manifest-path "${repository_root}/Cargo.toml" --release
    rust_binary_path="${repository_root}/target/release/hushwire"
fi

print -- "Building the SwiftUI client…"
swift_build_arguments=(
    --package-path "$macos_directory"
    --configuration release
)
if [[ -n "$swift_architecture" ]]; then
    swift_build_arguments+=(--arch "$swift_architecture")
fi
swift build "${swift_build_arguments[@]}" --product HushWireMac
swift_binary_directory="$(swift build "${swift_build_arguments[@]}" --show-bin-path)"

print -- "Assembling HushWire.app…"
/bin/mkdir -p "$output_directory"
/bin/rm -rf "$application_path"
/bin/mkdir -p \
    "${application_path}/Contents/MacOS" \
    "${application_path}/Contents/Resources/bin"

/usr/bin/ditto "${swift_binary_directory}/HushWireMac" "${application_path}/Contents/MacOS/HushWire"
/usr/bin/ditto "$rust_binary_path" "${application_path}/Contents/Resources/bin/hushwire"
/usr/bin/ditto "${macos_directory}/Resources/hushwire-control" "${application_path}/Contents/Resources/bin/hushwire-control"
/usr/bin/ditto "${macos_directory}/Resources/Info.plist" "${application_path}/Contents/Info.plist"

/bin/chmod 0755 \
    "${application_path}/Contents/MacOS/HushWire" \
    "${application_path}/Contents/Resources/bin/hushwire" \
    "${application_path}/Contents/Resources/bin/hushwire-control"

print -- "Applying an ad-hoc signature for local use…"
/usr/bin/codesign --force --deep --sign - "$application_path"
/usr/bin/codesign --verify --deep --strict "$application_path"

print -- "Built: $application_path"
print -- "Open it with: open '$application_path'"
