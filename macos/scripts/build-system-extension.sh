#!/bin/bash

set -euo pipefail

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_directory/../.." && pwd)"
signing_mode="${HUSHWIRE_SIGNING:-unsigned}"

case "$signing_mode" in
  unsigned)
    derived_data="$repository_root/dist/DerivedData/HushWireSystem"
    signing_arguments=(CODE_SIGNING_ALLOWED=NO)
    ;;
  development)
    derived_data="$repository_root/dist/DerivedData/HushWireSystemSigned"
    signing_arguments=(-allowProvisioningUpdates -allowProvisioningDeviceRegistration)
    ;;
  *)
    echo "HUSHWIRE_SIGNING must be 'unsigned' or 'development'" >&2
    exit 64
    ;;
esac

"$script_directory/generate-system-extension-project.sh"

xcodebuild \
  -project "$repository_root/macos/HushWireSystem.xcodeproj" \
  -scheme HushWireSystem \
  -configuration Debug \
  -derivedDataPath "$derived_data" \
  -quiet \
  "${signing_arguments[@]}" \
  build

app="$derived_data/Build/Products/Debug/HushWire.app"
extension="$app/Contents/Library/SystemExtensions/com.jamie.HushWire.PacketTunnel.systemextension"

test -d "$app"
test -d "$extension"

if [[ "$signing_mode" == development ]]; then
  codesign --verify --deep --strict "$app"
  echo "Built development-signed lifecycle skeleton: $app"
else
  echo "Built unsigned lifecycle skeleton: $app"
fi
echo "No System Extension was installed or activated."
