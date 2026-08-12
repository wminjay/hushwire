#!/bin/bash

set -euo pipefail

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_directory/../.." && pwd)"
team_id="95Q852BXKJ"
app_bundle_id="com.jamie.HushWire"
extension_bundle_id="com.jamie.HushWire.PacketTunnel"
app_group_id="$team_id.$app_bundle_id.shared"
extension_mach_service="$app_group_id.PacketTunnel"
app_entitlements="$repository_root/macos/SystemExtension/App/HushWire.direct.entitlements"
extension_entitlements="$repository_root/macos/SystemExtension/PacketTunnel/HushWirePacketTunnel.direct.entitlements"
extension_info_plist="$repository_root/macos/SystemExtension/PacketTunnel/Info.plist"
app_profile="${HUSHWIRE_DEVELOPER_ID_APP_PROFILE:-}"
extension_profile="${HUSHWIRE_DEVELOPER_ID_EXTENSION_PROFILE:-}"
signing_identity="${HUSHWIRE_DEVELOPER_ID_IDENTITY:-}"
notary_key="${HUSHWIRE_ASC_KEY_PATH:-}"
notary_key_id="${HUSHWIRE_ASC_KEY_ID:-}"
notary_issuer="${HUSHWIRE_ASC_ISSUER_ID:-}"
check_only=false

if [[ "${1:-}" == "--check-prerequisites" ]]; then
  check_only=true
elif [[ $# -ne 0 ]]; then
  echo "Usage: $0 [--check-prerequisites]" >&2
  exit 64
fi

release_output="${HUSHWIRE_RELEASE_OUTPUT_DIRECTORY:-$repository_root/dist/release}"
if [[ "$release_output" != /* ]]; then
  release_output="$repository_root/$release_output"
fi
case "$release_output" in
  "$repository_root/dist" | "$repository_root/dist/"*) ;;
  *)
    echo "HUSHWIRE_RELEASE_OUTPUT_DIRECTORY must stay below $repository_root/dist" >&2
    exit 64
    ;;
esac
if [[ "$release_output" == *"/../"* || "$release_output" == */.. ]]; then
  echo "HUSHWIRE_RELEASE_OUTPUT_DIRECTORY must not contain parent-directory traversal" >&2
  exit 64
fi

required_commands=(codesign ditto plutil security shasum spctl xcodebuild xcodegen xcrun)
for command_name in "${required_commands[@]}"; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required command: $command_name" >&2
    exit 69
  fi
done

required_variables=(
  HUSHWIRE_DEVELOPER_ID_APP_PROFILE
  HUSHWIRE_DEVELOPER_ID_EXTENSION_PROFILE
  HUSHWIRE_ASC_KEY_PATH
  HUSHWIRE_ASC_KEY_ID
  HUSHWIRE_ASC_ISSUER_ID
)
for variable_name in "${required_variables[@]}"; do
  if [[ -z "${!variable_name:-}" ]]; then
    echo "Missing required environment variable: $variable_name" >&2
    exit 64
  fi
done

for input_file in "$app_profile" "$extension_profile" "$notary_key"; do
  if [[ ! -f "$input_file" ]]; then
    echo "Required input file does not exist: $input_file" >&2
    exit 66
  fi
done

if [[ -z "$signing_identity" ]]; then
  developer_id_identities="$(
    security find-identity -v -p codesigning \
      | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p'
  )"
  identity_count="$(printf '%s\n' "$developer_id_identities" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [[ "$identity_count" != "1" ]]; then
    echo "Expected exactly one Developer ID Application identity; set HUSHWIRE_DEVELOPER_ID_IDENTITY explicitly" >&2
    exit 78
  fi
  signing_identity="$developer_id_identities"
fi
case "$signing_identity" in
  "Developer ID Application:"*) ;;
  *)
    echo "Signing identity must be a Developer ID Application identity: $signing_identity" >&2
    exit 78
    ;;
esac
if ! security find-identity -v -p codesigning | grep -Fq "\"$signing_identity\""; then
  echo "Developer ID signing identity is not available in the keychain: $signing_identity" >&2
  exit 78
fi

plutil -lint "$app_entitlements" "$extension_entitlements" >/dev/null
for entitlements in "$app_entitlements" "$extension_entitlements"; do
  network_entitlement="$(
    /usr/libexec/PlistBuddy \
      -c "Print :com.apple.developer.networking.networkextension" \
      "$entitlements"
  )"
  if [[ "$network_entitlement" != *"packet-tunnel-provider-systemextension"* ]]; then
    echo "Direct-distribution entitlement is missing from $entitlements" >&2
    exit 78
  fi
  application_groups="$(
    /usr/libexec/PlistBuddy \
      -c "Print :com.apple.security.application-groups" \
      "$entitlements"
  )"
  if [[ "$application_groups" != *"$app_group_id"* ]]; then
    echo "Direct-distribution App Group is missing from $entitlements" >&2
    exit 78
  fi
  if /usr/libexec/PlistBuddy \
      -c "Print :com.apple.security.get-task-allow" \
      "$entitlements" >/dev/null 2>&1; then
    echo "Release entitlements must not contain get-task-allow: $entitlements" >&2
    exit 78
  fi
done

configured_mach_service="$(
  plutil -extract NetworkExtension.NEMachServiceName raw -o - \
    "$extension_info_plist"
)"
if [[ "$configured_mach_service" != "$extension_mach_service" ]]; then
  echo "NEMachServiceName must be prefixed by the direct-distribution App Group" >&2
  echo "Expected $extension_mach_service, found $configured_mach_service" >&2
  exit 78
fi

mkdir -p "$repository_root/dist" "$release_output"
working_directory="$(mktemp -d "$repository_root/dist/hushwire-developer-id.XXXXXX")"
trap 'rm -rf "$working_directory"' EXIT

decode_profile() {
  local source_profile="$1"
  local decoded_profile="$2"
  security cms -D -i "$source_profile" -o "$decoded_profile"
}

profile_value() {
  local decoded_profile="$1"
  local key_path="$2"
  /usr/libexec/PlistBuddy -c "Print :$key_path" "$decoded_profile"
}

validate_profile() {
  local source_profile="$1"
  local decoded_profile="$2"
  local expected_bundle_id="$3"
  local require_system_extension_install="$4"

  decode_profile "$source_profile" "$decoded_profile"

  local application_identifier
  application_identifier="$(profile_value "$decoded_profile" "Entitlements:com.apple.application-identifier")"
  if [[ "$application_identifier" != "$team_id.$expected_bundle_id" ]]; then
    echo "Profile $source_profile is for $application_identifier, expected $team_id.$expected_bundle_id" >&2
    exit 78
  fi

  if [[ "$(profile_value "$decoded_profile" "ProvisionsAllDevices")" != "true" ]]; then
    echo "Profile is not a Developer ID direct-distribution profile: $source_profile" >&2
    exit 78
  fi

  local network_entitlements
  network_entitlements="$(profile_value "$decoded_profile" "Entitlements:com.apple.developer.networking.networkextension")"
  if [[ "$network_entitlements" != *"packet-tunnel-provider-systemextension"* ]]; then
    echo "Profile does not authorize packet-tunnel-provider-systemextension: $source_profile" >&2
    exit 78
  fi

  if [[ "$require_system_extension_install" == "true" ]] \
      && [[ "$(profile_value "$decoded_profile" "Entitlements:com.apple.developer.system-extension.install")" != "true" ]]; then
    echo "Container profile does not authorize System Extension installation: $source_profile" >&2
    exit 78
  fi
}

app_profile_plist="$working_directory/app-profile.plist"
extension_profile_plist="$working_directory/extension-profile.plist"
validate_profile "$app_profile" "$app_profile_plist" "$app_bundle_id" true
validate_profile "$extension_profile" "$extension_profile_plist" "$extension_bundle_id" false

xcrun notarytool history \
  --key "$notary_key" \
  --key-id "$notary_key_id" \
  --issuer "$notary_issuer" \
  --output-format json >/dev/null

if [[ "$check_only" == true ]]; then
  echo "Developer ID signing, profiles, entitlements, and notarization credentials are ready."
  exit 0
fi

"$script_directory/generate-system-extension-project.sh"

derived_data="$working_directory/DerivedData"
xcodebuild \
  -project "$repository_root/macos/HushWireSystem.xcodeproj" \
  -scheme HushWireSystem \
  -configuration Release \
  -derivedDataPath "$derived_data" \
  ARCHS="arm64 x86_64" \
  ONLY_ACTIVE_ARCH=NO \
  CODE_SIGNING_ALLOWED=NO \
  clean build

unsigned_app="$derived_data/Build/Products/Release/HushWire.app"
staged_app="$working_directory/HushWire.app"
ditto "$unsigned_app" "$staged_app"

staged_extension="$staged_app/Contents/Library/SystemExtensions/$extension_bundle_id.systemextension"
test -d "$staged_extension"
packaged_mach_service="$(
  plutil -extract NetworkExtension.NEMachServiceName raw -o - \
    "$staged_extension/Contents/Info.plist"
)"
if [[ "$packaged_mach_service" != "$extension_mach_service" ]]; then
  echo "Packaged System Extension has an invalid NEMachServiceName: $packaged_mach_service" >&2
  exit 78
fi
ditto "$app_profile" "$staged_app/Contents/embedded.provisionprofile"
ditto "$extension_profile" "$staged_extension/Contents/embedded.provisionprofile"
chmod 0644 \
  "$staged_app/Contents/embedded.provisionprofile" \
  "$staged_extension/Contents/embedded.provisionprofile"

codesign \
  --force \
  --sign "$signing_identity" \
  --entitlements "$extension_entitlements" \
  --options runtime \
  --timestamp \
  "$staged_extension"
codesign \
  --force \
  --sign "$signing_identity" \
  --entitlements "$app_entitlements" \
  --options runtime \
  --timestamp \
  "$staged_app"

codesign --verify --deep --strict --verbose=2 "$staged_app"
codesign -d --entitlements :- "$staged_app" \
  >"$working_directory/app-signed.entitlements"
codesign -d --entitlements :- "$staged_extension" \
  >"$working_directory/extension-signed.entitlements"
for signed_entitlements in \
    "$working_directory/app-signed.entitlements" \
    "$working_directory/extension-signed.entitlements"; do
  signed_network_entitlement="$(
    /usr/libexec/PlistBuddy \
      -c "Print :com.apple.developer.networking.networkextension" \
      "$signed_entitlements"
  )"
  if [[ "$signed_network_entitlement" != *"packet-tunnel-provider-systemextension"* ]]; then
    echo "Signed product lost its direct-distribution Network Extension entitlement" >&2
    exit 78
  fi
done
for signed_bundle in "$staged_extension" "$staged_app"; do
  signature_details="$(codesign -dvv "$signed_bundle" 2>&1)"
  case "$signature_details" in
    *"flags="*"runtime"*) ;;
    *)
      echo "Signed bundle is missing Hardened Runtime: $signed_bundle" >&2
      exit 78
      ;;
  esac
done

lipo "$staged_app/Contents/MacOS/HushWire" -verify_arch arm64 x86_64
lipo "$staged_extension/Contents/MacOS/HushWirePacketTunnel" \
  -verify_arch arm64 x86_64

version="$(plutil -extract CFBundleShortVersionString raw -o - "$staged_app/Contents/Info.plist")"
submission_archive="$working_directory/HushWire-$version-notarization.zip"
ditto -c -k --sequesterRsrc --keepParent "$staged_app" "$submission_archive"

notary_result="$working_directory/notarization.json"
xcrun notarytool submit "$submission_archive" \
  --key "$notary_key" \
  --key-id "$notary_key_id" \
  --issuer "$notary_issuer" \
  --wait \
  --output-format json >"$notary_result"
notary_status="$(plutil -extract status raw -o - "$notary_result")"
if [[ "$notary_status" != "Accepted" ]]; then
  submission_id="$(plutil -extract id raw -o - "$notary_result")"
  xcrun notarytool log "$submission_id" \
    --key "$notary_key" \
    --key-id "$notary_key_id" \
    --issuer "$notary_issuer" >&2 || true
  echo "Notarization was not accepted: $notary_status" >&2
  exit 70
fi

xcrun stapler staple "$staged_app"
xcrun stapler validate "$staged_app"
spctl --assess --type execute --verbose=4 "$staged_app"

artifact="$release_output/HushWire-$version-macos-universal.zip"
checksum="$artifact.sha256"
notary_record="$release_output/HushWire-$version-notarization.json"
rm -f "$artifact" "$checksum" "$notary_record"
ditto -c -k --sequesterRsrc --keepParent "$staged_app" "$artifact"
(
  cd "$release_output"
  shasum -a 256 "$(basename "$artifact")"
) >"$checksum.tmp"
mv "$checksum.tmp" "$checksum"
cp "$notary_result" "$notary_record"

echo "Created notarized release artifact: $artifact"
echo "Created checksum: $checksum"
echo "Saved notarization record: $notary_record"
