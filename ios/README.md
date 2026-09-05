# HushWire for iOS

The iOS client is a native SwiftUI app with an embedded Packet Tunnel app
extension. It reuses the same Rust protocol core as the macOS Network Extension
client and supports UDP and TCP profiles.

## Product model

- Store multiple imported TOML profiles locally.
- Select profiles only while disconnected.
- Run one device-wide HushWire tunnel at a time.
- Keep TOML, private keys, and PSKs in a device-only Keychain access group
  shared only by the signed app and its Packet Tunnel extension.
- Put only non-secret route policy, DNS choices, and the selected profile ID in
  `NETunnelProviderManager` preferences.
- Optionally install an ordered VPN On Demand policy that disconnects on exact
  trusted Wi-Fi SSID matches and either leaves the current state alone or
  connects on every other network.
- Let an On Demand launch read the selected TOML directly from the shared
  Keychain; the app's private provider-message channel remains a live-session
  compatibility path. Connection options and VPN preferences never contain
  secrets.

Automatic connection is opt-in per profile and requires at least one trusted
Wi-Fi SSID. For a full tunnel, enabling it is a persistent authorization shown
with a separate confirmation. Profiles created by older builds default to off.

## Build

Requirements:

- Xcode 26 or newer
- XcodeGen
- Rust with the following targets installed:
  - `aarch64-apple-ios`
  - `aarch64-apple-ios-sim`
  - `x86_64-apple-ios`

From the repository root:

```sh
ios/scripts/generate-project.sh
open ios/HushWireIOS.xcodeproj
```

The script creates `dist/HushWireCore-iOS.xcframework` and then regenerates the
Xcode project from `ios/project.yml`. Both generated outputs are ignored by
Git.

An unsigned compile check for both Apple platforms is:

```sh
xcodebuild -project ios/HushWireIOS.xcodeproj \
  -scheme HushWireIOS \
  -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO build

xcodebuild -project ios/HushWireIOS.xcodeproj \
  -scheme HushWireIOS \
  -sdk iphoneos \
  -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO build
```

Run unit tests on an available simulator with:

```sh
xcodebuild -project ios/HushWireIOS.xcodeproj \
  -scheme HushWireIOS \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro Max' test
```

The simulator verifies the UI, Rust linkage, and policy validation. Keychain
round-trip tests require a normally signed simulator test host. A live Packet
Tunnel must be verified on a physical iPhone.

## Signing and device testing

The checked-in project uses Apple Developer team `95Q852BXKJ` and these bundle
identifiers:

- app: `com.jamie.HushWire.iOS`
- extension: `com.jamie.HushWire.iOS.PacketTunnel`

Enable the Network Extensions / Packet Tunnel capability for both App IDs and
allow Xcode to create matching development profiles. The app and extension
entitlements both request `packet-tunnel-provider`.

On a physical iPhone:

1. Build and run the `HushWireIOS` scheme.
2. Import a client TOML from Files or open a `.toml` file with HushWire.
3. Review the inferred route policy, routes, endpoint, DNS, and recovery values.
   Hostname endpoints show both the configured name and the currently resolved
   IPv4 address.
4. Tap Connect and approve the system VPN configuration the first time.
5. Confirm that the UI reaches **已连接**, shows a recent authenticated
   handshake, and increments both traffic totals.
6. For full tunnel, verify public egress and DNS only after the explicit
   confirmation sheet; then disconnect and verify normal network restoration.
7. To use On Demand, add one or more trusted SSIDs and enable **离开可信 Wi-Fi
   后自动连接**. Joining a trusted SSID disconnects the tunnel; network traffic
   on another Wi-Fi or cellular network starts it without keeping the app open.

## Network safety

- **指定地址** accepts `/32` routes only and leaves default routing and DNS
  unchanged.
- **自定义分流** accepts one peer and non-default IPv4 CIDRs, protects the
  resolved endpoint, and applies routes/DNS only after authenticated preflight.
- **全局** requires exactly one `0.0.0.0/0`, explicit confirmation on every
  start, endpoint protection, recovery settings, and authenticated preflight.
- A failed preflight never installs the protected routes or DNS.
- Disconnect status is not shown until iOS reports that the tunnel stopped.
- Trusted Wi-Fi rules are ordered: an exact SSID `Disconnect` rule comes first,
  followed by either `Connect` (when explicitly enabled) or `Ignore`.
- An On Demand full-tunnel start is accepted only when the saved profile carries
  the user's persistent auto-connect authorization. The extension still waits
  for an authenticated preflight before changing routes or DNS.
- Trusted Wi-Fi names remain in app-local profile metadata and are omitted from
  exported diagnostics.

The client is IPv4-only. A full-tunnel label therefore means global IPv4
traffic, not IPv6.

## Privacy and diagnostics

The app does not collect analytics or tracking data. Its privacy manifest
declares app-local `UserDefaults` use and elapsed-time calculations. The Packet
Tunnel manifest declares elapsed-time calculations used for session recovery.

Diagnostics include only non-secret tunnel metadata and app lifecycle events.
Private-key and PSK assignments are redacted again before copying or sharing,
including assignments embedded in parser error excerpts.

The protocol and implementation remain experimental and unaudited. Do not use
the current preview for sensitive production traffic.

Before any TestFlight or App Store distribution, review the app's encryption
export-compliance answers for the intended countries. The project deliberately
does not hard-code an exemption claim in `Info.plist`.
