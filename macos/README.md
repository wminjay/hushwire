# HushWire for macOS (Personal Client)

This directory contains a small native SwiftUI client intended for a single user's Mac. It reuses the existing Rust tunnel core and does not install a persistent privileged helper or use Apple's Network Extension framework.

## What it does

- selects and remembers one TOML configuration
- validates the configuration before connection
- generates HushWire static key pairs
- starts and stops one privileged tunnel process
- restores the running state when the app is reopened
- shows recent tunnel logs
- protects against signaling an unrelated process if a stale PID is reused

Starting and stopping a TUN interface and changing routes requires administrator privileges. macOS therefore displays its standard authorization dialog for both operations.

## Requirements

- macOS 14 or newer
- Xcode command-line tools
- a Rust toolchain with Cargo
- a reachable HushWire peer or exit node

The app is built for the architecture of the Mac that runs the build script. The current build is for Apple Silicon when built on an Apple Silicon Mac.

## Build and open

From the repository root:

```sh
./macos/scripts/build-app.sh
open dist/HushWire.app
```

The result is `dist/HushWire.app`. It receives an ad-hoc local signature, which is sufficient for an app built and used on the same Mac. A Developer ID certificate and notarization would be needed before distributing it to other people.

To assemble a second test build without replacing an app that is already
running, choose a staging directory below `dist`:

```bash
HUSHWIRE_OUTPUT_DIRECTORY="$PWD/dist/staging" macos/scripts/build-app.sh
```

## Embedded Rust core

The Network Extension migration uses a stable C ABI instead of exposing Rust
types directly to Swift. Build the arm64/x86_64 universal XCFramework and run
the real Swift linkage smoke test with:

```bash
macos/scripts/build-core-xcframework.sh
macos/scripts/test-core-xcframework.sh
```

The generated product is `dist/HushWireCore.xcframework`. The committed ABI
surface is in `Core/include/HushWireCore.h`; callback buffers are borrowed only
until the callback returns, and `stop` waits for in-flight callbacks before it
erases session state. The framework contains protocol logic only: macOS still
owns packet flow, routes, DNS, and the UDP/TCP transport lifecycle.

## Packet Tunnel System Extension preview

The Xcode project is generated from `project.yml`; generated project state is
ignored so signing and target changes stay reviewable. Build the lifecycle-only
skeleton without signing or with the configured development team using:

```bash
macos/scripts/build-system-extension.sh
HUSHWIRE_SIGNING=development macos/scripts/build-system-extension.sh
```

The development build is written below
`dist/DerivedData/HushWireSystemSigned/Build/Products/Debug/HushWire.app`. The
build command does not install or activate the extension. First activation must
be initiated from the app and approved in macOS System Settings. This preview
intentionally rejects tunnel startup before calling
`setTunnelNetworkSettings`, so its lifecycle test cannot add routes or change
DNS.

The v0.6.0 GitHub release also includes `HushWire-aarch64-macos-app.zip` for Apple Silicon. It uses the same ad-hoc signature and is not notarized, so it is intended for personal testing; macOS may require using **Open** from Finder's context menu on first launch. Building locally remains the most predictable option.

## Prepare a client configuration

Use the app's **生成密钥** button (or `hushwire genkey`) to generate the client's private/public key pair. Generate a separate key pair on the peer. Generate the shared PSK once and copy it to both sides:

```sh
openssl rand -base64 32
```

A typical macOS client configuration looks like this:

```toml
[interface]
name = "utun10"
address = "10.77.0.1/24"
listen = "0.0.0.0:0"
transport = "udp"
mtu = 1280
private_key = "<client PrivateKey>"

[[peer]]
name = "exit"
endpoint = "203.0.113.20:27777"
allowed_ips = ["0.0.0.0/0"]
psk = "<same base64 PSK on both peers>"
public_key = "<exit peer PublicKey>"
persistent_keepalive = 25
udp_rebind_after = 90
```

`endpoint` currently has to be an IP address and port, not a hostname. For a split tunnel, replace `0.0.0.0/0` with only the networks that should use HushWire.

For TCP profiles, a nonzero `persistent_keepalive` automatically enables stale
session recovery after three keepalive intervals (minimum 15 seconds). Add
`session_timeout = <seconds>` to tune the threshold; it must be greater than
the keepalive interval. `session_timeout = 0` explicitly disables recovery.

Save the file somewhere private, select it in the app, and run **检查配置** before connecting. The configuration contains secrets and is currently stored as plain text; restrict its file permissions if other local accounts can access its directory:

```sh
chmod 600 my-client.toml
```

## Runtime files

- log: `~/Library/Logs/HushWire/tunnel.log`
- process state: `/var/run/hushwire-<uid>.pid`
- executable identity: `/var/run/hushwire-<uid>.binary`

Quitting the GUI does not disconnect an active tunnel. This lets the tunnel continue in the background; reopening the app finds it through the process state file. Use **断开** before deleting or replacing the app.

The privileged launcher starts the tunnel in a new POSIX session. This keeps
the long-running daemon outside AppleScript's temporary `authtrampoline`
process group, so macOS reclaiming the authorization helper does not terminate
the tunnel. The PID and executable checks remain in place for explicit stops.

The planned migration from this transitional launcher to a directly
distributed Packet Tunnel System Extension is documented in
[`../docs/macos-system-extension-plan.md`](../docs/macos-system-extension-plan.md).
The Rust CLI now drives the same platform-independent `Engine` intended for
the extension; TUN, route, firewall, and process management remain isolated in
the CLI adapter while the System Extension target is being built.

## Current limitations

- one active tunnel at a time
- IPv4 only
- config-file workflow; secrets are not yet moved into Keychain
- administrator prompt on every connect and disconnect
- intended for direct personal use, not the Mac App Store
- the HushWire protocol and implementation remain experimental and unaudited

Always use the app's **断开** action or send `SIGTERM` to the daemon so HushWire can remove installed routes. A forced kill or system crash can leave stale routes that require manual cleanup or a restart.
