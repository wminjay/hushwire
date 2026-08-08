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

Save the file somewhere private, select it in the app, and run **检查配置** before connecting. The configuration contains secrets and is currently stored as plain text; restrict its file permissions if other local accounts can access its directory:

```sh
chmod 600 my-client.toml
```

## Runtime files

- log: `~/Library/Logs/HushWire/tunnel.log`
- process state: `/var/run/hushwire-<uid>.pid`
- executable identity: `/var/run/hushwire-<uid>.binary`

Quitting the GUI does not disconnect an active tunnel. This lets the tunnel continue in the background; reopening the app finds it through the process state file. Use **断开** before deleting or replacing the app.

## Current limitations

- one active tunnel at a time
- IPv4 only
- config-file workflow; secrets are not yet moved into Keychain
- administrator prompt on every connect and disconnect
- intended for direct personal use, not the Mac App Store
- the HushWire protocol and implementation remain experimental and unaudited

Always use the app's **断开** action or send `SIGTERM` to the daemon so HushWire can remove installed routes. A forced kill or system crash can leave stale routes that require manual cleanup or a restart.
