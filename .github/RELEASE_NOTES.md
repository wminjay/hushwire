# Release Notes

> ⚠️ **Experimental.** Not audited. Noise handshake provides forward secrecy, but implementation is new.

## What is HushWire

A WireGuard-like L3 tunnel focused on observability and debuggability. Noise_IKpsk2 handshake with forward secrecy, ChaCha20-Poly1305 encrypted, anti-replay protected, with pluggable transport and exit-node support.

## Download

Prebuilt binaries are attached to each release (statically linked musl on Linux — runs on any glibc version):

| File | Platform |
|---|---|
| `hushwire-x86_64-linux.tar.gz` | Linux x86_64 (static) |
| `hushwire-aarch64-linux.tar.gz` | Linux ARM64 (static) |
| `hushwire-aarch64-macos.tar.gz` | macOS Apple Silicon |
| `HushWire-aarch64-macos-app.zip` | macOS Apple Silicon personal GUI client |

Each archive has a matching `.sha256` checksum.

The GUI app is ad-hoc signed and not notarized. It is intended for personal testing; macOS may require opening it from Finder's context menu the first time.

## Quick start

```sh
tar xzf hushwire-<arch>-<os>.tar.gz
./hushwire --version       # prints: hushwire 0.5.0
./hushwire genkey          # generate a static key pair (PrivateKey + PublicKey)
openssl rand -base64 32    # generate a PSK, use same value on both peers
sudo ./hushwire up -c my-node.toml
```

See the [README](https://github.com/wminjay/hushwire/blob/main/README.md) for configuration details.

## What's new in v0.5.0

- **Personal macOS client** — a native SwiftUI app can select and validate configs, generate keys, connect/disconnect with administrator authorization, restore running state, and display live logs.
- **One-sided restart recovery** — after an authenticated liveness timeout, the surviving client now discards its stale session and immediately starts a fresh Noise handshake instead of requiring a manual restart.
- **Reliable handshake retries** — unanswered handshakes retry every five seconds using the same exchange, with responder-side duplicate caching to stay safe under packet loss and reordering.
- **Dynamic endpoint safety** — listen placeholders such as `0.0.0.0:<port>`, `[::]:<port>`, and port `0` are never used as outbound destinations before a real peer address is learned.
- **Hardened macOS lifecycle** — privileged startup works from current macOS authorization processes, protected/external-volume configs are staged through a private temporary copy, and inherited signal state is normalized for graceful disconnect cleanup.
- **Real isolated recovery tests** — CI uses two Linux network namespaces to establish a tunnel, restart only the responder, preserve the client PID, and verify ping recovery without touching the runner's default network.

To enable automatic recovery on a NATed UDP client:

```toml
[[peer]]
persistent_keepalive = 25
udp_rebind_after = 90
```

Configure `udp_rebind_after` on the NATed client, not the public exit. The wire format and configuration remain compatible with v0.4.1, but the peer that must detect and recover from a one-sided restart needs the v0.5.0 binary.

## What works (v0.5.0)

- **Noise_IKpsk2 handshake** — ephemeral key exchange with forward secrecy (PFS)
- **ChaCha20-Poly1305 AEAD** data encryption with session keys (not PSK)
- **Anti-replay protection** — bounded FIFO nonce window per session (4096 entries)
- **Endpoint roaming** — peers behind NAT connect by sending keepalives; the server learns their real address and replies there (same technique as WireGuard)
- **IPv4 routing** by longest-prefix match
- **UDP transport** (default, low-latency)
- **TCP transport** (fallback for UDP-blocked networks, 2-byte length-prefix framing, TCP_NODELAY)
- **Automatic route management** — host routes, full-tunnel split routing, endpoint exception, all torn down on shutdown
- **Exit-node NAT** — `--exit-node` installs iptables MASQUERADE + ip_forward, restored on shutdown
- **Persistent keepalive** and **structured peer stats** logging
- **CLI**: `check`, `route`, `explain`, `plan-routes`, `doctor`, `up`, `genkey`, `--help`, `--version`
- **Personal macOS GUI**: config selection/checking, key generation, privileged connect/disconnect, process restoration, and live logs

## Tested in practice

- Dual-node tunnel on real Linux hosts (cross-region US ↔ CN, ~185ms RTT, 0% loss)
- Exit-node NAT verified — client traffic egresses via the exit node (`ifconfig.me` confirms)
- **NAT traversal** — a VM behind NAT establishes a bidirectional tunnel to a public-IP server (~280ms RTT, 0% loss)
- **Full-tunnel via exit node** — NAT'd client sends all traffic through the server
- Clean shutdown verified — routes, firewall rules, and TUN device removed on SIGTERM
- **One-sided restart recovery** — verified in isolated Linux network namespaces while preserving the client process
- **macOS GUI lifecycle** — privileged connect and graceful disconnect verified with a no-peer/no-route safety config while the default route stayed unchanged

## Known limitations

- **Exit-node NAT is Linux-only** — macOS is supported as a peer/client.
- **The macOS GUI is ad-hoc signed and not notarized** — it is a personal client, not an App Store build, and currently requests administrator authorization for both connect and disconnect.
- **Probe acknowledgements require v0.4.1 or newer on both peers**; the surviving peer needs v0.5.0 for automatic stale-session replacement after a one-sided restart.
- **Not audited** — experimental project.
