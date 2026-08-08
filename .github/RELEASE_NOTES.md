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
./hushwire --version       # prints: hushwire 0.5.1
./hushwire genkey          # generate a static key pair (PrivateKey + PublicKey)
openssl rand -base64 32    # generate a PSK, use same value on both peers
sudo ./hushwire up -c my-node.toml
```

See the [README](https://github.com/wminjay/hushwire/blob/main/README.md) for configuration details.

## What's new in v0.5.1

- **TCP one-sided restart recovery** — a re-established TCP stream no longer remains stuck on the Noise session lost by the restarted peer. Authenticated liveness timeout now invalidates the stale session and immediately starts a fresh handshake while preserving the client process.
- **Transport-independent session timeout** — `session_timeout` can explicitly tune stale-session recovery. TCP peers with persistent keepalive automatically default to three keepalive intervals with a 15-second minimum; `0` explicitly disables it.
- **UDP behavior preserved** — `udp_rebind_after` still takes precedence for UDP because it repairs both the cryptographic session and the NAT path.
- **Real UDP and TCP recovery tests** — CI runs the one-sided restart scenario for both transports inside isolated Linux network namespaces and verifies that the original client PID survives.

TCP recovery is automatic when keepalive is enabled, or can be tuned explicitly:

```toml
[[peer]]
persistent_keepalive = 5
session_timeout = 20
```

The wire format remains compatible with v0.4.1 and v0.5.0. The surviving TCP peer needs v0.5.1 to perform automatic stale-session replacement.

## What works (v0.5.1)

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
- **One-sided restart recovery over UDP and TCP** — verified in isolated Linux network namespaces while preserving the client process
- **Real macOS GUI tunnels** — UDP and TCP connectivity, one-sided server restart recovery with the original Mac client PID preserved, and graceful disconnect cleanup verified against an isolated public test server
- **macOS exit routing** — targeted and full IPv4 exit profiles verified through an isolated Linux exit node, including endpoint-loop prevention, NAT egress, HTTPS, and complete route cleanup on disconnect

## Known limitations

- **Exit-node NAT is Linux-only** — macOS is supported as a peer/client.
- **IPv4 routing only; DNS is unmanaged** — full-tunnel profiles do not carry IPv6 or replace existing local/VPN DNS resolvers, so those paths require separate policy when bypass must be prevented.
- **The macOS GUI is ad-hoc signed and not notarized** — it is a personal client, not an App Store build, and currently requests administrator authorization for both connect and disconnect.
- **Probe acknowledgements require v0.4.1 or newer on both peers**; the surviving peer needs v0.5.0 for UDP stale-session replacement and v0.5.1 for TCP recovery.
- **Not audited** — experimental project.
