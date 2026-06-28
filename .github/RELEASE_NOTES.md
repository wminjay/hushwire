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

Each `.tar.gz` has a matching `.sha256` checksum.

## Quick start

```sh
tar xzf hushwire-<arch>-<os>.tar.gz
./hushwire genkey          # generate a static key pair (PrivateKey + PublicKey)
openssl rand -base64 32    # generate a PSK, use same value on both peers
sudo ./hushwire up -c my-node.toml
```

See the [README](https://github.com/wminjay/hushwire/blob/main/README.md) for configuration details.

## What works (v0.3.0)

- **Noise_IKpsk2 handshake** — ephemeral key exchange with forward secrecy (PFS)
- **ChaCha20-Poly1305 AEAD** data encryption with session keys (not PSK)
- **Anti-replay protection** — bounded FIFO nonce window per session (4096 entries)
- **Endpoint roaming** — peers behind NAT connect by sending keepalives; the server learns their real address and replies there (same technique as WireGuard)
- **IPv4 routing** by longest-prefix match
- **UDP transport** (pluggable via `PacketTransport` trait)
- **Automatic route management** — host routes, full-tunnel split routing, endpoint exception, all torn down on shutdown
- **Exit-node NAT** — `--exit-node` installs iptables MASQUERADE + ip_forward, restored on shutdown
- **Persistent keepalive** and **structured peer stats** logging
- **CLI**: `check`, `route`, `explain`, `plan-routes`, `doctor`, `up`

## Tested in practice

- Dual-node tunnel on real Linux hosts (cross-region US ↔ CN, ~185ms RTT, 0% loss)
- Exit-node NAT verified — client traffic egresses via the exit node (`ifconfig.me` confirms)
- **NAT traversal** — a VM behind NAT establishes a bidirectional tunnel to a public-IP server (~280ms RTT, 0% loss)
- **Full-tunnel via exit node** — NAT'd client sends all traffic through the server
- Clean shutdown verified — routes, firewall rules, and TUN device removed on SIGTERM

## Known limitations

- **UDP only** — TCP/TLS transports not yet implemented.
- **Linux-focused** — macOS works as a peer but exit-node NAT is Linux-only.
- **Not audited** — experimental project.
