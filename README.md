# HushWire

> **Status: experimental / alpha.** HushWire has not been audited. The crypto is a static pre-shared-key AEAD without a handshake, so there is no forward secrecy. Do not rely on it for sensitive traffic yet.

HushWire is an experimental WireGuard-like L3 tunnel focused on observability and debuggability.

## Quick Start

```sh
# Build
cargo build --release

# Generate a shared 32-byte PSK (do this once, use the same value on both peers)
openssl rand -base64 32

# Write a config for each peer (see examples/), then:
sudo ./target/release/hushwire up -c my-node.toml

# Dry-run checks that need no root:
./target/release/hushwire check    -c my-node.toml
./target/release/hushwire route    -c my-node.toml 10.77.0.2
./target/release/hushwire explain  -c my-node.toml 10.77.0.2
./target/release/hushwire doctor   -c my-node.toml
```

The daemon creates a TUN interface, installs host routes, and tears everything down on shutdown. Two peers with matching PSKs and swapped endpoints can ping each other's tunnel IPs once UDP port 27777 is reachable between them.

## Overview

The first milestone is intentionally small:

- create a TUN interface
- read IPv4 packets from it
- route packets by longest-prefix match against peer `allowed_ips`
- encrypt and authenticate each packet with ChaCha20-Poly1305 using a per-peer pre-shared key
- send packets over a pluggable packet transport, currently UDP
- write received packets back into the TUN interface
- emit structured events for route decisions and packet flow
- install host routes for the tunnel and tear them down on shutdown
- optional persistent keepalive to keep NAT mappings alive

## Packet Security

Each transport packet is encrypted and authenticated with ChaCha20-Poly1305 under a per-peer 32-byte pre-shared key (PSK). The on-wire layout is:

```text
  offset  size  field
  0       1     version   (0x02)
  1       1     msg_type  (0x00 = data, 0x01 = keepalive)
  2..13   12    nonce     (random)
  13..    N     ciphertext + 16-byte Poly1305 tag
```

`version || msg_type` is bound into the AEAD as additional authenticated data, so the header cannot be tampered with without failing decryption. The PSK is supplied base64-encoded in the peer config and validated at load time. This is symmetric pre-shared-key encryption, not a handshake: both peers must be configured with the same PSK.

Each peer also keeps a bounded FIFO of recently seen nonces (default 4096 entries) and drops any packet whose nonce has already been seen, so a captured ciphertext cannot be replayed. Because the nonces are random 96-bit values rather than a monotonic counter, the window is a set rather than a counter sliding window: a nonce older than 4096 packets ago is no longer tracked and would theoretically be replayable, the same bounded-window trade-off other tunnel implementations make. Fresh nonces collide inside the window with negligible (~2^-48) probability, so legitimate packets are effectively never misjudged as replays.

Noise-based key exchange (per-peer session keys without sharing a PSK) is a future milestone.

## Transport Strategy

UDP is the default data plane because it avoids TCP-over-TCP head-of-line blocking when the tunnel carries TCP traffic.

- `udp` — **implemented.** Default low-latency packet transport.
- `tcp` — **planned.** Compatibility fallback for networks that only allow TCP egress. Will require length-prefix framing on top of the byte stream.
- `tls` — **under consideration.** Would provide certificate-based peer authentication; note that HushWire already encrypts every packet with ChaCha20-Poly1305, so TLS would be used for identity rather than confidentiality.

`faketcp` and `websocket` transports were considered and dropped: they add significant complexity without fitting HushWire's goal of being an observable, debuggable tunnel. The `PacketTransport` trait is designed so a new transport can be added without touching the data path.

## Exit Node Shape

To send peer A's traffic through peer B, configure peer A with a full-tunnel route:

```toml
[[peer]]
name = "peer-b-exit"
endpoint = "203.0.113.20:27777"
allowed_ips = ["0.0.0.0/0"]
```

That means peer A will send every IPv4 destination to peer B through HushWire.

Peer B must also be configured as an exit node at the operating-system level. Passing `--exit-node` to `up` does this automatically (on Linux, via iptables):

- enable IPv4 forwarding (`net.ipv4.ip_forward=1`, restored to its prior value on shutdown)
- install `MASQUERADE` for the tunnel subnet on the POSTROUTING chain
- `ACCEPT` forwarded traffic in and out of the TUN interface
- keep firewall rules open for the HushWire transport port

All firewall rules and the original `ip_forward` value are removed when the daemon shuts down.

Use `plan-routes` to see the host routes needed for a config:

```sh
cargo run -- plan-routes -c examples/exit-peer-a.toml
```

Use `doctor` to inspect the current machine without changing routes:

```sh
cargo run -- doctor -c examples/exit-peer-a.toml
cargo run -- doctor -c examples/exit-peer-b.toml --exit-node
```

## Example

Terminal A (regular peer):

```sh
sudo cargo run -- up -c examples/node-a.toml
```

Terminal B (regular peer):

```sh
sudo cargo run -- up -c examples/node-b.toml
```

If peer B is an exit node, run it with `--exit-node` so HushWire installs forwarding and NAT:

```sh
sudo cargo run -- up -c examples/exit-peer-b.toml --exit-node
```

On startup HushWire installs the host routes implied by each peer's `allowed_ips` (including the split `0.0.0.0/1` + `128.0.0.0/1` for a full-tunnel route, plus a host-route exception for the peer endpoint so the tunnel does not loop back into itself). Routes and firewall rules are removed on shutdown.

## Commands

```sh
cargo run -- check -c examples/node-a.toml
cargo run -- route -c examples/node-a.toml 10.77.0.2
cargo run -- explain -c examples/node-a.toml 10.77.0.2
cargo run -- plan-routes -c examples/exit-peer-a.toml
cargo run -- doctor -c examples/exit-peer-a.toml
sudo cargo run -- up -c examples/node-a.toml
sudo cargo run -- up -c examples/exit-peer-b.toml --exit-node
```
