# HushWire

> **Status: experimental.** HushWire has not been audited. v0.6.0 replaces the earlier custom cryptographic construction with the standard `snow` Noise state machine, but the complete tunnel remains untested in adversarial conditions. Do not rely on it for sensitive traffic yet.

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

## macOS Personal Client

A native SwiftUI client for personal, direct-install use lives in [`macos/`](macos/README.md). It bundles the Rust tunnel binary and provides config selection, validation, key generation, connect/disconnect controls, and live logs.

```sh
./macos/scripts/build-app.sh
open dist/HushWire.app
```

The local build uses an ad-hoc signature and macOS requests administrator authorization when starting or stopping the tunnel. It is not an App Store or Network Extension build.

The platform-independent Rust packet engine also exports a versioned C ABI for
the in-progress Packet Tunnel System Extension. A universal macOS XCFramework
and its Swift linkage smoke test can be built with:

```sh
macos/scripts/build-core-xcframework.sh
macos/scripts/test-core-xcframework.sh
```

The daemon creates a TUN interface, installs host routes, and tears everything down on shutdown. Two peers with matching configs (exchanged public keys + shared PSK) can ping each other's tunnel IPs once the transport port is reachable between them.

## Overview

- create a TUN interface
- read IPv4 packets from it
- route packets by longest-prefix match against peer `allowed_ips`
- standard **Noise_IKpsk2** state machine (`snow`) with ephemeral keys → forward secrecy (PFS)
- encrypt and authenticate each data packet with ChaCha20-Poly1305 using a session key
- anti-replay protection per session
- send packets over a pluggable packet transport (UDP or TCP)
- write received packets back into the TUN interface
- emit structured events for route decisions and packet flow
- install host routes for the tunnel and tear them down on shutdown
- optional persistent keepalive to keep NAT mappings alive
- optional authenticated liveness probes and UDP port rebinding to recover a broken NAT path

## Packet Security

HushWire v0.6 uses `snow`'s standard `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` state machine to negotiate ephemeral session keys. Data is encrypted with ChaCha20-Poly1305 under the resulting transport keys, **not** directly with the static PSK. The ephemeral exchange provides forward secrecy for completed sessions.

The PSK serves only as an authentication factor — it's mixed into the key derivation at the end of the handshake to verify both peers are authorized, but never directly encrypts data.

### Key generation

```sh
hushwire genkey
# PrivateKey = ...  (put in your [interface] section)
# PublicKey  = ...  (give to your peer for their [[peer]] section)
```

### Handshake

The two handshake messages are produced and consumed by the standard Noise IKpsk2 state machine. The responder verifies that the static public key revealed by Noise exactly matches the configured `public_key`; the initiator already pins the responder's configured static key. The PSK is mixed at Noise position 2. A responder keeps a newly derived session as a candidate until the initiator sends the first authenticated transport packet, so replaying an old handshake initiation cannot immediately replace a working session.

### Data packet layout

```text
  offset  size  field
  0       1     version     (0x03)
  1       1     packet_kind (0x00=transport, 0x01=handshake_init, 0x02=handshake_response)
  2..10   8     session_id  (identifies the transport session)
  10..18  8     counter     (big-endian monotonic u64 AEAD nonce)
  18..    N     Noise ciphertext + 16-byte Poly1305 tag
```

Handshake packets use the shorter `version || packet_kind || handshake_id` header followed by a Noise handshake message. The version and random handshake ID are bound into the Noise prologue, so changing either breaks the transcript.

Each transport direction starts its counter at zero and increments it once per encryption; no randomness is used for the nonce, so packets under one key cannot collide. The data/keepalive message type is inside the authenticated ciphertext. Receivers use a 4096-counter sliding window, accept legitimate reordering, reject duplicates and packets older than the window, and advance the window only after the AEAD tag authenticates. A forged high counter therefore cannot move the window.

Sessions begin a replacement handshake after 120 seconds or 2^32 messages and stop being accepted after 180 seconds. The old session continues carrying traffic while the replacement is negotiated, avoiding an intentional gap during normal rekey.

Keepalive packets use an empty encrypted payload for one-way keepalives, `0x01` for an active liveness probe, and `0x02` for its acknowledgement.

### v0.6 compatibility

Wire protocol v3 is intentionally incompatible with v0.5.1 and earlier. Both ends of a peer link must be upgraded together. The TOML shape is unchanged for a single peer, but a multi-peer interface must give every peer a unique PSK and unique static `public_key`; duplicate credentials are rejected during `check`/startup.

## Transport Strategy

UDP is the default data plane because it avoids TCP-over-TCP head-of-line blocking when the tunnel carries TCP traffic.

- `udp` — **default.** Low-latency packet transport.
- `tcp` — **implemented.** Fallback for networks that block or QoS UDP. Uses 2-byte length-prefix framing on the TCP byte stream. Both sides listen; dialer connects on first send (symmetric, no listener/dialer role in config). `TCP_NODELAY` is set to avoid latency from Nagle's algorithm.
- `tls` — **under consideration.** Would provide certificate-based peer authentication; note that HushWire already encrypts every packet with ChaCha20-Poly1305, so TLS would be used for identity rather than confidentiality.

Configure with `transport = "tcp"` or `transport = "udp"` in the `[interface]` section.

TCP peers with `persistent_keepalive` enabled also use authenticated probes for
session recovery. If the peer stops responding, HushWire discards the stale
Noise session and starts a fresh handshake over the re-established TCP stream.
The default timeout is three keepalive intervals with a 15-second minimum. Set
`session_timeout` explicitly to tune it, or set it to `0` to disable automatic
TCP session recovery:

```toml
[[peer]]
persistent_keepalive = 5
session_timeout = 20
```

An explicit `session_timeout` must be greater than `persistent_keepalive`.
It can also be used for UDP session-only recovery, but `udp_rebind_after` takes
precedence when both are configured because rebinding also repairs the NAT path.

### UDP NAT resilience

Multiple clients behind the same NAT should use unique local UDP listen ports. This is especially important behind double NAT, where some devices incorrectly collide or retain mappings when several clients use the same source port. A client that does not need a predictable inbound port can let the operating system choose one:

```toml
[interface]
listen = "0.0.0.0:0"
transport = "udp"
```

Port `0` is replaced with an ephemeral port at bind time and remains stable for the lifetime of the process. HushWire logs the actual bound address in the `tunnel started` event.

For automatic recovery when an established UDP path becomes one-way, enable rebinding on the client-side peer:

```toml
[[peer]]
name = "exit"
endpoint = "203.0.113.20:27777"
allowed_ips = ["0.0.0.0/0"]
psk = "<base64-32-byte-psk>"
public_key = "<base64-peer-public-key>"
persistent_keepalive = 25
udp_rebind_after = 90
```

With `udp_rebind_after` enabled, persistent keepalives become authenticated probes. The peer returns an authenticated acknowledgement, so the client can distinguish an idle tunnel from a broken return path. If no authenticated packet arrives for the configured number of seconds, HushWire binds a fresh ephemeral UDP source port, discards the timed-out peer's stale session, and starts a fresh Noise handshake. Because rebinding changes the interface-wide socket, it also sends a one-shot authenticated keepalive to every other active peer—including peers with periodic keepalives disabled—so their learned endpoints move to the new port.

`udp_rebind_after` is disabled by default and must be greater than `persistent_keepalive`. Enable it on NATed clients, not on a public exit node: rebinding changes the interface-wide UDP socket and therefore the source port used for every peer on that interface. Both ends must run the v3 wire protocol. Real tunnel traffic starts a cold handshake immediately; a configured periodic keepalive can also start it when its interval becomes due. An unanswered exchange is retried every five seconds and replaced with a fresh handshake after 30 seconds.

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

HushWire currently manages IPv4 routes only and does not change the system DNS
configuration. A full-tunnel profile therefore does not by itself prevent DNS
queries from using an existing local or VPN resolver, and it does not carry
IPv6 traffic. Configure DNS and IPv6 separately when those paths must not bypass
the tunnel.

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
