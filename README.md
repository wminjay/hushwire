# HushWire

> **Status: experimental.** HushWire has not been audited. The Noise handshake provides forward secrecy, but the implementation is new and untested in adversarial conditions. Do not rely on it for sensitive traffic yet.

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

The daemon creates a TUN interface, installs host routes, and tears everything down on shutdown. Two peers with matching configs (exchanged public keys + shared PSK) can ping each other's tunnel IPs once the transport port is reachable between them.

## Overview

- create a TUN interface
- read IPv4 packets from it
- route packets by longest-prefix match against peer `allowed_ips`
- **Noise_IKpsk2 handshake** with ephemeral keys → forward secrecy (PFS)
- encrypt and authenticate each data packet with ChaCha20-Poly1305 using a session key
- anti-replay protection per session
- send packets over a pluggable packet transport (UDP or TCP)
- write received packets back into the TUN interface
- emit structured events for route decisions and packet flow
- install host routes for the tunnel and tear them down on shutdown
- optional persistent keepalive to keep NAT mappings alive
- optional authenticated liveness probes and UDP port rebinding to recover a broken NAT path

## Packet Security

HushWire uses a Noise_IKpsk2 handshake (same family as WireGuard) to negotiate ephemeral session keys. Data is encrypted with ChaCha20-Poly1305 under the session key, **not** the static PSK. This provides **forward secrecy**: even if the PSK or static private key is compromised later, previously captured traffic cannot be decrypted (session keys are ephemeral and destroyed after use).

The PSK serves only as an authentication factor — it's mixed into the key derivation at the end of the handshake to verify both peers are authorized, but never directly encrypts data.

### Key generation

```sh
hushwire genkey
# PrivateKey = ...  (put in your [interface] section)
# PublicKey  = ...  (give to your peer for their [[peer]] section)
```

### Handshake

On-wire handshake (2 messages, 3 Diffie-Hellman operations):

```text
  Initiator                         Responder
  msg1: eph_i_pub + PSK(static_i)   →
                                   ←  msg2: eph_r_pub + PSK(session_id)
  both derive: keys = HKDF(DH1 || DH2 || DH3 || psk)
```

### Data packet layout

```text
  offset  size  field
  0       1     version    (0x02)
  1       1     msg_type   (0x00=data, 0x01=keepalive, 0x02=handshake_init, 0x03=handshake_response)
  2..10   8     session_id (identifies which session key to use)
  10..14  4     nonce_rand (random, completes the 12-byte AEAD nonce)
  14..    N     ciphertext + 16-byte Poly1305 tag
```

`version || msg_type` is bound into the AEAD as additional authenticated data, so the header cannot be tampered with without failing decryption. The 12-byte AEAD nonce = `session_id(8) || nonce_rand(4)`. The receiver uses `session_id` to look up the correct session key, then decrypts.

Each peer keeps a bounded FIFO of recently seen nonces per session (default 4096 entries) and drops any packet whose nonce has already been seen, so a captured ciphertext cannot be replayed. The replay filter is reset when a new session is established (rekey). Fresh nonces collide inside the window with negligible (~2^-48) probability.

Keepalive packets use an empty encrypted payload for legacy one-way keepalives, `0x01` for an active liveness probe, and `0x02` for its acknowledgement.

## Transport Strategy

UDP is the default data plane because it avoids TCP-over-TCP head-of-line blocking when the tunnel carries TCP traffic.

- `udp` — **default.** Low-latency packet transport.
- `tcp` — **implemented.** Fallback for networks that block or QoS UDP. Uses 2-byte length-prefix framing on the TCP byte stream. Both sides listen; dialer connects on first send (symmetric, no listener/dialer role in config). `TCP_NODELAY` is set to avoid latency from Nagle's algorithm.
- `tls` — **under consideration.** Would provide certificate-based peer authentication; note that HushWire already encrypts every packet with ChaCha20-Poly1305, so TLS would be used for identity rather than confidentiality.

Configure with `transport = "tcp"` or `transport = "udp"` in the `[interface]` section.

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

With `udp_rebind_after` enabled, persistent keepalives become authenticated probes. The peer returns an authenticated acknowledgement, so the client can distinguish an idle tunnel from a broken return path. If no authenticated packet arrives for the configured number of seconds, HushWire binds a fresh ephemeral UDP source port and immediately sends a one-shot authenticated keepalive to every active peer—including peers with periodic keepalives disabled—so all learned endpoints move to the new port.

`udp_rebind_after` is disabled by default and must be greater than `persistent_keepalive`. Enable it on NATed clients, not on a public exit node: rebinding changes the interface-wide UDP socket and therefore the source port used for every peer on that interface. Both ends must support probe acknowledgements; older peers accept the keepalive but do not reply. A cold start still needs real tunnel traffic to initiate the Noise handshake.

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
