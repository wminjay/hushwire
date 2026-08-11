# Release Notes

> ⚠️ **Experimental and not audited.** Protocol v3 fixes known flaws in the earlier cryptographic construction, but HushWire is not yet suitable for sensitive production traffic.

## What is HushWire

HushWire is an experimental WireGuard-like IPv4 L3 tunnel focused on observability and debuggability, with UDP/TCP transports, exit-node support, and a personal macOS GUI.

## Download

| File | Platform |
|---|---|
| `hushwire-x86_64-linux.tar.gz` | Linux x86_64 (static) |
| `hushwire-aarch64-linux.tar.gz` | Linux ARM64 (static) |
| `hushwire-aarch64-macos.tar.gz` | macOS Apple Silicon |
| `HushWire-aarch64-macos-app.zip` | macOS Apple Silicon personal GUI client |

Each archive has a matching `.sha256` checksum. The GUI app is ad-hoc signed and not notarized; it is intended for personal testing.

## v0.7.0-rc.2: simultaneous-rekey liveness hotfix

This release candidate fixes a liveness regression introduced in v0.7.0-rc.1. When both ends started the scheduled rekey at nearly the same time, a passive endpoint could override the shared handshake-identifier tie-break while the active endpoint still followed it. Some identifier orderings therefore left both endpoints waiting as responders until the stale handshake candidates expired, causing a roughly two-minute traffic interruption.

- Normal scheduled rekeys now use the same deterministic handshake-identifier tie-break at both endpoints.
- A passive endpoint still prefers an inbound initiation after explicit peer invalidation, preserving recovery when a client restarts or returns from a changed NAT endpoint.
- Regression coverage verifies both simultaneous scheduled rekey and explicit restart-recovery behavior.

Validation includes the full Rust and macOS test suites, UDP/TCP recovery and multi-peer network-namespace tests, the gateway-policy integration test, and live JP canary rekeys under continuous traffic.

## v0.7.0-rc.1: controlled network policy release candidate

This release candidate is wire-compatible with v0.6.x. It is not wire-compatible with the v0.4.x/v0.5.x protocol, so both ends of an older link must be staged, restarted, and rollback-protected as one unit. Existing tunnel keys and TOML remain valid; the new `[gateway]` section is optional.

- The macOS System Extension preview adds an explicit IPv4 full-tunnel mode while retaining `/32` host-route isolation as the safe default.
- Full tunnel requires confirmation on every start and an authenticated preflight before installing default routes or DNS. The peer endpoint is excluded from the tunnel to prevent routing loops.
- The macOS UI now exposes effective policy, DNS, handshake, route, endpoint, and peer traffic state, and its layout adapts to the additional information.
- Disconnect is owned by macOS Packet Tunnel lifecycle handling, avoiding duplicate cleanup and misleading failures; rapid reconnects no longer reuse a just-cancelled local flow.
- Passive peers recover when a restarted client appears from a new NAT endpoint, without requiring a server restart.
- Linux can manage an exact, tagged LAN forwarding/NAT policy from optional `[gateway]` configuration, with idempotent reconciliation and ownership-safe cleanup.
- Direct-distribution entitlements and a notarizing System Extension packager are included, but the signed/notarized application is not part of this automated draft release.

Validation includes Rust formatting, clippy and unit tests; Swift package and macOS bridge smoke tests; UDP/TCP network-namespace recovery with either endpoint restarted; isolated System Extension `/32`, TCP full-tunnel, DNS, endpoint-exclusion, rollback and reboot tests; and live ownership-safe gateway-policy migrations on four LAN gateways without restarting their existing tunnel processes.

This candidate is intentionally published as a draft. Developer ID signing, notarization, clean-machine installation, physical-Mac sleep/wake and interface-switch testing, and a 24-hour soak remain release gates for stable v0.7.0.

## v0.6.1: shutdown cleanup and preview-state fixes

v0.6.1 is wire-compatible with v0.6.0 and requires no key or TOML changes.

- Linux route deletion now performs a short bounded retry when a supervisor using `KillMode=control-group` interrupts the transient `ip route del` child during shutdown. Cleanup still verifies that the exact route is gone and reports a real residual route after the retry limit.
- The macOS System Extension development preview queries the installed extension properties on App launch, so reopening the GUI restores the real enabled/approval/uninstall state instead of showing “not checked.”
- Reopening the preview App while connected now reports that it recovered the system-managed session, while the provider, tunnel, traffic and default route remain unchanged.
- The preview's `/32`-only policy is shared with its smoke test and explicitly rejects subnet/default routes, a fixed local listen port, and configurations without peer routes before any VPN settings are installed.

Verification included three consecutive systemd start/stop cycles with exact route checks and no cleanup warning; connected GUI quit/reopen and live App replacement without restarting the provider; startup while the isolated peer was unavailable followed by automatic authentication when it returned; and unchanged default routing, DNS, Tailscale, and production listeners throughout.

## v0.6.0: security protocol replacement

This release replaces wire protocol v2 and its custom cryptographic construction with protocol v3 using `snow`'s standard `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` state machine.

The replacement addresses the known v2 issues:

- the per-packet nonce had only 32 random bits under one session key, reaching roughly 50% collision probability around 77,000 packets;
- handshake encryption reused a fixed ChaCha20-Poly1305 nonce;
- configured initiator static public keys were not compared after decryption, so inbound peer selection effectively depended on the PSK;
- packet counters and the advertised rekey limit were not actually enforced;
- replay memory covered only the latest FIFO entries, allowing sufficiently old ciphertexts to leave the remembered set.

Protocol v3 now provides:

- a monotonic `u64` transport counter used as Noise's stateless AEAD nonce;
- a 4096-counter sliding replay window that advances only after authentication;
- strict configured static-key verification on the responder and responder-key pinning on the initiator;
- rejection of duplicate peer PSKs and duplicate peer static public keys;
- soft rekey after 120 seconds or 2^32 messages, with a 180-second reject deadline;
- responder candidate sessions that are promoted only after the first authenticated transport packet, preventing a replayed msg1 from immediately replacing a working session;
- receive-only retention of the previous authenticated session through its reject deadline, so in-flight packets are not discarded while peers switch keys;
- suppression of a competing local rekey while a valid responder candidate is pending, avoiding back-to-back replacement sessions;
- deterministic simultaneous-handshake resolution and bounded retry lifetimes.

## Reliability fixes

- TCP transport now preserves partially written length-prefixed frames across `EAGAIN`/`WouldBlock` with a bounded pending-write queue. A short socket write can no longer desynchronize the encrypted stream.
- Linux route cleanup now verifies whether a route is already absent when deletion races with interface teardown, while still reporting a real route that remains installed.
- The personal macOS client's privileged launcher starts HushWire in an independent session, so authorization-helper cleanup no longer terminates a healthy tunnel.

## Breaking compatibility and migration

v0.6.0 cannot communicate with v0.5.1 or earlier. Upgrade and restart both ends of each link together. The single-peer TOML format is unchanged. For a multi-peer interface, assign every `[[peer]]` a distinct PSK and distinct static `public_key`; duplicate credentials now fail validation.

Do not merge a v0.6 peer into an old production instance until every endpoint attached to that instance is ready to move at the same time.

## Quick start

```sh
tar xzf hushwire-<arch>-<os>.tar.gz
./hushwire --version       # hushwire 0.7.0-rc.2
./hushwire genkey
openssl rand -base64 32
sudo ./hushwire up -c my-node.toml
```

See the [README](https://github.com/wminjay/hushwire/blob/main/README.md) for configuration and routing details.

## Existing tunnel capabilities

- UDP transport and TCP fallback with length-prefix framing
- one-sided peer-restart recovery with authenticated keepalive probes
- endpoint roaming and optional UDP source-port rebinding
- IPv4 longest-prefix routing and full-tunnel split routes
- Linux exit-node forwarding/NAT via `--exit-node`
- route/firewall/TUN cleanup on shutdown
- CLI diagnostics and structured logs
- reusable platform-independent packet engine with IP/transport actions,
  handshake events, and peer-stat snapshots
- versioned C ABI and arm64/x86_64 macOS XCFramework for the staged Packet
  Tunnel System Extension migration
- personal SwiftUI macOS client whose tunnel process detaches from the
  temporary macOS authorization launcher's process group

## Verification in this release

- in-memory Noise handshake, identity, PSK, tamper, replay, and multi-client isolation tests;
- an 80,000-packet regression proving monotonic non-repeating counters past the old collision-risk range;
- candidate-session, lost-response, simultaneous-initiation, and one-sided-restart state-machine tests;
- two in-memory packet engines completing a handshake and exchanging IPv4
  packets in both directions without TUN devices or sockets;
- a C ABI end-to-end handshake/data/lifecycle test and a Swift program that
  links the universal XCFramework and exercises create/start/stop/destroy;
- isolated Linux network-namespace recovery tests for both UDP and TCP in CI;
- exact-hash 64 MiB transfers over both UDP and TCP, including sustained TCP backpressure;
- an isolated macOS `/32` Packet Tunnel run across the 120-second automatic rekey boundary, with uninterrupted packets at the key transition, one responder handshake, and no decrypt/authentication errors;
- macOS CLI/GUI builds, Swift tests, detached-session regression coverage,
  signature checks, and privileged start/stop smoke tests in CI.

## Known limitations

- HushWire is experimental and has not received an independent security audit.
- Wire protocol v3 has no compatibility mode for v2.
- IPv4 only; DNS configuration is not managed.
- exit-node NAT is Linux-only.
- UDP and TCP are selected per process; one process does not listen on both transports simultaneously.
- the macOS app is a personal, ad-hoc-signed client rather than a Network Extension/App Store VPN.
