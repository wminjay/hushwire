# HushWire iOS Stitch Design Spec

This is the implementation-facing design artifact for the native HushWire iOS client. Stitch establishes the information hierarchy and visual direction; the shipping interface must be implemented with native SwiftUI and Network Extension APIs rather than embedding the generated HTML.

## Stitch Source

- Project: `projects/11685670541458728234` (`HushWire iOS Client`)
- Design system: `assets/795481195449873120` (`HushWire Quiet Network`)
- Generated on: 2026-09-04
- Primary screens:
  - `d3aad3a963694500a3911a3d974b84d3` — First Launch / No Configuration
  - `6f15f1f6653d468c9bb889291dd921fc` — Home / Disconnected
  - `d086b5d6d7f24f879d1905377b364357` — Home / Connected
  - `50e6c796d9ff4b7a919476a4797a4b1d` — Configuration
  - `7a857c94d9b04cf3b6b333d92998fd3d` — Diagnostics
  - `67c48522f0674c849115dc94c645b0eb` — Automatic Recovery
  - `e559710d69394ecd99d6bb3f3c837cab` — Full-Tunnel Confirmation
  - `ecd943558f5240d5b2957980d71f02f3` — Profile Selector

Full-resolution PNG and generated HTML references are stored in [`stitch/`](./stitch/). The HTML is reference material only and is not application source.

## Product Direction

HushWire should feel like a trustworthy personal network utility: calm, precise, and transparent about the effect a tunnel will have on the device. It is not a commercial VPN catalog and must not include maps, subscriptions, promotional server lists, fake latency, account upsells, or advertising.

The default view answers four questions without opening a console:

1. Is the tunnel actually authenticated and healthy?
2. Which local configuration is active?
3. What traffic, routes, and DNS settings are affected?
4. What is the current and cumulative traffic activity?

Detailed configuration and diagnostics use progressive disclosure so technical values remain available without making the connection screen overflow.

## Navigation

Use three stable tabs:

- **连接** — current state, primary connect/disconnect action, route impact, live traffic, and concise session health.
- **配置** — imported profile, network policy, interface/peer metadata, routes, DNS, keepalive, rebind, and validation.
- **诊断** — authenticated-session health, resolved endpoint, traffic, effective network impact, recent events, and redacted export.

The first-launch screen opens directly into configuration import. Do not add an onboarding carousel.

## Connection States

- **No configuration:** explain local TOML validation, network-scope review, and the real iOS VPN permission that appears on first connection.
- **Disconnected:** inactive shield, neutral status, one prominent Connect action, profile summary, and last-session summary.
- **Connecting/authenticating:** preserve the home layout, disable profile switching, show a small progress treatment, and do not claim that routing is active before authenticated preflight succeeds.
- **Connected:** authenticated green/teal state, duration, restrained Disconnect action, live rates, totals, latest handshake, endpoint, transport, and route impact.
- **Recovering:** amber state, last authenticated handshake age, automatic endpoint/session recovery detail, zero current rates with cumulative totals preserved, and no redundant Retry button.
- **Failed:** red is limited to the failure message and recovery action. Clearly state whether network settings were installed or remained unchanged.
- **Disconnecting:** keep the same layout and show progress until iOS reports the tunnel stopped; do not optimistically label it disconnected.

## Network Safety

- Route policies are **指定地址 (/32)**, **自定义分流**, and **全局**.
- The home screen always shows the effective route mode and whether default routing or DNS changed.
- Every full-tunnel start presents the confirmation sheet. There is no “do not ask again” option.
- The confirmation summarizes default routing, DNS servers, endpoint protection, and direct exceptions.
- State that routes and DNS are applied only after authenticated preflight succeeds and are restored by iOS after disconnection.
- Do not reproduce the macOS System Extension activation controls on iOS. The first VPN-profile authorization is the real system-provided sheet.

## Configuration Visibility and Secrets

Show these non-secret values when available:

- profile name;
- interface/tunnel address;
- configured and resolved endpoint;
- UDP or TCP transport;
- MTU and peer count;
- included routes and direct exceptions;
- DNS policy;
- persistent keepalive, UDP rebind, or TCP session timeout;
- latest handshake age, current endpoint health, transfer rates, and byte totals.

Never show private keys or PSKs. A status row may confirm that credentials are present and protected. Diagnostics and sharing must redact secrets. The interface does not offer an encryption-algorithm selector because the current wire protocol defines its cryptographic suite rather than negotiating a user-selectable cipher.

Transport comes from the imported profile. It cannot be changed while connected.

## Multiple Profiles

The approved v1 product model is multiple locally imported profiles with only one active tunnel. Switching, editing, importing, and deletion are available only while disconnected. Each profile keeps its own TOML in the device-only Keychain and stores only non-secret display metadata in app preferences.

## Visual System

- Canvas: quiet near-white; use the native system background in SwiftUI.
- Surfaces: system background with subtle separators and restrained elevation.
- Primary: `#2878FF` for connection and navigation actions.
- Healthy/authenticated: `#0F9F8F`.
- Recovering/network-impact warning: `#EAA21A`.
- Destructive/failure: system red, used sparingly.
- Typography: Stitch uses Inter for reference; implementation uses the iOS system font and monospaced digits for changing numeric values.
- Corners: approximately 12pt for grouped surfaces.
- Touch targets: at least 44pt.

Use semantic system colors so dark mode, increased contrast, and accessibility settings remain functional. Status must never depend on color alone.

## Implementation Fidelity

- Source viewport is 780 physical pixels, representing a 390pt iPhone at 2× scale.
- Preserve the stable header, profile selector, central connection state, route-impact summary, and bottom tabs between connection states.
- Keep changing traffic numbers in fixed-width or monospaced layouts to avoid jitter.
- Configuration and diagnostics are vertically scrollable; horizontal scrolling is not part of the primary UI.
- Use native navigation bars, sheets, lists, segmented controls, confirmation dialogs, file importers, and SF Symbols.
- Stitch-generated icons and copy are direction, not assets that must be embedded verbatim.
- The settings/diagnostics action belongs in the trailing navigation position even if a generated screenshot places it on the leading side.
- Respect Dynamic Type, VoiceOver labels/values, Reduce Motion, safe areas, and both light and dark appearance.

## Visual QA

Before implementation is considered aligned:

1. Capture all primary states on a 390pt-wide iPhone simulator.
2. Compare structure, spacing, action hierarchy, status semantics, and data visibility with the PNG references.
3. Test large Dynamic Type for clipping and scrolling.
4. Test VoiceOver labels for connection state, route impact, traffic direction, profile selection, and destructive actions.
5. Test Reduce Motion and dark mode independently of the light Stitch references.
6. Verify that screenshots, logs, copied diagnostics, and VPN provider configuration never expose private keys or PSKs.
