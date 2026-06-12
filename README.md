# Hop

iOS proxy client built on [sing-box](https://github.com/SagerNet/sing-box). SwiftUI app + Network Extension packet tunnel; the engine (libbox v1.13.12) is compiled from a pinned upstream commit and statically linked into the tunnel extension.

There is no App Store build. You sideload it.

## Features

- **Protocols:** VLESS (+ REALITY), Trojan, Hysteria2, TUIC, Shadowsocks, VMess, HTTP, SOCKS, WireGuard, AnyTLS. Transports: TCP, WebSocket, gRPC, HTTPUpgrade, QUIC.
- **Import:** share links, plain/base64 subscriptions, and Shadowrocket `.conf` (`[Proxy]`, `[Proxy Group]`, `[Rule]`) — by paste, QR scan, or URL scheme. Subscriptions refresh in place without duplicating nodes.
- **Export:** per-node share links via copy (expiring pasteboard), share sheet, or QR. Links round-trip through the importer.
- **Groups:** manual select and URL-test (sing-box `selector`/`urltest`).
- **Rules:** domain/suffix/keyword/regex, IP CIDR, ports, geosite/geoip (remote rule-sets), network type, Wi-Fi SSID; targets can be a node, group, direct, reject, or the active outbound. Switchable rule configurations with prebuilt China/Iran bypass sets.
- **Tunnel:** kill switch (`includeAllNetworks`), Connect On Demand, DoH presets, strict route, protocol sniffing.
- **UI:** live traffic + per-connection telemetry, node search, bulk latency tests (TCP/TLS/ICMP), log viewer with export, optional auto-refresh of stale subscriptions on foreground.

## Install

1. Grab `Hop-unsigned.ipa` from [Releases](../../releases) (built by CI from a pinned engine commit; SHA-256 in the release notes) or build it yourself (below).
2. Re-sign with your own certificate/profile (SideStore, AltStore, ESign, KSign, …).
3. **Your signer must keep, on both `Hop.app` and the embedded `PlugIns/HopTunnel.appex`:**
   - the App Group (`group.cat.string.hop`)
   - the keychain access group (`<team-prefix>.cat.string.hop`)
   - and on the **appex**: the `packet-tunnel-provider` Network Extension entitlement.

   The IPA is ad-hoc fakesigned so each binary carries these entitlements for your signer to re-map. If the signer strips the appex or its entitlements, the VPN flips from connecting to disconnected immediately — that's the symptom. Free (non-developer) Apple IDs cannot sign the Network Extension entitlement; the app will run but the tunnel won't start.

## URL scheme

```
hop://import?url=<https subscription url>
hop://import?text=<percent-encoded links or config>
```

Payloads open the import preview; nothing is applied without confirmation.

## Build

Requirements: Xcode, [XcodeGen](https://github.com/yonaskolb/XcodeGen), Go 1.23+ (engine only).

```sh
./scripts/build-libbox.sh   # once: clones sing-box at a pinned tag+commit, ~10-15 min
xcodegen generate
xcodebuild -project Hop.xcodeproj -scheme Hop -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
```

Tests (no signing or device needed):

```sh
xcodebuild test -project Hop.xcodeproj -scheme Hop \
  -destination 'platform=iOS Simulator,name=iPhone 17' CODE_SIGNING_ALLOWED=NO
```

`build-libbox.sh` refuses to build if the upstream tag no longer resolves to the pinned commit, and records the engine's checksum in `Frameworks/Libbox.xcframework.sha256`; an Xcode pre-build step (`scripts/verify-libbox.sh`) fails the build if the vendored engine stops matching it. CI builds the engine from the same pinned commit and prints both digests in the run summary.

Packaging an unsigned IPA from the build is scripted in `.github/workflows/unsigned-ipa.yml` (and documented in `AGENTS.md`).

## Security model

Short version — details live in `Hop/Services/ImportPolicy.swift`, `Shared/SecretStore.swift`, and the invariants section of `AGENTS.md`:

- **Secrets never touch disk.** Passwords, UUIDs, and private keys live in the iOS Keychain. Persisted state is secret-free; the generated sing-box config contains nonce-bound secret *references* that only the tunnel extension can resolve, so credentials don't cross IPC or land in provider configuration. Legacy plaintext state migrates automatically.
- **Imports are treated as hostile.** Subscriptions are HTTPS-only with SSRF blocking (private/loopback/metadata hosts rejected, redirects re-validated), size/recursion/item caps, regex safety checks, clamped URL-test scheduling, and display-name sanitization. Saving any node that disables TLS verification — including new nodes arriving via subscription *refresh* — requires an explicit blocking confirmation, and refreshes can never silently downgrade an existing node's TLS posture.
- **Logs can't be forged or leak credentials.** All log writes strip newlines; import warnings are redacted before logging; the shared tunnel log is size-rotated and file-protected.

Found a hole? Open an issue.

## License

[GPL-3.0-or-later](LICENSE) — required by the sing-box/libbox engine, and fine by us. Hop is original software; it does not copy Shadowrocket assets, branding, or metadata.
