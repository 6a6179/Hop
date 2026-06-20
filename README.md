# Hop

Hop is an open-source iOS 26+ proxy client built with Swift 6.2, SwiftUI, a Network Extension packet tunnel, and [sing-box](https://github.com/SagerNet/sing-box) libbox `v1.13.12`.

There is no App Store build. Use the unsigned IPA from [Releases](../../releases), then re-sign it, or build it yourself.

## Features

- Protocols: VLESS with REALITY, Trojan, Hysteria2, TUIC, Shadowsocks, VMess, HTTP, SOCKS, WireGuard, AnyTLS
- Transports: TCP, WebSocket, gRPC, HTTPUpgrade, QUIC
- Import: share links, plain/base64 subscriptions, and `.conf` files by paste, QR scan, or URL scheme
- Export: per-node share links by copy, share sheet, or QR
- Groups: manual select and URL-test
- Routing: domain, suffix, keyword, regex, IP CIDR, ports, geosite/geoip rule sets, network type, and Wi-Fi SSID
- Tunnel: kill switch, Connect On Demand, DoH presets, strict route, and protocol sniffing
- Tools: traffic and connection telemetry, node search, latency tests, logs, and subscription refresh

## Install

1. Download `Hop-unsigned.ipa` from [Releases](../../releases).
2. Re-sign it with provisioning that can include the Network Extension `packet-tunnel-provider` entitlement.
3. Install the signed IPA.

Signing support:

| Setup | Tunnel works? | Notes |
| --- | --- | --- |
| Free Apple ID | No | Free provisioning cannot include Network Extension entitlements. |
| Paid Apple Developer Program | Yes | Enable Network Extensions on the App ID. |
| Enterprise certificate | Maybe | Only works if the profile includes Network Extension support. |
| TrollStore | Yes | Entitlements are not checked on supported iOS versions. |

Your signer must preserve these entitlements on both `Hop.app` and `PlugIns/HopTunnel.appex`:

- `com.apple.security.application-groups`: `group.cat.string.hop`
- `keychain-access-groups`: `<team-prefix>.cat.string.hop`
- `com.apple.developer.networking.networkextension`: `packet-tunnel-provider`

If the signer strips the extension or its entitlements, the app may open but the VPN will disconnect immediately.

The release IPA is ad-hoc fakesigned with placeholder entitlements so re-signing tools can re-map them. It still cannot be installed until it is signed with valid provisioning.

## URL schemes

Hop registers:

```text
hop
vless vmess trojan ss ssr hysteria2 hy2 tuic socks socks5
```

Examples:

```text
hop://import?url=<https subscription url>
hop://import?text=<percent-encoded links or config>
```

Imported payloads open in the preview screen first. Nothing is saved without confirmation, and subscription URLs are not fetched until the user asks.

iOS does not let users choose a handler when multiple apps register the same custom scheme. If another proxy app was installed first, it may receive `vless://`, `ss://`, and similar links. Use Hop's paste import, in-app QR scanner, or `hop://import?text=...` to avoid that.

## Build

Requirements:

- Xcode
- [XcodeGen](https://github.com/yonaskolb/XcodeGen)
- Go 1.23 or newer, only needed to rebuild libbox

Build:

```sh
./scripts/build-libbox.sh
xcodegen generate
xcodebuild -project Hop.xcodeproj -scheme Hop \
  -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
```

Test:

```sh
xcodebuild test -project Hop.xcodeproj -scheme Hop \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' CODE_SIGNING_ALLOWED=NO
```

`scripts/build-libbox.sh` builds sing-box from a pinned tag and commit. `scripts/verify-libbox.sh` checks the vendored framework against `Frameworks/Libbox.xcframework.sha256` during builds.

Unsigned IPA packaging is in [`.github/workflows/unsigned-ipa.yml`](.github/workflows/unsigned-ipa.yml). A local packaging command is documented in [`AGENTS.md`](AGENTS.md).

## Security notes

- Secrets are stored in the iOS Keychain, not in the app state file.
- Imports and subscriptions are untrusted input. They are size-limited, sanitized, and previewed before saving.
- Subscription refreshes cannot silently weaken an existing profile's TLS posture.
- Nodes that disable TLS verification require an explicit confirmation before saving.
- Tunnel config passed through the shared App Group is authenticated before the extension resolves secret references.
- Logs strip newlines and redact import-controlled warnings to avoid forged log entries and credential leaks.
- Exported share links can contain credentials; only create or share them intentionally.

Relevant code:

- [`Hop/Services/ImportPolicy.swift`](Hop/Services/ImportPolicy.swift)
- [`Hop/Services/HopAppDataStore.swift`](Hop/Services/HopAppDataStore.swift)
- [`Shared/SecretStore.swift`](Shared/SecretStore.swift)
- [`AGENTS.md`](AGENTS.md)

Report security issues through [Issues](../../issues).

## License

[GPL-3.0-or-later](LICENSE)
