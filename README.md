# Hop

Hop is an open-source iOS 26+ proxy client built with Swift 6.2, SwiftUI, a Network Extension packet tunnel, and a client-only [Xray-core](https://github.com/XTLS/Xray-core) `v26.11.9` bridge.

There is no App Store build. Use the unsigned IPA from [Releases](../../releases), then re-sign it, or build it yourself.

## Features

- Protocols: VLESS (including ML-KEM Encryption/Auth), REALITY with ML-DSA-65 verification, Trojan, Hysteria2, Shadowsocks/SS2022, VMess AEAD, HTTP, SOCKS, and WireGuard
- Transports: RAW, WebSocket, gRPC, HTTPUpgrade, XHTTP, mKCP, Hysteria, FinalMask, mux/XUDP, and supported socket options
- TLS: certificate SHA-256 pins, verification names, ECH, post-quantum curve preferences, version bounds, ALPN, session resumption, and fingerprints
- Advanced configuration: versioned, schema-checked client options for DNS/FakeDNS, routing, policy, balancing, observatory, and local geodata
- Import: share links, plain/base64 subscriptions, and `.conf` files by paste, QR scan, or URL scheme
- Export: per-node share links by copy, share sheet, or QR
- Groups: manual select and URL-test
- Routing: domain, suffix, keyword, regex, IP CIDR, ports, protocol, and verified local geosite/geoip data
- Tunnel: kill switch, Connect On Demand, DoH presets, and protocol sniffing
- Tools: node search, latency tests, logs, and subscription refresh
- iOS safety: a hard 50 MiB Network Extension budget with preflight limits and a runtime memory watchdog

In Rule mode, enable **Settings → Protocol Sniffing** for domain, domain suffix, keyword, regex, GeoSite, and protocol rules. The tunnel uses sniffing to recover hostnames and identify protocols from IP packets. FakeDNS also requires this setting to map its synthetic addresses back to hostnames. IP, GeoIP, port, and network rules work with sniffing off. Rule evaluation stops at the first **Final** rule.

## Install

1. Download `Hop-unsigned.ipa` from a **Hop main build** on the [Releases page](../../releases). A **Hop preview (branch)** release contains work from the named branch. Older releases identify their branch under **Branch/ref**.
2. Re-sign the app and its embedded extension using the provisioning setup below.
3. Install the signed IPA.

After upgrading to the November engine, open Hop and reconnect once. This rebuilds the tunnel configuration for the new core so Connect On Demand can use it.

If a WireGuard profile specified an IPv4 or IPv6 DNS preference, Hop will ask you to review it before connecting. To accept the new core’s default, open that profile and tap **Use Default WireGuard DNS**. Other advanced settings that need review are listed in the [November field changes](docs/XRAY_FIELD_COVERAGE.md#november-field-changes).

Xray rejects unencrypted connections to public VLESS and Trojan servers. If an existing profile hits this check, use the TLS or REALITY settings supplied by the server operator. VLESS can also use VLESS Encryption.

Signing support:

| Setup | Tunnel works? | Notes |
| --- | --- | --- |
| Free Apple ID | No | Free provisioning cannot include Network Extension entitlements. |
| Paid Apple Developer Program | Yes | Enable Network Extensions on the App ID. |
| Enterprise certificate | Maybe | Only works if the profile includes Network Extension support. |

Register an App ID for the app and another for the extension on your team. Enable Network Extensions and App Groups on both. Create one App Group on your team, assign it to both App IDs, and regenerate both provisioning profiles. Keep each profile in its signed bundle so Hop can discover the shared group.

- `com.apple.security.application-groups`: use the **same registered group** on both binaries. Re-map the placeholder `group.cat.string.hop` to your team’s group.
- `keychain-access-groups`: use the same `<AppIdentifierPrefix>cat.string.hop` on both binaries. The signing prefix includes the trailing period. Keep the `cat.string.hop` suffix, which the Keychain lookup uses.
- `com.apple.developer.networking.networkextension`: `packet-tunnel-provider`

If the signer strips the extension or its entitlements, the app may open but the VPN will disconnect immediately.

The release IPA is ad-hoc fakesigned with placeholder entitlements so re-signing tools can re-map them. It still cannot be installed until it is signed with valid provisioning.

## URL schemes

Hop registers:

```text
hop
vless vmess trojan ss hysteria2 hy2 socks socks5 socks5+tls wireguard wg
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

- Xcode 26.5 (17F42), with iOS and Simulator SDKs 26.5 (23F73). Use `DEVELOPER_DIR` to select it when multiple Xcode versions are installed.
- [XcodeGen](https://github.com/yonaskolb/XcodeGen)
- Go 1.27.4 for the initial bridge build and later engine rebuilds

Build:

```sh
GOTOOLCHAIN=go1.27.4 ./scripts/build-libxray.sh
./scripts/verify-geodata.sh
xcodegen generate
xcodebuild -project Hop.xcodeproj -scheme Hop \
  -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
```

Test:

```sh
xcodebuild test -project Hop.xcodeproj -scheme Hop \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' CODE_SIGNING_ALLOWED=NO
```

`scripts/build-libxray.sh` builds the client-only bridge from pinned Xray-core and Go Mobile revisions and verifies its digest before installation. Maintainers updating the reviewed engine can run `scripts/build-libxray.sh --update-manifest` and then run the ordinary build again to check reproducibility. `scripts/verify-libxray.sh` checks the vendored framework against `Frameworks/LibXray.xcframework.sha256` during builds. The app links the bridge only for exact configuration validation; the Network Extension owns the single runtime core instance.

Unsigned IPA packaging is in [`.github/workflows/unsigned-ipa.yml`](.github/workflows/unsigned-ipa.yml). A local packaging command is documented in [`AGENTS.md`](AGENTS.md).

## Security notes

- Secrets are stored in the iOS Keychain, not in the app state file.
- The library and its authentication keys are device-only. A backup will not transfer your library to a new iPhone. Keep your original subscription URLs and share links for re-import.
- Imports and subscriptions are untrusted input. They are size-limited, sanitized, and previewed before saving.
- Subscription servers must support HTTPS over HTTP/1.1. Hop checks every resolved address, connects to an approved IP, and verifies the certificate against the URL hostname. The 30-second deadline includes redirects. Compressed and expanded responses each have a 5 MiB limit.
- Subscription refreshes cannot silently weaken an existing profile's TLS posture.
- Xray configurations that disable TLS verification are rejected; legacy nodes remain blocked until normal verification or certificate pins are selected.
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

Each IPA includes `Hop.app/Acknowledgments.txt` with licenses and credits for the linked Go dependencies and bundled routing data. The Iran IP list includes GeoLite2 data created by MaxMind. [MaxMind](https://www.maxmind.com) · [Acknowledgments](XrayBridge/Acknowledgments.txt)
