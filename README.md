<div align="center">

# Hop

**A fast, modern, open-source proxy client for iOS.**

Built on [sing-box](https://github.com/SagerNet/sing-box) — a native SwiftUI app paired with a Network Extension packet tunnel. The engine (libbox `v1.13.12`) is compiled from a pinned upstream commit and statically linked into the tunnel.

[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-blue)](LICENSE)
![Platform](https://img.shields.io/badge/platform-iOS%2026%2B-lightgrey)
![Engine](https://img.shields.io/badge/sing--box-v1.13.12-success)
![Swift](https://img.shields.io/badge/Swift-6.2-orange)

*No App Store build — you sideload it.*

</div>

---

## ✨ Features

| | |
|---|---|
| **Protocols** | VLESS (+ REALITY), Trojan, Hysteria2, TUIC, Shadowsocks, VMess, HTTP, SOCKS, WireGuard, AnyTLS |
| **Transports** | TCP, WebSocket, gRPC, HTTPUpgrade, QUIC |
| **Import** | Share links, plain/base64 subscriptions, and `.conf` files (`[Proxy]` / `[Proxy Group]` / `[Rule]`) — by paste, QR scan, or URL scheme. Subscriptions refresh in place without duplicating nodes. |
| **Export** | Per-node share links via copy (expiring pasteboard), share sheet, or QR — they round-trip cleanly back through the importer. |
| **Groups** | Manual select and URL-test (sing-box `selector` / `urltest`) |
| **Routing** | domain / suffix / keyword / regex, IP CIDR, ports, geosite & geoip (remote rule-sets), network type, Wi-Fi SSID — targeting a node, group, direct, reject, or the active outbound. Switchable rule sets with prebuilt China & Iran bypass profiles. |
| **Tunnel** | Kill switch (`includeAllNetworks`), Connect On Demand, DoH presets, strict route, protocol sniffing |
| **Insight** | Live traffic & per-connection telemetry, node search, bulk latency tests (TCP / TLS / ICMP), exportable log viewer, optional foreground auto-refresh of stale subscriptions |

---

## 📲 Install

**1. Get the IPA.** Download `Hop-unsigned.ipa` from [Releases](../../releases) (built by CI from a pinned engine commit — SHA-256 in the release notes), or [build it yourself](#-build).

**2. Re-sign it** with a certificate whose provisioning can carry the `packet-tunnel-provider` Network Extension entitlement. The straight answer on what qualifies:

| Signing setup | Tunnel works? |
|---|:---:|
| **Free Apple ID** — "personal team" via AltStore / SideStore / Sideloadly | ❌ &nbsp; Free provisioning can't include Network Extension. The app launches; the VPN never connects. |
| **Paid Apple Developer Program** ($99/yr) — incl. through AltStore / SideStore | ✅ &nbsp; Enable the Network Extensions capability on the App ID. Standard capability, no Apple approval needed (since 2016). |
| **Enterprise certificate** — what paid signing services resell | ⚠️ &nbsp; Only if that specific cert's profile includes Network Extension. Varies — confirm it "supports VPN" before paying. |
| **TrollStore** — iOS versions with the CoreTrust bug | ✅ &nbsp; Entitlements aren't checked at all. |

**3. Preserve the entitlements.** Your signer must keep, on **both** `Hop.app` and the embedded `PlugIns/HopTunnel.appex`:

- the App Group — `group.cat.string.hop`
- the keychain access group — `<team-prefix>.cat.string.hop`
- and on the **appex**: the `packet-tunnel-provider` Network Extension entitlement

> [!IMPORTANT]
> The IPA is ad-hoc fakesigned, so each binary already carries these entitlements for your signer to re-map. If the signer strips the appex or its entitlements — or your cert can't provide them — the VPN flips from *connecting* to *disconnected* immediately. That's the symptom.

---

## 🔗 URL schemes

Hop registers as a handler for proxy share links — tap one in a browser, or scan a share QR with the Camera app, and it opens in Hop:

```
vless://   vmess://   trojan://   ss://   ssr://   hysteria2://   hy2://   tuic://   socks://   socks5://
```

…plus its own scheme:

```
hop://import?url=<https subscription url>
hop://import?text=<percent-encoded links or config>
```

Every payload opens the import **preview** — nothing is applied without confirmation, and subscription URLs are never fetched until you ask. (`ssr://` is recognized but unsupported; you get a clear message rather than silence.)

> [!NOTE]
> **Scheme conflicts are an iOS limitation, not a Hop one.** Custom URL schemes are first-come-first-serve: if another proxy client that registers these schemes was installed *before* Hop, it keeps receiving the links. Apple defines the target as undefined when schemes collide — there's no prompt and no Settings toggle to pick a handler, and the earliest-installed app wins until it's removed. When another app owns the schemes, fall back to Hop's in-app QR scanner or paste import (neither touches the scheme system), or `hop://import?text=…` — the `hop://` scheme is Hop's alone and always deterministic.

---

## 🔨 Build

**Requirements:** Xcode · [XcodeGen](https://github.com/yonaskolb/XcodeGen) · Go 1.23+ (engine only)

```sh
./scripts/build-libbox.sh   # once: clones sing-box at a pinned tag+commit (~10–15 min)
xcodegen generate
xcodebuild -project Hop.xcodeproj -scheme Hop \
  -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
```

**Tests** — no signing or device required:

```sh
xcodebuild test -project Hop.xcodeproj -scheme Hop \
  -destination 'platform=iOS Simulator,name=iPhone 17' CODE_SIGNING_ALLOWED=NO
```

`build-libbox.sh` refuses to build if the upstream tag no longer resolves to the pinned commit, and records the engine's checksum in `Frameworks/Libbox.xcframework.sha256`. An Xcode pre-build step (`scripts/verify-libbox.sh`) then fails the build if the vendored engine stops matching it. CI builds the engine from the same pinned commit and prints both digests in the run summary. Packaging an unsigned IPA is scripted in [`.github/workflows/unsigned-ipa.yml`](.github/workflows/unsigned-ipa.yml) and documented in [`AGENTS.md`](AGENTS.md).

---

## 🔒 Security model

The short version — full details in [`ImportPolicy.swift`](Hop/Services/ImportPolicy.swift), [`SecretStore.swift`](Shared/SecretStore.swift), and the invariants section of [`AGENTS.md`](AGENTS.md):

- **Secrets never touch disk.** Passwords, UUIDs, and private keys live in the iOS Keychain. Persisted state is secret-free; the generated sing-box config carries nonce-bound secret *references* that only the tunnel extension can resolve — so credentials never cross IPC or land in provider configuration. Legacy plaintext state migrates automatically.
- **Imports are treated as hostile.** Subscriptions are HTTPS-only with SSRF blocking (private / loopback / metadata hosts rejected, redirects re-validated), size / recursion / item caps, regex safety checks, clamped URL-test scheduling, and display-name sanitization. Saving any node that disables TLS verification — including new nodes arriving via subscription *refresh* — requires an explicit blocking confirmation, and refreshes can never silently downgrade an existing node's TLS posture.
- **Logs can't be forged or leak credentials.** Every log write strips newlines, import warnings are redacted before logging, and the shared tunnel log is size-rotated and file-protected.

Found a hole? [Open an issue](../../issues).

---

## 📄 License

[**GPL-3.0-or-later**](LICENSE) — required by the sing-box/libbox engine, and fine by us. Hop is original software and does not copy any other client's assets, branding, or metadata.
