# Hop

Hop is an original iOS proxy/VPN client inspired by the workflow of apps like Shadowrocket, but with its own UI, branding, code, and architecture.

The first implementation focuses on:

- Secure modern outbound profiles: VLESS + REALITY, Trojan + TLS, Hysteria2 + TLS, TUIC + TLS, AnyTLS, Shadowsocks, VMess, HTTP, SOCKS, and WireGuard where sing-box supports them.
- Shadowrocket-compatible imports for single links, plain/base64 subscriptions, and `.conf` files with `[Proxy]`, `[Proxy Group]`, and `[Rule]` sections.
- Proxy groups with sing-box `selector` and `urltest` outbounds; unsupported imported group types are preserved disabled with warnings.
- Routing rules that can target direct, reject, the active outbound, a specific node, or a proxy group.
- Shared-container persistence for nodes, groups, subscriptions, rules, settings, tunnel startup config, and logs.
- A native SwiftUI shell for dashboard, profile/group/subscription/import management, routing rules, logs, and settings.
- `NETunnelProviderManager` app-side tunnel setup with runtime App Group and embedded extension bundle ID resolution.

Packet routing is handled by sing-box's `libbox` engine, compiled from source and embedded in `HopTunnel`. Build the engine once before generating the Xcode project (see Build).

## Build

The tunnel needs the sing-box engine (`Libbox.xcframework`). Build it once — requires the Go toolchain and takes ~10–15 minutes:

```sh
brew install go            # if needed; Go 1.23+ required
./scripts/build-libbox.sh  # clones sing-box v1.13.12, builds Frameworks/Libbox.xcframework
```

`build-libbox.sh` pins both the release tag **and** the exact upstream commit it
must resolve to, and refuses to build if the tag has moved. After building it
records the engine's checksum in `Frameworks/Libbox.xcframework.sha256`. The
Xcode build runs `scripts/verify-libbox.sh` as a pre-build step and fails if the
vendored engine no longer matches that checksum, so the privileged tunnel binary
has a tamper-evident provenance baseline. To verify the vendored engine manually:

```sh
./scripts/verify-libbox.sh            # verify against the checked-in checksum
./scripts/verify-libbox.sh --update   # re-record after a reviewed engine update
```

Then generate and build the app:

```sh
xcodegen generate
xcodebuild -project Hop.xcodeproj -scheme Hop -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
```

Run tests:

```sh
xcodebuild test -project Hop.xcodeproj -scheme Hop -destination 'platform=iOS Simulator,id=<booted-simulator-udid>' CODE_SIGNING_ALLOWED=NO
```

Real device VPN execution requires the sideload signer to preserve App Group and `packet-tunnel-provider` Network Extension entitlements for both the app and the embedded tunnel extension, and to keep `HopTunnel.appex` (the sing-box engine is statically linked into it) enabled and re-signed.

## Security

Untrusted import data (pasted links, subscriptions, Shadowrocket `.conf`) is
constrained by a single policy in `Hop/Services/ImportPolicy.swift`:

- Subscriptions are fetched HTTPS-only and may not point at local, private,
  link-local, or cloud-metadata addresses (basic SSRF protection), with a
  request timeout and a response-size cap.
- Payloads are bounded by total bytes, decoded bytes, line count, item count,
  and base64 recursion depth.
- Import-supplied regular expressions (`policy-regex-filter`, `DOMAIN-REGEX`)
  are length-capped and compile-checked before use.
- URL-test probe URLs are restricted to public hosts, and interval/tolerance
  values are clamped to safe ranges before they reach the tunnel scheduler.
- Profiles imported with TLS certificate verification disabled (`allowInsecure`)
  surface a warning on import and a visible marker in the editor.
- Parser warnings/logs are redacted so credentials in malformed links are never
  persisted or exported.

Secrets — proxy passwords, UUIDs, WireGuard private keys, and REALITY keys — are
stored in the iOS **Keychain** (`Shared/SecretStore.swift`), not in cleartext
files. Persisted state holds only non-secret metadata; the generated sing-box
config carries secret *references* (`Shared/SecretReference.swift`) that the
packet-tunnel extension resolves from the shared Keychain at start time, so no
credentials are written to disk or passed through IPC/provider configuration.
The app and extension share these items through the
`keychain-access-groups` entitlement (`$(AppIdentifierPrefix)cat.string.hop`),
which a real-device signer must preserve alongside the App Group and Network
Extension entitlements. Existing plaintext state is migrated into the Keychain
automatically on first load.

Persisted app state, the generated sing-box config, and the tunnel log are also
written with `completeUntilFirstUserAuthentication` file protection as
defense-in-depth, and the tunnel log is size-rotated.

## Licensing

The protocol engine is sing-box/libbox, which is GPL licensed. Hop is therefore intended to be distributed as GPL-3.0-or-later compatible source.
