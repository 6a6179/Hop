# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project overview

- Hop is an iOS SwiftUI app plus a Network Extension packet tunnel.
- The Xcode project is generated from `project.yml` with XcodeGen. Treat `project.yml` as the source of truth for targets, sources, settings, and dependencies.
- Main targets:
  - `Hop`: SwiftUI app, Swift 6.2.
  - `HopTunnel`: Network Extension, Swift 6.2. Its libbox/gomobile bridge keeps concurrency boundaries explicit with value snapshots, `@preconcurrency`, and narrow unchecked `Sendable` wrappers.
  - `HopTests`: iOS unit tests.
- Shared code lives in `Shared/` and is compiled into both app and extension.
- `Frameworks/Libbox.xcframework` is a vendored static sing-box/libbox engine. Its provenance is checked by `scripts/verify-libbox.sh` against `Frameworks/Libbox.xcframework.sha256`.

## Before editing

- Check this file and any more-specific `AGENTS.md` files before modifying files.
- Prefer small, focused changes that preserve the current SwiftUI/XcodeGen structure.
- Do not manually edit `Hop.xcodeproj/project.pbxproj` for durable project changes. Edit `project.yml`, then run `xcodegen generate`.
- Do not replace or rebuild `Frameworks/Libbox.xcframework` unless explicitly asked. If it is rebuilt with `scripts/build-libbox.sh`, expect the checksum manifest to change too.
- The worktree may be dirty or uncommitted; do not revert unrelated user changes.

## Formatting and style

- Use the repo SwiftFormat config: `.swiftformat`.
- Format Swift changes with:

```sh
swiftformat Hop HopTunnel Shared HopTests
```

- Keep Swift code idiomatic and concise. Prefer value models for app state and avoid unnecessary abstractions.
- For Swift concurrency:
  - Keep app code compatible with Swift 6.2 checking.
  - Be careful when crossing from gomobile/libbox callback types into Swift concurrency; convert non-Sendable libbox objects into Hop-owned value types before dispatching or crossing actor/thread boundaries.
  - Keep `HopTunnel` in Swift 6.2 and avoid broad `@unchecked Sendable`; use it only for tightly scoped bridge wrappers with clear synchronization or lifetime guarantees.

## Invariants to preserve

Security and consistency properties that code changes must not regress:

- `SingBoxConfigBuilder` emits WireGuard profiles as sing-box `endpoints`, never as outbounds — the vendored sing-box 1.13 removed the `wireguard` outbound type and rejects the whole config if one appears. Endpoint tags share the outbound tag namespace, so groups and routes can reference them like any profile tag.
- Imported and refreshed data is untrusted (subscription servers and share links are attacker-controllable):
  - Subscription refreshes must never silently weaken a matched profile's security — layer demotions (REALITY → TLS → none) and `allowInsecure` flips are blocked by `SubscriptionRefreshMerger.securityPreservingDowngrades`, which records warnings the store logs.
  - Subscription refreshes must not install routing rules from the response; rules only apply through reviewed manual imports.
  - Every UI path that saves imported nodes with `allowInsecure` must run the blocking `insecureTLSImportConfirmation` first. The sheet flows gate themselves; the QR-scan and refresh paths in `ProfilesView` gate via `pendingInsecureScan`. New import paths need the same gate.
  - Subscription refreshes extend that gate to *new* nodes: `SubscriptionRefreshMerger.newInsecureProfileNames` decides which imported allow-insecure nodes are new (vs. updates to already-insecure nodes), `HopStore.refreshSubscription` returns `.needsInsecureConfirmation` instead of applying them, and `autoRefreshStaleSubscriptions` skips such refreshes outright — no user is present to confirm.
  - URL-scheme payloads — `hop://import` and the registered proxy share-link schemes (`AppShellView.proxyLinkSchemes`, mirrored in the app Info.plist's `CFBundleURLTypes`; a test asserts they stay in sync) — are untrusted (any app can open them). They only flow into the prefilled `ImportTextSheet`, never applied directly, so the preview and allow-insecure gates stay in force. The sheet auto-previews only payloads that parse locally; subscription URLs are never fetched without an explicit user tap.
  - Imported display names are sanitized (`ImportPolicy.sanitizeImportedName`, applied via `ImportResult.sanitizingNames()` at the `importText` exits): bidi/invisible characters are stripped and length is capped so a crafted name can't spoof the allow-insecure confirmation alert. Keep new parser entry points on this path.
  - Centralized limits and validation for untrusted import data live in `ImportPolicy`; route new parsing through it rather than adding ad-hoc checks.
- `HopStore` persists once per logical mutation: `didSet` observers call `persistUnlessBatched()`, multi-property mutations are wrapped in `withBatchedPersist`, and saves run on a serial background queue. Tests that assert on persisted state must call `flushPendingPersists()` first.
- `HopAppDataStore.save` skips the Keychain `replaceAll` when the secret set is unchanged since the last write (`SecretWriteCache`); the first save after launch always writes, and a failed `replaceAll` (the `SecretBackend` write methods return success flags for this) invalidates the cache so the next save retries instead of skipping forever. Secret changes must flow through profile values so the cache observes them — do not write profile secrets to the Keychain through side channels the cache can't see (the connect-time re-ensure in `TunnelController` writes identical values and is fine).
- `SecretStore.replaceAll` upserts new items before pruning stale keys. Never reintroduce a clear-then-rewrite pass: the tunnel extension can resolve secrets concurrently and must never observe an empty keychain.
- Tunnel-extension logging goes through `PacketTunnelProvider.writeTunnelLog`, and app-side logging through `TunnelController.appendLog`/`appendLogs` — both strip newlines so remote- or import-controlled text cannot forge log entries; keep new log writes on those paths.
- A manual `disconnect()` clears `isOnDemandEnabled` (and saves the manager) before `stopVPNTunnel`, or iOS immediately relaunches the tunnel under the on-demand rule and the user's stop does not stick. The next `connect()` re-arms on-demand from settings.
- Node share links (`ProxyShareLink`) embed credentials by design; they are only produced from the explicit context-menu actions, and pasteboard copies set an expiration. Don't add share/export paths that emit credentials implicitly.
- The libbox service state in `PacketTunnelProvider` (`commandServer`, `lastRawConfig`, `configSecretNonce`, `lastConfigSecretsAreResolved`) is guarded by `serviceStateLock` and accessed from three threads. Never call into libbox while holding the lock — its callbacks can re-enter the provider and deadlock. Clear the state under the lock before tearing the server down.
- Credential fields in editors (passwords, private keys) render as `SecureField` via `ProfileTextField(isSecure: true)`.
- Pin GitHub Actions `uses:` references to commit SHAs with the tag in a trailing comment; do not move them back to mutable tags.

## Build and test commands

Regenerate the project after `project.yml` changes:

```sh
xcodegen generate
```

Build the app without signing:

```sh
xcodebuild \
  -project Hop.xcodeproj \
  -scheme Hop \
  -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO \
  build
```

Run unit tests on an available simulator:

```sh
xcodebuild test \
  -project Hop.xcodeproj \
  -scheme Hop \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  CODE_SIGNING_ALLOWED=NO
```

If that simulator is unavailable, list devices with:

```sh
xcrun simctl list devices available
```

Then use a concrete simulator `id=` destination.

## Unsigned IPA packaging

A useful unsigned device-build flow is:

```sh
rm -rf build/UnsignedIPA
mkdir -p build/UnsignedIPA
xcodebuild \
  -project Hop.xcodeproj \
  -scheme Hop \
  -configuration Release \
  -sdk iphoneos \
  -destination 'generic/platform=iOS' \
  -derivedDataPath build/UnsignedIPA/DerivedData \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY="" \
  DEVELOPMENT_TEAM="" \
  PROVISIONING_PROFILE_SPECIFIER="" \
  build

APP="build/UnsignedIPA/DerivedData/Build/Products/Release-iphoneos/Hop.app"
STAGE="build/UnsignedIPA/staging"
rm -rf "$STAGE" build/UnsignedIPA/Hop-unsigned.ipa
mkdir -p "$STAGE/Payload"
ditto "$APP" "$STAGE/Payload/Hop.app"
find "$STAGE/Payload/Hop.app" \( -name _CodeSignature -o -name embedded.mobileprovision \) -print -exec rm -rf {} +
xattr -cr "$STAGE/Payload/Hop.app" || true
# Fakesign with the real entitlements (placeholder team prefix) so sideload
# signers can mirror them; without this, re-signing drops the Packet Tunnel
# entitlement from HopTunnel.appex and iOS kills the extension at launch.
sed 's/\$(AppIdentifierPrefix)/XXXXXXXXXX./' HopTunnel/HopTunnel.entitlements > "$STAGE/HopTunnel.entitlements"
sed 's/\$(AppIdentifierPrefix)/XXXXXXXXXX./' Hop/Hop.entitlements > "$STAGE/Hop.entitlements"
codesign --force --sign - --entitlements "$STAGE/HopTunnel.entitlements" "$STAGE/Payload/Hop.app/PlugIns/HopTunnel.appex"
codesign --force --sign - --entitlements "$STAGE/Hop.entitlements" "$STAGE/Payload/Hop.app"
(cd "$STAGE" && ditto -c -k --sequesterRsrc --keepParent Payload ../Hop-unsigned.ipa)
```

Remember: this IPA still cannot be installed on a physical device without later signing/provisioning. The ad-hoc fakesign step only embeds the entitlements each binary needs so the later signer can re-map them — the signer must keep the Packet Tunnel entitlement and App Group on both Hop.app and the embedded HopTunnel.appex, or the tunnel extension will not launch.

## Validation expectations

- For code changes, run the narrowest relevant tests first, then the full unit test suite when practical.
- For project configuration changes, run `xcodegen generate` and at least an unsigned device build.
- For UI changes, verify both compile-time previews/builds and a simulator/app run when feasible.
- Report any warnings that matter, but do not fix unrelated issues unless asked.

## Repository hygiene

- Keep generated build products under `build/` and do not commit them unless the user explicitly asks.
- Do not add secrets, provisioning profiles, signing identities, or private API keys to the repo.
- Avoid changing bundle identifiers, entitlements, deployment targets, or signing settings unless the task requires it.
