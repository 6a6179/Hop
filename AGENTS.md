# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project overview

- Hop is an iOS SwiftUI app plus a Network Extension packet tunnel.
- The Xcode project is generated from `project.yml` with XcodeGen. Treat `project.yml` as the source of truth for targets, sources, settings, and dependencies.
- Main targets:
  - `Hop`: SwiftUI app, Swift 6.2.
  - `HopTunnel`: Network Extension, intentionally Swift 5.0 because libbox/gomobile bridge types are not Swift 6 Sendable-friendly.
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
  - Do not raise `HopTunnel` back to Swift 6 without auditing the libbox bridge.

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
(cd "$STAGE" && ditto -c -k --sequesterRsrc --keepParent Payload ../Hop-unsigned.ipa)
```

Remember: an unsigned IPA cannot be installed on a physical device without later signing/provisioning, especially because Hop includes a Network Extension entitlement.

## Validation expectations

- For code changes, run the narrowest relevant tests first, then the full unit test suite when practical.
- For project configuration changes, run `xcodegen generate` and at least an unsigned device build.
- For UI changes, verify both compile-time previews/builds and a simulator/app run when feasible.
- Report any warnings that matter, but do not fix unrelated issues unless asked.

## Repository hygiene

- Keep generated build products under `build/` and do not commit them unless the user explicitly asks.
- Do not add secrets, provisioning profiles, signing identities, or private API keys to the repo.
- Avoid changing bundle identifiers, entitlements, deployment targets, or signing settings unless the task requires it.
