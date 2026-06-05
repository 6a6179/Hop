#!/usr/bin/env bash
#
# Builds Libbox.xcframework — the sing-box engine that powers Hop's packet
# tunnel — and drops it into Frameworks/. Pinned to a known-good sing-box
# release so the build is reproducible.
#
# This uses sing-box's own `build_libbox` tool, so the gomobile flags and
# build tags always match what upstream ships, instead of us hand-maintaining
# them here.
#
# Requirements:
#   - Go 1.23+                       (brew install go)
#   - Xcode + command line tools     (clang, for cgo)
#   - git
#
# Usage:
#   ./scripts/build-libbox.sh
#
# Output:
#   Frameworks/Libbox.xcframework    (device + simulator slices)
#
set -euo pipefail

# Latest sing-box stable as of writing. Bump deliberately — the generated
# Libbox Swift API can change between minor versions, and HopTunnel is written
# against this one (see HopTunnel/PlatformInterface.swift).
SING_BOX_VERSION="v1.13.12"
# Immutable commit the tag must resolve to. A tag is mutable (it can be moved or
# re-pointed upstream), so we pin and verify the exact commit before running any
# upstream build code — guards against a compromised/retagged dependency
# (CWE-345 / CWE-494). When bumping SING_BOX_VERSION, update this to the new
# tag's commit (e.g. `git ls-remote https://github.com/SagerNet/sing-box <tag>`).
SING_BOX_COMMIT="1086ab2563320e0da0c23b3a491d8dfa0939dff4"
APPLE_TARGETS="ios,iossimulator"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
frameworks_dir="$repo_root/Frameworks"

err()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$*"; }

command -v go  >/dev/null 2>&1 || err "Go is required (brew install go). Need 1.23+."
command -v git >/dev/null 2>&1 || err "git is required."

# sing-box links with -checklinkname=0, which needs Go 1.23+.
go_version="$(go env GOVERSION 2>/dev/null || true)"   # e.g. "go1.23.4"
go_minor="$(printf '%s' "$go_version" | sed -E 's/^go1\.([0-9]+).*/\1/')"
if [[ -z "$go_minor" || "$go_minor" -lt 23 ]]; then
  err "Go 1.23+ required, found '${go_version:-unknown}'."
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
src_dir="$work_dir/sing-box"

info "Cloning sing-box $SING_BOX_VERSION ..."
git clone --quiet --depth 1 --branch "$SING_BOX_VERSION" \
  https://github.com/SagerNet/sing-box "$src_dir"

cd "$src_dir"

# Verify the tag resolved to the pinned commit BEFORE running any upstream code.
actual_commit="$(git rev-parse HEAD)"
if [[ "$actual_commit" != "$SING_BOX_COMMIT" ]]; then
  err "sing-box $SING_BOX_VERSION resolved to $actual_commit, expected $SING_BOX_COMMIT.
The upstream tag may have moved or been tampered with. Refusing to build the
tunnel engine from an unverified commit. If this is an intentional version bump,
update SING_BOX_COMMIT in this script after reviewing the upstream changes."
fi
info "Verified sing-box commit $actual_commit"

info "Installing gomobile/gobind toolchain ..."
make lib_install
export PATH="$(go env GOPATH)/bin:$PATH"

info "Building Libbox.xcframework for $APPLE_TARGETS — this can take 10-15 min ..."
go run ./cmd/internal/build_libbox -target apple -platform "$APPLE_TARGETS"

[[ -d "$src_dir/Libbox.xcframework" ]] \
  || err "build_libbox finished but Libbox.xcframework was not produced."

mkdir -p "$frameworks_dir"
rm -rf "$frameworks_dir/Libbox.xcframework"
mv "$src_dir/Libbox.xcframework" "$frameworks_dir/"

# Record the trusted checksum of the freshly built engine so the Xcode build's
# pre-build verification (scripts/verify-libbox.sh) accepts this exact binary.
info "Recording provenance checksum ..."
"$repo_root/scripts/verify-libbox.sh" --update

info "Done -> $frameworks_dir/Libbox.xcframework"
info "Commit the updated Frameworks/Libbox.xcframework.sha256 alongside the engine."
info "Next: xcodegen generate && xcodebuild -scheme Hop ... (see README)"
