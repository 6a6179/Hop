#!/usr/bin/env bash
# Build Hop's pinned, client-only Xray gomobile bridge for iOS.
set -euo pipefail

GO_VERSION="go1.26.5"
XRAY_TAG="v26.6.27"
XRAY_COMMIT="45cf2898ab12e97a55dd8f1f3d78d903340bdc9e"
XRAY_MODULE_VERSION="v1.260327.1-0.20260627131803-45cf2898ab12"
GOMOBILE_VERSION="v0.0.0-20260709172247-6129f5bee9d5"
GOMOBILE_COMMIT="6129f5bee9d516e31842c9815bf24f60fa682b6e"
IOS_VERSION="26.0"
XRAY_IOS_PATCH="XrayBridge/patches/0001-bound-ios-tun-memory.patch"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
bridge_dir="$repo_root/XrayBridge"
frameworks_dir="$repo_root/Frameworks"
destination="$frameworks_dir/LibXray.xcframework"

err()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$*"; }

command -v go >/dev/null 2>&1 || err "Go $GO_VERSION is required."
command -v git >/dev/null 2>&1 || err "git is required."
command -v python3 >/dev/null 2>&1 || err "python3 is required to normalize the xcframework metadata."
command -v shasum >/dev/null 2>&1 || err "shasum is required."
command -v xcodebuild >/dev/null 2>&1 || err "Xcode is required."
[[ "$(go env GOVERSION 2>/dev/null)" == "$GO_VERSION" ]] \
  || err "Go $GO_VERSION is required; found $(go env GOVERSION 2>/dev/null || printf unknown)."
[[ -f "$bridge_dir/go.mod" ]] || err "XrayBridge/go.mod is missing."
[[ -f "$repo_root/$XRAY_IOS_PATCH" ]] || err "$XRAY_IOS_PATCH is missing."

remote_commit="$(git ls-remote https://github.com/XTLS/Xray-core.git "refs/tags/$XRAY_TAG" | awk 'NR == 1 { print $1 }')"
[[ "$remote_commit" == "$XRAY_COMMIT" ]] || err "Xray-core $XRAY_TAG resolved to ${remote_commit:-nothing}, expected $XRAY_COMMIT."

module_json="$(cd "$bridge_dir" && GOWORK=off go mod download -json "github.com/xtls/xray-core@$XRAY_MODULE_VERSION")"
module_commit="$(printf '%s\n' "$module_json" | awk -F'"' '/"Hash":/ { print $4; exit }')"
[[ "$module_commit" == "$XRAY_COMMIT" ]] || err "Downloaded Xray module resolved to ${module_commit:-nothing}, expected $XRAY_COMMIT."
selected_version="$(cd "$bridge_dir" && GOWORK=off go list -mod=readonly -m -f '{{.Version}}' github.com/xtls/xray-core)"
[[ "$selected_version" == "$XRAY_MODULE_VERSION" ]] || err "XrayBridge selects $selected_version, expected $XRAY_MODULE_VERSION."

mobile_json="$(GOWORK=off go mod download -json "golang.org/x/mobile@$GOMOBILE_VERSION")"
mobile_commit="$(printf '%s\n' "$mobile_json" | awk -F'"' '/"Hash":/ { print $4; exit }')"
[[ "$mobile_commit" == "$GOMOBILE_COMMIT" ]] || err "Go Mobile resolved to ${mobile_commit:-nothing}, expected $GOMOBILE_COMMIT."

work_dir="/private/tmp/hop-libxray-build"
lock_dir="$work_dir.lock"
mkdir "$lock_dir" 2>/dev/null || err "another LibXray build is active (remove stale $lock_dir if no build is running)."
cleanup() {
  rm -rf "$work_dir"
  rmdir "$lock_dir" 2>/dev/null || true
}
trap cleanup EXIT
rm -rf "$work_dir"
bin_dir="$work_dir/bin"
output="$work_dir/LibXray.xcframework"
mkdir -p "$bin_dir"

# Keep the upstream module immutable and pinned, but patch a temporary copy
# while compiling. Xray's generic gVisor defaults permit multi-megabyte buffers
# per flow and its current UDP path retains much larger queues than an iOS
# packet-tunnel process can afford. A fixed private work path plus a relative
# module replacement keeps Go's embedded source/build metadata deterministic.
module_dir="$(printf '%s\n' "$module_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Dir"])')"
patch_digest="$(shasum -a 256 "$repo_root/$XRAY_IOS_PATCH" | awk '{print $1}')"
(
  cd "$module_dir"
  git apply --unidiff-zero --check "$repo_root/$XRAY_IOS_PATCH"
)
patched_module="$work_dir/xray-core"
cp -R "$module_dir" "$patched_module"
chmod -R u+w "$patched_module"
(
  cd "$patched_module"
  git apply --unidiff-zero "$repo_root/$XRAY_IOS_PATCH"
)
build_bridge="$work_dir/XrayBridge"
cp -R "$bridge_dir" "$build_bridge"
chmod -R u+w "$build_bridge"
(
  cd "$build_bridge"
  GOWORK=off go mod edit -replace=github.com/xtls/xray-core=../xray-core
)

info "Installing pinned gomobile $GOMOBILE_COMMIT ..."
GOBIN="$bin_dir" GOWORK=off go install "golang.org/x/mobile/cmd/gomobile@$GOMOBILE_VERSION"
GOBIN="$bin_dir" GOWORK=off go install "golang.org/x/mobile/cmd/gobind@$GOMOBILE_VERSION"
export PATH="$bin_dir:$PATH"
"$bin_dir/gomobile" init

info "Building LibXray.xcframework for iOS and iOS Simulator ..."
(
  cd "$build_bridge"
  GOWORK=off ZERO_AR_DATE=1 "$bin_dir/gomobile" bind \
    -target=ios,iossimulator \
    -iosversion="$IOS_VERSION" \
    -trimpath \
    -ldflags='-s -w -buildid=' \
    -o "$output" \
    .
)

[[ -d "$output" ]] || err "gomobile completed without producing LibXray.xcframework."

# gomobile stamps framework plists with the current time and xcodebuild may
# return XCFramework slices in either order. Normalize both sources of noise.
python3 - "$output" "${XRAY_TAG#v}" <<'PY'
import pathlib
import plistlib
import sys

root = pathlib.Path(sys.argv[1])
version = sys.argv[2]
for path in root.rglob("Info.plist"):
    with path.open("rb") as file:
        value = plistlib.load(file)
    if "CFBundleVersion" in value:
        value["CFBundleVersion"] = version
        value["CFBundleShortVersionString"] = version
    libraries = value.get("AvailableLibraries")
    if libraries is not None:
        libraries.sort(key=lambda item: item["LibraryIdentifier"])
    with path.open("wb") as file:
        plistlib.dump(value, file, sort_keys=True)
PY

header="$(find "$output" -type f -name 'LibXray.h' -print -quit)"
[[ -n "$header" ]] || err "LibXray.h is missing from the generated framework."
if ! grep -Rqs --include='*.h' 'LibXrayInvoke' "$output"; then
  grep -R -E 'Invoke|FOUNDATION_EXPORT' "$output" --include='*.h' >&2 || true
  err "Generated framework does not export LibXrayInvoke."
fi

mkdir -p "$frameworks_dir"
rm -rf "$destination"
mv "$output" "$destination"
"$repo_root/scripts/verify-libxray.sh" --update

info "Done -> $destination"
info "Pinned Xray: $XRAY_TAG ($XRAY_COMMIT)"
info "Applied iOS patch: $XRAY_IOS_PATCH ($patch_digest)"
info "Pinned Go Mobile: $GOMOBILE_COMMIT"
