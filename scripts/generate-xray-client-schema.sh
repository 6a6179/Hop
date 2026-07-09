#!/usr/bin/env bash
# Regenerate or verify the checked-in client-schema manifest from pinned Xray structs.
set -euo pipefail

GO_VERSION="go1.26.5"
XRAY_TAG="v26.6.27"
XRAY_COMMIT="45cf2898ab12e97a55dd8f1f3d78d903340bdc9e"
XRAY_MODULE_VERSION="v1.260327.1-0.20260627131803-45cf2898ab12"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
bridge_dir="$repo_root/XrayBridge"
output="$repo_root/Hop/Resources/xray-client-schema-v26.6.27.json"

err()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$*"; }

mode="write"
case "${1:-}" in
  "") ;;
  --check) mode="check" ;;
  *) err "usage: $0 [--check]" ;;
esac

command -v go >/dev/null 2>&1 || err "Go $GO_VERSION is required."
[[ "$(go env GOVERSION 2>/dev/null)" == "$GO_VERSION" ]] \
  || err "Go $GO_VERSION is required; found $(go env GOVERSION 2>/dev/null || printf unknown)."

selected_version="$(cd "$bridge_dir" && GOWORK=off go list -mod=readonly -m -f '{{.Version}}' github.com/xtls/xray-core)"
[[ "$selected_version" == "$XRAY_MODULE_VERSION" ]] \
  || err "XrayBridge selects $selected_version, expected $XRAY_MODULE_VERSION."

module_json="$(cd "$bridge_dir" && GOWORK=off go mod download -json "github.com/xtls/xray-core@$XRAY_MODULE_VERSION")"
module_commit="$(printf '%s\n' "$module_json" | awk -F'"' '/"Hash":/ { print $4; exit }')"
[[ "$module_commit" == "$XRAY_COMMIT" ]] \
  || err "Downloaded Xray module resolved to ${module_commit:-nothing}, expected $XRAY_COMMIT ($XRAY_TAG)."
xray_source="$(printf '%s\n' "$module_json" | awk -F'"' '/"Dir":/ { print $4; exit }')"
[[ -d "$xray_source/infra/conf" ]] || err "Pinned Xray infra/conf source is unavailable."

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
(
  cd "$bridge_dir"
  GOWORK=off go run -mod=readonly ./cmd/schema-manifest -xray-source "$xray_source"
) > "$tmp"

if [[ "$mode" == "check" ]]; then
  [[ -f "$output" ]] || err "checked-in manifest is missing: $output"
  if ! cmp -s "$tmp" "$output"; then
    diff -u "$output" "$tmp" || true
    err "Xray client-schema manifest is stale; run scripts/generate-xray-client-schema.sh."
  fi
  info "Xray client-schema manifest matches pinned $XRAY_TAG ($XRAY_COMMIT)."
  exit 0
fi

mkdir -p "$(dirname "$output")"
mv "$tmp" "$output"
trap - EXIT
info "Generated $output from pinned $XRAY_TAG ($XRAY_COMMIT)."
