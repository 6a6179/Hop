#!/usr/bin/env bash
#
# Verifies the integrity of the vendored Frameworks/Libbox.xcframework against
# a checked-in checksum manifest, giving the privileged tunnel engine a
# tamper-evident provenance baseline.
#
# Any change to the vendored binary that isn't an intentional, reviewed update
# (which regenerates the manifest via `--update`) makes verification fail. The
# Xcode build runs this as a pre-build step, and scripts/build-libbox.sh runs
# `--update` automatically after producing a fresh framework.
#
# Usage:
#   ./scripts/verify-libbox.sh            # verify (default; non-zero on mismatch)
#   ./scripts/verify-libbox.sh --update   # record the current digest as trusted
#
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
frameworks_dir="$repo_root/Frameworks"
xcframework="$frameworks_dir/Libbox.xcframework"
manifest="$frameworks_dir/Libbox.xcframework.sha256"

err()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$*"; }

command -v shasum >/dev/null 2>&1 || err "shasum is required."
[[ -d "$xcframework" ]] || err "Frameworks/Libbox.xcframework not found. Run scripts/build-libbox.sh first."

# Deterministic digest over every regular file in the xcframework: hash each
# file (with its relative path), sort stably, then hash the combined list.
# Spurious filesystem noise (.DS_Store, AppleDouble) is excluded.
compute_digest() {
  ( cd "$frameworks_dir" \
      && find "Libbox.xcframework" -type f \
           -not -name '.DS_Store' -not -name '._*' -print0 \
      | LC_ALL=C sort -z \
      | xargs -0 shasum -a 256 ) \
    | shasum -a 256 \
    | awk '{print $1}'
}

digest="$(compute_digest)"

if [[ "${1:-}" == "--update" ]]; then
  printf '%s\n' "$digest" > "$manifest"
  info "Recorded trusted Libbox.xcframework digest:"
  printf '  %s\n' "$digest"
  info "Wrote $manifest"
  exit 0
fi

[[ -f "$manifest" ]] \
  || err "Provenance manifest missing: $manifest
Run '$0 --update' after a reviewed engine update to record the trusted digest."

expected="$(tr -d '[:space:]' < "$manifest")"
if [[ "$digest" != "$expected" ]]; then
  err "Libbox.xcframework checksum mismatch!
  expected: $expected
  actual:   $digest
The vendored tunnel engine does not match the checked-in provenance manifest.
If this is an intentional, reviewed engine update, run: $0 --update"
fi

info "Libbox.xcframework matches the provenance manifest."
printf '  %s\n' "$digest"
