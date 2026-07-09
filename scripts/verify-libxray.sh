#!/usr/bin/env bash
# Verify the vendored Xray framework against its reviewed checksum manifest.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
frameworks_dir="$repo_root/Frameworks"
xcframework="$frameworks_dir/LibXray.xcframework"
manifest="$frameworks_dir/LibXray.xcframework.sha256"

err()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$*"; }

command -v shasum >/dev/null 2>&1 || err "shasum is required."
[[ -d "$xcframework" ]] || err "Frameworks/LibXray.xcframework not found. Run scripts/build-libxray.sh first."

compute_digest() {
  ( cd "$frameworks_dir" \
      && find "LibXray.xcframework" \( -type f -o -type l \) \
           -not -name '.DS_Store' -not -name '._*' -print0 \
      | LC_ALL=C sort -z \
      | while IFS= read -r -d '' path; do
          if [[ -L "$path" ]]; then
            printf 'L %s -> %s\n' "$path" "$(readlink "$path")"
          else
            printf 'F %s %s\n' "$(shasum -a 256 "$path" | awk '{print $1}')" "$path"
          fi
        done ) \
    | shasum -a 256 \
    | awk '{print $1}'
}

digest="$(compute_digest)"

if [[ "${1:-}" == "--update" ]]; then
  [[ $# -eq 1 ]] || err "usage: $0 [--update]"
  printf '%s\n' "$digest" > "$manifest"
  info "Recorded trusted LibXray.xcframework digest:"
  printf '  %s\n' "$digest"
  info "Wrote $manifest"
  exit 0
fi

[[ $# -eq 0 ]] || err "usage: $0 [--update]"
[[ -f "$manifest" ]] || err "Provenance manifest missing: $manifest
Run '$0 --update' after a reviewed engine build."

expected="$(tr -d '[:space:]' < "$manifest")"
[[ "$digest" == "$expected" ]] || err "LibXray.xcframework checksum mismatch!
  expected: $expected
  actual:   $digest
If this is an intentional reviewed update, run: $0 --update"

info "LibXray.xcframework matches the provenance manifest."
printf '  %s\n' "$digest"
