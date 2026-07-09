#!/bin/sh
set -eu
export LC_ALL=C
umask 022

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TAG=v26.6.27
ARCHIVE=Xray-macos-arm64-v8a.zip
URL="https://github.com/XTLS/Xray-core/releases/download/$TAG/$ARCHIVE"
EXPECTED_ARCHIVE_SHA256=5b63cf477b4281dc0d9d3af4d7b87391ab868a842b430e9ce8957ea0b60ecab7
EXPECTED_GEOIP_SHA256=6c7ecd14515ee22f50a796f87fb28220353e2ef7a267846e7f8766289d58e841
EXPECTED_GEOSITE_SHA256=21bf8b6e0233cb481a6f40dbe09b850981642598d848be8500ce0281019f5d8c
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl --fail --show-error --silent --location --retry 3 "$URL" -o "$TMP/$ARCHIVE"
ACTUAL=$(shasum -a 256 "$TMP/$ARCHIVE" | awk '{print $1}')
[ "$ACTUAL" = "$EXPECTED_ARCHIVE_SHA256" ] || {
  echo "geodata archive checksum mismatch: expected $EXPECTED_ARCHIVE_SHA256, got $ACTUAL" >&2
  exit 1
}
unzip -q "$TMP/$ARCHIVE" geoip.dat geosite.dat -d "$TMP"

# Keep only categories used by the built-in China and Iran configurations.
# PRIVATE is required by both presets and is an ordinary entry in geoip.dat.
OUTPUT="$TMP/pruned"
(
  cd "$ROOT/XrayBridge"
  go run ./cmd/prune-geodata \
    -geoip "$TMP/geoip.dat" \
    -geosite "$TMP/geosite.dat" \
    -geoip-codes CN,IR,PRIVATE \
    -geosite-codes CATEGORY-IR \
    -out "$OUTPUT"
)

ACTUAL_GEOIP_SHA256=$(shasum -a 256 "$OUTPUT/geoip.dat" | awk '{print $1}')
ACTUAL_GEOSITE_SHA256=$(shasum -a 256 "$OUTPUT/geosite.dat" | awk '{print $1}')
[ "$ACTUAL_GEOIP_SHA256" = "$EXPECTED_GEOIP_SHA256" ] || {
  echo "pruned geoip.dat is not reproducible: expected $EXPECTED_GEOIP_SHA256, got $ACTUAL_GEOIP_SHA256" >&2
  exit 1
}
[ "$ACTUAL_GEOSITE_SHA256" = "$EXPECTED_GEOSITE_SHA256" ] || {
  echo "pruned geosite.dat is not reproducible: expected $EXPECTED_GEOSITE_SHA256, got $ACTUAL_GEOSITE_SHA256" >&2
  exit 1
}

mkdir -p "$ROOT/Geodata"
install -m 0644 "$OUTPUT/geoip.dat" "$ROOT/Geodata/geoip.dat"
install -m 0644 "$OUTPUT/geosite.dat" "$ROOT/Geodata/geosite.dat"
(
  cd "$ROOT/Geodata"
  shasum -a 256 geoip.dat geosite.dat > geodata.sha256
)
"$ROOT/scripts/verify-geodata.sh"
echo "Generated verified, pruned Xray geodata in $ROOT/Geodata"
