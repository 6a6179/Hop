#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT/Geodata"
[ -f geodata.sha256 ] || { echo "Missing Geodata/geodata.sha256" >&2; exit 1; }

# Keep the bundle well below the size of the 28 MiB upstream assets and fail
# closed if the manifest is extended to checksum an unexpected path.
awk '
  NR == 1 && $1 ~ /^[0-9a-f]{64}$/ && $2 == "geoip.dat" { next }
  NR == 2 && $1 ~ /^[0-9a-f]{64}$/ && $2 == "geosite.dat" { next }
  { exit 1 }
  END { if (NR != 2) exit 1 }
' geodata.sha256 || { echo "Invalid Geodata/geodata.sha256 manifest" >&2; exit 1; }

shasum -a 256 -c geodata.sha256

GEOIP_BYTES=$(wc -c < geoip.dat | tr -d ' ')
GEOSITE_BYTES=$(wc -c < geosite.dat | tr -d ' ')
[ "$GEOIP_BYTES" -le 262144 ] || { echo "geoip.dat exceeds the 256 KiB memory envelope" >&2; exit 1; }
[ "$GEOSITE_BYTES" -le 65536 ] || { echo "geosite.dat exceeds the 64 KiB memory envelope" >&2; exit 1; }
