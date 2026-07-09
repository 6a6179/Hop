# Verified Xray geodata

Hop ships a deliberately small subset of the official Xray-core `v26.6.27`
release assets so routing data stays within the iOS Network Extension memory
budget.

| Asset | Included categories | Size |
| --- | --- | ---: |
| `geoip.dat` | `CN`, `IR`, `PRIVATE` | 111,518 bytes |
| `geosite.dat` | `CATEGORY-IR` | 3,542 bytes |

The source is the official `Xray-macos-arm64-v8a.zip` release archive with
SHA-256 `5b63cf477b4281dc0d9d3af4d7b87391ab868a842b430e9ce8957ea0b60ecab7`.
`scripts/build-geodata.sh` verifies that archive, runs the pinned Go pruner,
and checks the deterministic output hashes before replacing these files.
`scripts/verify-geodata.sh` checks the committed hashes and size ceilings on
every tunnel build.

Both `Hop.app` and `HopTunnel.appex` contain the two `.dat` files at the bundle
resource root. Before calling Xray, `VerifiedXrayGeodata` verifies their sizes
and SHA-256 digests. Adding any category requires updating the Swift allowlist,
the build script, the checked-in assets, and the physical-device memory matrix.
