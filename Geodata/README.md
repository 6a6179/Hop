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
Xray obtains the data from Loyalsoldier/v2ray-rules-dat. The retained IR
networks include GeoLite2 data created by MaxMind, available from
[MaxMind](https://www.maxmind.com). CN uses Yifan Gao's operator IP lists.
PRIVATE uses Loyalsoldier's special-use ranges. CATEGORY-IR comes from
V2Fly's Domain List Community. [Credits, source configurations and data terms](NOTICE.txt)

`scripts/build-geodata.sh` verifies that archive, runs the pinned Go pruner,
and checks the deterministic output hashes before replacing these files.
`scripts/verify-geodata.sh` checks the committed hashes and size ceilings on
every tunnel build.

Both `Hop.app` and `HopTunnel.appex` contain the two `.dat` files at the bundle
resource root. Before calling Xray, `VerifiedXrayGeodata` verifies their sizes
and SHA-256 digests. Adding any category requires updating the Swift allowlist,
the build script, the checked-in assets, and the source credits. Regenerate
the packaged credits with `GOTOOLCHAIN=go1.27.4 scripts/generate-acknowledgments.py`.

### Measure a category change on a device

1. Build and sign Release versions of both the baseline and candidate for the
   same physical iPhone. Record its model, iOS build, source revisions, asset
   sizes and hashes, and the test profile. Use the same server and routing
   configuration in both runs.
2. Test the built-in China and Iran presets and a rule that uses the new
   category. Cold-start the tunnel, exercise matching and fallback traffic,
   keep DNS and proxied traffic active for five minutes, then disconnect and
   reconnect three times. Verify the expected direct, proxy and reject routes
   with known destinations.
3. In Instruments, capture the **HopTunnel** process's physical footprint
   from startup through the final reconnect using VM Tracker. Record peak and
   steady-state MiB, together with any memory-watchdog messages and device
   jetsam reports. Attach the measurements and trace to the change's review.
   The expected workload should stay below the 42 MiB soft threshold with
   no watchdog termination or jetsam. A 46 MiB hard-limit event fails the run.
