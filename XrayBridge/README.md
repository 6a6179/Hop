# Hop Xray bridge

This package is the sole Go/Swift boundary for Hop. `gomobile bind` exports:

```text
LibXrayInvoke(requestJSON: String) -> String
```

Requests use schema version `1` and one of `validate`, `start`, `stop`,
`stats`, `collectMemory`, or `version`. Responses always use the shape
`{"version":1,"ok":...,"result":...,"error":...}`. The compatibility aliases
`runXrayFromJson`, `stopXray`, and `getXrayState` remain accepted by the bridge.

Xray-core is pinned to tag `v26.6.27`, commit
`45cf2898ab12e97a55dd8f1f3d78d903340bdc9e`. Do not replace the explicit
registration list with `main/distro/all`: Hop intentionally omits command,
reverse-proxy, metrics-listener, and shell/CLI packages.

The iOS patch duplicates NetworkExtension's TUN descriptor before wrapping it
in `os.File`. Go closes only its duplicate, waking pending reads without
closing the system-owned descriptor. Packet-reader attachment is synchronized
so delayed shutdown cannot detach a replacement reader.

`scripts/build-libxray.sh` runs the patched TUN lifetime and shutdown regression
tests with the race detector before building the framework.
