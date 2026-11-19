# Hop Xray bridge

This package is the sole Go/Swift boundary for Hop. `gomobile bind` exports:

```text
LibXrayInvoke(requestJSON: String) -> String
```

Requests use schema version `1` and one of `validate`, `start`, `stop`,
`collectMemory`, or `version`. Responses always use the shape
`{"version":1,"ok":...,"result":...,"error":...}`. The compatibility aliases
`runXrayFromJson` and `stopXray` remain accepted by the bridge.

Xray-core is pinned to tag `v26.11.9`, commit
`676eaf66f8f05d4d558ee7a74b4736623d3feeb9`. Do not replace the explicit
registration list with `main/distro/all`: Hop intentionally omits command,
reverse-proxy, metrics-listener, and shell/CLI packages.

Xray's Darwin TUN driver duplicates NetworkExtension's descriptor before
wrapping it in `os.File`. Go closes its duplicate at shutdown, and the system
retains its original handle for the next connection.

Hop limits the November TCP stack to a 128 KiB window and 64 flows per stack.
UDP receive queues share a 2 MiB budget per stack. Both the packet-tunnel
inbound and the WireGuard userspace stack use these limits.

`scripts/build-libxray.sh` runs the TUN lifetime, destination-IP routing, XDNS
socket cleanup, and bridge tests with the race detector before building the framework.
The bridge releases the core’s DNS and outbound manager references after
validation, failed start, or shutdown.
