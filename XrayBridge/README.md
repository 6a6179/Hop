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
`676eaf66f8f05d4d558ee7a74b4736623d3feeb9`. Keep the direct registration list
in `registrations.go` explicit. Its transitive dependencies include Xray's
commander, metrics and reverse packages, whose initializers can register
configuration types. Hop's Swift configuration builder restricts which
features reach validation and startup. Inspect the iOS package graph with
`GOOS=ios GOARCH=arm64 CGO_ENABLED=1 go list -deps .` from this directory.

Xray's Darwin TUN driver duplicates NetworkExtension's descriptor before
wrapping it in `os.File`. Go closes its duplicate at shutdown, and the system
retains its original handle for the next connection.

Hop limits the November TCP stack to a 128 KiB window and 64 flows per stack.
UDP receive queues share a 2 MiB budget per stack. A flow belongs to one
source and destination pair, so routing runs independently for each peer.
Both the packet-tunnel inbound and the WireGuard userspace stack use these limits.

Each outbound TCP Mux worker accepts up to the configured number of active
sessions, from 1 to 8. An enabled Mux with zero or omitted concurrency uses
8. This limit applies per worker. XUDP has a separate concurrency setting.

The DNS outbound admits up to 16 outstanding lookup workers across core
instances. A and AAAA queries retain the selected preset's address handling,
including FakeDNS. Other record types use that preset's DoH resolver and
route, or Apple's scoped system resolver in System mode. The DoH path retains
the upstream DNS message. In System mode, Hop reconstructs the reply from
the records and status that Apple's DNS-SD API returns.

`scripts/build-libxray.sh` runs the TUN lifetime, DNS flow and response handling,
destination-IP routing, XDNS socket cleanup, and bridge tests with the race
detector before building the framework.
The bridge releases the core’s DNS and outbound manager references after
validation, failed start, or shutdown.
