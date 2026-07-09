# Third-party notices

`LibXray.xcframework` statically includes
[XTLS/Xray-core](https://github.com/XTLS/Xray-core) `v26.6.27` at commit
`45cf2898ab12e97a55dd8f1f3d78d903340bdc9e`, licensed under the Mozilla Public
License 2.0. The complete, reproducible transitive Go module inventory is
recorded in `go.mod` and `go.sum`.

The iOS build applies the reviewed source patch in
`patches/0001-bound-ios-tun-memory.patch`. It bounds each gVisor TUN TCP
receive/send buffer to 256 KiB, removes per-packet UDP clone churn, bounds UDP
queues, and avoids retaining duplicate Darwin ingress buffers so sustained
traffic remains inside the Network Extension memory budget.

The build uses [Go Mobile](https://go.googlesource.com/mobile) at commit
`6129f5bee9d516e31842c9815bf24f60fa682b6e` (BSD 3-Clause). It generates the
Objective-C boundary and supplies its binding support code.
