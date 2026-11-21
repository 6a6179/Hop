# Third-party notices

`LibXray.xcframework` statically includes
[XTLS/Xray-core](https://github.com/XTLS/Xray-core) `v26.11.9` at commit
`676eaf66f8f05d4d558ee7a74b4736623d3feeb9`, licensed under the Mozilla Public
License 2.0. The complete, reproducible transitive Go module inventory is
recorded in `go.mod` and `go.sum`. The IPA includes the generated
[`Acknowledgments.txt`](Acknowledgments.txt) in the host app. It contains
license texts for Go, Go Mobile and dependencies used for both iOS
architectures, plus credits for the pruned routing data.

Regenerate it with `GOTOOLCHAIN=go1.27.4 scripts/generate-acknowledgments.py`
from the repository root. Use `--check` to verify the checked-in bytes. The
engine build repeats the check against the patched Xray module and release
packaging compares the resource in the IPA with the checked-in copy.

Hop builds the following changes to the upstream source.

- `0001-bound-ios-tun-memory.patch` adapts the lightweight TUN stack to the iOS packet tunnel's memory budget and descriptor lifetime.
- `0002-release-system-dialer.patch` synchronizes the core's DNS and outbound manager references so the bridge can release them when an instance closes.
- `0003-prefer-packet-destination.patch` preserves the packet destination for IP rules when route-only sniffing supplies a hostname.
- `0004-bound-client-queues.patch` limits the WireGuard, Hysteria, and mKCP client queues.
- `0005-xdns-resolver-dial.patch` makes the XDNS client dial its configured resolvers directly.
- `0006-reclaim-completed-dns-flows.patch` reclaims completed DNS exchanges on the tunnel's virtual resolvers so their UDP flows do not exhaust the iOS flow limit.
- `0007-dns-terminal-errors.patch` returns SERVFAIL to the client when an upstream DNS lookup fails, allowing the client to retry.
- `0008-isolate-udp-routes-and-rollback-core.patch` routes UDP destinations independently and cleans up partially constructed core instances.
- `0009-bound-dns-lookups.patch` bounds concurrent address lookups across tunnel instances.
- `0010-forward-dns-records.patch` forwards additional DNS record types using the configured resolver.
- `0011-honor-ios-mux-concurrency.patch` preserves the configured per-worker TCP Mux concurrency and enforces Hop’s eight-session limit when creating the outbound handler.

These patches are distributed in `patches/` alongside the bridge source.

Additional upstream notices include the following.

- REALITY includes MPL 2.0 code and code derived from Go. [REALITY license](https://github.com/XTLS/REALITY/blob/4bb46b2afd8b4f1f082fbaccae34fd3c7a3f8973/LICENSE) and [Go-derived code notice](https://github.com/XTLS/REALITY/blob/4bb46b2afd8b4f1f082fbaccae34fd3c7a3f8973/LICENSE-Go).
- The Lua binding `gopher-luar` v1.0.11 uses MPL 2.0. [License](https://github.com/layeh/gopher-luar/blob/2aa5885def8a7168875e5d2e469e4116584707c0/LICENSE).
- The `go-brrr` v1.3.1 Brotli implementation is copyright Andrii Berezhynskyi and distributed under the MIT License. [License](https://github.com/molecule-man/go-brrr/blob/4c40d5fdda5b3abf7fd3792d774c26a2c8b70b27/LICENSE).
- Canonical's `ratelimit` v1.0.2 is distributed under LGPLv3 with a linking exception. [License and exception](https://github.com/juju/ratelimit/blob/v1.0.2/LICENSE).

The build uses [Go Mobile](https://go.googlesource.com/mobile) at commit
`6129f5bee9d516e31842c9815bf24f60fa682b6e` (BSD 3-Clause). It generates the
Objective-C boundary and supplies its binding support code.
