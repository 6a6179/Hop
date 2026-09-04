# Xray client field coverage

Audited against Xray **v26.6.27**, commit `45cf2898ab12e97a55dd8f1f3d78d903340bdc9e`, and its Go 1.26.5 runtime. This is **Hop's iOS client scope**, not every field in Xray's shared client/server structs.

The editor uses short native fields and expandable sections for less-common options. The generated schema describes upstream shapes; the builder's allowlists decide what Hop can actually run. Raw JSON remains optional, not a requirement for normal editing.

## Protocols

Every profile has a server address and port. Protocol-specific coverage:

| Protocol | Client fields | Deliberate exclusions |
|---|---|---|
| VLESS | ID, flow, encryption/auth, email, preconnections, Vision padding | `seed` is ignored upstream; reverse proxy is outside Hop's client scope. |
| Trojan | Password, email | `flow` was removed upstream. |
| Shadowsocks | Method, password, email | Insecure/unsupported ciphers; external plugins. |
| VMess | ID, security, email, experiments | Legacy nonzero `alterId`; insecure ciphers. |
| HTTP | Username, password, email, headers | Server/listener settings. |
| SOCKS | Username, password, email | Server/listener settings. |
| Hysteria2 | Password, upload/download, port hopping/interval, Salamander/password, UDP idle timeout | Version is fixed to 2; timeout is 2–600 seconds. Legacy congestion/bandwidth/hopping fields moved to FinalMask. |
| WireGuard | Private key, local addresses, peers, peer endpoints/public keys/PSKs/allowed IPs/keepalive, MTU, reserved bytes, domain strategy | `noKernelTun` is forced on; peer email/level are server-side fields. |

`level` is fixed to Hop's memory-bounded policy. Legacy `servers`/`vnext` containers do not create parallel editable endpoints: Hop represents nodes as separate profiles. TUIC, AnyTLS and the removed generic QUIC transport cannot run in this pinned core.

## Security

| Layer | Client coverage | Not exposed |
|---|---|---|
| TLS | SNI, ALPN, fingerprint, certificate pins, verification names, inline ECH, curves, TLS min/max, cipher suites, session resumption | Custom certificates/roots and `disableSystemRoot` need typed trust-review support; resolver-form ECH is unsupported, so `echSockopt` would do nothing. |
| REALITY | Public key (`password` upstream), short ID, SNI, fingerprint, SpiderX, ML-DSA verify key | ALPN is not a REALITY field. `show` prints authentication/session material. Server private keys, targets, fallback limits and related server fields are excluded. |

`allowInsecure` is retained only to review legacy imports; the pinned core rejects it. TLS server keys, unknown-SNI rejection, external certificate files and key logging are not client editor options. Security-critical fields remain typed so subscription refreshes cannot bypass review.

## Transports and shared options

| Section | Client coverage | Constraints |
|---|---|---|
| RAW/TCP | Header type and HTTP header settings | PROXY-protocol acceptance is listener-only. |
| WebSocket | Host, path, headers, heartbeat | PROXY-protocol acceptance is listener-only. |
| gRPC | Authority, service name, multi-mode, idle/health timeouts, permit-without-stream, user agent | Initial window stays at `0` (the core default), as required by Hop's iOS policy. |
| HTTP Upgrade | Host, path, headers | PROXY-protocol acceptance is listener-only. |
| XHTTP | Host, path, mode; headers, padding, request/session/sequence placement, chunk/post limits, post timing and XMux fields | `noSSEHeader`, `scMaxBufferedPosts`, `scStreamUpServerSecs`, `serverMaxHeaderBytes` are server-only. Separate `downloadSettings` needs a typed, reviewed secondary connection. Outer client fields are normalized into `extra`; ignored/colliding placements are rejected. |
| mKCP | MTU, TTI, upload/download capacity, congestion-window multiplier, send window | Old `header` and `seed` were removed. Buffer caps still apply. |
| Hysteria | Version/auth from protocol fields; UDP idle timeout | Bandwidth, congestion and hopping use FinalMask QUIC parameters. |
| Mux | Enabled, concurrency, XUDP concurrency, UDP/443 policy | Concurrency caps still apply. |
| Socket | TCP Fast Open, domain strategy, dialer proxy, keepalive interval/idle, interface, address/port strategy, Happy Eyeballs, XHTTP penetration | See unavailable options below. |
| FinalMask | TCP/UDP mask lists and QUIC parameters; per-type settings | Payload/window/layer caps and existing secret/network-destination validation apply. QUIC incoming streams stay at `0`. |

FinalMask's pinned loaders register TCP `header-custom`, `fragment`, `sudoku`; UDP `header-custom`, `mkcp-legacy`, `noise`, `salamander`, `sudoku`, `xdns`, `xicmp`, `realm`. A registered type is not permission to bypass Hop's validation: secret-bearing settings must use supported secret-handling paths, and unsupported server fields remain unavailable. XDNS uses client `resolvers`; its old `domain` field was removed.

Socket options rejected rather than silently ignored:

- `mark`, `tproxy`, `tcpCongestion`, `tcpWindowClamp`, `tcpMaxSeg`, `tcpUserTimeout`: no Darwin outbound implementation.
- `tcpMptcp`: Go 1.26.5's non-Linux implementation falls back to ordinary TCP.
- `acceptProxyProtocol`, `trustedXForwardedFor`, `v6only`: listener-side behavior.
- `customSockopt`: deliberately outside Hop's safe iOS socket surface.

Independent stream address/port overrides, custom TLS trust stores and split XHTTP download connections remain unsupported. Adding them requires real typed models, import/refresh security review and runtime tests—not merely showing a field that gets discarded.

## Evidence and regression checks

Authority: the pinned core's `infra/conf` builders, transport dialers/listeners, Darwin socket implementation, and Go's non-Linux MPTCP implementation—not documentation for a newer core. The schema generator check detects drift against that source. Protocol and transport tests verify emitted fields, exact-core parsing, collisions, ignored-field rejection and memory ceilings. A parse test does not establish a successful live connection.
