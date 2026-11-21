# Xray client field coverage

Audited against Xray **v26.11.9**, commit `676eaf66f8f05d4d558ee7a74b4736623d3feeb9`, and its Go 1.27.4 runtime. This is **Hop's iOS client scope**, not every field in Xray's shared client/server structs.

The editor uses short native fields and expandable sections for less-common options. The generated schema describes upstream shapes; the builder's allowlists decide what Hop can actually run. Raw JSON remains optional, not a requirement for normal editing.

## Protocols

Every profile has a server address and port. The table lists the supported client options.

| Protocol | Client fields | Deliberate exclusions |
|---|---|---|
| VLESS | ID, flow, encryption/auth, email, preconnections, Vision padding | `seed` is ignored upstream; reverse proxy is outside Hop's client scope. |
| Trojan | Password, email | `flow` was removed upstream. |
| Shadowsocks | Method, password, email | Insecure/unsupported ciphers and external plugins. For oversized base64 SS2022 keys accepted by earlier versions, Hop derives the same wire key for the new core and preserves the original for sharing. |
| VMess | ID, security, email, experiments | Legacy nonzero `alterId`; insecure ciphers. |
| HTTP | Username, password, email, headers | Server/listener settings. |
| SOCKS | Username, password, email | Server/listener settings. |
| Hysteria2 | Password, upload/download, port hopping/interval, Salamander/password, UDP idle timeout | Version is fixed to 2; timeout is 2–600 seconds. Legacy congestion/bandwidth/hopping fields moved to FinalMask. |
| WireGuard | Private key, local addresses, peers, peer endpoints/public keys/PSKs/allowed IPs/keepalive, MTU, reserved bytes | Hop forces `noKernelTun` on. Peer email and level are server-only. November removes outbound `domainStrategy`. The default and legacy `ForceIP` omit that field. An explicit address-family strategy requires user review. Hop excludes the new `remoteDNS` destinations. |

Existing public VLESS and Trojan nodes configured with plaintext transport can stop validating when upgrading from a core predating v26.7.28. Configure the server’s TLS or REALITY settings, or use the server’s VLESS Encryption parameters. Xray still permits plaintext for its built-in private IP ranges and private domain suffixes. A FinalMask transport alone does not satisfy the public-server check.

`level` is fixed to Hop's memory-bounded policy. Legacy `servers`/`vnext` containers do not create parallel editable endpoints: Hop represents nodes as separate profiles. TUIC, AnyTLS and the removed generic QUIC transport cannot run in this pinned core.

## Security

| Layer | Client coverage | Not exposed |
|---|---|---|
| TLS | SNI, ALPN, fingerprint, certificate pins, verification names, inline ECH, curves, TLS min/max, cipher suites, session resumption | Custom certificates/roots and `disableSystemRoot` need typed trust-review support; resolver-form ECH is unsupported, so `echSockopt` would do nothing. |
| REALITY | Public key (`password` upstream), short ID, SNI, fingerprint, SpiderX, ML-DSA verify key | ALPN is not a REALITY field. `show` prints authentication/session material. Server private keys, targets, fallback limits and related server fields are excluded. |

`allowInsecure` is retained only to review legacy imports; the pinned core rejects it. TLS server keys, unknown-SNI rejection, external certificate files and key logging are not client editor options. Hop explicitly sets `useSystemCA: true` on every TLS outbound to keep iOS system trust after the new core changed its default. This setting is compiler-owned. Security-critical fields remain typed so subscription refreshes cannot bypass review.

## Transports and shared options

| Section | Client coverage | Constraints |
|---|---|---|
| RAW/TCP | Header type and HTTP header settings | PROXY-protocol acceptance is listener-only. |
| WebSocket | Host, path, headers, heartbeat | PROXY-protocol acceptance is listener-only. |
| gRPC | Authority, service name, multi-mode, idle/health timeouts, permit-without-stream, user agent | Initial window stays at `0` (the core default), as required by Hop's iOS policy. |
| HTTP Upgrade | Host, path, headers | PROXY-protocol acceptance is listener-only. |
| XHTTP | Host, path, mode; headers, padding, request/session/sequence placement, chunk/post limits, post timing and XMux fields | Hop limits XMux to one physical connection. Leave `maxConcurrency` unset or zero. `noSSEHeader`, `scMaxBufferedPosts`, `scStreamUpServerSecs`, `serverMaxHeaderBytes` are server-only. Separate `downloadSettings` needs a typed, reviewed secondary connection. Outer client fields are normalized into `extra`; ignored/colliding placements are rejected. |
| mKCP | MTU, TTI, upload/download capacity, congestion-window multiplier, send window | Old `header` and `seed` were removed. Buffer caps still apply. |
| Hysteria | Version/auth from protocol fields, UDP idle timeout | Bandwidth and congestion use FinalMask QUIC parameters. Port hopping uses a UDP `udphop` layer on the same endpoint. |
| Mux | Enabled, concurrency, XUDP concurrency, UDP/443 policy | Each TCP Mux worker honors concurrency 1–8. With Mux enabled, zero or omitted TCP concurrency selects 8. Separate XUDP workers support up to 16. |
| Socket | TCP Fast Open, domain strategy, dialer proxy, keepalive interval/idle, interface, address/port strategy, Happy Eyeballs, XHTTP penetration | See unavailable options below. |
| FinalMask | TCP/UDP mask lists and QUIC parameters; per-type settings | Payload/window/layer caps and existing secret/network-destination validation apply. QUIC incoming streams stay at `0`. |

FinalMask supports TCP `header-custom`, `fragment` and `sudoku`, plus UDP `header-custom`, `mkcp-legacy`, `noise`, `salamander`, `sudoku`, `xdns`, `xicmp`, `realm` and bounded `udphop`. Hop excludes the upstream TCP `xmc` mask and the TCP/UDP `filter` masks.

## November field changes

| Upstream field or type | Hop policy |
|---|---|
| `QuicParamsConfig.udpHop` removed, new UDP `udphop` mask | The compiler translates legacy QUIC hopping for Hysteria and XHTTP over HTTP/3. With a socket dialer proxy, choose per-connection remote hopping (`perConnRemote`). Interval hopping requires a direct socket to the endpoint. Remote ports are limited to 64 after expanding ranges, with intervals of 5–3,600 seconds. Remote IP pools are excluded. |
| `XDNS.domains`, `XDNS.resolvers` | Hop admits A, AAAA and TXT queries and up to four public UDP IP endpoints. Legacy settings migrate when the new fields can preserve domain-to-resolver assignments. November also changes the wire format, so the XDNS server must support it. |
| `XDNS.extraPoll`, resolver `worker`, `tlsConfig`, `quicConfig`, domain `lenLimit`, `labelLimit`, `edns0` | Excluded. The client controls polling, concurrency, verification and resource limits. |
| MASQUE outbound and transport, XDrive transport | Excluded from Hop. These introduce proxy or storage credentials, new network destinations, transport buffers and concurrency controls. |
| DNS, routing and UDP noise `script`; DNS server `id` | Hop excludes configuration-supplied scripts and the script-specific resolver identifier. |
| `XHTTP.h2Params`, QUIC `brutalDisableLossCompensation`, `disableChromeParrot`, `disableGSO`, `disableStatelessReset` | Excluded from advanced configuration pending reviewed iOS bounds and behavior. |
| Realm `ipMode` and `portMapping`; routing rule `localOS` | Excluded from imported and advanced routing. |
| `ResponseConfig.customResponseData`, Freedom final-rule `delay` and `logLevel` | Hop generates its own Direct and Reject outbounds. Custom response bytes, delays and per-rule logging are unavailable. |
| Outbound `proxySettings` | The core now rejects this field. Hop supports conversion of representable transport-layer proxy chains to `sockopt.dialerProxy`. |
| `LogConfig.logLevel`, Hysteria masquerade `xForwarded` | The log field uses new casing. Hop owns logging. The masquerade addition only affects servers. |

## Socket options

Hop excludes the following socket settings.

- `mark`, `tproxy`, `tcpCongestion`, `tcpWindowClamp`, `tcpMaxSeg`, `tcpUserTimeout`: no Darwin outbound implementation.
- `tcpMptcp`: Go's non-Linux implementation falls back to ordinary TCP.
- `acceptProxyProtocol`, `trustedXForwardedFor`, `v6only`: listener-side behavior.
- `customSockopt`: deliberately outside Hop's safe iOS socket surface.

Independent stream address/port overrides, custom TLS trust stores and split XHTTP download connections remain unsupported. Adding them requires real typed models, import/refresh security review and runtime tests—not merely showing a field that gets discarded.

## Evidence and regression checks

Authority: the pinned core's `infra/conf` builders, transport dialers/listeners, Darwin socket implementation, and Go's non-Linux MPTCP implementation—not documentation for a newer core. The schema generator check detects drift against that source. Protocol and transport tests verify emitted fields, exact-core parsing, collisions, ignored-field rejection and memory ceilings. A parse test does not establish a successful live connection.
