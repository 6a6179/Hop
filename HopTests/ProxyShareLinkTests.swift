@testable import Hop
import XCTest

/// Round-trip tests for ProxyShareLink.shareLink(for:) ↔ ProxyImportService.importText.
final class ProxyShareLinkTests: XCTestCase {
    private let importService = ProxyImportService()

    // MARK: - Round-trip helpers

    private func roundTrip(_ profile: ProxyProfile, file: StaticString = #filePath, line: UInt = #line) throws -> ProxyProfile {
        let link = try XCTUnwrap(ProxyShareLink.shareLink(for: profile), "shareLink returned nil for \(profile.proto)", file: file, line: line)
        let result = try importService.importText(link)
        return try XCTUnwrap(result.profiles.first, "import returned no profiles from link: \(link)", file: file, line: line)
    }

    // MARK: - VLESS + REALITY + gRPC

    func testVLESSRealityGRPCRoundTrip() throws {
        let profile = ProxyProfile(
            name: "VLESS REALITY gRPC",
            endpoint: Endpoint(host: "edge.example.net", port: 443),
            options: .vless(VLESSOptions(uuid: "11111111-1111-4111-8111-111111111111", flow: "xtls-rprx-vision")),
            security: .reality(RealityOptions(publicKey: "REALITYPUBLICKEY", shortID: "abcd1234", serverName: "www.cloudflare.com")),
            transport: TransportOptions(type: .grpc, serviceName: "GrpcService"),
        )

        let reparsed = try roundTrip(profile)

        XCTAssertEqual(reparsed.proto, .vless)
        XCTAssertEqual(reparsed.endpoint.host, "edge.example.net")
        XCTAssertEqual(reparsed.endpoint.port, 443)
        XCTAssertEqual(reparsed.security.layer, .reality)
        XCTAssertEqual(reparsed.security.reality?.publicKey, "REALITYPUBLICKEY")
        XCTAssertEqual(reparsed.security.reality?.shortID, "abcd1234")
        XCTAssertEqual(reparsed.transport.type, .grpc)
        XCTAssertEqual(reparsed.transport.serviceName, "GrpcService")
        if case let .vless(options) = reparsed.options {
            XCTAssertEqual(options.uuid, "11111111-1111-4111-8111-111111111111")
        } else {
            XCTFail("Expected VLESS options")
        }
    }

    // MARK: - VLESS + TLS + WebSocket

    func testVLESSTLSWebSocketRoundTrip() throws {
        let profile = ProxyProfile(
            name: "VLESS TLS WS",
            endpoint: Endpoint(host: "ws.example.net", port: 443),
            options: .vless(VLESSOptions(uuid: "11111111-1111-4111-8111-111111111111")),
            security: .tls(TLSOptions(serverName: "ws.example.net")),
            transport: TransportOptions(type: .websocket, path: "/ws", host: "cdn.example.net"),
        )

        let reparsed = try roundTrip(profile)

        XCTAssertEqual(reparsed.proto, .vless)
        XCTAssertEqual(reparsed.security.layer, .tls)
        XCTAssertEqual(reparsed.transport.type, .websocket)
        XCTAssertEqual(reparsed.transport.path, "/ws")
        XCTAssertEqual(reparsed.transport.host, "cdn.example.net")
        if case let .vless(options) = reparsed.options {
            XCTAssertEqual(options.uuid, "11111111-1111-4111-8111-111111111111")
        } else {
            XCTFail("Expected VLESS options")
        }
    }

    // MARK: - Trojan + TLS

    func testTrojanTLSRoundTrip() throws {
        let profile = ProxyProfile(
            name: "Trojan TLS",
            endpoint: Endpoint(host: "de.example.net", port: 443),
            options: .trojan(TrojanOptions(password: "s3cr3tpassword")),
            security: .tls(TLSOptions(serverName: "de.example.net", alpn: ["h2", "http/1.1"])),
        )

        let reparsed = try roundTrip(profile)

        XCTAssertEqual(reparsed.proto, .trojan)
        XCTAssertEqual(reparsed.endpoint.host, "de.example.net")
        XCTAssertEqual(reparsed.security.layer, .tls)
        XCTAssertEqual(reparsed.security.tls?.allowInsecure, false)
        if case let .trojan(options) = reparsed.options {
            XCTAssertEqual(options.password, "s3cr3tpassword")
        } else {
            XCTFail("Expected Trojan options")
        }
    }

    // MARK: - Hysteria2 + obfs

    func testHysteria2WithObfsRoundTrip() throws {
        let profile = ProxyProfile(
            name: "Hysteria2 Obfs",
            endpoint: Endpoint(host: "nyc.example.net", port: 443),
            options: .hysteria2(Hysteria2Options(
                password: "hy2password",
                obfs: "salamander",
                obfsPassword: "obfs-secret",
                up: "20 mbps",
                down: "100 mbps",
                ports: "20000-20100",
                hopIntervalSeconds: 30,
                udpIdleTimeoutSeconds: 60,
            )),
            security: .tls(TLSOptions(serverName: "nyc.example.net")),
            transport: TransportOptions(type: .hysteria),
        )

        let reparsed = try roundTrip(profile)

        XCTAssertEqual(reparsed.proto, .hysteria2)
        XCTAssertEqual(reparsed.endpoint.host, "nyc.example.net")
        XCTAssertEqual(reparsed.security.layer, .tls)
        if case let .hysteria2(options) = reparsed.options {
            XCTAssertEqual(options.password, "hy2password")
            XCTAssertEqual(options.obfs, "salamander")
            XCTAssertEqual(options.obfsPassword, "obfs-secret")
            XCTAssertEqual(options.up, "20 mbps")
            XCTAssertEqual(options.down, "100 mbps")
            XCTAssertEqual(options.ports, "20000-20100")
            XCTAssertEqual(options.hopIntervalSeconds, 30)
            XCTAssertEqual(options.udpIdleTimeoutSeconds, 60)
        } else {
            XCTFail("Expected Hysteria2 options")
        }
    }

    func testTLSModernOptionsAndXHTTPRoundTrip() throws {
        let profile = ProxyProfile(
            name: "Modern TLS",
            endpoint: Endpoint(host: "edge.example.net", port: 443),
            options: .vless(VLESSOptions(
                uuid: "11111111-1111-4111-8111-111111111111",
                flow: "xtls-rprx-vision",
                encryption: "mlkem768x25519plus.native.1rtt..AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )),
            security: .tls(TLSOptions(
                serverName: "edge.example.net",
                alpn: ["h2"],
                pinnedPeerCertSHA256: String(repeating: "ab", count: 32),
                verifyPeerCertByName: "verify.example.net",
                echConfigList: "dGVzdA==",
                curvePreferences: ["X25519MLKEM768"],
                minVersion: "1.2",
                maxVersion: "1.3",
                enableSessionResumption: true,
            )),
            transport: TransportOptions(type: .xhttp, path: "/x", host: "cdn.example.net", xhttpMode: "stream-up"),
        )

        let reparsed = try roundTrip(profile)
        XCTAssertEqual(reparsed.transport.type, .xhttp)
        XCTAssertEqual(reparsed.transport.xhttpMode, "stream-up")
        XCTAssertEqual(reparsed.security.tls?.pinnedPeerCertSHA256, String(repeating: "ab", count: 32))
        XCTAssertEqual(reparsed.security.tls?.verifyPeerCertByName, "verify.example.net")
        XCTAssertEqual(reparsed.security.tls?.echConfigList, "dGVzdA==")
        XCTAssertEqual(reparsed.security.tls?.curvePreferences, ["X25519MLKEM768"])
        XCTAssertEqual(reparsed.security.tls?.minVersion, "1.2")
        XCTAssertEqual(reparsed.security.tls?.maxVersion, "1.3")
        XCTAssertEqual(reparsed.security.tls?.enableSessionResumption, true)
    }

    // MARK: - TUIC is unsupported by Xray

    func testTUICShareLinkReturnsNil() {
        let profile = ProxyProfile(
            name: "TUIC Node",
            endpoint: Endpoint(host: "tuic.example.net", port: 443),
            options: .tuic(TUICOptions(uuid: "22222222-2222-4222-8222-222222222222", password: "tuicpassword", congestionControl: "bbr")),
            security: .tls(TLSOptions(serverName: "tuic.example.net", alpn: ["h3"])),
        )

        XCTAssertNil(ProxyShareLink.shareLink(for: profile))
    }

    // MARK: - Shadowsocks with special chars in password

    func testShadowsocksWithSpecialCharsInPasswordRoundTrip() throws {
        // Password contains `:`, `@`, `/` — all must survive the SIP002 base64url encoding
        let profile = ProxyProfile(
            name: "SS Special",
            endpoint: Endpoint(host: "ss.example.net", port: 8388),
            options: .shadowsocks(ShadowsocksOptions(method: "2022-blake3-aes-128-gcm", password: "p:a@s/s")),
            security: .none,
        )

        let reparsed = try roundTrip(profile)

        XCTAssertEqual(reparsed.proto, .shadowsocks)
        XCTAssertEqual(reparsed.endpoint.host, "ss.example.net")
        if case let .shadowsocks(options) = reparsed.options {
            XCTAssertEqual(options.method, "2022-blake3-aes-128-gcm")
            XCTAssertEqual(options.password, "p:a@s/s")
        } else {
            XCTFail("Expected Shadowsocks options")
        }
    }

    // MARK: - VMess + WebSocket + TLS

    func testVMessWebSocketTLSRoundTrip() throws {
        let profile = ProxyProfile(
            name: "VMess WS TLS",
            endpoint: Endpoint(host: "vmess.example.net", port: 443),
            options: .vmess(VMessOptions(uuid: "33333333-3333-4333-8333-333333333333", security: "auto", alterID: 0)),
            security: .tls(TLSOptions(serverName: "vmess.example.net")),
            transport: TransportOptions(type: .websocket, path: "/ws", host: "cdn.example.net"),
        )

        let reparsed = try roundTrip(profile)

        XCTAssertEqual(reparsed.proto, .vmess)
        XCTAssertEqual(reparsed.endpoint.host, "vmess.example.net")
        XCTAssertEqual(reparsed.security.layer, .tls)
        XCTAssertEqual(reparsed.transport.type, .websocket)
        if case let .vmess(options) = reparsed.options {
            XCTAssertEqual(options.uuid, "33333333-3333-4333-8333-333333333333")
        } else {
            XCTFail("Expected VMess options")
        }
    }

    // MARK: - HTTP (no TLS) with username/password

    func testHTTPNoTLSWithCredentialsRoundTrip() throws {
        let profile = ProxyProfile(
            name: "Plain HTTP",
            endpoint: Endpoint(host: "http.example.net", port: 8080),
            options: .http(HTTPOptions(username: "user", password: "pass")),
            security: .none,
        )

        let reparsed = try roundTrip(profile)

        XCTAssertEqual(reparsed.proto, .http)
        XCTAssertEqual(reparsed.security.layer, .none)
        if case let .http(options) = reparsed.options {
            XCTAssertEqual(options.username, "user")
            XCTAssertEqual(options.password, "pass")
        } else {
            XCTFail("Expected HTTP options")
        }
    }

    // MARK: - SOCKS with TLS

    func testSOCKSWithTLSRoundTrip() throws {
        let profile = ProxyProfile(
            name: "SOCKS TLS",
            endpoint: Endpoint(host: "socks.example.net", port: 443),
            options: .socks(SOCKSOptions(username: "socks-user", password: "socks-pass")),
            security: .tls(TLSOptions(serverName: "socks.example.net")),
        )

        // share link uses socks5+tls://
        let link = try XCTUnwrap(ProxyShareLink.shareLink(for: profile))
        XCTAssertTrue(link.hasPrefix("socks5+tls://"), "SOCKS with TLS must use socks5+tls scheme, got: \(link)")

        let reparsed = try roundTrip(profile)
        XCTAssertEqual(reparsed.proto, .socks)
        XCTAssertEqual(reparsed.security.layer, .tls)
        if case let .socks(options) = reparsed.options {
            XCTAssertEqual(options.username, "socks-user")
            XCTAssertEqual(options.password, "socks-pass")
        } else {
            XCTFail("Expected SOCKS options")
        }
    }

    // MARK: - Names with spaces and Unicode

    func testProfileNameWithSpacesAndUnicodeSurvivesRoundTrip() throws {
        let profile = ProxyProfile(
            name: "Tokyo 東京 Node",
            endpoint: Endpoint(host: "jp.example.net", port: 443),
            options: .trojan(TrojanOptions(password: "secret")),
            security: .tls(TLSOptions(serverName: "jp.example.net")),
        )

        let reparsed = try roundTrip(profile)
        // After sanitization the name must be preserved (spaces and CJK are fine)
        XCTAssertEqual(reparsed.name, "Tokyo 東京 Node")
    }

    // MARK: - WireGuard custom client link and unsupported AnyTLS

    func testWireGuardRoundTrip() throws {
        let profile = ProxyProfile(
            name: "WG",
            endpoint: Endpoint(host: "wg.example.net", port: 51820),
            options: .wireGuard(WireGuardOptions(
                privateKey: "PRIVATEKEY",
                peerPublicKey: "PEERPUBLICKEY",
                preSharedKey: "PRESHARED",
                localAddress: ["10.0.0.2/32"],
                allowedIPs: ["0.0.0.0/0", "::/0"],
                reserved: [1, 2, 3],
                keepAliveSeconds: 25,
                mtu: 1280,
                domainStrategy: "ForceIP",
            )),
            security: .none,
        )
        let reparsed = try roundTrip(profile)
        guard case let .wireGuard(options) = reparsed.options else {
            return XCTFail("Expected WireGuard options")
        }
        XCTAssertEqual(Optional(options), profile.options.wireGuardValue)
    }

    func testWireGuardMultiPeerExtensionRoundTrip() throws {
        let peers = try [
            WireGuardPeer(
                id: XCTUnwrap(UUID(uuidString: "11111111-1111-4111-8111-111111111111")),
                publicKey: "PEER-ONE",
                endpoint: Endpoint(host: "one.example.net", port: 51820),
                preSharedKey: "PSK-ONE",
                allowedIPs: ["10.1.0.0/16"],
                keepAliveSeconds: 25,
            ),
            WireGuardPeer(
                id: XCTUnwrap(UUID(uuidString: "22222222-2222-4222-8222-222222222222")),
                publicKey: "PEER-TWO",
                endpoint: Endpoint(host: "two.example.net", port: 51821),
                preSharedKey: "PSK-TWO",
                allowedIPs: ["10.2.0.0/16"],
            ),
        ]
        let profile = ProxyProfile(
            name: "WG Multi",
            endpoint: Endpoint(host: "fallback.example.net", port: 51820),
            options: .wireGuard(WireGuardOptions(
                privateKey: "PRIVATEKEY",
                peerPublicKey: peers[0].publicKey,
                localAddress: ["10.0.0.2/32"],
                mtu: 1280,
                peers: peers,
            )),
            security: .none,
        )

        let link = try XCTUnwrap(ProxyShareLink.shareLink(for: profile))
        XCTAssertTrue(link.contains("peers="))
        let reparsed = try roundTrip(profile)
        XCTAssertEqual(reparsed.options.wireGuardValue?.peers, peers)
    }

    func testFinalMaskAndTransportLongTailRoundTrip() throws {
        let finalMask: JSONValue = .object([
            "tcp": .array([.object(["type": .string("header-http")])]),
        ])
        let profile = ProxyProfile(
            name: "FinalMask",
            endpoint: Endpoint(host: "edge.example.net", port: 443),
            options: .vless(VLESSOptions(uuid: "11111111-1111-4111-8111-111111111111")),
            security: .tls(TLSOptions(serverName: "edge.example.net")),
            transport: TransportOptions(
                type: .xhttp,
                path: "/x",
                xhttpMode: "stream-up",
                xhttpExtra: .object(["downloadSettings": .object(["address": .string("edge.example.net")])]),
                finalMask: finalMask,
                mux: XrayMuxOptions(enabled: true, concurrency: 4, xudpConcurrency: 8),
                socketOptions: .object(["tcpKeepAliveInterval": .number(30)]),
            ),
        )
        let reparsed = try roundTrip(profile)
        XCTAssertEqual(reparsed.transport.xhttpExtra, profile.transport.xhttpExtra)
        XCTAssertEqual(reparsed.transport.finalMask, finalMask)
        XCTAssertEqual(reparsed.transport.mux, profile.transport.mux)
        XCTAssertEqual(reparsed.transport.socketOptions, profile.transport.socketOptions)
    }

    func testAnyTLSShareLinkReturnsNil() {
        let profile = ProxyProfile(
            name: "AnyTLS",
            endpoint: Endpoint(host: "anytls.example.net", port: 443),
            options: .anyTLS(AnyTLSOptions(password: "secret")),
            security: .tls(TLSOptions(serverName: "anytls.example.net")),
        )
        XCTAssertNil(ProxyShareLink.shareLink(for: profile), "AnyTLS has no interoperable share link format")
    }

    // MARK: - VLESS REALITY: allowInsecure field

    func testVLESSRealityAllowInsecurePreservedThroughRoundTrip() throws {
        // REALITY overrides allowInsecure to false in the parser (security enforced)
        let profile = ProxyProfile(
            name: "VLESS REALITY",
            endpoint: Endpoint(host: "edge.example.net", port: 443),
            options: .vless(VLESSOptions(uuid: "11111111-1111-4111-8111-111111111111")),
            security: .reality(RealityOptions(publicKey: "KEY", shortID: "sid")),
        )
        // REALITY should never have allowInsecure = true; assert round-trip keeps it false
        XCTAssertEqual(profile.security.tls?.allowInsecure, false)
        let reparsed = try roundTrip(profile)
        XCTAssertEqual(reparsed.security.tls?.allowInsecure, false)
    }
}

private extension ProtocolOptions {
    var wireGuardValue: WireGuardOptions? {
        guard case let .wireGuard(value) = self else { return nil }
        return value
    }
}
