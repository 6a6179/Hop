@testable import Hop
import XCTest

final class XrayConfigBuilderTests: XCTestCase {
    private let builder = XrayConfigBuilder()

    func testBuildsVLESSRealityPostQuantumConfigAndExactCoreAcceptsIt() async throws {
        let profile = try ProxyProfile(
            id: XCTUnwrap(UUID(uuidString: "00000000-0000-4000-8000-000000000001")),
            name: "PQ VLESS",
            endpoint: Endpoint(host: "edge.example.com", port: 443),
            options: .vless(VLESSOptions(
                uuid: "11111111-1111-4111-8111-111111111111",
                flow: "xtls-rprx-vision",
                encryption: "mlkem768x25519plus.native.1rtt.100-100-100.\(base64URL(bytes: 32))",
            )),
            security: .reality(RealityOptions(
                publicKey: base64URL(bytes: 32),
                shortID: "6ba85179e30d4fc2",
                serverName: "www.example.com",
                spiderX: "/",
                utlsFingerprint: "chrome",
            )),
        )

        let json = try builder.build(profile: profile, routingMode: .global, rules: [])
        let root = try parse(json)
        let inbound = try XCTUnwrap((root["inbounds"] as? [[String: Any]])?.first)
        let inboundSettings = try XCTUnwrap(inbound["settings"] as? [String: Any])
        let outbound = try profileOutbound(root)
        let outboundSettings = try XCTUnwrap(outbound["settings"] as? [String: Any])
        let stream = try XCTUnwrap(outbound["streamSettings"] as? [String: Any])
        let reality = try XCTUnwrap(stream["realitySettings"] as? [String: Any])

        XCTAssertEqual(inbound["protocol"] as? String, "tun")
        XCTAssertEqual(inboundSettings["gateway"] as? [String], ["172.19.0.1/30", "fdfe:dcba:9876::1/126"])
        XCTAssertEqual(outbound["protocol"] as? String, "vless")
        XCTAssertEqual(outboundSettings["flow"] as? String, "xtls-rprx-vision")
        XCTAssertTrue((outboundSettings["encryption"] as? String)?.hasPrefix("mlkem768x25519plus.native.1rtt") == true)
        XCTAssertEqual(stream["security"] as? String, "reality")
        XCTAssertEqual(reality["shortId"] as? String, "6ba85179e30d4fc2")
        XCTAssertEqual(reality["password"] as? String, base64URL(bytes: 32))
        XCTAssertNil(reality["publicKey"])

        try await XrayCoreClient.validate(configJSON: json)
    }

    func testRenderedConfigOmitsAppTelemetryFeatures() throws {
        let root = try parse(builder.build(profile: basicVLESS(), routingMode: .global, rules: []))

        XCTAssertNil(root["stats"])
        XCTAssertNil((root["policy"] as? [String: Any])?["system"])

        var settings = AppSettings.defaults
        settings.xrayAdvanced = XrayAdvancedDocument([
            "policy": .object([
                "system": .object(["statsInboundUplink": .bool(true)]),
            ]),
        ])
        XCTAssertThrowsError(try builder.build(profile: basicVLESS(), routingMode: .global, rules: [], settings: settings)) { error in
            XCTAssertTrue(error.localizedDescription.contains("cannot be supplied"))
        }
    }

    func testBuildsTLSXHTTPAndEnforcesSafeDefaults() async throws {
        let profile = ProxyProfile(
            name: "XHTTP TLS",
            endpoint: Endpoint(host: "xhttp.example.com", port: 443),
            options: .trojan(TrojanOptions(password: "secret")),
            security: .tls(TLSOptions(
                serverName: "xhttp.example.com",
                alpn: ["h2"],
                utlsFingerprint: "chrome",
                pinnedPeerCertSHA256: String(repeating: "ab", count: 32),
                verifyPeerCertByName: "xhttp.example.com",
                echConfigList: "https://dns.example/dns-query",
                curvePreferences: ["X25519MLKEM768", "X25519"],
                minVersion: "1.3",
                maxVersion: "1.3",
                enableSessionResumption: true,
            )),
            transport: TransportOptions(
                type: .xhttp,
                path: "/hop",
                host: "cdn.example.com",
                xhttpMode: "stream-up",
            ),
        )

        let json = try builder.build(profile: profile, routingMode: .global, rules: [])
        let outbound = try profileOutbound(parse(json))
        let stream = try XCTUnwrap(outbound["streamSettings"] as? [String: Any])
        let tls = try XCTUnwrap(stream["tlsSettings"] as? [String: Any])
        let xhttp = try XCTUnwrap(stream["xhttpSettings"] as? [String: Any])
        let extra = try XCTUnwrap(xhttp["extra"] as? [String: Any])
        let xmux = try XCTUnwrap(extra["xmux"] as? [String: Any])

        XCTAssertEqual(tls["pinnedPeerCertSha256"] as? String, String(repeating: "ab", count: 32))
        XCTAssertEqual(tls["curvePreferences"] as? [String], ["X25519MLKEM768", "X25519"])
        XCTAssertEqual(tls["enableSessionResumption"] as? Bool, true)
        XCTAssertEqual(xhttp["mode"] as? String, "stream-up")
        XCTAssertEqual((extra["scMaxBufferedPosts"] as? NSNumber)?.intValue, 2)
        XCTAssertEqual((extra["scMaxEachPostBytes"] as? NSNumber)?.intValue, 256 * 1024)
        XCTAssertEqual((xmux["maxConnections"] as? NSNumber)?.intValue, 2)

        try await XrayCoreClient.validate(configJSON: json)
    }

    func testBuildsHysteria2FinalMaskWithinIOSLimits() async throws {
        let profile = ProxyProfile(
            name: "Hysteria2",
            endpoint: Endpoint(host: "hy.example.com", port: 443),
            options: .hysteria2(Hysteria2Options(
                password: "auth",
                obfs: "salamander",
                obfsPassword: "obfs-secret",
                up: "100 mbps",
                down: "200 mbps",
                ports: "20000-20100",
                hopIntervalSeconds: 30,
                udpIdleTimeoutSeconds: 60,
            )),
            security: .tls(TLSOptions(serverName: "hy.example.com", alpn: ["h3"])),
            transport: TransportOptions(type: .hysteria),
        )

        let json = try builder.build(profile: profile, routingMode: .global, rules: [])
        let outbound = try profileOutbound(parse(json))
        let stream = try XCTUnwrap(outbound["streamSettings"] as? [String: Any])
        let hysteria = try XCTUnwrap(stream["hysteriaSettings"] as? [String: Any])
        let finalMask = try XCTUnwrap(stream["finalmask"] as? [String: Any])
        let quic = try XCTUnwrap(finalMask["quicParams"] as? [String: Any])
        let udp = try XCTUnwrap(finalMask["udp"] as? [[String: Any]])

        XCTAssertEqual(outbound["protocol"] as? String, "hysteria")
        XCTAssertEqual(stream["network"] as? String, "hysteria")
        XCTAssertEqual(hysteria["auth"] as? String, "auth")
        XCTAssertEqual(quic["congestion"] as? String, "brutal")
        XCTAssertEqual((quic["maxConnectionReceiveWindow"] as? NSNumber)?.intValue, 4 * 1024 * 1024)
        XCTAssertEqual((quic["maxIncomingStreams"] as? NSNumber)?.intValue, 16)
        XCTAssertEqual(udp.first?["type"] as? String, "salamander")

        try await XrayCoreClient.validate(configJSON: json)
    }

    func testBuildsWireGuardWithNoKernelTun() async throws {
        let profile = ProxyProfile(
            name: "WireGuard",
            endpoint: Endpoint(host: "wg.example.com", port: 5182),
            options: .wireGuard(WireGuardOptions(
                privateKey: base64URL(bytes: 32, padded: true),
                peerPublicKey: base64URL(bytes: 32, padded: true),
                localAddress: ["10.0.0.2/32"],
                allowedIPs: ["0.0.0.0/0", "::/0"],
                reserved: [1, 2, 3],
                keepAliveSeconds: 25,
                mtu: 1280,
                domainStrategy: "ForceIP",
            )),
            security: .none,
        )

        let json = try builder.build(profile: profile, routingMode: .global, rules: [])
        let outbound = try profileOutbound(parse(json))
        let settings = try XCTUnwrap(outbound["settings"] as? [String: Any])
        let peer = try XCTUnwrap((settings["peers"] as? [[String: Any]])?.first)

        XCTAssertEqual(settings["noKernelTun"] as? Bool, true)
        XCTAssertEqual(settings["reserved"] as? [Int], [1, 2, 3])
        XCTAssertEqual(peer["endpoint"] as? String, "wg.example.com:5182")

        try await XrayCoreClient.validate(configJSON: json)
    }

    func testBuildsFourWireGuardPeersAndRejectsFifth() throws {
        let peers = (0 ..< 4).map { index in
            WireGuardPeer(
                publicKey: base64URL(bytes: 32, padded: true),
                endpoint: Endpoint(host: "wg\(index).example.com", port: 51820 + index),
                preSharedKey: "psk-\(index)",
                allowedIPs: ["10.\(index).0.0/16"],
                keepAliveSeconds: 20 + index,
            )
        }
        func profile(_ peers: [WireGuardPeer]) -> ProxyProfile {
            ProxyProfile(
                name: "WireGuard",
                endpoint: Endpoint(host: "fallback.example.com", port: 51820),
                options: .wireGuard(WireGuardOptions(
                    privateKey: base64URL(bytes: 32, padded: true),
                    peerPublicKey: peers[0].publicKey,
                    localAddress: ["10.0.0.2/32"],
                    peers: peers,
                )),
                security: .none,
            )
        }

        let json = try builder.build(profile: profile(peers), routingMode: .global, rules: [])
        let settings = try XCTUnwrap(try profileOutbound(parse(json))["settings"] as? [String: Any])
        let rendered = try XCTUnwrap(settings["peers"] as? [[String: Any]])
        XCTAssertEqual(rendered.count, 4)
        XCTAssertEqual(rendered.map { $0["endpoint"] as? String }, (0 ..< 4).map { "wg\($0).example.com:\(51820 + $0)" })
        XCTAssertEqual(settings["noKernelTun"] as? Bool, true)

        XCTAssertThrowsError(try builder.build(profile: profile(peers + [WireGuardPeer(publicKey: "fifth")]), routingMode: .global, rules: [])) { error in
            XCTAssertTrue(error.localizedDescription.contains("at most 4 peers"))
        }
    }

    func testLegacyWireGuardStateDecodesToOneEffectivePeer() throws {
        let json = #"{"privateKey":"private","peerPublicKey":"public","preSharedKey":"psk","localAddress":["10.0.0.2/32"],"allowedIPs":["0.0.0.0/0"],"keepAliveSeconds":25}"#
        let options = try JSONDecoder().decode(WireGuardOptions.self, from: Data(json.utf8))
        XCTAssertNil(options.peers)
        XCTAssertEqual(options.effectivePeers.count, 1)
        XCTAssertEqual(options.effectivePeers[0].publicKey, "public")
        XCTAssertEqual(options.effectivePeers[0].preSharedKey, "psk")
    }

    func testExactCoreAcceptsRemainingClientProtocolsAndTransports() async throws {
        let profiles = [
            ProxyProfile(
                name: "Shadowsocks",
                endpoint: Endpoint(host: "ss.example.com", port: 8388),
                options: .shadowsocks(ShadowsocksOptions(method: "aes-256-gcm", password: "secret")),
                security: .none,
            ),
            ProxyProfile(
                name: "VMess WebSocket",
                endpoint: Endpoint(host: "vmess.example.com", port: 443),
                options: .vmess(VMessOptions(uuid: "22222222-2222-4222-8222-222222222222", security: "auto", alterID: 0)),
                security: .tls(TLSOptions(serverName: "vmess.example.com")),
                transport: TransportOptions(type: .websocket, path: "/ws", host: "cdn.example.com"),
            ),
            ProxyProfile(
                name: "HTTP",
                endpoint: Endpoint(host: "http.example.com", port: 8080),
                options: .http(HTTPOptions(username: "user", password: "secret")),
                security: .none,
            ),
            ProxyProfile(
                name: "SOCKS Upgrade",
                endpoint: Endpoint(host: "socks.example.com", port: 443),
                options: .socks(SOCKSOptions(username: "user", password: "secret")),
                security: .tls(TLSOptions(serverName: "socks.example.com")),
                transport: TransportOptions(type: .httpUpgrade, path: "/up", host: "socks.example.com"),
            ),
            ProxyProfile(
                name: "VLESS mKCP",
                endpoint: Endpoint(host: "kcp.example.com", port: 443),
                options: .vless(VLESSOptions(uuid: "33333333-3333-4333-8333-333333333333", encryption: "none")),
                security: .none,
                transport: TransportOptions(type: .mKCP, kcp: XrayKCPOptions(mtu: 1350, tti: 20)),
            ),
            ProxyProfile(
                name: "Trojan gRPC",
                endpoint: Endpoint(host: "grpc.example.com", port: 443),
                options: .trojan(TrojanOptions(password: "secret")),
                security: .tls(TLSOptions(serverName: "grpc.example.com", alpn: ["h2"])),
                transport: TransportOptions(type: .grpc, host: "grpc.example.com", serviceName: "hop"),
            ),
        ]

        for profile in profiles {
            let json = try builder.build(profile: profile, routingMode: .global, rules: [])
            try await XrayCoreClient.validate(configJSON: json)
        }
    }

    func testAdvancedJSONMergesLongTailAndRejectsCollisions() throws {
        var profile = basicVLESS()
        profile.xrayAdvanced = try XrayAdvancedDocument(jsonString: """
        {
          "settings": {"email": "client@example.com"},
          "streamSettings": {"sockopt": {"tcpFastOpen": true}},
          "targetStrategy": "UseIPv4"
        }
        """)
        let json = try builder.build(profile: profile, routingMode: .global, rules: [])
        let outbound = try profileOutbound(parse(json))
        XCTAssertEqual((outbound["settings"] as? [String: Any])?["email"] as? String, "client@example.com")
        XCTAssertEqual(((outbound["streamSettings"] as? [String: Any])?["sockopt"] as? [String: Any])?["tcpFastOpen"] as? Bool, true)
        XCTAssertEqual(outbound["targetStrategy"] as? String, "UseIPv4")

        profile.xrayAdvanced = try XrayAdvancedDocument(jsonString: #"{"settings":{"address":"attacker.example"}}"#)
        assertRejected(profile, contains: "collides")

        profile.xrayAdvanced = try XrayAdvancedDocument(jsonString: #"{"settings":{"typo":true}}"#)
        assertRejected(profile, contains: "Unknown or server-only")
    }

    func testAdvancedJSONRejectsSecretsAndServerOnlyTransportFields() throws {
        var profile = basicVLESS()
        profile.xrayAdvanced = try XrayAdvancedDocument(jsonString: #"{"streamSettings":{"sockopt":{"customSockopt":"unsafe"}}}"#)
        assertRejected(profile, contains: "Unknown or server-only")

        profile.xrayAdvanced = try XrayAdvancedDocument(jsonString: #"{"streamSettings":{"rawSettings":{"acceptProxyProtocol":true}}}"#)
        assertRejected(profile, contains: "Unknown or server-only")
    }

    func testAdvancedFakeDNSIsBoundedAndWiredIntoTypedTunnel() async throws {
        var settings = AppSettings.defaults
        settings.xrayAdvanced = XrayAdvancedDocument([
            "fakeDns": .object([
                "ipPool": .string("198.18.0.0/15"),
                "poolSize": .number(1024),
            ]),
        ])
        let json = try builder.build(profile: basicVLESS(), routingMode: .global, rules: [], settings: settings)
        let root = try parse(json)
        let dns = try XCTUnwrap(root["dns"] as? [String: Any])
        let inbound = try XCTUnwrap((root["inbounds"] as? [[String: Any]])?.first)
        let sniffing = try XCTUnwrap(inbound["sniffing"] as? [String: Any])

        XCTAssertEqual((dns["servers"] as? [Any])?.first as? String, "fakedns")
        XCTAssertTrue((sniffing["destOverride"] as? [String])?.contains("fakedns") == true)
        try await XrayCoreClient.validate(configJSON: json)

        settings.xrayAdvanced = XrayAdvancedDocument([
            "fakeDns": .object([
                "ipPool": .string("198.18.0.0/15"),
                "poolSize": .number(4097),
            ]),
        ])
        XCTAssertThrowsError(try builder.build(profile: basicVLESS(), routingMode: .global, rules: [], settings: settings)) { error in
            XCTAssertTrue(error.localizedDescription.contains("4096-entry"))
        }
    }

    func testRejectsRemovedProtocolsUnsafeSecurityAndAppleRules() throws {
        var profile = basicVLESS()
        profile.security = .tls(TLSOptions(serverName: "example.com", allowInsecure: true))
        assertRejected(profile, contains: "allowInsecure")

        profile = ProxyProfile(
            name: "VMess legacy",
            endpoint: Endpoint(host: "example.com", port: 443),
            options: .vmess(VMessOptions(uuid: UUID().uuidString, security: "auto", alterID: 1)),
            security: .none,
        )
        assertRejected(profile, contains: "alterID")

        profile = ProxyProfile(
            name: "SS legacy",
            endpoint: Endpoint(host: "example.com", port: 8388),
            options: .shadowsocks(ShadowsocksOptions(method: "aes-256-cfb", password: "secret")),
            security: .none,
        )
        assertRejected(profile, contains: "insecure Shadowsocks")

        profile = basicVLESS()
        XCTAssertThrowsError(try builder.build(
            profile: profile,
            routingMode: .rule,
            rules: [RoutingRule(kind: .wifiSSID, value: "Home", target: .direct)],
        )) { error in
            XCTAssertTrue(error.localizedDescription.contains("Apple-specific"))
        }
    }

    func testRejectsRealityOnUnsupportedTransportAndMemoryExcess() {
        var profile = basicVLESS()
        profile.security = .reality(RealityOptions(publicKey: base64URL(bytes: 32), serverName: "example.com"))
        profile.transport = TransportOptions(type: .websocket, path: "/")
        assertRejected(profile, contains: "REALITY supports only")

        profile = basicVLESS()
        profile.transport = TransportOptions(
            type: .xhttp,
            xhttpExtra: .object([
                "xmux": .object(["maxConnections": .number(3)]),
            ]),
        )
        assertRejected(profile, contains: "iOS memory limit")

        profile = basicVLESS()
        profile.transport = TransportOptions(
            type: .tcp,
            finalMask: .object([
                "tcp": .array((0 ..< 5).map { _ in .object(["type": .string("noise")]) }),
            ]),
        )
        assertRejected(profile, contains: "4-layer")

        profile = basicVLESS()
        profile.transport = TransportOptions(
            type: .mKCP,
            kcp: XrayKCPOptions(tti: 50, downlinkCapacity: 21),
        )
        assertRejected(profile, contains: "read-buffer limit")

        profile = basicVLESS()
        profile.transport = TransportOptions(
            type: .xhttp,
            xhttpExtra: .object([
                "xPaddingBytes": .object(["from": .number(1), "to": .number(256 * 1024 + 1)]),
            ]),
        )
        assertRejected(profile, contains: "iOS memory limit")

        var settings = AppSettings.defaults
        settings.xrayAdvanced = XrayAdvancedDocument([
            "policy": .object([
                "levels": .object([
                    "0": .object(["bufferSize": .number(257)]),
                ]),
            ]),
        ])
        XCTAssertThrowsError(try builder.build(profile: basicVLESS(), routingMode: .global, rules: [], settings: settings)) { error in
            XCTAssertTrue(error.localizedDescription.contains("iOS memory limit"))
        }
    }

    func testURLTestGroupUsesBoundedObservatoryAndBalancer() async throws {
        let profile = basicVLESS()
        let group = ProxyGroup(
            name: "Auto",
            type: .urlTest,
            members: [.profile(profile.id)],
        )
        let json = try builder.build(
            profiles: [profile],
            groups: [group],
            selectedTarget: .group(group.id),
            routingMode: .global,
            rules: [],
        )
        let root = try parse(json)
        let observatory = try XCTUnwrap(root["observatory"] as? [String: Any])
        let routing = try XCTUnwrap(root["routing"] as? [String: Any])
        let balancer = try XCTUnwrap((routing["balancers"] as? [[String: Any]])?.first)

        XCTAssertEqual(observatory["probeURL"] as? String, ProxyGroupTestOptions.defaultURL)
        XCTAssertEqual(balancer["strategy"] as? [String: String], ["type": "leastPing"])
        try await XrayCoreClient.validate(configJSON: json)
    }

    func testJSONValueAndAdvancedDocumentRoundTripAndLegacyTLSDecode() throws {
        let source = #"{"a":1,"array":[true,null,"x"],"object":{"b":2}}"#
        let document = try XrayAdvancedDocument(jsonString: source)
        XCTAssertEqual(try XrayAdvancedDocument(jsonString: document.jsonString), document)

        let legacyTLS = #"{"serverName":"example.com","alpn":["h2"],"allowInsecure":false,"utlsFingerprint":"chrome"}"#
        let tls = try JSONDecoder().decode(TLSOptions.self, from: Data(legacyTLS.utf8))
        XCTAssertEqual(tls.curvePreferences, [])
        XCTAssertNil(tls.pinnedPeerCertSHA256)
        XCTAssertFalse(tls.enableSessionResumption)
    }

    private func basicVLESS() -> ProxyProfile {
        ProxyProfile(
            name: "VLESS",
            endpoint: Endpoint(host: "example.com", port: 443),
            options: .vless(VLESSOptions(uuid: "11111111-1111-4111-8111-111111111111", encryption: "none")),
            security: .tls(TLSOptions(serverName: "example.com")),
        )
    }

    private func assertRejected(_ profile: ProxyProfile, contains expected: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try builder.build(profile: profile, routingMode: .global, rules: []), file: file, line: line) { error in
            XCTAssertTrue(error.localizedDescription.contains(expected), "Unexpected error: \(error)", file: file, line: line)
        }
    }

    private func parse(_ json: String) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
    }

    private func profileOutbound(_ root: [String: Any]) throws -> [String: Any] {
        try XCTUnwrap((root["outbounds"] as? [[String: Any]])?.first { ($0["tag"] as? String)?.hasPrefix("proxy-") == true })
    }

    private func base64URL(bytes: Int, padded: Bool = false) -> String {
        let value = Data(repeating: 7, count: bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
        return padded ? value : value.replacingOccurrences(of: "=", with: "")
    }
}
