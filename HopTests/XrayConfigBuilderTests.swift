@testable import Hop
import XCTest

final class XrayConfigBuilderTests: XCTestCase {
    private let builder = XrayConfigBuilder()

    func testRenderedConfigIsCompactAndDeterministic() throws {
        let profile = basicVLESS()
        let first = try builder.build(profile: profile, routingMode: .global, rules: [])
        let second = try builder.build(profile: profile, routingMode: .global, rules: [])

        XCTAssertEqual(first, second)
        XCTAssertFalse(first.contains("\n"))
        _ = try parse(first)
    }

    func testRenderedConfigIsCappedAt512KiB() {
        XCTAssertEqual(IOSRuntimeLimits.default.maxRenderedConfigBytes, 512 * 1024)

        let profiles = (0 ..< 10).map { index in
            var profile = basicVLESS()
            profile.id = UUID()
            profile.name = "Large \(index)"
            profile.xrayAdvanced = XrayAdvancedDocument([
                "settings": .object([
                    "email": .string(String(repeating: "a", count: 58 * 1024)),
                ]),
            ])
            return profile
        }
        let group = ProxyGroup(
            name: "All",
            type: .urlTest,
            members: profiles.map { .profile($0.id) },
        )

        XCTAssertThrowsError(try builder.build(
            profiles: profiles,
            groups: [group],
            selectedTarget: .group(group.id),
            routingMode: .global,
            rules: [],
        )) { error in
            XCTAssertTrue(error.localizedDescription.contains("Rendered config"), "Unexpected error: \(error)")
        }
    }

    func testAdvancedEncodedByteCountMatchesEditableJSON() {
        let document = XrayAdvancedDocument([
            "nested": .object([
                "unicode": .string("東京"),
                "path": .string("/a/b\nnext"),
            ]),
        ])

        XCTAssertEqual(document.encodedByteCount, document.jsonString.utf8.count)
    }

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

    func testEmitsMemoryBoundPolicyDNSAndGRPCDefaultsAcceptedByExactCore() async throws {
        var profile = basicVLESS()
        profile.transport = TransportOptions(
            type: .grpc,
            host: "example.com",
            serviceName: "hop",
        )

        let json = try builder.build(profile: profile, routingMode: .global, rules: [])
        let root = try parse(json)
        let dns = try XCTUnwrap(root["dns"] as? [String: Any])
        let policy = try XCTUnwrap(root["policy"] as? [String: Any])
        let levels = try XCTUnwrap(policy["levels"] as? [String: Any])
        let levelZero = try XCTUnwrap(levels["0"] as? [String: Any])
        let outbound = try profileOutbound(root)
        let stream = try XCTUnwrap(outbound["streamSettings"] as? [String: Any])
        let grpc = try XCTUnwrap(stream["grpcSettings"] as? [String: Any])

        XCTAssertEqual(dns["disableCache"] as? Bool, true)
        XCTAssertEqual((levelZero["bufferSize"] as? NSNumber)?.intValue, 0)
        XCTAssertEqual((levelZero["handshake"] as? NSNumber)?.intValue, 15)
        XCTAssertEqual((levelZero["connIdle"] as? NSNumber)?.intValue, 120)
        XCTAssertEqual((levelZero["uplinkOnly"] as? NSNumber)?.intValue, 1)
        XCTAssertEqual((levelZero["downlinkOnly"] as? NSNumber)?.intValue, 1)
        XCTAssertEqual((grpc["initial_windows_size"] as? NSNumber)?.intValue, 0)

        try await XrayCoreClient.validate(configJSON: json)
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
                echConfigList: "AQIDBA==",
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
                xhttpExtra: .object(["noSSEHeader": .bool(true)]),
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
        XCTAssertEqual((extra["scMaxBufferedPosts"] as? NSNumber)?.intValue, 1)
        XCTAssertEqual((extra["scMaxEachPostBytes"] as? NSNumber)?.intValue, 128 * 1024)
        XCTAssertEqual((xmux["maxConnections"] as? NSNumber)?.intValue, 1)
        XCTAssertEqual(extra["noSSEHeader"] as? Bool, true)

        try await XrayCoreClient.validate(configJSON: json)
    }

    func testXHTTPRejectsUnsafeZeroesAndBoundsPaddingAndSessionIDs() async throws {
        for unsafeExtra: JSONValue in [
            .object(["scMaxBufferedPosts": .number(0)]),
            .object(["scMaxEachPostBytes": .number(0)]),
            .object(["xmux": .object(["maxConnections": .number(0)])]),
        ] {
            var profile = basicVLESS()
            profile.transport = TransportOptions(type: .xhttp, xhttpExtra: unsafeExtra)
            assertRejected(profile, contains: "unsafe upstream memory default")
        }

        var profile = basicVLESS()
        profile.transport = TransportOptions(
            type: .xhttp,
            xhttpExtra: .object(["xPaddingBytes": .number(16 * 1024 + 1)]),
        )
        assertRejected(profile, contains: "iOS memory limit")

        profile.transport.xhttpExtra = .object(["sessionIDLength": .number(129)])
        assertRejected(profile, contains: "iOS memory limit")

        profile.transport.xhttpExtra = .object([
            "xPaddingBytes": .number(16 * 1024),
            "sessionIDLength": .number(128),
        ])
        let json = try builder.build(profile: profile, routingMode: .global, rules: [])
        try await XrayCoreClient.validate(configJSON: json)
    }

    func testMemorySensitiveFieldsRejectNullBooleanAndMalformedValues() {
        for unsafeExtra: JSONValue in [
            .object(["scMaxBufferedPosts": .null]),
            .object(["scMaxEachPostBytes": .bool(true)]),
            .object(["xmux": .object(["maxConnections": .null])]),
            .object(["xPaddingBytes": .object(["from": .number(1), "to": .null])]),
        ] {
            var profile = basicVLESS()
            profile.transport = TransportOptions(type: .xhttp, xhttpExtra: unsafeExtra)
            assertRejected(profile, contains: "must be numeric")
        }

        for key in [
            "initStreamReceiveWindow",
            "maxStreamReceiveWindow",
            "initConnectionReceiveWindow",
            "maxConnectionReceiveWindow",
            "maxIncomingStreams",
        ] {
            var profile = basicVLESS()
            profile.transport = TransportOptions(
                type: .tcp,
                finalMask: .object([
                    "quicParams": .object([key: .null]),
                ]),
            )
            assertRejected(profile, contains: "must be numeric")
        }
    }

    func testRejectsOpaqueXHTTPDownloadSettingsAcrossTypedAndAdvancedPaths() {
        var profile = basicVLESS()
        profile.transport = TransportOptions(
            type: .xhttp,
            xhttpExtra: .object([
                "downloadSettings": .object([
                    "address": .string("downlink.example"),
                    "port": .number(80),
                    "network": .string("xhttp"),
                    "security": .string("none"),
                ]),
            ]),
        )
        assertRejected(profile, contains: "/transport/xhttpExtra/downloadSettings")

        profile = basicVLESS()
        profile.transport = TransportOptions(type: .xhttp)
        profile.xrayAdvanced = XrayAdvancedDocument([
            "streamSettings": .object([
                "xhttpSettings": .object([
                    "extra": .object([
                        "downloadSettings": .object([
                            "address": .string("downlink.example"),
                            "port": .number(80),
                        ]),
                    ]),
                ]),
            ]),
        ])
        assertRejected(profile, contains: "cannot be supplied")

        profile = basicVLESS()
        profile.transport = TransportOptions(
            type: .xhttp,
            xhttpExtra: .object(["downloadſettings": .null]),
        )
        assertRejected(profile, contains: "/transport/xhttpExtra/downloadSettings")

        profile = basicVLESS()
        profile.transport = TransportOptions(type: .xhttp)
        profile.xrayAdvanced = XrayAdvancedDocument([
            "streamSettings": .object([
                "xhttpSettings": .object([
                    "extra": .object([
                        "nested": .object(["downloadſettings": .null]),
                    ]),
                ]),
            ]),
        ])
        assertRejected(profile, contains: "cannot be supplied")

        profile.xrayAdvanced = XrayAdvancedDocument([
            "streamSettings": .object([
                "xhttpSettings": .object([
                    "extra": .object([
                        "DownloadSettings": .null,
                    ]),
                ]),
            ]),
        ])
        assertRejected(profile, contains: "cannot be supplied")
    }

    func testECHAllowsInlineBase64AndRejectsResolverOrMalformedForms() throws {
        var profile = basicVLESS()
        profile.security.tls?.echConfigList = "AQIDBA=="
        let json = try builder.build(profile: profile, routingMode: .global, rules: [])
        let outbound = try profileOutbound(parse(json))
        let stream = try XCTUnwrap(outbound["streamSettings"] as? [String: Any])
        let tls = try XCTUnwrap(stream["tlsSettings"] as? [String: Any])
        XCTAssertEqual(tls["echConfigList"] as? String, "AQIDBA==")

        for unsafe in [
            "https://dns.example/dns-query",
            "example.com+udp://1.1.1.1:53",
            "example.com+h2c://1.1.1.1/dns-query",
            "not-base64!",
        ] {
            profile.security.tls?.echConfigList = unsafe
            assertRejected(profile, contains: "/security/tls/echConfigList")
        }

        profile.security.tls?.echConfigList = nil
        profile.xrayAdvanced = XrayAdvancedDocument([
            "streamSettings": .object([
                "tlsSettings": .object([
                    "echConfigList": .string("https://127.0.0.1/dns-query"),
                ]),
            ]),
        ])
        assertRejected(profile, contains: "cannot be supplied")
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
        XCTAssertEqual((quic["initStreamReceiveWindow"] as? NSNumber)?.intValue, 512 * 1024)
        XCTAssertEqual((quic["maxStreamReceiveWindow"] as? NSNumber)?.intValue, 512 * 1024)
        XCTAssertEqual((quic["initConnectionReceiveWindow"] as? NSNumber)?.intValue, 2 * 1024 * 1024)
        XCTAssertEqual((quic["maxConnectionReceiveWindow"] as? NSNumber)?.intValue, 2 * 1024 * 1024)
        XCTAssertEqual((quic["maxIncomingStreams"] as? NSNumber)?.intValue, 0)
        XCTAssertEqual(udp.first?["type"] as? String, "salamander")

        try await XrayCoreClient.validate(configJSON: json)
    }

    func testAdvancedOnlyFinalMaskReceivesSafeQUICDefaults() async throws {
        var profile = basicVLESS()
        profile.transport = TransportOptions(type: .xhttp, path: "/", xhttpMode: "stream-one")
        profile.xrayAdvanced = XrayAdvancedDocument([
            "streamSettings": .object([
                "finalmask": .object([
                    "quicParams": .object(["congestion": .string("reno")]),
                ]),
            ]),
        ])

        let json = try builder.build(profile: profile, routingMode: .global, rules: [])
        let outbound = try profileOutbound(parse(json))
        let stream = try XCTUnwrap(outbound["streamSettings"] as? [String: Any])
        let finalMask = try XCTUnwrap(stream["finalmask"] as? [String: Any])
        let quic = try XCTUnwrap(finalMask["quicParams"] as? [String: Any])

        XCTAssertEqual((quic["initStreamReceiveWindow"] as? NSNumber)?.intValue, 512 * 1024)
        XCTAssertEqual((quic["maxStreamReceiveWindow"] as? NSNumber)?.intValue, 512 * 1024)
        XCTAssertEqual((quic["initConnectionReceiveWindow"] as? NSNumber)?.intValue, 2 * 1024 * 1024)
        XCTAssertEqual((quic["maxConnectionReceiveWindow"] as? NSNumber)?.intValue, 2 * 1024 * 1024)
        XCTAssertEqual((quic["maxIncomingStreams"] as? NSNumber)?.intValue, 0)

        try await XrayCoreClient.validate(configJSON: json)
    }

    func testQUICRejectsZeroWindowsAndIncomingStreams() {
        for (key, value) in [
            ("initStreamReceiveWindow", 0),
            ("maxStreamReceiveWindow", 0),
            ("initConnectionReceiveWindow", 0),
            ("maxConnectionReceiveWindow", 0),
        ] {
            var profile = basicVLESS()
            profile.transport = TransportOptions(
                type: .tcp,
                finalMask: .object([
                    "quicParams": .object([key: .number(Double(value))]),
                ]),
            )
            assertRejected(profile, contains: "unsafe upstream memory default")
        }

        var profile = basicVLESS()
        profile.transport = TransportOptions(
            type: .tcp,
            finalMask: .object([
                "quicParams": .object(["maxIncomingStreams": .number(8)]),
            ]),
        )
        assertRejected(profile, contains: "iOS memory limit")
    }

    func testFinalMaskAcceptsOnlyPublicLiteralXDNSResolvers() throws {
        for resolver in [
            "observe.invalid:txt+udp://1.1.1.1:53",
            "observe.invalid:aaaa+udp://[2606:4700:4700::1111]:53",
            "observe.invalid:aaaa+udp://[2001:4860:4860::8888]:53",
            "observe.invalid:aaaa+udp://[64:ff9b::808:808]:53",
        ] {
            var profile = basicVLESS()
            profile.transport.finalMask = xdnsFinalMask(resolver)
            XCTAssertNoThrow(try builder.build(profile: profile, routingMode: .global, rules: []), resolver)
        }

        for resolver in [
            "observe.invalid:txt+udp://127.0.0.1:53",
            "observe.invalid:txt+udp://10.0.0.1:53",
            "observe.invalid:txt+udp://100.64.0.1:53",
            "observe.invalid:txt+udp://169.254.169.254:53",
            "observe.invalid:txt+udp://192.0.2.1:53",
            "observe.invalid:txt+udp://[::1]:53",
            "observe.invalid:txt+udp://[fe80::1]:53",
            "observe.invalid:txt+udp://[fc00::1]:53",
            "observe.invalid:txt+udp://[2001:db8::1]:53",
            "observe.invalid:txt+udp://[2001:2::1]:53",
            "observe.invalid:txt+udp://[3fff::1]:53",
            "observe.invalid:txt+udp://[5f00::1]:53",
            "observe.invalid:txt+udp://[100:0:0:1::1]:53",
            "observe.invalid:txt+udp://[64:ff9b::c0a8:101]:53",
            "observe.invalid:txt+udp://[::ffff:192.168.1.1]:53",
            "observe.invalid:txt+udp://resolver.example:53",
            "observe.invalid:txt+udp://1.1.1.1",
            "observe.invalid:txt+udp://1.1.1.1:65536",
            "observe.invalid:mx+udp://1.1.1.1:53",
            "observe.invalid:txt+tcp://1.1.1.1:53",
        ] {
            var profile = basicVLESS()
            profile.transport.finalMask = xdnsFinalMask(resolver)
            assertRejected(profile, contains: "XDNS resolvers")
        }
    }

    func testFinalMaskBoundsXDNSResolversAndRejectsServerDomains() {
        let resolvers = [
            "observe.invalid:txt+udp://1.1.1.1:53",
            "observe.invalid:txt+udp://9.9.9.9:53",
            "observe.invalid:txt+udp://8.8.8.8:53",
            "observe.invalid:txt+udp://208.67.222.222:53",
        ]
        XCTAssertEqual(resolvers.count, IOSRuntimeLimits.default.maxXDNSResolvers)

        var profile = basicVLESS()
        profile.transport.finalMask = xdnsFinalMask(resolvers)
        XCTAssertNoThrow(try builder.build(profile: profile, routingMode: .global, rules: []))

        profile.transport.finalMask = xdnsFinalMask(resolvers + ["observe.invalid:txt+udp://1.0.0.1:53"])
        assertRejected(profile, contains: "resolver iOS limit")

        for key in ["domain", "Domains"] {
            profile.transport.finalMask = .object([
                "udp": .array([
                    .object([
                        "type": .string("xdns"),
                        "settings": .object([
                            "resolvers": .array([.string(resolvers[0])]),
                            key: key == "domain"
                                ? .string("example.com")
                                : .array([.string("example.com")]),
                        ]),
                    ]),
                ]),
            ])
            assertRejected(profile, contains: "server domains")
        }
    }

    func testFinalMaskDestinationValidationHandlesCaseVariantsAndRejectsDuplicates() {
        var profile = basicVLESS()
        profile.transport.finalMask = .object([
            "UDP": .array([
                .object([
                    "Type": .string("XDNS"),
                    "Settings": .object([
                        "Resolvers": .array([.string("observe.invalid:txt+udp://127.0.0.1:53")]),
                    ]),
                ]),
            ]),
        ])
        assertRejected(profile, contains: "XDNS resolvers")

        profile.transport.finalMask = .object([
            "udp": .array([]),
            "UDP": .array([]),
        ])
        assertRejected(profile, contains: "duplicate keys")

        profile.transport.finalMask = .object([
            "udp": .array([
                .object([
                    "type": .string("noise"),
                    "Type": .string("xdns"),
                    "settings": .object([:]),
                ]),
            ]),
        ])
        assertRejected(profile, contains: "duplicate keys")
    }

    func testFinalMaskForbiddenFieldsUseUnicodeFolding() {
        for key in ["allowInſecure", "echConfigLiſt", "paſſword"] {
            var profile = basicVLESS()
            profile.transport.finalMask = .object([
                "tcp": .array([
                    .object([
                        "type": .string("noise"),
                        "settings": .object([
                            "nested": .object([key: .string("unsafe")]),
                        ]),
                    ]),
                ]),
            ])
            assertRejected(profile, contains: "cannot be supplied")
        }

        var profile = basicVLESS()
        profile.xrayAdvanced = XrayAdvancedDocument([
            "settings": .object(["ſeed": .string("must-not-persist")]),
        ])
        assertRejected(profile, contains: "cannot be supplied")
    }

    func testFinalMaskRequiresSecureRealmControlAndAllowedDestinations() async throws {
        var profile = basicVLESS()
        profile.transport.finalMask = realmFinalMask(url: "realm://token@1.1.1.1/realm-id")
        let json = try builder.build(profile: profile, routingMode: .global, rules: [])
        try await XrayCoreClient.validate(configJSON: json)

        profile.transport.finalMask = realmFinalMask(
            url: "realm://token@1.1.1.1/realm-id",
            stunServers: ["[2606:4700:4700::1111]:3478"],
        )
        XCTAssertNoThrow(try builder.build(profile: profile, routingMode: .global, rules: []))
        profile.transport.finalMask = realmFinalMask(
            url: "realm://token@1.1.1.1/realm-id",
            stunServers: ["[2001:4860:4860::8888]:3478"],
        )
        XCTAssertNoThrow(try builder.build(profile: profile, routingMode: .global, rules: []))

        let unsafeURLs = [
            "realm+http://token@1.1.1.1/realm-id",
            "ReAlM+HtTp://token@1.1.1.1/realm-id",
            "realm://1.1.1.1/realm-id",
            "realm://token:password@1.1.1.1/realm-id",
            "realm://token@/realm-id",
            "realm://token@1.1.1.1/",
            "realm://token@127.0.0.1/realm-id",
            "realm://token@2130706433/realm-id",
            "realm://token@1.1.1.1:65536/realm-id",
        ]
        for url in unsafeURLs {
            profile.transport.finalMask = realmFinalMask(url: url)
            assertRejected(profile, contains: "Realm control URLs")
        }

        for stunServer in [
            "stun.example.com:3478",
            "127.0.0.1:3478",
            "10.0.0.1:3478",
            "192.0.2.1:3478",
            "[::1]:3478",
            "[2001:db8::1]:3478",
            "[2001:2::1]:3478",
            "[3fff::1]:3478",
            "[5f00::1]:3478",
            "[64:ff9b::c0a8:101]:3478",
        ] {
            profile.transport.finalMask = realmFinalMask(
                url: "realm://token@1.1.1.1/realm-id",
                stunServers: [stunServer],
            )
            assertRejected(profile, contains: "Realm STUN servers")
        }

        profile.transport.finalMask = realmFinalMask(
            url: "realm://token@1.1.1.1/realm-id",
            stunServers: Array(repeating: "1.1.1.1:3478", count: IOSRuntimeLimits.default.maxRealmSTUNServers + 1),
        )
        assertRejected(profile, contains: "iOS STUN limit")

        profile.transport.finalMask = .object([
            "udp": .array([
                .object([
                    "Type": .string("Realm"),
                    "Settings": .object([
                        "URL": .string("realm+http://token@1.1.1.1/realm-id"),
                        "StunServers": .array([.string("1.1.1.1:3478")]),
                    ]),
                ]),
            ]),
        ])
        assertRejected(profile, contains: "Realm control URLs")

        profile.transport.finalMask = .object([
            "udp": .array([
                .object([
                    "type": .string("realm"),
                    "settings": .object([
                        "url": .string("realm://token@1.1.1.1/realm-id"),
                        "URL": .string("realm+http://token@1.1.1.1/realm-id"),
                        "stunServers": .array([.string("1.1.1.1:3478")]),
                    ]),
                ]),
            ]),
        ])
        assertRejected(profile, contains: "duplicate keys")
    }

    func testTokenizedRealmURLPassesSecondBuilderAdmission() throws {
        var profile = basicVLESS()
        profile.transport.finalMask = realmFinalMask(url: "realm://token@1.1.1.1/realm-id")
        let tokenized = profile.tokenizingSecrets(nonce: "realm-test-nonce")
        let json = try builder.build(profile: tokenized, routingMode: .global, rules: [])
        XCTAssertTrue(json.contains("##HOP_SECRET:realm-test-nonce:"))
        XCTAssertFalse(json.contains("realm://token@"))
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
                "PoolSize": .number(1024),
            ]),
        ])
        try await XrayCoreClient.validate(configJSON: builder.build(profile: basicVLESS(), routingMode: .global, rules: [], settings: settings))

        settings.xrayAdvanced = XrayAdvancedDocument([
            "fakeDns": .object([
                "ipPool": .string("198.18.0.0/15"),
                "poolſize": .number(4097),
            ]),
        ])
        XCTAssertThrowsError(try builder.build(profile: basicVLESS(), routingMode: .global, rules: [], settings: settings)) { error in
            XCTAssertTrue(error.localizedDescription.contains("4096-entry"))
        }

        settings.xrayAdvanced = XrayAdvancedDocument([
            "fakeDns": .object([
                "ipPool": .string("198.18.0.0/15"),
                "poolSize": .number(1),
                "PoolSize": .number(2),
            ]),
        ])
        XCTAssertThrowsError(try builder.build(profile: basicVLESS(), routingMode: .global, rules: [], settings: settings)) { error in
            XCTAssertTrue(error.localizedDescription.contains("duplicate keys"), "Unexpected error: \(error)")
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
                "xPaddingBytes": .object(["from": .number(1), "to": .number(16 * 1024 + 1)]),
            ]),
        )
        assertRejected(profile, contains: "iOS memory limit")

        var settings = AppSettings.defaults
        settings.xrayAdvanced = XrayAdvancedDocument([
            "policy": .object([
                "levels": .object([
                    "1": .object(["bufferSize": .number(17)]),
                ]),
            ]),
        ])
        XCTAssertThrowsError(try builder.build(profile: basicVLESS(), routingMode: .global, rules: [], settings: settings)) { error in
            XCTAssertTrue(error.localizedDescription.contains("iOS memory limit"))
        }
    }

    func testAdvancedPolicyBufferCeilingRejectsNegativeAndCollisions() async throws {
        var settings = AppSettings.defaults
        settings.xrayAdvanced = XrayAdvancedDocument([
            "policy": .object([
                "levels": .object([
                    "1": .object([
                        "bufferSize": .number(16),
                        "handshake": .number(15),
                        "connIdle": .number(120),
                        "uplinkOnly": .number(1),
                        "downlinkOnly": .number(1),
                    ]),
                ]),
            ]),
        ])
        let json = try builder.build(profile: basicVLESS(), routingMode: .global, rules: [], settings: settings)
        try await XrayCoreClient.validate(configJSON: json)

        for unsafe in [-1, 17] {
            settings.xrayAdvanced = XrayAdvancedDocument([
                "policy": .object([
                    "levels": .object([
                        "1": .object(["bufferSize": .number(Double(unsafe))]),
                    ]),
                ]),
            ])
            XCTAssertThrowsError(try builder.build(profile: basicVLESS(), routingMode: .global, rules: [], settings: settings))
        }

        for (key, value) in [("handshake", 16), ("connIdle", 121), ("uplinkOnly", 2), ("downlinkOnly", 2)] {
            settings.xrayAdvanced = XrayAdvancedDocument([
                "policy": .object([
                    "levels": .object([
                        "1": .object([key: .number(Double(value))]),
                    ]),
                ]),
            ])
            XCTAssertThrowsError(try builder.build(profile: basicVLESS(), routingMode: .global, rules: [], settings: settings))
        }

        settings.xrayAdvanced = XrayAdvancedDocument([
            "policy": .object([
                "levels": .object([
                    "0": .object(["bufferSize": .number(0)]),
                ]),
            ]),
        ])
        XCTAssertThrowsError(try builder.build(profile: basicVLESS(), routingMode: .global, rules: [], settings: settings)) { error in
            XCTAssertTrue(error.localizedDescription.contains("level-0 policy"))
        }
    }

    func testAdvancedPolicyLevelsMustBeCanonicalAndCannotAliasLevelZero() {
        var settings = AppSettings.defaults
        for level in ["0", "00", "01", "+1", "-1", "4294967296", " 1"] {
            settings.xrayAdvanced = XrayAdvancedDocument([
                "policy": .object([
                    "levels": .object([
                        level: .object(["bufferSize": .number(0)]),
                    ]),
                ]),
            ])
            XCTAssertThrowsError(try builder.build(profile: basicVLESS(), routingMode: .global, rules: [], settings: settings))
        }
    }

    func testProfileAdvancedCannotSelectPolicyLevel() {
        var profile = basicVLESS()
        profile.xrayAdvanced = XrayAdvancedDocument([
            "settings": .object([
                "level": .number(1),
            ]),
        ])

        assertRejected(profile, contains: "Unknown or server-only")
    }

    func testBurstObservatoryIsUnavailableOnIOS() {
        var settings = AppSettings.defaults
        settings.xrayAdvanced = XrayAdvancedDocument([
            "burstObservatory": .object([
                "subjectSelector": .array([.string("proxy-")]),
                "pingConfig": .object([
                    "sampling": .number(40 * 1024 * 1024),
                ]),
            ]),
        ])

        XCTAssertThrowsError(try builder.build(profile: basicVLESS(), routingMode: .global, rules: [], settings: settings)) { error in
            XCTAssertTrue(error.localizedDescription.contains("Unknown or server-only"), "Unexpected error: \(error)")
        }
    }

    func testAdvancedKCPMemoryFieldsUseMergedContext() async throws {
        for (settings, expected) in [
            (["uplinkCapacity": JSONValue.number(21)], "write-buffer limit"),
            (["downlinkCapacity": JSONValue.number(21)], "read-buffer limit"),
            (["cwndMultiplier": JSONValue.number(17)], "congestion-window multiplier"),
            (["maxSendingWindow": JSONValue.number(2 * 1024 * 1024)], "collides"),
        ] {
            var profile = basicVLESS()
            profile.security = .none
            profile.transport = TransportOptions(type: .mKCP)
            profile.xrayAdvanced = XrayAdvancedDocument([
                "streamSettings": .object([
                    "kcpSettings": .object(settings),
                ]),
            ])
            assertRejected(profile, contains: expected)
        }

        var profile = basicVLESS()
        profile.security = .none
        profile.transport = TransportOptions(type: .mKCP)
        profile.xrayAdvanced = XrayAdvancedDocument([
            "streamSettings": .object([
                "kcpSettings": .object([
                    "uplinkCapacity": .number(20),
                    "downlinkCapacity": .number(20),
                    "cwndMultiplier": .number(16),
                ]),
            ]),
        ])
        let json = try builder.build(profile: profile, routingMode: .global, rules: [])
        try await XrayCoreClient.validate(configJSON: json)
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

    func testProxyGroupReachabilityEnforcesDepthAndWorkBudgets() throws {
        let profile = basicVLESS()
        let safe = selectGroupChain(
            length: IOSRuntimeLimits.default.maxProxyGroupDepth,
            terminal: .profile(profile.id),
        )
        XCTAssertNoThrow(try builder.build(
            profiles: [profile],
            groups: safe.groups,
            selectedTarget: safe.selected,
            routingMode: .global,
            rules: [],
        ))

        let tooDeep = selectGroupChain(
            length: IOSRuntimeLimits.default.maxProxyGroupDepth + 1,
            terminal: .profile(profile.id),
        )
        XCTAssertThrowsError(try builder.build(
            profiles: [profile],
            groups: tooDeep.groups,
            selectedTarget: tooDeep.selected,
            routingMode: .global,
            rules: [],
        )) { error in
            XCTAssertTrue(error.localizedDescription.contains("dependency depth"), "Unexpected error: \(error)")
        }

        let missingMembers = (0 ... IOSRuntimeLimits.default.maxProxyGroupResolutionSteps)
            .map { OutboundTarget.named("missing-\($0)") }
        let exhausting = ProxyGroup(name: "Fallbacks", type: .select, members: missingMembers)
        XCTAssertThrowsError(try builder.build(
            profiles: [profile],
            groups: [exhausting],
            selectedTarget: .group(exhausting.id),
            routingMode: .global,
            rules: [],
        )) { error in
            XCTAssertTrue(error.localizedDescription.contains("work limit"), "Unexpected error: \(error)")
        }
    }

    func testRoutingAtomBoundaryDoesNotDoubleChargeTargetResolution() throws {
        let rule = RoutingRule(kind: .final, value: "", target: .direct)
        let maximumRules = Array(repeating: rule, count: IOSRuntimeLimits.default.maxRoutingAtoms)
        XCTAssertNoThrow(try builder.build(
            profile: basicVLESS(),
            routingMode: .rule,
            rules: maximumRules,
        ))

        let excessiveRules = maximumRules + [rule]
        XCTAssertThrowsError(try builder.build(
            profile: basicVLESS(),
            routingMode: .rule,
            rules: excessiveRules,
        )) { error in
            XCTAssertTrue(error.localizedDescription.contains("Routing contains 4097 atoms"), "Unexpected error: \(error)")
        }
    }

    func testProxyGroupDefaultMemberDedupAndCycleBehaviorRemainBounded() throws {
        let profile = basicVLESS()
        let failing = selectGroupChain(length: 14, terminal: .named("missing"))
        XCTAssertThrowsError(try builder.build(
            profiles: [profile],
            groups: failing.groups,
            selectedTarget: failing.selected,
            routingMode: .global,
            rules: [],
        )) { error in
            XCTAssertTrue(error.localizedDescription.contains("no runnable member"), "Unexpected error: \(error)")
            XCTAssertFalse(error.localizedDescription.contains("work limit"), "Unexpected error: \(error)")
        }

        let firstID = UUID()
        let secondID = UUID()
        let first = ProxyGroup(id: firstID, name: "Cycle A", type: .urlTest, members: [.group(secondID)])
        let second = ProxyGroup(id: secondID, name: "Cycle B", type: .urlTest, members: [.group(firstID)])
        XCTAssertThrowsError(try builder.build(
            profiles: [profile],
            groups: [first, second],
            selectedTarget: .group(firstID),
            routingMode: .global,
            rules: [],
        )) { error in
            XCTAssertTrue(error.localizedDescription.contains("dependency cycle"), "Unexpected error: \(error)")
        }
    }

    func testNamedTargetsFailClosedOnNormalizedNameAmbiguityAndRecoverWhenUnique() throws {
        var manualProfile = basicVLESS()
        manualProfile.name = "Shared Node"
        let manualGroup = ProxyGroup(
            name: "Manual",
            type: .select,
            members: [.named(" shared node ")],
            defaultTarget: .named("SHARED NODE"),
        )
        let namedRule = RoutingRule(kind: .domain, value: "example.com", target: .named("Shared Node"))

        XCTAssertNoThrow(try builder.build(
            profiles: [manualProfile],
            groups: [manualGroup],
            selectedTarget: .group(manualGroup.id),
            routingMode: .rule,
            rules: [namedRule],
        ))

        var subscriptionProfile = manualProfile
        subscriptionProfile.id = UUID()
        subscriptionProfile.name = " shared NODE "
        subscriptionProfile.subscriptionID = UUID()
        XCTAssertThrowsError(try builder.build(
            profiles: [manualProfile, subscriptionProfile],
            groups: [manualGroup],
            selectedTarget: .group(manualGroup.id),
            routingMode: .rule,
            rules: [namedRule],
        )) { error in
            XCTAssertTrue(error.localizedDescription.contains("ambiguous"), "Unexpected error: \(error)")
        }

        XCTAssertNoThrow(try builder.build(
            profiles: [manualProfile],
            groups: [manualGroup],
            selectedTarget: .group(manualGroup.id),
            routingMode: .rule,
            rules: [namedRule],
        ))

        let firstGroup = ProxyGroup(name: "Duplicate Group", type: .select, members: [.profile(manualProfile.id)])
        let secondGroup = ProxyGroup(name: " duplicate group ", type: .select, members: [.profile(manualProfile.id)])
        XCTAssertThrowsError(try builder.build(
            profiles: [manualProfile],
            groups: [firstGroup, secondGroup],
            selectedTarget: .named("Duplicate Group"),
            routingMode: .global,
            rules: [],
        )) { error in
            XCTAssertTrue(error.localizedDescription.contains("ambiguous"), "Unexpected error: \(error)")
        }
        XCTAssertNoThrow(try builder.build(
            profiles: [manualProfile],
            groups: [firstGroup, secondGroup],
            selectedTarget: .group(firstGroup.id),
            routingMode: .global,
            rules: [],
        ))

        let collidingGroup = ProxyGroup(name: "Shared Node", type: .select, members: [.profile(manualProfile.id)])
        XCTAssertThrowsError(try builder.build(
            profiles: [manualProfile],
            groups: [collidingGroup],
            selectedTarget: .named("shared node"),
            routingMode: .global,
            rules: [],
        )) { error in
            XCTAssertTrue(error.localizedDescription.contains("ambiguous"), "Unexpected error: \(error)")
        }
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

    func testJSONValueIntegerConversionUsesExactSignedRange() throws {
        let twoTo63 = Double(bitPattern: 0x43E0_0000_0000_0000)
        XCTAssertNil(JSONValue.number(twoTo63).integerValue)
        XCTAssertEqual(JSONValue.number(Double(Int.min)).integerValue, Int.min)
        XCTAssertEqual(JSONValue.number(twoTo63.nextDown).integerValue, Int(exactly: twoTo63.nextDown))
        XCTAssertNil(JSONValue.number(1.5).integerValue)
        XCTAssertNil(JSONValue.number(.nan).integerValue)
        XCTAssertNil(JSONValue.number(.infinity).integerValue)

        let decoded = try JSONDecoder().decode(JSONValue.self, from: Data("9223372036854775808".utf8))
        XCTAssertEqual(decoded, .number(twoTo63))
        XCTAssertNil(decoded.integerValue)
    }

    func testOutOfRangeMemoryBoundsFailClosedWithoutTrapping() throws {
        let twoTo63 = Double(bitPattern: 0x43E0_0000_0000_0000)
        let generatedSizes: [JSONValue] = [
            .number(twoTo63),
            .array([.number(twoTo63)]),
            .object(["from": .number(1), "to": .number(twoTo63)]),
            .object(["nested": .array([.number(twoTo63)])]),
        ]
        for generatedSize in generatedSizes {
            var profile = basicVLESS()
            profile.transport.finalMask = .object([
                "tcp": .array([
                    .object([
                        "type": .string("noise"),
                        "settings": .object(["length": generatedSize]),
                    ]),
                ]),
            ])
            assertRejected(profile, contains: "FinalMask may generate")
        }

        var profile = basicVLESS()
        profile.xrayAdvanced = XrayAdvancedDocument([
            "mux": .object(["concurrency": .number(twoTo63)]),
        ])
        assertRejected(profile, contains: "iOS memory limit")

        var settings = AppSettings.defaults
        settings.xrayAdvanced = XrayAdvancedDocument([
            "fakeDns": .object([
                "ipPool": .string("198.18.0.0/15"),
                "poolSize": .number(twoTo63),
            ]),
        ])
        XCTAssertThrowsError(try builder.build(profile: basicVLESS(), routingMode: .global, rules: [], settings: settings)) { error in
            XCTAssertTrue(error.localizedDescription.contains("in-range integer"), "Unexpected error: \(error)")
        }

        settings.xrayAdvanced = XrayAdvancedDocument([
            "fakeDns": .array([
                .object(["ipPool": .string("198.18.0.0/16"), "poolSize": .number(4096)]),
                .object(["ipPool": .string("198.19.0.0/16"), "poolSize": .number(4096)]),
            ]),
        ])
        XCTAssertThrowsError(try builder.build(profile: basicVLESS(), routingMode: .global, rules: [], settings: settings)) { error in
            XCTAssertTrue(error.localizedDescription.contains("4096-entry"), "Unexpected error: \(error)")
        }
    }

    func testCaseFoldedMemoryBoundsAndCollisionsFailClosed() throws {
        var profile = basicVLESS()
        profile.transport.finalMask = .object([
            "tcp": .array([
                .object([
                    "type": .string("noise"),
                    "settings": .object(["Length": .number(64)]),
                ]),
            ]),
        ])
        XCTAssertNoThrow(try builder.build(profile: profile, routingMode: .global, rules: []))

        for key in ["Length", "PACKETSIZE", "Packetſize", "Padding_Max"] {
            profile.transport.finalMask = .object([
                "tcp": .array([
                    .object([
                        "type": .string("noise"),
                        "settings": .object([
                            key: .number(Double(IOSRuntimeLimits.default.maxFinalMaskGeneratedPayloadBytes + 1)),
                        ]),
                    ]),
                ]),
            ])
            assertRejected(profile, contains: "FinalMask may generate")
        }

        profile.transport.finalMask = .object([
            "tcp": .array([
                .object([
                    "type": .string("noise"),
                    "settings": .object([
                        "Concurrency": .number(Double(IOSRuntimeLimits.default.maxMuxConcurrency + 1)),
                    ]),
                ]),
            ]),
        ])
        assertRejected(profile, contains: "iOS memory limit")

        profile.transport.finalMask = .object([
            "tcp": .array([
                .object([
                    "type": .string("noise"),
                    "settings": .object([
                        "length": .number(1),
                        "Length": .number(2),
                    ]),
                ]),
            ]),
        ])
        assertRejected(profile, contains: "duplicate generated-size keys")

        profile.transport.finalMask = .object([
            "tcp": .array([
                .object([
                    "type": .string("noise"),
                    "settings": .object([
                        "packetSize": .number(1),
                        "packetſize": .number(2),
                    ]),
                ]),
            ]),
        ])
        assertRejected(profile, contains: "duplicate generated-size keys")

        profile.transport.finalMask = .object([
            "tcp": .array([
                .object([
                    "type": .string("noise"),
                    "settings": .object([
                        "concurrency": .number(1),
                        "Concurrency": .number(2),
                    ]),
                ]),
            ]),
        ])
        assertRejected(profile, contains: "duplicate protected keys")

        profile = basicVLESS()
        profile.transport = TransportOptions(
            type: .xhttp,
            xhttpExtra: .object([
                "xmux": .object([
                    "maxConnectionſ": .number(3),
                ]),
            ]),
        )
        assertRejected(profile, contains: "duplicate protected keys")
    }

    private func basicVLESS() -> ProxyProfile {
        ProxyProfile(
            name: "VLESS",
            endpoint: Endpoint(host: "example.com", port: 443),
            options: .vless(VLESSOptions(uuid: "11111111-1111-4111-8111-111111111111", encryption: "none")),
            security: .tls(TLSOptions(serverName: "example.com")),
        )
    }

    private func xdnsFinalMask(_ resolver: String) -> JSONValue {
        xdnsFinalMask([resolver])
    }

    private func xdnsFinalMask(_ resolvers: [String]) -> JSONValue {
        .object([
            "udp": .array([
                .object([
                    "type": .string("xdns"),
                    "settings": .object([
                        "resolvers": .array(resolvers.map(JSONValue.string)),
                    ]),
                ]),
            ]),
        ])
    }

    private func realmFinalMask(
        url: String,
        stunServers: [String] = ["1.1.1.1:3478"],
    ) -> JSONValue {
        .object([
            "udp": .array([
                .object([
                    "type": .string("realm"),
                    "settings": .object([
                        "url": .string(url),
                        "stunServers": .array(stunServers.map(JSONValue.string)),
                    ]),
                ]),
            ]),
        ])
    }

    private func selectGroupChain(
        length: Int,
        terminal: OutboundTarget,
    ) -> (groups: [ProxyGroup], selected: OutboundTarget) {
        var groups: [ProxyGroup] = []
        var target = terminal
        for index in 0 ..< length {
            let group = ProxyGroup(
                name: "Chain \(index)",
                type: .select,
                members: [target],
                defaultTarget: target,
            )
            groups.append(group)
            target = .group(group.id)
        }
        return (groups, target)
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
