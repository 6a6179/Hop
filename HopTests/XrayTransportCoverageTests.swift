@testable import Hop
import XCTest

final class XrayTransportCoverageTests: XCTestCase {
    func testECHResolverSocketOptionsAreRejectedForInlineOnlyECH() {
        var profile = profile()
        profile.xrayAdvanced = XrayAdvancedDocument([
            "streamSettings": .object([
                "tlsSettings": .object(["echSockopt": .object(["tcpFastOpen": .bool(true)])]),
            ]),
        ])
        XCTAssertThrowsError(try XrayConfigBuilder().build(profile: profile, routingMode: .global, rules: [])) { error in
            XCTAssertTrue(error.localizedDescription.contains("echSockopt"), "\(error)")
        }
    }

    func testSocketFieldsWithoutAnIOSClientImplementationAreRejected() {
        let unsupported: [String: JSONValue] = [
            "mark": .number(1), "tproxy": .string("tproxy"), "tcpCongestion": .string("bbr"),
            "tcpWindowClamp": .number(1024), "tcpMaxSeg": .number(1200), "tcpUserTimeout": .number(30),
            "tcpMptcp": .bool(true), "v6only": .bool(true), "trustedXForwardedFor": .array([.string("127.0.0.1")]),
            "acceptProxyProtocol": .bool(true), "customSockopt": .array([]),
        ]
        for (key, value) in unsupported {
            for useTypedSocket in [true, false] {
                var profile = profile()
                let socket = JSONValue.object([key: value])
                if useTypedSocket {
                    profile.transport.socketOptions = socket
                } else {
                    profile.xrayAdvanced = XrayAdvancedDocument(["streamSettings": .object(["sockopt": socket])])
                }
                XCTAssertThrowsError(try XrayConfigBuilder().build(profile: profile, routingMode: .global, rules: [])) { error in
                    XCTAssertTrue(error.localizedDescription.contains(key), "\(error)")
                }
            }
        }
    }

    func testGRPCInitialWindowStaysAtTheIOSDefault() async throws {
        var profile = profile()
        profile.transport = TransportOptions(type: .grpc, serviceName: "tunnel")
        profile.xrayAdvanced = XrayAdvancedDocument([
            "streamSettings": .object(["grpcSettings": .object(["initial_windows_size": .number(0)])]),
        ])
        let json = try XrayConfigBuilder().build(profile: profile, routingMode: .global, rules: [])
        XCTAssertTrue(json.contains("\"initial_windows_size\":0"))
        try await XrayCoreClient.validate(configJSON: json)

        profile.xrayAdvanced = XrayAdvancedDocument([
            "streamSettings": .object([
                "grpcSettings": .object(["initial_windows_size": .number(Double(IOSRuntimeLimits.default.maxGRPCInitialWindowBytes + 1))]),
            ]),
        ])
        XCTAssertThrowsError(try XrayConfigBuilder().build(profile: profile, routingMode: .global, rules: []))
    }

    func testXHTTPLongTailFieldsReachCoreFromOuterAndExtraSettings() async throws {
        var profile = profile()
        profile.transport.xhttpExtra = .object([
            "headers": .object(["X-Typed": .string("kept")]),
            "xPaddingKey": .string("padding"),
        ])
        profile.xrayAdvanced = XrayAdvancedDocument([
            "streamSettings": .object([
                "xhttpSettings": .object([
                    "headers": .object(["X-Advanced": .string("also-kept")]),
                    "xPaddingBytes": .string("64-128"),
                    "scMaxEachPostBytes": .number(1024),
                    "xmux": .object(["maxConnections": .number(1)]),
                ]),
            ]),
        ])

        let json = try XrayConfigBuilder().build(profile: profile, routingMode: .global, rules: [])
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        let outbound = try XCTUnwrap((root["outbounds"] as? [[String: Any]])?.first { $0["protocol"] as? String == "vless" })
        let stream = try XCTUnwrap(outbound["streamSettings"] as? [String: Any])
        let xhttp = try XCTUnwrap(stream["xhttpSettings"] as? [String: Any])
        let extra = try XCTUnwrap(xhttp["extra"] as? [String: Any])
        XCTAssertEqual(Set(xhttp.keys), ["host", "path", "mode", "extra"])
        XCTAssertEqual(xhttp["host"] as? String, "front.example")
        XCTAssertEqual(xhttp["path"] as? String, "/tunnel")
        XCTAssertEqual(xhttp["mode"] as? String, "packet-up")
        XCTAssertEqual(extra["headers"] as? [String: String], ["X-Typed": "kept", "X-Advanced": "also-kept"])
        XCTAssertEqual(extra["xPaddingKey"] as? String, "padding")
        XCTAssertEqual(extra["xPaddingBytes"] as? String, "64-128")
        XCTAssertEqual(extra["scMaxEachPostBytes"] as? Int, 1024)
        XCTAssertEqual(extra["scMaxBufferedPosts"] as? Int, 1)
        XCTAssertEqual((extra["xmux"] as? [String: Any])?["maxConnections"] as? Int, 1)
        try await XrayCoreClient.validate(configJSON: json)
    }

    func testXHTTPRejectsFieldsTheCoreIgnoresInsideExtra() {
        for key in ["host", "path", "mode", "extra"] {
            for useTypedExtra in [true, false] {
                var profile = profile()
                let extra = JSONValue.object([key: key == "extra" ? .object([:]) : .string("ignored")])
                if useTypedExtra {
                    profile.transport.xhttpExtra = extra
                } else {
                    profile.xrayAdvanced = XrayAdvancedDocument([
                        "streamSettings": .object(["xhttpSettings": .object(["extra": extra])]),
                    ])
                }
                XCTAssertThrowsError(try XrayConfigBuilder().build(profile: profile, routingMode: .global, rules: [])) { error in
                    XCTAssertTrue(error.localizedDescription.contains("belongs outside extra"), "\(error)")
                }
            }
        }
    }

    func testXHTTPRejectsServerOnlyFieldsFromTypedAndAdvancedSettings() {
        for key in ["scMaxBufferedPosts", "scStreamUpServerSecs", "serverMaxHeaderBytes", "noSSEHeader"] {
            for useTypedExtra in [true, false] {
                var profile = profile()
                let fields = JSONValue.object([key: key == "noSSEHeader" ? .bool(true) : .number(1)])
                if useTypedExtra {
                    profile.transport.xhttpExtra = fields
                } else {
                    profile.xrayAdvanced = XrayAdvancedDocument([
                        "streamSettings": .object(["xhttpSettings": fields]),
                    ])
                }
                XCTAssertThrowsError(try XrayConfigBuilder().build(profile: profile, routingMode: .global, rules: [])) { error in
                    XCTAssertTrue(error.localizedDescription.contains(key), "\(error)")
                }
            }
        }
    }

    func testXHTTPNormalizationRejectsTypedAndAdvancedCollisions() {
        var profile = profile()
        profile.transport.xhttpExtra = .object(["headers": .object(["X-Shared": .string("typed")])])
        profile.xrayAdvanced = XrayAdvancedDocument([
            "streamSettings": .object([
                "xhttpSettings": .object(["headers": .object(["X-Shared": .string("advanced")])]),
            ]),
        ])
        XCTAssertThrowsError(try XrayConfigBuilder().build(profile: profile, routingMode: .global, rules: [])) { error in
            XCTAssertTrue(error.localizedDescription.contains("collides"), "\(error)")
        }
    }

    func testXHTTPNormalizationStillRejectsExcessiveMemoryAndInvalidXMux() {
        for value in [JSONValue.object(["maxConnections": .number(999)]), .string("invalid"), .null] {
            var profile = profile()
            profile.xrayAdvanced = XrayAdvancedDocument([
                "streamSettings": .object(["xhttpSettings": .object(["xmux": value])]),
            ])
            XCTAssertThrowsError(try XrayConfigBuilder().build(profile: profile, routingMode: .global, rules: []))
        }
    }

    private func profile() -> ProxyProfile {
        ProxyProfile(
            name: "XHTTP",
            endpoint: Endpoint(host: "edge.example", port: 443),
            options: .vless(VLESSOptions(uuid: "11111111-1111-4111-8111-111111111111")),
            security: .tls(TLSOptions(serverName: "edge.example")),
            transport: TransportOptions(type: .xhttp, path: "/tunnel", host: "front.example", xhttpMode: "packet-up"),
        )
    }
}
