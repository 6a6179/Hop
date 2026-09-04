import Foundation
@testable import Hop
import XCTest

@MainActor
final class ProfileEditorTests: XCTestCase {
    func testLegacyInsecureTLSCanBeRepairedWithAValidCertificatePin() throws {
        let profile = ProxyProfile(
            name: "Legacy", endpoint: Endpoint(host: "example.com", port: 443),
            options: .trojan(TrojanOptions(password: "secret")),
            security: .tls(TLSOptions(allowInsecure: true)),
        )
        var draft = ProfileEditorDraft(profile: profile)
        XCTAssertNil(draft.validation.profile)
        draft.tlsPinnedCertificates = "not-a-pin"
        XCTAssertNil(draft.validation.profile)
        draft.tlsPinnedCertificates = String(repeating: "ab", count: 32)
        let saved = try XCTUnwrap(draft.validation.profile, draft.validation.message ?? "")
        XCTAssertEqual(saved.security.tls?.allowInsecure, false)
        XCTAssertEqual(saved.security.tls?.pinnedPeerCertSHA256, draft.tlsPinnedCertificates)
    }

    func testWireGuardReservedBytesRejectMalformedTokensWithoutDroppingThem() throws {
        let profile = ProxyProfile(
            name: "WireGuard", endpoint: Endpoint(host: "example.com", port: 51820),
            options: .wireGuard(WireGuardOptions(privateKey: "private-key", peerPublicKey: "peer-key", localAddress: ["10.0.0.2/32"])),
            security: .none,
        )
        var draft = ProfileEditorDraft(profile: profile)
        for value in ["1,2,3,junk", "1,,2,3", ",1,2,3", "1,2,3,", "1,junk,3", "1,2,256"] {
            draft.wireGuardReserved = value
            XCTAssertNil(draft.validation.profile, value)
            XCTAssertTrue(draft.validation.message?.contains("reserved bytes") == true, value)
        }
        draft.wireGuardReserved = " 0, 128, 255 "
        let saved = try XCTUnwrap(draft.validation.profile, draft.validation.message ?? "")
        guard case let .wireGuard(options) = saved.options else { return XCTFail("Expected WireGuard") }
        XCTAssertEqual(options.reserved, [0, 128, 255])
    }

    func testRenamingPreservesOpaqueCredentialsIncludingWhitespaceOnlyPasswords() throws {
        for credential in [" secret ", " \t "] {
            let protocols: [ProtocolOptions] = [
                .trojan(TrojanOptions(password: credential)),
                .hysteria2(Hysteria2Options(password: credential, obfs: "salamander", obfsPassword: credential)),
                .shadowsocks(ShadowsocksOptions(method: "aes-128-gcm", password: credential)),
                .http(HTTPOptions(username: credential, password: credential)),
                .socks(SOCKSOptions(username: credential, password: credential)),
            ]
            for options in protocols {
                let profile = ProxyProfile(
                    name: "Before",
                    endpoint: Endpoint(host: "example.com", port: 443),
                    options: options,
                    security: .tls(TLSOptions()),
                )
                var draft = ProfileEditorDraft(profile: profile)
                draft.name = "Renamed"
                let validation = draft.validation
                let saved = try XCTUnwrap(validation.profile, validation.message ?? "")
                XCTAssertEqual(saved.options, options, "\(profile.proto)")
            }
        }
    }

    func testEditingPasswordPreservesBytesAndStillRejectsEmptyPassword() throws {
        let profile = ProxyProfile(
            name: "Trojan",
            endpoint: Endpoint(host: "example.com", port: 443),
            options: .trojan(TrojanOptions(password: "old")),
            security: .tls(TLSOptions()),
        )
        var draft = ProfileEditorDraft(profile: profile)
        draft.trojanPassword = " new\tpassword "
        let saved = try XCTUnwrap(draft.validation.profile)
        XCTAssertEqual(saved.options, .trojan(TrojanOptions(password: " new\tpassword ")))
        draft.trojanPassword = ""
        XCTAssertNil(draft.validation.profile)
    }

    func testALPNPreservesOrderAndCustomValuesAndSupportsEditing() throws {
        let alpn = ["http/1.1", "h2", "custom-alpn", "custom,token", " spaced-token "]
        let securities: [ProxySecurity] = [
            .tls(TLSOptions(alpn: alpn)),
            .reality(RealityOptions(publicKey: "public-key", serverName: "example.com"), alpn: alpn),
        ]
        for security in securities {
            let profile = ProxyProfile(
                name: "ALPN",
                endpoint: Endpoint(host: "example.com", port: 443),
                options: .trojan(TrojanOptions(password: "secret")),
                security: security,
            )
            var draft = ProfileEditorDraft(profile: profile)
            draft.name = "Renamed"
            XCTAssertEqual(try XCTUnwrap(draft.validation.profile).security.tls?.alpn, alpn)
            draft.tlsALPN = "h3, app/custom, http/1.1"
            XCTAssertEqual(try XCTUnwrap(draft.validation.profile).security.tls?.alpn, ["h3", "app/custom", "http/1.1"])
            draft.tlsALPN = ""
            XCTAssertEqual(try XCTUnwrap(draft.validation.profile).security.tls?.alpn, [])
        }
    }

    func testWireGuardEditsFirstExplicitEndpointWithoutRetargetingOtherPeers() throws {
        let fallback = Endpoint(host: "fallback.example.com", port: 51820)
        let first = WireGuardPeer(publicKey: "first-key", endpoint: Endpoint(host: "first.example.com", port: 51821))
        let second = WireGuardPeer(publicKey: "second-key")
        let profile = ProxyProfile(
            name: "WireGuard",
            endpoint: fallback,
            options: .wireGuard(WireGuardOptions(
                privateKey: "private-key",
                peerPublicKey: first.publicKey,
                localAddress: ["10.0.0.2/32"],
                peers: [first, second],
            )),
            security: .none,
        )
        var draft = ProfileEditorDraft(profile: profile)
        XCTAssertEqual(draft.host, first.endpoint?.host)
        XCTAssertEqual(draft.port, "51821")
        XCTAssertEqual(try XCTUnwrap(draft.validation.profile), profile)

        draft.host = "new.example.com"
        draft.port = "51822"
        let saved = try XCTUnwrap(draft.validation.profile)
        XCTAssertEqual(saved.endpoint, fallback)
        guard case let .wireGuard(options) = saved.options else { return XCTFail("Expected WireGuard") }
        XCTAssertEqual(options.effectivePeers[0].id, first.id)
        XCTAssertEqual(options.effectivePeers[0].endpoint, Endpoint(host: "new.example.com", port: 51822))
        XCTAssertEqual(options.effectivePeers[1], second)
        let reopened = ProfileEditorDraft(profile: saved)
        XCTAssertEqual(reopened.host, "new.example.com")
        XCTAssertEqual(reopened.port, "51822")
        draft.wireGuardFallbackHost = "fallback-new.example.com"
        draft.wireGuardFallbackPort = "51823"
        let changedFallback = try XCTUnwrap(draft.validation.profile, draft.validation.message ?? "")
        XCTAssertEqual(changedFallback.endpoint, Endpoint(host: "fallback-new.example.com", port: 51823))
        guard case let .wireGuard(changedOptions) = changedFallback.options else { return XCTFail("Expected WireGuard") }
        XCTAssertEqual(changedOptions.peers, options.peers)
        draft.wireGuardFallbackPort = "invalid"
        XCTAssertNil(draft.validation.profile)
    }

    func testWireGuardEditsFallbackWhenFirstPeerHasNoExplicitEndpoint() throws {
        let first = WireGuardPeer(publicKey: "first-key")
        for peers: [WireGuardPeer]? in [nil, [first]] {
            let profile = ProxyProfile(
                name: "WireGuard",
                endpoint: Endpoint(host: "old.example.com", port: 51820),
                options: .wireGuard(WireGuardOptions(
                    privateKey: "private-key",
                    peerPublicKey: first.publicKey,
                    localAddress: ["10.0.0.2/32"],
                    peers: peers,
                )),
                security: .none,
            )
            var draft = ProfileEditorDraft(profile: profile)
            draft.host = "new.example.com"
            draft.port = "51821"
            let saved = try XCTUnwrap(draft.validation.profile)
            XCTAssertEqual(saved.endpoint, Endpoint(host: "new.example.com", port: 51821))
            guard case let .wireGuard(options) = saved.options else { return XCTFail("Expected WireGuard") }
            XCTAssertEqual(options.peers, peers)
        }
    }

    func testNativeAdvancedFieldsPreserveSiblingsAndRejectInvalidNumbers() {
        let profile = ProxyProfile(
            name: "WebSocket", endpoint: Endpoint(host: "example.com", port: 443),
            options: .trojan(TrojanOptions(password: "secret")), security: .tls(TLSOptions()),
            transport: TransportOptions(type: .websocket),
            xrayAdvanced: XrayAdvancedDocument(["settings": .object(["email": .string("kept@example.com")])]),
        )
        var draft = ProfileEditorDraft(profile: profile)
        let path = ["streamSettings", "wsSettings", "heartbeatPeriod"]
        draft.setAdvancedValue(.number(30), at: path)
        XCTAssertNotNil(draft.validation.profile, draft.validation.message ?? "")
        XCTAssertEqual(draft.advancedValue(at: ["settings", "email"]), .string("kept@example.com"))
        draft.setAdvancedValue(.string("not-a-number"), at: path)
        XCTAssertNil(draft.validation.profile)
        draft.setAdvancedValue(nil, at: path)
        XCTAssertNil(draft.advancedValue(at: ["streamSettings"]))
        XCTAssertEqual(draft.advancedValue(at: ["settings", "email"]), .string("kept@example.com"))
        draft.xrayAdvancedJSON = "{"
        draft.setAdvancedValue(.number(30), at: path)
        XCTAssertEqual(draft.xrayAdvancedJSON, "{")
    }

    func testNativeKCPAndMuxFieldsRoundTripAndEdit() throws {
        let profile = ProxyProfile(
            name: "KCP", endpoint: Endpoint(host: "example.com", port: 443),
            options: .vmess(VMessOptions(uuid: "abcd", security: "auto", alterID: 0)), security: .none,
            transport: TransportOptions(type: .mKCP, kcp: XrayKCPOptions(mtu: 1280, tti: 30), mux: XrayMuxOptions(enabled: true, concurrency: 4, xudpConcurrency: 4)),
        )
        var draft = ProfileEditorDraft(profile: profile)
        XCTAssertEqual(try XCTUnwrap(draft.validation.profile, draft.validation.message ?? "").transport, profile.transport)
        draft.kcpFields = .object(["mtu": .number(1300), "tti": .number(40)])
        draft.muxFields = .object(["enabled": .bool(true), "concurrency": .number(2)])
        let saved = try XCTUnwrap(draft.validation.profile, draft.validation.message ?? "")
        XCTAssertEqual(saved.transport.kcp?.mtu, 1300)
        XCTAssertEqual(saved.transport.kcp?.tti, 40)
        XCTAssertEqual(saved.transport.mux?.concurrency, 2)
        XCTAssertEqual(saved.transport.mux?.xudpConcurrency, XrayMuxOptions().xudpConcurrency)
        draft.kcpFields = .object(["mtu": .string("oops")])
        XCTAssertNil(draft.validation.profile)
    }

    func testAdditionalPeerControlsPreserveIDsAndSupportAddRemove() throws {
        let first = WireGuardPeer(publicKey: "first", endpoint: Endpoint(host: "first.example.com", port: 51820))
        let second = WireGuardPeer(publicKey: "second")
        let profile = ProxyProfile(name: "WireGuard", endpoint: Endpoint(host: "fallback.example.com", port: 51820), options: .wireGuard(WireGuardOptions(privateKey: "private", peerPublicKey: first.publicKey, localAddress: ["10.0.0.2/32"], peers: [first, second])), security: .none)
        var draft = ProfileEditorDraft(profile: profile)
        draft.extraWireGuardPeers[0].publicKey = "edited"
        var saved = try XCTUnwrap(draft.validation.profile, draft.validation.message ?? "")
        guard case let .wireGuard(edited) = saved.options else { return XCTFail("Expected WireGuard") }
        XCTAssertEqual(edited.peers?.map(\.id), [first.id, second.id])
        XCTAssertEqual(edited.peers?[1].publicKey, "edited")
        draft.extraWireGuardPeers.removeAll()
        saved = try XCTUnwrap(draft.validation.profile, draft.validation.message ?? "")
        guard case let .wireGuard(removed) = saved.options else { return XCTFail("Expected WireGuard") }
        XCTAssertEqual(removed.peers, [first])
        draft.extraWireGuardPeers.append(WireGuardPeerDraft(peer: WireGuardPeer(publicKey: "new")))
        saved = try XCTUnwrap(draft.validation.profile, draft.validation.message ?? "")
        guard case let .wireGuard(added) = saved.options else { return XCTFail("Expected WireGuard") }
        XCTAssertEqual(added.peers?.count, 2)
        XCTAssertEqual(added.peers?[0], first)
    }

    func testNativeFormCoversEveryRuntimeAllowedProtocolAndTransportKey() throws {
        let schema = XrayFormSchema.shared
        for proto in ProxyProtocol.allCases where proto != .tuic && proto != .anyTLS {
            var draft = ProfileEditorDraft(profile: ProxyProfile(name: "Coverage", endpoint: Endpoint(host: "example.com", port: 443), options: .trojan(TrojanOptions(password: "secret")), security: .tls(TLSOptions())))
            draft.proto = proto
            guard let definition = draft.protocolDefinition else {
                XCTAssertTrue(XrayConfigBuilder.editorProtocolKeys(proto).isEmpty)
                continue
            }
            let fields = try schema.fields(XCTUnwrap(schema.definition(definition)), value: nil, context: definition)
            XCTAssertTrue(XrayConfigBuilder.editorProtocolKeys(proto).isSubset(of: Set(fields.keys)), "\(proto)")
        }
        for (type, definition) in [(TransportType.tcp, "TCPConfig"), (.websocket, "WebSocketConfig"), (.grpc, "GRPCConfig"), (.httpUpgrade, "HttpUpgradeConfig"), (.xhttp, "SplitHTTPConfig"), (.mKCP, "KCPConfig"), (.hysteria, "HysteriaConfig")] {
            let fields = try schema.fields(XCTUnwrap(schema.definition(definition)), value: nil, context: definition)
            XCTAssertTrue(XrayConfigBuilder.editorTransportKeys(type).isSubset(of: Set(fields.keys)), "\(type)")
        }
        let socketFields = try schema.fields(XCTUnwrap(schema.definition("SocketConfig")), value: nil, context: "SocketConfig")
        XCTAssertTrue(XrayConfigBuilder.editorSocketKeys.isSubset(of: Set(socketFields.keys)))
    }

    func testHysteriaNativeFinalMaskCanSetItsQUICOptions() throws {
        let profile = ProxyProfile(name: "Hysteria", endpoint: Endpoint(host: "example.com", port: 443), options: .hysteria2(Hysteria2Options(password: "secret")), security: .tls(TLSOptions()), transport: TransportOptions(type: .hysteria))
        var draft = ProfileEditorDraft(profile: profile)
        draft.finalMask = .object(["quicParams": .object(["initStreamReceiveWindow": .number(65536)])])
        let saved = try XCTUnwrap(draft.validation.profile, draft.validation.message ?? "")
        XCTAssertEqual(saved.transport.finalMask, draft.finalMask)
    }

    func testProtocolChangesNormalizeForcedTransportAndSecurity() {
        let profile = ProxyProfile(name: "Switch", endpoint: Endpoint(host: "example.com", port: 443), options: .vless(VLESSOptions(uuid: "kept-uuid")), security: .tls(TLSOptions()), transport: TransportOptions(type: .websocket))
        var draft = ProfileEditorDraft(profile: profile)
        draft.hysteriaPassword = "kept-password"
        draft.proto = .hysteria2
        XCTAssertEqual(draft.transportType, .hysteria)
        XCTAssertEqual(draft.securityLayer, .tls)
        XCTAssertNotNil(draft.validation.profile, draft.validation.message ?? "")

        draft.proto = .vless
        XCTAssertEqual(draft.transportType, .tcp)
        XCTAssertEqual(draft.securityLayer, .tls)
        XCTAssertNotNil(draft.validation.profile, draft.validation.message ?? "")
        XCTAssertEqual(draft.vlessUUID, "kept-uuid")
        XCTAssertEqual(draft.hysteriaPassword, "kept-password")

        draft.proto = .wireGuard
        XCTAssertEqual(draft.transportType, .tcp)
        XCTAssertEqual(draft.securityLayer, .none)
        draft.proto = .vless
        XCTAssertEqual(draft.transportType, .tcp)
        XCTAssertEqual(draft.securityLayer, .tls)
        XCTAssertNotNil(draft.validation.profile, draft.validation.message ?? "")
    }

    func testInactiveProtocolFieldsDoNotBlockSaveButValidateWhenSelected() {
        let profile = ProxyProfile(name: "Switch", endpoint: Endpoint(host: "example.com", port: 443), options: .trojan(TrojanOptions(password: "secret")), security: .tls(TLSOptions()))
        var draft = ProfileEditorDraft(profile: profile)
        draft.hysteriaPassword = "secret"
        draft.hysteriaHopInterval = "invalid"
        draft.hysteriaUDPIdleTimeout = "invalid"
        draft.wireGuardPrivateKey = "private-key"
        draft.wireGuardPeerPublicKey = "peer-key"
        draft.wireGuardLocalAddresses = "10.0.0.2/32"
        draft.wireGuardKeepAlive = "invalid"
        draft.wireGuardMTU = "invalid"
        draft.wireGuardReserved = "invalid"
        XCTAssertNotNil(draft.validation.profile, draft.validation.message ?? "")

        draft.proto = .hysteria2
        XCTAssertTrue(draft.validation.message?.contains("Hop interval") == true)
        draft.hysteriaHopInterval = "30"
        XCTAssertTrue(draft.validation.message?.contains("UDP idle timeout") == true)
        draft.proto = .trojan
        XCTAssertNotNil(draft.validation.profile, draft.validation.message ?? "")

        draft.proto = .wireGuard
        XCTAssertTrue(draft.validation.message?.contains("WireGuard keepalive") == true)
        draft.wireGuardKeepAlive = "25"
        XCTAssertTrue(draft.validation.message?.contains("WireGuard MTU") == true)
        draft.wireGuardMTU = "1280"
        XCTAssertTrue(draft.validation.message?.contains("WireGuard reserved bytes") == true)
        draft.proto = .trojan
        XCTAssertNotNil(draft.validation.profile, draft.validation.message ?? "")
    }

    func testInactiveTransportFieldsStayInDraftWithoutBlockingOrEnteringSavedConfig() throws {
        let profile = ProxyProfile(name: "Switch", endpoint: Endpoint(host: "example.com", port: 443), options: .trojan(TrojanOptions(password: "secret")), security: .tls(TLSOptions()), transport: TransportOptions(type: .xhttp))
        var draft = ProfileEditorDraft(profile: profile)
        draft.xhttpMode = "invalid"
        XCTAssertNil(draft.validation.profile)
        draft.transportType = .tcp
        var saved = try XCTUnwrap(draft.validation.profile, draft.validation.message ?? "")
        XCTAssertNil(saved.transport.xhttpMode)
        XCTAssertEqual(draft.xhttpMode, "invalid")
        draft.transportType = .xhttp
        XCTAssertNil(draft.validation.profile)

        draft.xhttpMode = "auto"
        draft.xhttpExtra = .object(["noGRPCHeader": .string("invalid")])
        XCTAssertNil(draft.validation.profile)
        draft.kcpFields = .object(["tti": .string("invalid")])
        draft.transportType = .tcp
        saved = try XCTUnwrap(draft.validation.profile, draft.validation.message ?? "")
        XCTAssertNil(saved.transport.xhttpExtra)
        XCTAssertNil(saved.transport.kcp)
        XCTAssertNotNil(draft.xhttpExtra)
        XCTAssertNotNil(draft.kcpFields)
        draft.transportType = .mKCP
        XCTAssertNil(draft.validation.profile)
    }

    func testWireGuardIgnoresHiddenConnectionDraftWithoutClearingIt() throws {
        let profile = ProxyProfile(name: "WireGuard", endpoint: Endpoint(host: "example.com", port: 51820), options: .wireGuard(WireGuardOptions(privateKey: "private-key", peerPublicKey: "peer-key", localAddress: ["10.0.0.2/32"])), security: .none)
        var draft = ProfileEditorDraft(profile: profile)
        draft.muxFields = .object(["concurrency": .string("invalid")])
        draft.finalMask = .string("invalid")
        draft.socketOptions = .string("invalid")
        let saved = try XCTUnwrap(draft.validation.profile, draft.validation.message ?? "")
        XCTAssertEqual(saved.transport, .tcp)
        XCTAssertNotNil(draft.muxFields)
        XCTAssertNotNil(draft.finalMask)
        XCTAssertNotNil(draft.socketOptions)
        draft.trojanPassword = "secret"
        draft.proto = .trojan
        XCTAssertNil(draft.validation.profile)
    }
}
