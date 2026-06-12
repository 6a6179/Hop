@testable import Hop
import XCTest

final class ProxyLinkParserTests: XCTestCase {
    private let parser = ProxyLinkParser()
    private let importService = ProxyImportService()
    private let x25519Encryption = "mlkem768x25519plus.native.0rtt..AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    private let mlkem768Encryption = "mlkem768x25519plus.native.0rtt..\(String(repeating: "A", count: 1579))"

    func testParsesVLESSRealityLink() throws {
        let profile = try parser.parse("vless://11111111-1111-4111-8111-111111111111@edge.example.net:443?security=reality&sni=www.cloudflare.com&fp=chrome&pbk=PUBLICKEY&sid=abcd&spx=%2F&type=tcp&flow=xtls-rprx-vision#Tokyo")

        XCTAssertEqual(profile.proto, .vless)
        XCTAssertEqual(profile.endpoint.host, "edge.example.net")
        XCTAssertEqual(profile.security.layer, .reality)
        XCTAssertEqual(profile.security.reality?.publicKey, "PUBLICKEY")
        XCTAssertEqual(profile.security.reality?.shortID, "abcd")
        XCTAssertEqual(profile.security.reality?.spiderX, "/")
        if case let .vless(options) = profile.options {
            XCTAssertEqual(options.flow, "xtls-rprx-vision")
        } else {
            XCTFail("Expected VLESS options")
        }
    }

    func testParsesVLESSRealityAliasFieldsAndALPN() throws {
        let link = "vless://11111111-1111-4111-8111-111111111111@edge.example.net:443?security=reality&server-name=www.microsoft.com&fingerprint=firefox&public-key=PUBLICKEY&short-id=abcd&spider_x=%2Falias%3Fed%3D204&pqv=MLDSA65VERIFY&alpn=h2,http/1.1&type=tcp#Alias"
        let profile = try parser.parse(link)

        XCTAssertEqual(profile.security.layer, .reality)
        XCTAssertEqual(profile.security.tls?.serverName, "www.microsoft.com")
        XCTAssertEqual(profile.security.tls?.alpn, ["h2", "http/1.1"])
        XCTAssertEqual(profile.security.tls?.utlsFingerprint, "firefox")
        XCTAssertEqual(profile.security.reality?.publicKey, "PUBLICKEY")
        XCTAssertEqual(profile.security.reality?.shortID, "abcd")
        XCTAssertEqual(profile.security.reality?.spiderX, "/alias?ed=204")
        XCTAssertEqual(profile.security.reality?.mldsa65Verify, "MLDSA65VERIFY")
    }

    func testParsesVLESSEncryptionAuthLink() throws {
        let profile = try parser.parse("vless://11111111-1111-4111-8111-111111111111@edge.example.net:443?security=reality&encryption=\(x25519Encryption)#Tokyo")

        if case let .vless(options) = profile.options {
            XCTAssertEqual(options.encryption, x25519Encryption)
            XCTAssertEqual(options.encryptionAuthLabel, "X25519 auth")
        } else {
            XCTFail("Expected VLESS options")
        }
    }

    func testImportWarnsForVLESSEncryptionAuthLink() throws {
        let result = try importService.importText("vless://11111111-1111-4111-8111-111111111111@edge.example.net:443?encryption=\(mlkem768Encryption)#Tokyo")

        XCTAssertEqual(result.profiles.count, 1)
        XCTAssertTrue(result.warnings.contains { warning in
            warning.message.contains("ML-KEM-768 auth") && warning.message.contains("cannot run Xray VLESS Encryption/Auth yet")
        })
    }

    func testParsesTrojanTLSLink() throws {
        let profile = try parser.parse("trojan://secret@de.example.net:443?security=tls&sni=de.example.net&alpn=h2,http/1.1#Frankfurt")

        XCTAssertEqual(profile.proto, .trojan)
        XCTAssertEqual(profile.security.layer, .tls)
        XCTAssertEqual(profile.security.tls?.serverName, "de.example.net")
        XCTAssertEqual(profile.security.tls?.alpn, ["h2", "http/1.1"])
    }

    func testParsesHysteria2TLSObfsLink() throws {
        let profile = try parser.parse("hysteria2://secret@nyc.example.net:443?security=tls&sni=nyc.example.net&obfs=salamander&obfs-password=obfs-secret#NYC")

        XCTAssertEqual(profile.proto, .hysteria2)
        XCTAssertEqual(profile.security.layer, .tls)
        if case let .hysteria2(options) = profile.options {
            XCTAssertEqual(options.obfs, "salamander")
            XCTAssertEqual(options.obfsPassword, "obfs-secret")
        } else {
            XCTFail("Expected Hysteria2 options")
        }
    }

    func testParsesTUICTLSLink() throws {
        let profile = try parser.parse("tuic://22222222-2222-4222-8222-222222222222:secret@tuic.example.net:443?sni=tuic.example.net&congestion_control=bbr#TUIC")

        XCTAssertEqual(profile.proto, .tuic)
        XCTAssertEqual(profile.security.layer, .tls)
        if case let .tuic(options) = profile.options {
            XCTAssertEqual(options.congestionControl, "bbr")
        } else {
            XCTFail("Expected TUIC options")
        }
    }

    func testParsesShadowsocksSIP002AndLegacyBase64Links() throws {
        let sip002 = try parser.parse("ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.net:8388#SIP002")
        XCTAssertEqual(sip002.proto, .shadowsocks)
        XCTAssertEqual(sip002.endpoint.host, "ss.example.net")
        if case let .shadowsocks(options) = sip002.options {
            XCTAssertEqual(options.method, "aes-256-gcm")
            XCTAssertEqual(options.password, "secret")
        } else {
            XCTFail("Expected Shadowsocks options")
        }

        let legacyPayload = "aes-128-gcm:legacy-pass@legacy.example.net:8388".base64Encoded()
        let legacy = try parser.parse("ss://\(legacyPayload)#Legacy")
        XCTAssertEqual(legacy.endpoint.host, "legacy.example.net")
        if case let .shadowsocks(options) = legacy.options {
            XCTAssertEqual(options.method, "aes-128-gcm")
            XCTAssertEqual(options.password, "legacy-pass")
        } else {
            XCTFail("Expected Shadowsocks options")
        }
    }

    func testParsesClassicVMessBase64JSON() throws {
        let vmessJSON = """
        {
          "v": "2",
          "ps": "VMess WS",
          "add": "vmess.example.net",
          "port": "443",
          "id": "33333333-3333-4333-8333-333333333333",
          "aid": "0",
          "scy": "auto",
          "net": "ws",
          "type": "none",
          "host": "cdn.example.net",
          "path": "/ws",
          "tls": "tls",
          "sni": "vmess.example.net"
        }
        """

        let profile = try parser.parse("vmess://\(vmessJSON.base64Encoded())")

        XCTAssertEqual(profile.name, "VMess WS")
        XCTAssertEqual(profile.proto, .vmess)
        XCTAssertEqual(profile.endpoint.port, 443)
        XCTAssertEqual(profile.security.layer, .tls)
        XCTAssertEqual(profile.transport.type, .websocket)
        XCTAssertEqual(profile.transport.path, "/ws")
        XCTAssertEqual(profile.transport.host, "cdn.example.net")
    }

    /// `type` is the VMess header-obfuscation mode, not the cipher. A common
    /// link shape omits `scy` and carries `"type":"none"` — that must yield the
    /// `auto` cipher, not VMess-layer encryption disabled.
    func testVMessJSONWithoutCipherFallsBackToAutoNotHeaderType() throws {
        let vmessJSON = """
        {"ps":"NoScy","add":"vmess.example.net","port":"443","id":"33333333-3333-4333-8333-333333333333","aid":"0","net":"tcp","type":"none"}
        """

        let profile = try parser.parse("vmess://\(vmessJSON.base64Encoded())")

        if case let .vmess(options) = profile.options {
            XCTAssertEqual(options.security, "auto", "header type must not become the cipher")
        } else {
            XCTFail("Expected VMess options")
        }
    }

    func testVMessJSONWithOutOfRangePortIsRejected() {
        for badPort in ["0", "-1", "99999", "65536"] {
            let vmessJSON = """
            {"ps":"Bad","add":"vmess.example.net","port":\(badPort),"id":"33333333-3333-4333-8333-333333333333","net":"tcp"}
            """
            XCTAssertThrowsError(
                try parser.parse("vmess://\(vmessJSON.base64Encoded())"),
                "VMess port \(badPort) must be rejected",
            )
        }
    }

    func testParsesVMessURLSecurityAsTLSAndEncryptionAsCipher() throws {
        let profile = try parser.parse("vmess://33333333-3333-4333-8333-333333333333@vmess.example.net:443?security=tls&encryption=chacha20-poly1305&sni=vmess.example.net&alpn=h2,http/1.1&type=ws&path=%2Fws&host=cdn.example.net#VMess")

        XCTAssertEqual(profile.security.layer, .tls)
        XCTAssertEqual(profile.security.tls?.serverName, "vmess.example.net")
        XCTAssertEqual(profile.security.tls?.alpn, ["h2", "http/1.1"])
        if case let .vmess(options) = profile.options {
            XCTAssertEqual(options.security, "chacha20-poly1305")
        } else {
            XCTFail("Expected VMess options")
        }
        XCTAssertEqual(profile.transport.type, .websocket)
        XCTAssertEqual(profile.transport.path, "/ws")
        XCTAssertEqual(profile.transport.host, "cdn.example.net")
    }

    func testParsesHTTPAndSOCKSLinks() throws {
        let result = try importService.importText(
            """
            https://user:pass@http.example.net:443#HTTPS
            socks5+tls://socks-user:socks-pass@socks.example.net:443#SOCKS
            """,
        )

        XCTAssertEqual(result.profiles.count, 2)
        XCTAssertEqual(result.profiles[0].proto, .http)
        XCTAssertEqual(result.profiles[0].security.layer, .tls)
        XCTAssertEqual(result.profiles[1].proto, .socks)
        XCTAssertEqual(result.profiles[1].security.layer, .tls)
    }

    func testParsesPlainAndBase64Subscriptions() throws {
        let subscription = """
        trojan://secret@one.example.net:443?security=tls#One
        hysteria2://secret@two.example.net:443?security=tls#Two
        """

        let plain = try importService.importText(subscription)
        let encoded = try importService.importText(subscription.base64Encoded())

        XCTAssertEqual(plain.profiles.map(\.name), ["One", "Two"])
        XCTAssertEqual(encoded.profiles.map(\.name), ["One", "Two"])
    }

    // MARK: - Default TLS for Hysteria2 and TUIC (regression)

    func testHysteria2WithoutSecurityParamDefaultsToTLS() throws {
        // No `security=` or `sni=` or `tls=` param — just the bare minimum
        let profile = try parser.parse("hysteria2://pass@example.com:443#n")
        XCTAssertEqual(profile.security.layer, .tls, "hysteria2 with no security param must default to TLS")
        XCTAssertEqual(profile.security.tls?.serverName, "example.com", "server name must default to the host")
    }

    func testTUICWithoutSecurityParamDefaultsToTLS() throws {
        // tuic:// requires uuid:password in user info
        let profile = try parser.parse("tuic://22222222-2222-4222-8222-222222222222:pass@example.com:443#n")
        XCTAssertEqual(profile.security.layer, .tls, "tuic with no security param must default to TLS")
        XCTAssertEqual(profile.security.tls?.serverName, "example.com", "server name must default to the host")
    }

    func testParsesWrappedAndUnpaddedBase64Subscriptions() throws {
        // Byte count chosen so the base64 form needs padding ("==") — that is
        // the case the padding computation must get right.
        let subscription = """
        trojan://secret@one.example.net:443?security=tls#One
        hysteria2://secret@two.example.net:443?security=tls#Two2
        """
        XCTAssertEqual(subscription.utf8.count % 3, 1, "fixture must exercise base64 padding")

        // Some panels emit RFC 2045-style base64 (wrapped at 76 columns) and/or
        // strip the trailing padding; both forms must still decode.
        let wrapped = Data(subscription.utf8).base64EncodedString(options: [.lineLength76Characters, .endLineWithLineFeed])
        let unpaddedWrapped = wrapped.replacingOccurrences(of: "=", with: "")
        XCTAssertNotEqual(wrapped, unpaddedWrapped, "fixture must exercise base64 padding")

        XCTAssertEqual(try importService.importText(wrapped).profiles.map(\.name), ["One", "Two2"])
        XCTAssertEqual(try importService.importText(unpaddedWrapped).profiles.map(\.name), ["One", "Two2"])
    }

    func testLinkPortsOutsideValidRangeAreRejected() {
        // URLComponents happily parses ports like 99999; the endpoint builder
        // must range-check them like the VMess JSON and Shadowrocket paths do.
        for badLink in [
            "vless://11111111-1111-4111-8111-111111111111@edge.example.net:0?security=tls#Zero",
            "trojan://secret@de.example.net:65536?security=tls#TooBig",
            "hysteria2://secret@nyc.example.net:99999#WayTooBig",
        ] {
            XCTAssertThrowsError(try parser.parse(badLink), "\(badLink) must be rejected")
        }
    }

    func testParsesShadowrocketConfWithGroupsRulesAndWarnings() throws {
        let conf = """
        [Proxy]
        Tokyo = vless, edge.example.net, 443, 11111111-1111-4111-8111-111111111111, tls=true, security=reality, sni=www.microsoft.com, fp=chrome, pbk=PUBLICKEY, sid=abcd, spx=/shadow, pqv=MLDSA65VERIFY, alpn="h2,http/1.1", flow=xtls-rprx-vision, encryption=\(x25519Encryption)
        Frankfurt = trojan, de.example.net, 443, replace-me, tls=true, sni=de.example.net
        SS = ss, ss.example.net, 8388, aes-128-gcm, ss-pass
        OldSnell = snell, old.example.net, 443, password=skip

        [Proxy Group]
        Proxy = select, Tokyo, Frankfurt
        Auto = url-test, Tokyo, Frankfurt, url=https://cp.cloudflare.com/generate_204, interval=300, tolerance=25
        RegexAuto = url-test, policy-regex-filter=Tokyo
        LegacyFallback = fallback, Tokyo, Frankfurt

        [Rule]
        DOMAIN-SUFFIX,apple.com,DIRECT
        GEOIP,US,Proxy
        FINAL,Auto
        """

        let result = try importService.importText(conf)

        XCTAssertEqual(result.profiles.map(\.name), ["Tokyo", "Frankfurt", "SS"])
        XCTAssertEqual(result.groups.count, 4)
        XCTAssertEqual(result.groups.first { $0.name == "Proxy" }?.type, .select)
        XCTAssertEqual(result.groups.first { $0.name == "Auto" }?.type, .urlTest)
        XCTAssertEqual(result.groups.first { $0.name == "Auto" }?.testOptions.intervalSeconds, 300)
        XCTAssertEqual(result.groups.first { $0.name == "RegexAuto" }?.members.count, 1)
        XCTAssertEqual(result.groups.first { $0.name == "LegacyFallback" }?.isEnabled, false)
        XCTAssertEqual(result.rules.count, 3)
        XCTAssertEqual(result.rules.last?.kind, .final)
        XCTAssertEqual(result.rules.last?.target, .named("Auto"))
        XCTAssertGreaterThanOrEqual(result.warnings.count, 2)
        XCTAssertTrue(result.warnings.contains { $0.message.contains("X25519 auth") })
        XCTAssertTrue(result.warnings.contains { $0.message.contains("ML-DSA-65") })
        if case let .vless(options) = result.profiles.first?.options {
            XCTAssertEqual(options.encryption, x25519Encryption)
        } else {
            XCTFail("Expected VLESS options")
        }
        XCTAssertEqual(result.profiles.first?.security.layer, .reality)
        XCTAssertEqual(result.profiles.first?.security.tls?.serverName, "www.microsoft.com")
        XCTAssertEqual(result.profiles.first?.security.tls?.alpn, ["h2", "http/1.1"])
        XCTAssertEqual(result.profiles.first?.security.reality?.publicKey, "PUBLICKEY")
        XCTAssertEqual(result.profiles.first?.security.reality?.shortID, "abcd")
        XCTAssertEqual(result.profiles.first?.security.reality?.spiderX, "/shadow")
        XCTAssertEqual(result.profiles.first?.security.reality?.mldsa65Verify, "MLDSA65VERIFY")
    }
}

private extension String {
    func base64Encoded() -> String {
        Data(utf8).base64EncodedString()
    }
}
