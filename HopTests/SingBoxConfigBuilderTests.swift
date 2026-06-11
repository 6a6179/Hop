@testable import Hop
import XCTest

final class SingBoxConfigBuilderTests: XCTestCase {
    private let builder = SingBoxConfigBuilder()

    func testVLESSRealityConfigContainsRealityAndVisionFlow() throws {
        let json = try builder.build(profile: SampleData.vlessReality, routingMode: .rule, rules: SampleData.rules)
        let root = try XCTUnwrap(parse(json))
        let outbound = try firstOutbound(root)
        let tls = try XCTUnwrap(outbound["tls"] as? [String: Any])
        let reality = try XCTUnwrap(tls["reality"] as? [String: Any])
        let utls = try XCTUnwrap(tls["utls"] as? [String: Any])

        XCTAssertEqual(outbound["type"] as? String, "vless")
        XCTAssertEqual(outbound["flow"] as? String, "xtls-rprx-vision")
        XCTAssertEqual(reality["enabled"] as? Bool, true)
        XCTAssertEqual(reality["short_id"] as? String, "6ba85179e30d4fc2")
        XCTAssertEqual(utls["fingerprint"] as? String, "chrome")
    }

    func testVLESSEncryptionAuthFailsClosedForSingBoxRuntime() throws {
        let profile = encryptedVLESSProfile()

        XCTAssertThrowsError(try builder.build(profile: profile, routingMode: .global, rules: [])) { error in
            let message = error.localizedDescription
            XCTAssertTrue(message.contains("X25519 auth"))
            XCTAssertTrue(message.contains("sing-box/libbox"))
            XCTAssertTrue(message.contains("cannot run encrypted VLESS"))
        }
    }

    func testInactiveUnsupportedProfileDoesNotPoisonBuild() throws {
        let unsupported = encryptedVLESSProfile()
        let selected = SampleData.trojanTLS

        let json = try builder.build(
            profiles: [unsupported, selected],
            groups: [],
            selectedTarget: .profile(selected.id),
            routingMode: .global,
            rules: [],
        )
        let root = try XCTUnwrap(parse(json))
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let route = try XCTUnwrap(root["route"] as? [String: Any])

        XCTAssertNil(outbounds.first { $0["tag"] as? String == proxyTag(unsupported) })
        XCTAssertNotNil(outbounds.first { $0["tag"] as? String == proxyTag(selected) })
        XCTAssertEqual(route["final"] as? String, proxyTag(selected))
        try assertNoDanglingOutboundReferences(root)
    }

    func testGroupsSkipUnsupportedMembers() throws {
        let unsupported = encryptedVLESSProfile()
        let selected = SampleData.vlessReality
        let group = ProxyGroup(
            name: "Mixed",
            type: .select,
            members: [
                .profile(unsupported.id),
                .profile(selected.id),
            ],
            defaultTarget: .profile(unsupported.id),
        )

        let json = try builder.build(
            profiles: [unsupported, selected],
            groups: [group],
            selectedTarget: .group(group.id),
            routingMode: .global,
            rules: [],
        )
        let root = try XCTUnwrap(parse(json))
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let groupOutbound = try XCTUnwrap(outbounds.first { $0["tag"] as? String == groupTag(group) })

        XCTAssertNil(outbounds.first { $0["tag"] as? String == proxyTag(unsupported) })
        XCTAssertEqual(groupOutbound["outbounds"] as? [String], [proxyTag(selected)])
        XCTAssertEqual(groupOutbound["default"] as? String, proxyTag(selected))
        try assertNoDanglingOutboundReferences(root)
    }

    func testRealityMLDSA65VerifyFailsClosedForSingBoxRuntime() throws {
        var profile = SampleData.vlessReality
        if var reality = profile.security.reality {
            reality.mldsa65Verify = "MLDSA65VERIFY"
            profile.security.reality = reality
        }

        XCTAssertThrowsError(try builder.build(profile: profile, routingMode: .global, rules: [])) { error in
            let message = error.localizedDescription
            XCTAssertTrue(message.contains("ML-DSA-65"))
            XCTAssertTrue(message.contains("sing-box/libbox"))
            XCTAssertTrue(message.contains("cannot enforce"))
        }
    }

    func testTrojanTLSConfigContainsTLSOptions() throws {
        let json = try builder.build(profile: SampleData.trojanTLS, routingMode: .global, rules: [])
        let root = try XCTUnwrap(parse(json))
        let outbound = try firstOutbound(root)
        let tls = try XCTUnwrap(outbound["tls"] as? [String: Any])

        XCTAssertEqual(outbound["type"] as? String, "trojan")
        XCTAssertEqual(outbound["password"] as? String, "replace-me")
        XCTAssertEqual(tls["enabled"] as? Bool, true)
        XCTAssertEqual(tls["server_name"] as? String, "de.example.net")
        XCTAssertEqual(tls["alpn"] as? [String], ["h2", "http/1.1"])
    }

    func testHysteria2ConfigContainsTLSAndObfs() throws {
        let json = try builder.build(profile: SampleData.hysteria2, routingMode: .global, rules: [])
        let root = try XCTUnwrap(parse(json))
        let outbound = try firstOutbound(root)
        let obfs = try XCTUnwrap(outbound["obfs"] as? [String: Any])
        let tls = try XCTUnwrap(outbound["tls"] as? [String: Any])

        XCTAssertEqual(outbound["type"] as? String, "hysteria2")
        XCTAssertEqual(obfs["type"] as? String, "salamander")
        XCTAssertEqual(obfs["password"] as? String, "obfs-secret")
        XCTAssertEqual(tls["server_name"] as? String, "nyc.example.net")
    }

    func testTUICConfigContainsTLSAndCongestionControl() throws {
        let profile = ProxyProfile(
            name: "TUIC TLS",
            endpoint: Endpoint(host: "tuic.example.net", port: 443),
            proto: .tuic,
            options: .tuic(TUICOptions(uuid: "22222222-2222-4222-8222-222222222222", password: "secret", congestionControl: "bbr")),
            security: .tls(TLSOptions(serverName: "tuic.example.net", alpn: ["h3"])),
        )

        let json = try builder.build(profile: profile, routingMode: .global, rules: [])
        let root = try XCTUnwrap(parse(json))
        let outbound = try firstOutbound(root)
        let tls = try XCTUnwrap(outbound["tls"] as? [String: Any])

        XCTAssertEqual(outbound["type"] as? String, "tuic")
        XCTAssertEqual(outbound["congestion_control"] as? String, "bbr")
        XCTAssertEqual(tls["server_name"] as? String, "tuic.example.net")
        XCTAssertEqual(tls["alpn"] as? [String], ["h3"])
    }

    func testRuleModeSerializesExpandedIOSRuleTypes() throws {
        let rules = [
            RoutingRule(kind: .final, value: "*", target: .selectedProxy),
            RoutingRule(kind: .port, value: "80, 443", target: .direct),
            RoutingRule(kind: .ipIsPrivate, value: "true", target: .reject),
            RoutingRule(kind: .networkType, value: "wifi, cellular", target: .selectedProxy),
            RoutingRule(kind: .networkIsConstrained, value: "false", target: .direct),
            RoutingRule(kind: .wifiSSID, value: "Home Wi-Fi, Office Wi-Fi", target: .selectedProxy),
            RoutingRule(kind: .protocolSniff, value: "tls, http", target: .selectedProxy),
        ]

        let json = try builder.build(profile: SampleData.vlessReality, routingMode: .rule, rules: rules)
        let root = try XCTUnwrap(parse(json))
        let route = try XCTUnwrap(root["route"] as? [String: Any])
        let routeRules = try XCTUnwrap(route["rules"] as? [[String: Any]]).filter { $0["action"] == nil }

        XCTAssertEqual(routeRules[0].keys.sorted(), ["outbound"])
        XCTAssertTrue((routeRules[0]["outbound"] as? String)?.hasPrefix("proxy-") ?? false)
        XCTAssertEqual((routeRules[1]["port"] as? [NSNumber])?.map(\.intValue), [80, 443])
        XCTAssertEqual(routeRules[1]["outbound"] as? String, "direct")
        XCTAssertEqual(routeRules[2]["ip_is_private"] as? Bool, true)
        XCTAssertEqual(routeRules[2]["outbound"] as? String, "reject")
        XCTAssertEqual(routeRules[3]["network_type"] as? [String], ["wifi", "cellular"])
        XCTAssertTrue((routeRules[3]["outbound"] as? String)?.hasPrefix("proxy-") ?? false)
        XCTAssertEqual(routeRules[4]["network_is_constrained"] as? Bool, false)
        XCTAssertEqual(routeRules[5]["wifi_ssid"] as? [String], ["Home Wi-Fi", "Office Wi-Fi"])
        XCTAssertEqual(routeRules[6]["protocol"] as? [String], ["tls", "http"])
    }

    func testRouteRulesHijackTunnelDNSBeforeUserRules() throws {
        let rules = [
            RoutingRule(kind: .geoIP, value: "private", target: .direct),
        ]

        let json = try builder.build(profile: SampleData.vlessReality, routingMode: .rule, rules: rules)
        let root = try XCTUnwrap(parse(json))
        let route = try XCTUnwrap(root["route"] as? [String: Any])
        let routeRules = try XCTUnwrap(route["rules"] as? [[String: Any]])

        XCTAssertEqual(routeRules.first?["action"] as? String, "hijack-dns")
        XCTAssertEqual(routeRules.first?["inbound"] as? String, "tun-in")
        XCTAssertEqual((routeRules.first?["port"] as? NSNumber)?.intValue, 53)
        XCTAssertEqual(routeRules.firstIndex { $0["ip_is_private"] as? Bool == true }, 2)
    }

    func testBuildAppliesAppSettingsToConfig() throws {
        let settings = AppSettings(
            appearance: .dark,
            logLevel: .debug,
            dnsPreset: .quad9,
            dnsStrategy: .ipv6Only,
            proxyDNS: false,
            sniffTraffic: false,
            strictRoute: false,
            logRetention: .oneHundred,
        )

        let json = try builder.build(profile: SampleData.vlessReality, routingMode: .global, rules: [], settings: settings)
        let root = try XCTUnwrap(parse(json))
        let log = try XCTUnwrap(root["log"] as? [String: Any])
        let dns = try XCTUnwrap(root["dns"] as? [String: Any])
        let servers = try XCTUnwrap(dns["servers"] as? [[String: Any]])
        let inbounds = try XCTUnwrap(root["inbounds"] as? [[String: Any]])
        let tun = try XCTUnwrap(inbounds.first)

        XCTAssertEqual(log["level"] as? String, "debug")
        XCTAssertEqual(dns["strategy"] as? String, "ipv6_only")
        XCTAssertEqual(dns["final"] as? String, "quad9")
        XCTAssertEqual(servers.first?["address"] as? String, "https://dns.quad9.net/dns-query")
        XCTAssertNil(servers.first?["detour"])
        XCTAssertNil(tun["sniff"]) // sniffing moved to a route action in sing-box 1.13
        XCTAssertEqual(tun["strict_route"] as? Bool, false)
    }

    func testBuildsSelectorAndURLTestGroups() throws {
        let json = try builder.build(
            profiles: SampleData.profiles,
            groups: SampleData.groups,
            selectedTarget: .group(SampleData.proxyGroup.id),
            routingMode: .global,
            rules: [],
        )
        let root = try XCTUnwrap(parse(json))
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let selector = try XCTUnwrap(outbounds.first { $0["tag"] as? String == groupTag(SampleData.proxyGroup) })
        let urlTest = try XCTUnwrap(outbounds.first { $0["tag"] as? String == groupTag(SampleData.autoGroup) })
        let route = try XCTUnwrap(root["route"] as? [String: Any])

        XCTAssertEqual(selector["type"] as? String, "selector")
        XCTAssertEqual(selector["default"] as? String, groupTag(SampleData.autoGroup))
        XCTAssertEqual(selector["outbounds"] as? [String], [
            groupTag(SampleData.autoGroup),
            proxyTag(SampleData.vlessReality),
            proxyTag(SampleData.trojanTLS),
            proxyTag(SampleData.hysteria2),
        ])
        XCTAssertEqual(urlTest["type"] as? String, "urltest")
        XCTAssertEqual(urlTest["url"] as? String, "https://www.gstatic.com/generate_204")
        XCTAssertEqual(urlTest["interval"] as? String, "600s")
        XCTAssertEqual(urlTest["tolerance"] as? Int, 50)
        XCTAssertEqual(route["final"] as? String, groupTag(SampleData.proxyGroup))
        try assertNoDanglingOutboundReferences(root)
    }

    func testSkipsGroupMembersThatDoNotGenerateOutbounds() throws {
        let unsupportedGroup = ProxyGroup(
            name: "Unsupported Child",
            type: .unsupported,
            members: [.profile(SampleData.vlessReality.id)],
            isEnabled: true,
        )
        let emptyGroup = ProxyGroup(
            name: "Empty Child",
            type: .urlTest,
            members: [.named("Missing Node")],
        )
        let parentGroup = ProxyGroup(
            name: "Parent",
            type: .select,
            members: [
                .group(unsupportedGroup.id),
                .group(emptyGroup.id),
                .profile(SampleData.vlessReality.id),
            ],
            defaultTarget: .group(unsupportedGroup.id),
        )

        let json = try builder.build(
            profiles: SampleData.profiles,
            groups: [parentGroup, unsupportedGroup, emptyGroup],
            selectedTarget: .group(parentGroup.id),
            routingMode: .global,
            rules: [],
        )
        let root = try XCTUnwrap(parse(json))
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let parent = try XCTUnwrap(outbounds.first { $0["tag"] as? String == groupTag(parentGroup) })

        XCTAssertNil(outbounds.first { $0["tag"] as? String == groupTag(unsupportedGroup) })
        XCTAssertNil(outbounds.first { $0["tag"] as? String == groupTag(emptyGroup) })
        XCTAssertEqual(parent["outbounds"] as? [String], [proxyTag(SampleData.vlessReality)])
        XCTAssertEqual(parent["default"] as? String, proxyTag(SampleData.vlessReality))
        try assertNoDanglingOutboundReferences(root)
    }

    func testSelectedTargetFallsBackWhenGroupCannotGenerateOutbound() throws {
        let emptyGroup = ProxyGroup(
            name: "Empty",
            type: .urlTest,
            members: [.named("Missing Node")],
        )

        let json = try builder.build(
            profiles: SampleData.profiles,
            groups: [emptyGroup],
            selectedTarget: .group(emptyGroup.id),
            routingMode: .global,
            rules: [],
        )
        let root = try XCTUnwrap(parse(json))
        let route = try XCTUnwrap(root["route"] as? [String: Any])
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])

        XCTAssertNil(outbounds.first { $0["tag"] as? String == groupTag(emptyGroup) })
        XCTAssertEqual(route["final"] as? String, proxyTag(SampleData.vlessReality))
        try assertNoDanglingOutboundReferences(root)
    }

    func testRulesCanTargetGroupsAndActiveOutbound() throws {
        let rules = [
            RoutingRule(kind: .domainSuffix, value: "video.example", target: .selectedProxy),
            RoutingRule(kind: .domainSuffix, value: "apple.com", target: .group(SampleData.proxyGroup.id)),
        ]
        let json = try builder.build(
            profiles: SampleData.profiles,
            groups: SampleData.groups,
            selectedTarget: .group(SampleData.autoGroup.id),
            routingMode: .rule,
            rules: rules,
        )
        let root = try XCTUnwrap(parse(json))
        let route = try XCTUnwrap(root["route"] as? [String: Any])
        let routeRules = try XCTUnwrap(route["rules"] as? [[String: Any]]).filter { $0["action"] == nil }

        XCTAssertEqual(route["final"] as? String, groupTag(SampleData.autoGroup))
        XCTAssertEqual(routeRules[0]["outbound"] as? String, groupTag(SampleData.autoGroup))
        XCTAssertEqual(routeRules[1]["outbound"] as? String, groupTag(SampleData.proxyGroup))
        try assertNoDanglingOutboundReferences(root)
    }

    func testDropsInvalidConditionalRulesInsteadOfEmittingCatchAll() throws {
        let longPattern = String(repeating: "a", count: ImportPolicy.maxRegexPatternLength + 1)
        let rules = [
            RoutingRule(kind: .geoSite, value: "../../evil/repo/main/payload", target: .direct),
            RoutingRule(kind: .domainRegex, value: longPattern, target: .direct),
            RoutingRule(kind: .port, value: "not-a-port", target: .reject),
            RoutingRule(kind: .domainSuffix, value: "apple.com", target: .direct),
            RoutingRule(kind: .final, value: "*", target: .reject),
        ]

        let json = try builder.build(profile: SampleData.vlessReality, routingMode: .rule, rules: rules)
        let root = try XCTUnwrap(parse(json))
        let route = try XCTUnwrap(root["route"] as? [String: Any])
        let routeRules = try XCTUnwrap(route["rules"] as? [[String: Any]]).filter { $0["action"] == nil }

        XCTAssertEqual(routeRules.count, 2)
        XCTAssertEqual(routeRules[0]["domain_suffix"] as? [String], ["apple.com"])
        XCTAssertEqual(routeRules[0]["outbound"] as? String, "direct")
        XCTAssertEqual(Set(routeRules[1].keys), ["outbound"])
        XCTAssertEqual(routeRules[1]["outbound"] as? String, "reject")
        XCTAssertFalse(json.contains("../"))
        try assertNoDanglingOutboundReferences(root)
    }

    func testNamedProxyGroupWinsOverReservedProxyAlias() throws {
        let group = ProxyGroup(
            name: "Proxy",
            type: .select,
            members: [.profile(SampleData.trojanTLS.id)],
            defaultTarget: .profile(SampleData.trojanTLS.id),
        )
        let rules = [
            RoutingRule(kind: .domainSuffix, value: "apple.com", target: .named("Proxy")),
        ]

        let json = try builder.build(
            profiles: SampleData.profiles,
            groups: [group],
            selectedTarget: .profile(SampleData.vlessReality.id),
            routingMode: .rule,
            rules: rules,
        )
        let root = try XCTUnwrap(parse(json))
        let route = try XCTUnwrap(root["route"] as? [String: Any])
        let routeRules = try XCTUnwrap(route["rules"] as? [[String: Any]]).filter { $0["action"] == nil }

        XCTAssertEqual(routeRules.first?["outbound"] as? String, groupTag(group))
        try assertNoDanglingOutboundReferences(root)
    }

    func testCredentiallessHTTPOutboundOmitsUsernameAndPassword() throws {
        // Optional-through-subscript assignment must drop nil credentials from
        // the outbound dictionary entirely (a wrapped Optional would fail
        // JSONSerialization, an empty string would change auth semantics).
        let profile = ProxyProfile(
            name: "Plain HTTP",
            endpoint: Endpoint(host: "proxy.example.net", port: 8080),
            proto: .http,
            options: .http(HTTPOptions(username: nil, password: nil)),
            security: .none,
        )

        let json = try builder.build(profile: profile, routingMode: .global, rules: [])
        let outbound = try firstOutbound(XCTUnwrap(parse(json)))

        XCTAssertEqual(outbound["type"] as? String, "http")
        XCTAssertNil(outbound["username"])
        XCTAssertNil(outbound["password"])
    }

    private func parse(_ json: String) throws -> [String: Any]? {
        let data = try XCTUnwrap(json.data(using: .utf8))
        return try JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    private func firstOutbound(_ root: [String: Any]) throws -> [String: Any] {
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        return try XCTUnwrap(outbounds.first)
    }

    private func encryptedVLESSProfile() -> ProxyProfile {
        ProxyProfile(
            name: "PQC VLESS",
            endpoint: Endpoint(host: "edge.example.net", port: 443),
            proto: .vless,
            options: .vless(VLESSOptions(
                uuid: "11111111-1111-4111-8111-111111111111",
                flow: "xtls-rprx-vision",
                encryption: "mlkem768x25519plus.native.0rtt..AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )),
            security: .reality(RealityOptions(publicKey: "PUBLICKEY", shortID: "abcd")),
        )
    }

    private func proxyTag(_ profile: ProxyProfile) -> String {
        "proxy-\(profile.id.uuidString.lowercased())"
    }

    private func groupTag(_ group: ProxyGroup) -> String {
        "group-\(group.id.uuidString.lowercased())"
    }

    private func assertNoDanglingOutboundReferences(_ root: [String: Any], file: StaticString = #filePath, line: UInt = #line) throws {
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]], file: file, line: line)
        let outboundTags = Set(outbounds.compactMap { $0["tag"] as? String })

        for outbound in outbounds {
            let tag = outbound["tag"] as? String ?? "<missing tag>"
            for reference in outbound["outbounds"] as? [String] ?? [] {
                XCTAssertTrue(outboundTags.contains(reference), "\(tag) references missing outbound \(reference)", file: file, line: line)
            }
            if let defaultTag = outbound["default"] as? String {
                XCTAssertTrue(outboundTags.contains(defaultTag), "\(tag) defaults to missing outbound \(defaultTag)", file: file, line: line)
            }
        }

        let route = try XCTUnwrap(root["route"] as? [String: Any], file: file, line: line)
        if let final = route["final"] as? String {
            XCTAssertTrue(outboundTags.contains(final), "route.final references missing outbound \(final)", file: file, line: line)
        }
        for rule in route["rules"] as? [[String: Any]] ?? [] {
            if let outbound = rule["outbound"] as? String {
                XCTAssertTrue(outboundTags.contains(outbound), "route rule references missing outbound \(outbound)", file: file, line: line)
            }
        }
        for ruleSet in route["rule_set"] as? [[String: Any]] ?? [] {
            if let detour = ruleSet["download_detour"] as? String {
                XCTAssertTrue(outboundTags.contains(detour), "rule-set references missing download detour \(detour)", file: file, line: line)
            }
        }
    }
}
