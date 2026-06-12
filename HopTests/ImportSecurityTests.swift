@testable import Hop
import XCTest

/// Security regression tests for untrusted import handling: subscription URL
/// policy, SSRF host classification, resource/regex limits, TLS-downgrade
/// warnings, scheduling clamps, and credential redaction.
final class ImportSecurityTests: XCTestCase {
    private let importService = ProxyImportService()

    // MARK: - Subscription URL policy (findings 1, 10)

    func testRejectsCleartextSubscriptionURL() async throws {
        let url = try XCTUnwrap(URL(string: "http://example.com/sub"))
        do {
            _ = try await importService.importSubscription(url: url)
            XCTFail("Expected cleartext subscription URL to be rejected")
        } catch let error as ProxyLinkParseError {
            guard case .insecureSubscriptionURL = error else {
                return XCTFail("Expected .insecureSubscriptionURL, got \(error)")
            }
        }
    }

    func testRejectsLocalPrivateAndMetadataSubscriptionHosts() async throws {
        let blocked = [
            "https://127.0.0.1/sub",
            "https://localhost/sub",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/sub",
            "https://10.0.0.5/sub",
            "https://192.168.1.1/sub",
            "https://172.16.4.4/sub",
            "https://metadata.google.internal/x",
            "https://router.local/sub",
        ]

        for raw in blocked {
            let url = try XCTUnwrap(URL(string: raw))
            do {
                _ = try await importService.importSubscription(url: url)
                XCTFail("Expected \(raw) to be rejected")
            } catch let error as ProxyLinkParseError {
                guard case .disallowedSubscriptionHost = error else {
                    XCTFail("Expected .disallowedSubscriptionHost for \(raw), got \(error)")
                    continue
                }
            }
        }
    }

    func testHostClassifierAcceptsPublicHostsAndRejectsReserved() {
        for reserved in ["127.0.0.1", "10.1.2.3", "172.16.5.4", "192.168.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fc00::1", "localhost", "foo.local", "host.internal",
                         // Trailing-dot FQDN forms must not slip past the
                         // hostname/suffix checks.
                         "localhost.", "router.local.", "host.internal."]
        {
            XCTAssertTrue(ImportPolicy.isDisallowedRemoteHost(reserved), "\(reserved) should be disallowed")
        }
        for allowed in ["example.com", "1.1.1.1", "8.8.8.8", "93.184.216.34", "sub.airport.io"] {
            XCTAssertFalse(ImportPolicy.isDisallowedRemoteHost(allowed), "\(allowed) should be allowed")
        }
    }

    func testResolvedAddressClassifierCatchesAlternateLoopbackForms() {
        // inet_pton rejects these, but the system resolver (and thus URLSession)
        // accepts them and they resolve to loopback. Resolved-address checking
        // closes the bypass. These forms are parsed locally — no DNS needed.
        for host in ["2130706433", "127.1", "0x7f000001"] {
            XCTAssertTrue(ImportPolicy.resolvedAddressesAreDisallowed(host), "\(host) resolves to loopback and must be flagged")
        }
    }

    func testSubscriptionURLRejectsAlternateLoopbackEncodings() throws {
        for raw in ["https://2130706433/sub", "https://127.1/sub", "https://0x7f000001/sub", "https://localhost./sub"] {
            guard let url = URL(string: raw), url.host != nil else {
                continue // skip forms this platform's URL parser rejects outright
            }
            XCTAssertThrowsError(try ImportPolicy.validateSubscriptionURL(url), "\(raw) must be rejected") { error in
                guard case ProxyLinkParseError.disallowedSubscriptionHost = error else {
                    return XCTFail("Expected .disallowedSubscriptionHost for \(raw), got \(error)")
                }
            }
        }
    }

    // MARK: - Probe URL policy (finding 10)

    func testProbeURLPolicy() {
        XCTAssertTrue(ImportPolicy.isAllowedProbeURL("https://www.gstatic.com/generate_204"))
        XCTAssertTrue(ImportPolicy.isAllowedProbeURL("http://cp.cloudflare.com/generate_204"))
        XCTAssertFalse(ImportPolicy.isAllowedProbeURL("http://127.0.0.1/generate_204"))
        XCTAssertFalse(ImportPolicy.isAllowedProbeURL("http://127.1/generate_204"))
        XCTAssertFalse(ImportPolicy.isAllowedProbeURL("https://2130706433/generate_204"))
        XCTAssertFalse(ImportPolicy.isAllowedProbeURL("https://0x7f000001/generate_204"))
        XCTAssertFalse(ImportPolicy.isAllowedProbeURL("https://169.254.169.254/latest"))
        XCTAssertFalse(ImportPolicy.isAllowedProbeURL("ftp://example.com/x"))
        XCTAssertFalse(ImportPolicy.isAllowedProbeURL("not a url"))
    }

    // MARK: - Regex safety (findings 7, 8)

    func testRegexSafety() {
        XCTAssertTrue(ImportPolicy.isSafeRegexPattern("^stun\\..+"))
        XCTAssertTrue(ImportPolicy.isSafeRegexPattern("Tokyo|Osaka"))
        XCTAssertTrue(ImportPolicy.isSafeRegexPattern("(abc)+"), "a single quantified group is safe")
        XCTAssertTrue(ImportPolicy.isSafeRegexPattern("[a-z0-9]+"))
        XCTAssertFalse(ImportPolicy.isSafeRegexPattern(""))
        XCTAssertFalse(ImportPolicy.isSafeRegexPattern("("), "uncompilable pattern must be rejected")
        XCTAssertFalse(ImportPolicy.isSafeRegexPattern(String(repeating: "a", count: ImportPolicy.maxRegexPatternLength + 1)))
        // Catastrophic-backtracking shapes must be rejected even though they are
        // short and compile (ReDoS, CWE-1333).
        for evil in ["(a+)+", "(a*)*$", "(.+)+", "(a+|b+)+", "((ab)+)+", "(\\d+)+"] {
            XCTAssertFalse(ImportPolicy.isSafeRegexPattern(evil), "\(evil) must be rejected as ReDoS-prone")
        }
        // Second-order nesting: the unbounded repetition sits one group deeper,
        // so the quantified outer group never directly contains a quantifier.
        for evil in ["((a+)b)+", "((a+)b*)+", "((\\d+)\\D)+", "(x(a+))+", "(((a+)b)c)*"] {
            XCTAssertFalse(ImportPolicy.isSafeRegexPattern(evil), "\(evil) must be rejected as ReDoS-prone")
        }
        // …while an unquantified wrapper around a quantified group stays safe.
        XCTAssertTrue(ImportPolicy.isSafeRegexPattern("((a+)b)"), "no outer repetition — star height 1")
        XCTAssertTrue(ImportPolicy.isSafeRegexPattern("(jp|us)-(node)+"), "sibling groups must not be conflated")
    }

    func testUnsafePolicyRegexFilterIsIgnored() throws {
        let longPattern = String(repeating: "a", count: ImportPolicy.maxRegexPatternLength + 10)
        let conf = """
        [Proxy]
        Tokyo = trojan, t.example.net, 443, password=p, tls=true

        [Proxy Group]
        Bad = url-test, policy-regex-filter=\(longPattern)
        """

        let result = try importService.importText(conf)
        let group = try XCTUnwrap(result.groups.first { $0.name == "Bad" })
        XCTAssertTrue(group.members.isEmpty)
        XCTAssertTrue(result.warnings.contains { $0.message.contains("unsafe policy-regex-filter") })
    }

    func testUnsafeDomainRegexRuleIsSkipped() throws {
        let longPattern = String(repeating: "a", count: ImportPolicy.maxRegexPatternLength + 10)
        let conf = """
        [Proxy]
        Tokyo = trojan, t.example.net, 443, password=p, tls=true

        [Rule]
        DOMAIN-REGEX,\(longPattern),DIRECT
        DOMAIN-SUFFIX,apple.com,DIRECT
        """

        let result = try importService.importText(conf)
        XCTAssertFalse(result.rules.contains { $0.kind == .domainRegex })
        XCTAssertTrue(result.rules.contains { $0.kind == .domainSuffix })
        XCTAssertTrue(result.warnings.contains { $0.message.contains("DOMAIN-REGEX") })
    }

    // MARK: - URL-test scheduling clamps (findings 10, 12)

    func testURLTestIntervalAndToleranceClampedOnImport() throws {
        let conf = """
        [Proxy]
        Tokyo = trojan, t.example.net, 443, password=p, tls=true

        [Proxy Group]
        Auto = url-test, Tokyo, interval=0, tolerance=9999999
        """

        let result = try importService.importText(conf)
        let group = try XCTUnwrap(result.groups.first { $0.name == "Auto" })
        XCTAssertEqual(group.testOptions.intervalSeconds, ImportPolicy.minURLTestIntervalSeconds)
        XCTAssertEqual(group.testOptions.toleranceMilliseconds, ImportPolicy.maxURLTestToleranceMilliseconds)
    }

    func testDisallowedURLTestURLReplacedWithDefault() throws {
        let conf = """
        [Proxy]
        Tokyo = trojan, t.example.net, 443, password=p, tls=true

        [Proxy Group]
        Auto = url-test, Tokyo, url=http://169.254.169.254/latest
        """

        let result = try importService.importText(conf)
        let group = try XCTUnwrap(result.groups.first { $0.name == "Auto" })
        XCTAssertEqual(group.testOptions.url, ProxyGroupTestOptions.defaultURL)
        XCTAssertTrue(result.warnings.contains { $0.message.contains("disallowed URL-test URL") })
    }

    // MARK: - TLS downgrade warnings (finding 2)

    func testInsecureTLSLinkImportProducesRedactedWarning() throws {
        let result = try importService.importText("trojan://topsecretpass@de.example.net:443?security=tls&allowInsecure=1#Frankfurt")
        XCTAssertEqual(result.profiles.count, 1)
        XCTAssertEqual(result.profiles.first?.security.tls?.allowInsecure, true)
        XCTAssertTrue(result.warnings.contains { $0.message.lowercased().contains("allow-insecure") })
        XCTAssertFalse(result.warnings.contains { $0.message.contains("topsecretpass") })
    }

    func testInsecureTLSShadowrocketProducesWarning() throws {
        let conf = """
        [Proxy]
        Insecure = trojan, evil.example.net, 443, password=p, tls=true, allowInsecure=true
        """

        let result = try importService.importText(conf)
        XCTAssertEqual(result.profiles.first?.security.tls?.allowInsecure, true)
        XCTAssertTrue(result.warnings.contains { $0.message.contains("allow-insecure") })
    }

    // MARK: - Resource limits (finding 5)

    func testOversizedPayloadRejected() {
        let huge = String(repeating: "a", count: ImportPolicy.maxPayloadBytes + 1)
        XCTAssertThrowsError(try importService.importText(huge)) { error in
            guard case ProxyLinkParseError.payloadTooLarge = error else {
                return XCTFail("Expected .payloadTooLarge, got \(error)")
            }
        }
    }

    func testImportResultTruncationDropsExcessItems() {
        let result = ImportResult(profiles: Array(repeating: SampleData.trojanTLS, count: 10))
        let truncated = result.truncated(to: 4)
        XCTAssertEqual(truncated.profiles.count, 4)
        XCTAssertTrue(truncated.warnings.contains { $0.message.contains("truncated") })
        XCTAssertEqual(result.truncated(to: 100).profiles.count, 10)
    }

    func testOutOfRangePortInShadowrocketProxyIsSkipped() throws {
        let conf = """
        [Proxy]
        Bad = trojan, t.example.net, 99999, password=p, tls=true
        Good = trojan, t.example.net, 443, password=p, tls=true
        """
        let result = try importService.importText(conf)
        XCTAssertEqual(result.profiles.map(\.name), ["Good"], "out-of-range port must be dropped")
        XCTAssertTrue(result.warnings.contains { $0.message.contains("out-of-range") })
    }

    // MARK: - Redaction (finding 6)

    func testRedactionStripsCredentialsFromLinksAndConfigLines() {
        let link = ImportPolicy.redactForLog("vless://11111111-1111-4111-8111-111111111111@edge.example.net:443?pbk=SECRETKEY#Tokyo")
        XCTAssertFalse(link.contains("11111111-1111-4111-8111-111111111111"))
        XCTAssertFalse(link.contains("SECRETKEY"))
        XCTAssertFalse(link.contains("edge.example.net"))
        XCTAssertTrue(link.contains("vless"))
        XCTAssertTrue(link.contains("Tokyo"))

        let conf = ImportPolicy.redactForLog("Frankfurt = trojan, de.example.net, 443, super-secret-pass")
        XCTAssertFalse(conf.contains("super-secret-pass"))
        XCTAssertFalse(conf.contains("de.example.net"))
        XCTAssertTrue(conf.contains("Frankfurt"))
    }

    func testFailedLinkParseWarningIsRedacted() throws {
        let result = try importService.importText(
            """
            trojan://topsecretpassword@bad.example.net#NoPort
            trojan://ok@good.example.net:443?security=tls#OK
            """,
        )

        XCTAssertEqual(result.profiles.count, 1)
        XCTAssertFalse(result.warnings.contains { $0.message.contains("topsecretpassword") })
    }

    // MARK: - Config builder enforcement (findings 8, 12 defense-in-depth)

    func testConfigBuilderSanitizesURLTestAndDomainRegex() throws {
        let builder = SingBoxConfigBuilder()
        let profile = SampleData.trojanTLS
        let group = ProxyGroup(
            name: "Auto",
            type: .urlTest,
            members: [.profile(profile.id)],
            defaultTarget: .profile(profile.id),
            testOptions: ProxyGroupTestOptions(url: "http://169.254.169.254/x", intervalSeconds: 0, toleranceMilliseconds: 9_999_999),
        )
        let longPattern = String(repeating: "a", count: ImportPolicy.maxRegexPatternLength + 10)
        let rules = [RoutingRule(kind: .domainRegex, value: longPattern, target: .direct)]

        let json = try builder.build(
            profiles: [profile],
            groups: [group],
            selectedTarget: .group(group.id),
            routingMode: .rule,
            rules: rules,
        )
        let root = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let urlTest = try XCTUnwrap(outbounds.first { ($0["type"] as? String) == "urltest" })

        XCTAssertEqual(urlTest["url"] as? String, ProxyGroupTestOptions.defaultURL)
        XCTAssertEqual(urlTest["interval"] as? String, "\(ImportPolicy.minURLTestIntervalSeconds)s")
        XCTAssertEqual(urlTest["tolerance"] as? Int, ImportPolicy.maxURLTestToleranceMilliseconds)

        let route = try XCTUnwrap(root["route"] as? [String: Any])
        for rule in route["rules"] as? [[String: Any]] ?? [] {
            if let regexes = rule["domain_regex"] as? [String] {
                XCTAssertFalse(regexes.contains(longPattern))
            }
        }
    }

    // MARK: - sanitizeImportedName (ImportPolicy)

    func testSanitizeImportedNameStripsRTLOverrideAndZeroWidthCharacters() {
        // U+202E is the RTL override; U+200B is zero-width space
        let withRTL = "Safe\u{202E}EVIL"
        let withZW = "Safe\u{200B}Hidden"
        XCTAssertFalse(ImportPolicy.sanitizeImportedName(withRTL).unicodeScalars.contains { $0 == "\u{202E}" })
        XCTAssertFalse(ImportPolicy.sanitizeImportedName(withZW).unicodeScalars.contains { $0 == "\u{200B}" })
    }

    func testSanitizeImportedNameCollapsesWhitespaceRunsAndNewlines() {
        XCTAssertEqual(ImportPolicy.sanitizeImportedName("hello\nworld"), "hello world")
        XCTAssertEqual(ImportPolicy.sanitizeImportedName("hello\t\tworld"), "hello world")
        XCTAssertEqual(ImportPolicy.sanitizeImportedName("a   b   c"), "a b c")
    }

    func testSanitizeImportedNameCapsAtMaxLength() {
        let long = String(repeating: "a", count: ImportPolicy.maxImportedNameLength + 20)
        let result = ImportPolicy.sanitizeImportedName(long)
        XCTAssertEqual(result.count, ImportPolicy.maxImportedNameLength)
    }

    func testSanitizeImportedNameReturnsFallbackForEmptyOrAllStrippedInput() {
        XCTAssertEqual(ImportPolicy.sanitizeImportedName("", fallback: "FB"), "FB")
        // A name that is entirely invisible/control characters should produce the fallback
        let allControl = "\u{202E}\u{200B}\u{200C}\u{200D}"
        XCTAssertEqual(ImportPolicy.sanitizeImportedName(allControl, fallback: "Fallback"), "Fallback")
    }

    func testSanitizeImportedNameEndToEndVLESSWithRTLFragmentName() throws {
        // U+202E = %E2%80%AE in UTF-8 (3 bytes: E2 80 AE)
        // Construct a vless:// link with a name containing a RTL override in the fragment
        let linkWithRTL = "vless://11111111-1111-4111-8111-111111111111@edge.example.net:443?security=tls&sni=edge.example.net#Safe%E2%80%AEEvil"
        let result = try importService.importText(linkWithRTL)
        let profile = try XCTUnwrap(result.profiles.first)
        XCTAssertFalse(profile.name.unicodeScalars.contains { $0 == "\u{202E}" }, "RTL override must be stripped from imported profile name")
    }

    // MARK: - ImportResult.sanitizingNames

    func testSanitizingNamesCleanesProfileNamesAndGroupNames() {
        let profile = ProxyProfile(
            name: "Evil\u{202E}Name",
            endpoint: Endpoint(host: "example.com", port: 443),
            proto: .trojan,
            options: .trojan(TrojanOptions(password: "p")),
            security: .tls(TLSOptions(serverName: "example.com")),
        )
        let group = ProxyGroup(
            name: "Group\u{200B}Hidden",
            type: .select,
            members: [.profile(profile.id)],
        )
        let result = ImportResult(profiles: [profile], groups: [group])
        let sanitized = result.sanitizingNames()

        XCTAssertFalse(sanitized.profiles[0].name.unicodeScalars.contains { $0 == "\u{202E}" })
        XCTAssertFalse(sanitized.groups[0].name.unicodeScalars.contains { $0 == "\u{200B}" })
    }

    func testSanitizingNamesSanitizesNamedGroupMembersAndDefaultTarget() {
        // Named targets in group members and defaultTarget must be sanitized
        let dirtyName = "Target\u{202E}DIRTY"
        let group = ProxyGroup(
            name: "G",
            type: .select,
            members: [.named(dirtyName)],
            defaultTarget: .named(dirtyName),
        )
        let result = ImportResult(groups: [group])
        let sanitized = result.sanitizingNames()

        if case let .named(name) = sanitized.groups[0].members.first {
            XCTAssertFalse(name.unicodeScalars.contains { $0 == "\u{202E}" })
        } else {
            XCTFail("Expected .named member")
        }
        if case let .named(name) = sanitized.groups[0].defaultTarget {
            XCTAssertFalse(name.unicodeScalars.contains { $0 == "\u{202E}" })
        } else {
            XCTFail("Expected .named defaultTarget")
        }
    }

    func testSanitizingNamesSanitizesRuleNamedTargets() {
        let dirtyTarget = "Proxy\u{200B}Dirty"
        let rule = RoutingRule(kind: .domainSuffix, value: "apple.com", target: .named(dirtyTarget))
        let result = ImportResult(rules: [rule])
        let sanitized = result.sanitizingNames()

        if case let .named(name) = sanitized.rules[0].target {
            XCTAssertFalse(name.unicodeScalars.contains { $0 == "\u{200B}" })
        } else {
            XCTFail("Expected .named rule target")
        }
    }

    func testGeoRuleSetRejectsPathTraversalCategory() throws {
        let builder = SingBoxConfigBuilder()
        let profile = SampleData.trojanTLS
        let rules = [RoutingRule(kind: .geoSite, value: "../../evil/repo/main/payload", target: .direct)]

        let json = try builder.build(
            profiles: [profile],
            groups: [],
            selectedTarget: .profile(profile.id),
            routingMode: .rule,
            rules: rules,
        )
        XCTAssertFalse(json.contains("../"), "geo category must not introduce path traversal into the rule-set URL")
        XCTAssertFalse(json.contains("evil/repo"), "unsafe geo category must be dropped, not fetched")
    }
}
