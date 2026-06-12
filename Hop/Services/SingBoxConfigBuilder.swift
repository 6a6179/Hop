import Foundation

enum SingBoxConfigError: LocalizedError {
    case unsupportedProfile(String)
    case serializationFailed

    var errorDescription: String? {
        switch self {
        case let .unsupportedProfile(reason):
            reason
        case .serializationFailed:
            "Unable to serialize sing-box configuration."
        }
    }
}

struct SingBoxConfigBuilder {
    func build(profile: ProxyProfile, routingMode: RoutingMode, rules: [RoutingRule], settings: AppSettings = .defaults, logOutputPath: String? = nil) throws -> String {
        try build(
            profiles: [profile],
            groups: [],
            selectedTarget: .profile(profile.id),
            routingMode: routingMode,
            rules: rules,
            settings: settings,
            logOutputPath: logOutputPath,
        )
    }

    func build(
        profiles: [ProxyProfile],
        groups: [ProxyGroup],
        selectedTarget: OutboundTarget,
        routingMode: RoutingMode,
        rules: [RoutingRule],
        settings: AppSettings = .defaults,
        logOutputPath: String? = nil,
    ) throws -> String {
        if let unsupportedReason = directlySelectedUnsupportedReason(for: selectedTarget, profiles: profiles) {
            throw SingBoxConfigError.unsupportedProfile(unsupportedReason)
        }

        let singBoxProfiles = profiles.filter { singBoxUnsupportedReason(for: $0) == nil }
        let resolver = OutboundTagResolver(profiles: singBoxProfiles, groups: groups)
        let selectedOutboundTag = resolver.tag(for: selectedTarget) ?? resolver.defaultProxyTag ?? "direct"
        // sing-box 1.13 removed the `wireguard` outbound type (the engine fails
        // the whole config with "unknown outbound type"); WireGuard runs as an
        // `endpoints` entry instead. Endpoint tags share the outbound namespace,
        // so groups and routes can reference them like any other profile tag.
        let endpoints = singBoxProfiles
            .filter(\.isWireGuard)
            .compactMap { profile in
                endpointDictionary(for: profile, tag: resolver.tag(for: profile))
            }
        let profileOutbounds = try singBoxProfiles.filter { !$0.isWireGuard }.map { profile in
            try outboundDictionary(for: profile, tag: resolver.tag(for: profile))
        }
        let groupOutbounds = groups.compactMap { group in
            groupDictionary(for: group, resolver: resolver)
        }
        var outbounds = profileOutbounds + groupOutbounds
        outbounds.append([
            "type": "direct",
            "tag": "direct",
        ])
        outbounds.append([
            "type": "block",
            "tag": "reject",
        ])

        var logDictionary: [String: Any] = [
            "level": settings.logLevel.rawValue,
            "timestamp": true,
        ]
        if let logOutputPath, !logOutputPath.isEmpty {
            logDictionary["output"] = logOutputPath
        }

        var config: [String: Any] = [
            "log": logDictionary,
            "dns": dnsDictionary(settings: settings, routingMode: routingMode, proxyTag: selectedOutboundTag),
            "inbounds": [
                [
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": "hop0",
                    "address": [
                        "172.19.0.1/30",
                        "fdfe:dcba:9876::1/126",
                    ],
                    "auto_route": true,
                    "strict_route": settings.strictRoute,
                ],
            ],
            "outbounds": outbounds,
            "route": routeDictionary(mode: routingMode, rules: rules, selectedTag: selectedOutboundTag, resolver: resolver, sniff: settings.sniffTraffic),
        ]
        if !endpoints.isEmpty {
            config["endpoints"] = endpoints
        }

        let data = try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys])
        guard let string = String(data: data, encoding: .utf8) else {
            throw SingBoxConfigError.serializationFailed
        }
        return string
    }

    private func directlySelectedUnsupportedReason(for target: OutboundTarget, profiles: [ProxyProfile]) -> String? {
        switch target {
        case let .profile(id):
            return profiles.first { $0.id == id }.flatMap(singBoxUnsupportedReason)
        case let .named(name):
            let normalized = name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return profiles.first { $0.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == normalized }.flatMap(singBoxUnsupportedReason)
        case .selectedProxy, .direct, .reject, .group:
            return nil
        }
    }

    private func singBoxUnsupportedReason(for profile: ProxyProfile) -> String? {
        if case let .vless(options) = profile.options,
           options.normalizedEncryption != nil
        {
            return "\(options.encryptionAuthLabel) requires Xray VLESS Encryption/Auth; the bundled sing-box/libbox engine cannot run encrypted VLESS profiles yet."
        }
        if profile.security.reality?.mldsa65Verify?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false {
            return "REALITY ML-DSA-65 verification requires Xray mldsa65Verify/pqv support; the bundled sing-box/libbox engine cannot enforce it yet."
        }
        // sing-box rejects the entire config — not just the one outbound — for
        // TLS-mandatory protocols/transports emitted without a `tls` block, so
        // these profiles are screened out here with an explanation instead of
        // bricking the whole tunnel. Imports and the editor both default/require
        // TLS for them; this guard covers profiles persisted by older builds.
        if profile.security.layer == .none {
            switch profile.proto {
            case .tuic, .hysteria2, .anyTLS:
                return "\(profile.proto.displayName) requires TLS; sing-box rejects a \(profile.proto.displayName) outbound without it. Edit the node and set its Security to TLS."
            default:
                break
            }
            if profile.transport.type == .quic {
                return "QUIC transport requires TLS; sing-box rejects a QUIC-transport outbound without it. Edit the node and set its Security to TLS."
            }
        }
        return nil
    }

    private func groupDictionary(for group: ProxyGroup, resolver: OutboundTagResolver) -> [String: Any]? {
        guard group.isEnabled,
              let singBoxType = group.type.singBoxType,
              resolver.isRunnable(group)
        else {
            return nil
        }

        let groupTag = resolver.tag(for: group)
        let outbounds = group.members
            .compactMap { resolver.tag(for: $0) }
            .filter { $0 != groupTag }
        guard !outbounds.isEmpty else {
            return nil
        }

        var dictionary: [String: Any] = [
            "type": singBoxType,
            "tag": groupTag,
            "outbounds": outbounds,
            "interrupt_exist_connections": false,
        ]

        switch group.type {
        case .select:
            if let defaultTarget = group.defaultTarget,
               let defaultTag = resolver.tag(for: defaultTarget),
               defaultTag != groupTag,
               outbounds.contains(defaultTag)
            {
                dictionary["default"] = defaultTag
            } else {
                dictionary["default"] = outbounds.first
            }
        case .urlTest:
            // Enforce probe-destination and scheduling policy at the final
            // emit point so no import/editor path can schedule SSRF-style or
            // runaway urltest probes in the privileged tunnel.
            dictionary["url"] = ImportPolicy.isAllowedProbeURL(group.testOptions.url) ? group.testOptions.url : ProxyGroupTestOptions.defaultURL
            dictionary["interval"] = "\(ImportPolicy.clampURLTestInterval(group.testOptions.intervalSeconds))s"
            dictionary["tolerance"] = ImportPolicy.clampURLTestTolerance(group.testOptions.toleranceMilliseconds)
        case .unsupported:
            return nil
        }

        return dictionary
    }

    private func dnsDictionary(settings: AppSettings, routingMode: RoutingMode, proxyTag: String) -> [String: Any] {
        let selectedServer = dnsServerDictionary(settings: settings, routingMode: routingMode, proxyTag: proxyTag)
        var servers: [[String: Any]] = []

        if let selectedServer {
            servers.append(selectedServer)
        }

        servers.append([
            "tag": "local",
            "address": "local",
        ])

        return [
            "servers": servers,
            "final": selectedServer?["tag"] ?? "local",
            "strategy": settings.dnsStrategy.rawValue,
        ]
    }

    private func dnsServerDictionary(settings: AppSettings, routingMode: RoutingMode, proxyTag: String) -> [String: Any]? {
        let tag: String
        let address: String

        switch settings.dnsPreset {
        case .cloudflare:
            tag = "cloudflare"
            address = "https://1.1.1.1/dns-query"
        case .google:
            tag = "google"
            address = "https://dns.google/dns-query"
        case .quad9:
            tag = "quad9"
            address = "https://dns.quad9.net/dns-query"
        case .system:
            return nil
        }

        var server: [String: Any] = [
            "tag": tag,
            "address": address,
        ]

        // Direct mode routes all traffic off-proxy; sending DNS through the
        // proxy there would leak the user's query history to the proxy server
        // in the one mode that promises to bypass it.
        if settings.proxyDNS, routingMode != .direct {
            server["detour"] = proxyTag
        }

        return server
    }

    /// Builds the `endpoints` entry for a WireGuard profile (sing-box 1.13 has
    /// no `wireguard` outbound). The local interface addresses and peer allowed
    /// IPs must be CIDR prefixes or the engine rejects the config, so bare IPs
    /// are normalized to host prefixes.
    private func endpointDictionary(for profile: ProxyProfile, tag: String) -> [String: Any]? {
        guard case let .wireGuard(options) = profile.options else {
            return nil
        }
        var peer: [String: Any] = [
            "address": profile.endpoint.host,
            "port": profile.endpoint.port,
            "public_key": options.peerPublicKey,
            "allowed_ips": ["0.0.0.0/0", "::/0"],
        ]
        if let preSharedKey = options.preSharedKey, !preSharedKey.isEmpty {
            peer["pre_shared_key"] = preSharedKey
        }
        return [
            "type": "wireguard",
            "tag": tag,
            "address": options.localAddress.map(Self.normalizedHostPrefix),
            "private_key": options.privateKey,
            "peers": [peer],
        ]
    }

    /// Appends a host prefix length to a bare IP ("10.0.0.2" → "10.0.0.2/32",
    /// "fd00::2" → "fd00::2/128"); values that already carry one pass through.
    private static func normalizedHostPrefix(_ address: String) -> String {
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.contains("/") else {
            return trimmed
        }
        return trimmed + (trimmed.contains(":") ? "/128" : "/32")
    }

    private func outboundDictionary(for profile: ProxyProfile, tag: String) throws -> [String: Any] {
        var outbound: [String: Any] = [
            "tag": tag,
            "server": profile.endpoint.host,
            "server_port": profile.endpoint.port,
        ]

        switch profile.options {
        case let .vless(options):
            guard profile.proto == .vless else { throw SingBoxConfigError.unsupportedProfile("Mismatched VLESS profile.") }
            if options.normalizedEncryption != nil {
                throw SingBoxConfigError.unsupportedProfile(
                    "\(options.encryptionAuthLabel) requires Xray VLESS Encryption/Auth; the bundled sing-box/libbox engine cannot run encrypted VLESS profiles yet.",
                )
            }
            outbound["type"] = "vless"
            outbound["uuid"] = options.uuid
            if let flow = options.flow, !flow.isEmpty {
                outbound["flow"] = flow
            }
        case let .trojan(options):
            guard profile.proto == .trojan else { throw SingBoxConfigError.unsupportedProfile("Mismatched Trojan profile.") }
            outbound["type"] = "trojan"
            outbound["password"] = options.password
        case let .hysteria2(options):
            guard profile.proto == .hysteria2 else { throw SingBoxConfigError.unsupportedProfile("Mismatched Hysteria2 profile.") }
            outbound["type"] = "hysteria2"
            outbound["password"] = options.password
            if let obfs = options.obfs, let obfsPassword = options.obfsPassword {
                outbound["obfs"] = [
                    "type": obfs,
                    "password": obfsPassword,
                ]
            }
        case let .tuic(options):
            guard profile.proto == .tuic else { throw SingBoxConfigError.unsupportedProfile("Mismatched TUIC profile.") }
            outbound["type"] = "tuic"
            outbound["uuid"] = options.uuid
            outbound["password"] = options.password
            if let congestionControl = options.congestionControl {
                outbound["congestion_control"] = congestionControl
            }
        case let .shadowsocks(options):
            guard profile.proto == .shadowsocks else { throw SingBoxConfigError.unsupportedProfile("Mismatched Shadowsocks profile.") }
            outbound["type"] = "shadowsocks"
            outbound["method"] = options.method
            outbound["password"] = options.password
        case let .vmess(options):
            guard profile.proto == .vmess else { throw SingBoxConfigError.unsupportedProfile("Mismatched VMess profile.") }
            outbound["type"] = "vmess"
            outbound["uuid"] = options.uuid
            outbound["security"] = options.security
            outbound["alter_id"] = options.alterID
        case let .http(options):
            guard profile.proto == .http else { throw SingBoxConfigError.unsupportedProfile("Mismatched HTTP profile.") }
            outbound["type"] = "http"
            outbound["username"] = options.username
            outbound["password"] = options.password
        case let .socks(options):
            guard profile.proto == .socks else { throw SingBoxConfigError.unsupportedProfile("Mismatched SOCKS profile.") }
            outbound["type"] = "socks"
            outbound["username"] = options.username
            outbound["password"] = options.password
        case .wireGuard:
            // WireGuard is emitted via `endpointDictionary`; reaching this case
            // means a caller bypassed the endpoint split in `build`.
            throw SingBoxConfigError.unsupportedProfile("WireGuard profiles run as sing-box endpoints, not outbounds.")
        case let .anyTLS(options):
            guard profile.proto == .anyTLS else { throw SingBoxConfigError.unsupportedProfile("Mismatched AnyTLS profile.") }
            outbound["type"] = "anytls"
            outbound["password"] = options.password
        }

        if let tls = try tlsDictionary(from: profile.security) {
            outbound["tls"] = tls
        }
        if let transport = transportDictionary(from: profile.transport) {
            outbound["transport"] = transport
        }

        // No `compactMapValues` needed: assigning an optional through the
        // subscript (e.g. `outbound["username"] = options.username`) removes
        // the key when nil, so the dictionary never holds wrapped optionals.
        return outbound
    }

    private func tlsDictionary(from security: ProxySecurity) throws -> [String: Any]? {
        switch security.layer {
        case .none:
            return nil
        case .tls, .reality:
            guard let tls = security.tls else { return nil }
            var result: [String: Any] = [
                "enabled": true,
                "disable_sni": false,
                "insecure": tls.allowInsecure,
            ]
            if let serverName = tls.serverName, !serverName.isEmpty {
                result["server_name"] = serverName
            }
            if !tls.alpn.isEmpty {
                result["alpn"] = tls.alpn
            }
            if let fingerprint = tls.utlsFingerprint, !fingerprint.isEmpty {
                result["utls"] = [
                    "enabled": true,
                    "fingerprint": fingerprint,
                ]
            }
            if security.layer == .reality, let reality = security.reality {
                if reality.mldsa65Verify?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false {
                    throw SingBoxConfigError.unsupportedProfile(
                        "REALITY ML-DSA-65 verification requires Xray mldsa65Verify/pqv support; the bundled sing-box/libbox engine cannot enforce it yet.",
                    )
                }
                var realityDictionary: [String: Any] = [
                    "enabled": true,
                    "public_key": reality.publicKey,
                ]
                if let shortID = reality.shortID, !shortID.isEmpty {
                    realityDictionary["short_id"] = shortID
                }
                // sing-box's REALITY client takes only public_key + short_id.
                // `spider_x` is an Xray/Shadowrocket concept we keep on the model
                // for import round-tripping but must not emit, or the engine
                // rejects the whole config ("unknown field spider_x").
                result["reality"] = realityDictionary
            }
            return result
        }
    }

    private func transportDictionary(from transport: TransportOptions) -> [String: Any]? {
        guard let type = transport.type.singBoxType else {
            return nil
        }

        var dictionary: [String: Any] = [
            "type": type,
        ]
        if let path = transport.path, !path.isEmpty {
            dictionary["path"] = path
        }
        if let host = transport.host, !host.isEmpty {
            dictionary["headers"] = [
                "Host": host,
            ]
        }
        if let serviceName = transport.serviceName, !serviceName.isEmpty {
            dictionary["service_name"] = serviceName
        }
        return dictionary
    }

    private func routeDictionary(mode: RoutingMode, rules: [RoutingRule], selectedTag: String, resolver: OutboundTagResolver, sniff: Bool) -> [String: Any] {
        var ruleDicts: [[String: Any]] = []
        var ruleSets: [String: [String: Any]] = [:]

        ruleDicts.append(dnsHijackRule)

        // sing-box 1.13 removed inbound-level sniffing; it is a route action now.
        if sniff {
            ruleDicts.append(["action": "sniff"])
        }
        if case .rule = mode {
            for rule in rules {
                if let rule = ruleDictionary(from: rule, selectedTag: selectedTag, resolver: resolver, ruleSets: &ruleSets) {
                    ruleDicts.append(rule)
                }
            }
        }

        var route: [String: Any] = [
            "auto_detect_interface": true,
            // Resolve outbound server domains via the direct/local resolver so a
            // server hostname doesn't depend on the not-yet-established tunnel.
            "default_domain_resolver": ["server": "local"],
        ]
        if !ruleDicts.isEmpty {
            route["rules"] = ruleDicts
        }
        if !ruleSets.isEmpty {
            route["rule_set"] = ruleSets.keys.sorted().map { ruleSets[$0]! }
        }
        switch mode {
        case .direct:
            route["final"] = "direct"
        case .global, .rule:
            route["final"] = selectedTag
        }

        return route
    }

    private var dnsHijackRule: [String: Any] {
        [
            "inbound": "tun-in",
            "port": 53,
            "action": "hijack-dns",
        ]
    }

    private func ruleDictionary(from rule: RoutingRule, selectedTag: String, resolver: OutboundTagResolver, ruleSets: inout [String: [String: Any]]) -> [String: Any]? {
        var dictionary: [String: Any] = [
            "outbound": rule.target == .selectedProxy ? selectedTag : resolver.tag(for: rule.target) ?? selectedTag,
        ]

        switch rule.kind {
        case .final:
            break
        case .domain:
            addStringList("domain", from: rule.value, to: &dictionary)
        case .domainSuffix:
            addStringList("domain_suffix", from: rule.value, to: &dictionary)
        case .domainKeyword:
            addStringList("domain_keyword", from: rule.value, to: &dictionary)
        case .domainRegex:
            // Drop oversized/uncompilable patterns so a malicious imported rule
            // cannot hand a catastrophic regex to the tunnel's route engine.
            addStringList("domain_regex", values: stringList(from: rule.value).filter(ImportPolicy.isSafeRegexPattern), to: &dictionary)
        case .ipCIDR:
            addStringList("ip_cidr", from: rule.value, to: &dictionary)
        case .ipIsPrivate:
            addBool("ip_is_private", from: rule.value, to: &dictionary)
        case .sourceIPCIDR:
            addStringList("source_ip_cidr", from: rule.value, to: &dictionary)
        case .sourceIPIsPrivate:
            addBool("source_ip_is_private", from: rule.value, to: &dictionary)
        case .port:
            addIntList("port", from: rule.value, to: &dictionary)
        case .portRange:
            addStringList("port_range", from: rule.value, to: &dictionary)
        case .sourcePort:
            addIntList("source_port", from: rule.value, to: &dictionary)
        case .sourcePortRange:
            addStringList("source_port_range", from: rule.value, to: &dictionary)
        case .network:
            addStringList("network", from: rule.value, to: &dictionary)
        case .protocolSniff:
            addStringList("protocol", from: rule.value, to: &dictionary)
        case .geoSite:
            // sing-box 1.12 removed the bundled geosite/geoip databases in favor
            // of rule-sets, so map geosite categories to the published remote sets.
            let tags = stringList(from: rule.value).compactMap { geoRuleSet(kind: "geosite", name: $0, downloadDetour: selectedTag, into: &ruleSets) }
            if !tags.isEmpty {
                dictionary["rule_set"] = tags
            }
        case .geoIP:
            dictionary.merge(geoIPConditions(from: rule.value, source: false, downloadDetour: selectedTag, into: &ruleSets)) { _, new in new }
        case .sourceGeoIP:
            dictionary.merge(geoIPConditions(from: rule.value, source: true, downloadDetour: selectedTag, into: &ruleSets)) { _, new in new }
        case .networkType:
            addStringList("network_type", from: rule.value, to: &dictionary)
        case .networkIsExpensive:
            addBool("network_is_expensive", from: rule.value, to: &dictionary)
        case .networkIsConstrained:
            addBool("network_is_constrained", from: rule.value, to: &dictionary)
        case .wifiSSID:
            addStringList("wifi_ssid", from: rule.value, to: &dictionary)
        case .wifiBSSID:
            addStringList("wifi_bssid", from: rule.value, to: &dictionary)
        }

        guard rule.kind == .final || dictionary.keys.contains(where: { $0 != "outbound" }) else {
            return nil
        }
        return dictionary
    }

    /// `geoip: ["private"]` has a built-in replacement (`ip_is_private`); country
    /// codes become remote geoip rule-sets. (Source country codes fall back to a
    /// destination rule-set — sing-box has no source rule-set match.)
    private func geoIPConditions(from value: String, source: Bool, downloadDetour: String, into ruleSets: inout [String: [String: Any]]) -> [String: Any] {
        var result: [String: Any] = [:]
        var tags: [String] = []
        for entry in stringList(from: value) {
            switch entry.lowercased() {
            case "private":
                result[source ? "source_ip_is_private" : "ip_is_private"] = true
            case "!private":
                result[source ? "source_ip_is_private" : "ip_is_private"] = false
            default:
                if let tag = geoRuleSet(kind: "geoip", name: entry, downloadDetour: downloadDetour, into: &ruleSets) {
                    tags.append(tag)
                }
            }
        }
        if !tags.isEmpty {
            result["rule_set"] = tags
        }
        return result
    }

    private func geoRuleSet(kind: String, name: String, downloadDetour: String, into ruleSets: inout [String: [String: Any]]) -> String? {
        let normalized = name.lowercased()
        // The category name is interpolated into the rule-set download URL path,
        // so allow only `[a-z0-9_-]`. Otherwise an imported GEOSITE/GEOIP value
        // like `../../owner/repo/main/x` redirects the engine's fetch to an
        // attacker-chosen path under raw.githubusercontent.com.
        guard !normalized.isEmpty,
              normalized.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") })
        else {
            return nil
        }
        let tag = "\(kind)-\(normalized)"
        if ruleSets[tag] == nil {
            let repository = kind == "geosite" ? "sing-geosite" : "sing-geoip"
            ruleSets[tag] = [
                "tag": tag,
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/SagerNet/\(repository)/rule-set/\(tag).srs",
                "download_detour": downloadDetour,
            ]
        }
        return tag
    }

    private func stringList(from value: String) -> [String] {
        value
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    private func intList(from value: String) -> [Int] {
        value
            .split(separator: ",")
            .compactMap { Int($0.trimmingCharacters(in: .whitespacesAndNewlines)) }
    }

    private func addStringList(_ key: String, from value: String, to dictionary: inout [String: Any]) {
        addStringList(key, values: stringList(from: value), to: &dictionary)
    }

    private func addStringList(_ key: String, values: [String], to dictionary: inout [String: Any]) {
        guard !values.isEmpty else { return }
        dictionary[key] = values
    }

    private func addIntList(_ key: String, from value: String, to dictionary: inout [String: Any]) {
        let values = intList(from: value)
        guard !values.isEmpty else { return }
        dictionary[key] = values
    }

    private func addBool(_ key: String, from value: String, to dictionary: inout [String: Any]) {
        guard let value = boolValue(from: value) else { return }
        dictionary[key] = value
    }

    private func boolValue(from value: String) -> Bool? {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        switch normalized {
        case "true", "yes", "1":
            return true
        case "false", "no", "0":
            return false
        default:
            return nil
        }
    }
}

private extension ProxyProfile {
    var isWireGuard: Bool {
        if case .wireGuard = options {
            return true
        }
        return false
    }
}

private struct OutboundTagResolver {
    var profiles: [ProxyProfile]
    var groups: [ProxyGroup]
    private let runnableGroupIDs: Set<ProxyGroup.ID>

    init(profiles: [ProxyProfile], groups: [ProxyGroup]) {
        self.profiles = profiles
        self.groups = groups
        runnableGroupIDs = Self.runnableGroupIDs(profiles: profiles, groups: groups)
    }

    var defaultProxyTag: String? {
        profiles.first.map(tag(for:)) ?? groups.first(where: isRunnable).map(tag(for:))
    }

    func isRunnable(_ group: ProxyGroup) -> Bool {
        runnableGroupIDs.contains(group.id)
    }

    func tag(for profile: ProxyProfile) -> String {
        "proxy-\(profile.id.uuidString.lowercased())"
    }

    func tag(for group: ProxyGroup) -> String {
        "group-\(group.id.uuidString.lowercased())"
    }

    func tag(for target: OutboundTarget) -> String? {
        switch target {
        case .selectedProxy:
            defaultProxyTag
        case .direct:
            "direct"
        case .reject:
            "reject"
        case let .profile(id):
            profiles.first { $0.id == id }.map(tag(for:))
        case let .group(id):
            groups.first { $0.id == id && runnableGroupIDs.contains($0.id) }.map(tag(for:))
        case let .named(name):
            tag(forNamed: name)
        }
    }

    private func tag(forNamed name: String) -> String? {
        let normalized = name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let profile = profiles.first(where: { $0.name.lowercased() == normalized }) {
            return tag(for: profile)
        }
        if let group = groups.first(where: { $0.name.lowercased() == normalized && runnableGroupIDs.contains($0.id) }) {
            return tag(for: group)
        }
        if normalized == "direct" {
            return "direct"
        }
        if normalized == "reject" {
            return "reject"
        }
        if normalized == "proxy" {
            return defaultProxyTag
        }
        return nil
    }

    private static func runnableGroupIDs(profiles: [ProxyProfile], groups: [ProxyGroup]) -> Set<ProxyGroup.ID> {
        var runnableGroupIDs: Set<ProxyGroup.ID> = []
        var changed = true

        while changed {
            changed = false
            for group in groups where !runnableGroupIDs.contains(group.id) {
                guard group.isEnabled,
                      group.type.singBoxType != nil,
                      group.members.contains(where: {
                          targetIsRunnable($0, profiles: profiles, groups: groups, runnableGroupIDs: runnableGroupIDs)
                      })
                else {
                    continue
                }

                runnableGroupIDs.insert(group.id)
                changed = true
            }
        }

        return runnableGroupIDs
    }

    private static func targetIsRunnable(
        _ target: OutboundTarget,
        profiles: [ProxyProfile],
        groups: [ProxyGroup],
        runnableGroupIDs: Set<ProxyGroup.ID>,
    ) -> Bool {
        switch target {
        case .selectedProxy:
            !profiles.isEmpty || !runnableGroupIDs.isEmpty
        case .direct, .reject:
            true
        case let .profile(id):
            profiles.contains { $0.id == id }
        case let .group(id):
            runnableGroupIDs.contains(id)
        case let .named(name):
            namedTargetIsRunnable(name, profiles: profiles, groups: groups, runnableGroupIDs: runnableGroupIDs)
        }
    }

    private static func namedTargetIsRunnable(
        _ name: String,
        profiles: [ProxyProfile],
        groups: [ProxyGroup],
        runnableGroupIDs: Set<ProxyGroup.ID>,
    ) -> Bool {
        let normalized = name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if normalized == "direct" || normalized == "reject" {
            return true
        }
        if normalized == "proxy" {
            return !profiles.isEmpty || !runnableGroupIDs.isEmpty
        }
        if profiles.contains(where: { $0.name.lowercased() == normalized }) {
            return true
        }
        return groups.contains { $0.name.lowercased() == normalized && runnableGroupIDs.contains($0.id) }
    }
}
