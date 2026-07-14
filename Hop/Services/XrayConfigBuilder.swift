import Foundation

enum XrayConfigError: LocalizedError {
    case validationFailed([XrayValidationIssue])
    case serializationFailed

    var errorDescription: String? {
        switch self {
        case let .validationFailed(issues):
            issues.map { "\($0.path): \($0.message)" }.joined(separator: "\n")
        case .serializationFailed:
            "Unable to serialize Xray configuration."
        }
    }
}

struct XrayConfigBuilder {
    static let coreVersion = "v26.6.27"

    var limits: IOSRuntimeLimits = .default

    func build(
        profile: ProxyProfile,
        routingMode: RoutingMode,
        rules: [RoutingRule],
        settings: AppSettings = .defaults,
        logOutputPath: String? = nil,
    ) throws -> String {
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
        logOutputPath _: String? = nil,
    ) throws -> String {
        try validateGlobalAdvanced(settings.xrayAdvanced)

        let resolver = XrayReachabilityResolver(profiles: profiles, groups: groups, limits: limits)
        let selectedDestination = try resolver.resolve(routingMode == .direct ? .direct : selectedTarget)
        let ruleDestinations = try routingMode == .rule ? rules.map { rule in
            rule.target == .selectedProxy ? selectedDestination : try resolver.resolve(rule.target)
        } : []

        let reachableProfiles = profiles.filter { resolver.profileIDs.contains($0.id) }
        try require(
            reachableProfiles.count + 3 <= limits.maxReachableOutbounds,
            path: "/outbounds",
            "The configuration needs \(reachableProfiles.count + 3) outbounds; iOS permits at most \(limits.maxReachableOutbounds).",
        )
        try require(
            resolver.urlGroups.values.reduce(0) { $0 + $1.memberTags.count } <= limits.maxObservatoryTargets,
            path: "/observatory/subjectSelector",
            "URL-test groups exceed the \(limits.maxObservatoryTargets)-target iOS limit.",
        )

        let routingAtoms = routingMode == .rule ? rules.reduce(0) { $0 + atomCount(in: $1) } : 0
        try require(
            routingAtoms <= limits.maxRoutingAtoms,
            path: "/routing/rules",
            "Routing contains \(routingAtoms) atoms; iOS permits at most \(limits.maxRoutingAtoms).",
        )

        try validateURLGroups(Array(resolver.urlGroups.values))
        try validateHeavyOutboundCount(reachableProfiles)

        var outbounds = try reachableProfiles.map(outboundDictionary)
        outbounds.append([
            "tag": .string("direct"),
            "protocol": .string("freedom"),
            "settings": .object([:]),
        ])
        outbounds.append([
            "tag": .string("reject"),
            "protocol": .string("blackhole"),
            "settings": .object([:]),
        ])
        outbounds.append([
            "tag": .string("dns-out"),
            "protocol": .string("dns"),
            "settings": .object([:]),
        ])

        var root: JSONObject = try [
            "log": .object([
                "access": .string("none"),
                "loglevel": .string(xrayLogLevel(settings.logLevel)),
                "maskAddress": .string("half"),
            ]),
            "dns": .object(dnsDictionary(settings: settings)),
            "inbounds": .array([.object(tunInboundDictionary(settings: settings))]),
            "outbounds": .array(outbounds.map(JSONValue.object)),
            "policy": .object([
                "levels": .object([
                    "0": .object([
                        "bufferSize": .number(0),
                        "handshake": .number(Double(limits.maxPolicyHandshakeSeconds)),
                        "connIdle": .number(Double(limits.maxPolicyConnectionIdleSeconds)),
                        "uplinkOnly": .number(Double(limits.maxPolicyHalfCloseSeconds)),
                        "downlinkOnly": .number(Double(limits.maxPolicyHalfCloseSeconds)),
                    ]),
                ]),
            ]),
            "routing": .object(routingDictionary(
                mode: routingMode,
                rules: rules,
                selected: selectedDestination,
                ruleDestinations: ruleDestinations,
                resolver: resolver,
                sniff: settings.sniffTraffic,
            )),
        ]

        if let observatory = try observatoryDictionary(from: Array(resolver.urlGroups.values)) {
            root["observatory"] = .object(observatory)
        }

        if let advanced = settings.xrayAdvanced, !advanced.isEmpty {
            try mergeAdvanced(advanced.values, into: &root, path: "")
        }
        if root["fakeDns"] != nil {
            try enableFakeDNS(in: &root, sniff: settings.sniffTraffic)
        }

        try validateRenderedLimits(root)
        let data = try JSONSerialization.data(
            withJSONObject: JSONValue.object(root).foundationValue,
            // This file is read by machines, not edited by users. Compact JSON
            // cuts the bytes copied, authenticated, scanned for secret tokens,
            // and parsed on every tunnel start; sorted keys keep it deterministic.
            options: [.sortedKeys, .withoutEscapingSlashes],
        )
        try require(
            data.count <= limits.maxRenderedConfigBytes,
            path: "/",
            "Rendered config is \(data.count) bytes; iOS permits at most \(limits.maxRenderedConfigBytes).",
        )
        guard let string = String(data: data, encoding: .utf8) else {
            throw XrayConfigError.serializationFailed
        }
        return string
    }

    func validationIssues(
        profiles: [ProxyProfile],
        groups: [ProxyGroup],
        selectedTarget: OutboundTarget,
        routingMode: RoutingMode,
        rules: [RoutingRule],
        settings: AppSettings = .defaults,
    ) -> [XrayValidationIssue] {
        do {
            _ = try build(
                profiles: profiles,
                groups: groups,
                selectedTarget: selectedTarget,
                routingMode: routingMode,
                rules: rules,
                settings: settings,
            )
            return []
        } catch let XrayConfigError.validationFailed(issues) {
            return issues
        } catch {
            return [XrayValidationIssue(path: "/", message: error.localizedDescription)]
        }
    }

    /// Reuses the pinned runtime policy during persistence migration without
    /// admitting a profile or starting the core.
    func validateTLSOptionsForMigration(_ tls: TLSOptions) throws {
        try validateCertificatePins(tls.pinnedPeerCertSHA256, path: "/migration/security/tls/pinnedPeerCertSHA256")
        try validateTLSOptions(tls, path: "/migration/security/tls")
    }
}

private extension XrayConfigBuilder {
    typealias JSONObject = [String: JSONValue]

    static let secureShadowsocksMethods: Set<String> = [
        "aes-128-gcm",
        "aes-256-gcm",
        "chacha20-poly1305",
        "chacha20-ietf-poly1305",
        "xchacha20-poly1305",
        "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
    ]

    static let vmessSecurityValues: Set<String> = [
        "auto",
        "aes-128-gcm",
        "chacha20-poly1305",
    ]

    static let tlsCurves: Set<String> = [
        "curvep256", "curvep384", "curvep521", "x25519",
        "x25519mlkem768", "secp256r1mlkem768", "secp384r1mlkem1024",
    ]

    static let tlsVersions: [String: Int] = ["1.0": 10, "1.1": 11, "1.2": 12, "1.3": 13]

    static let tlsCipherSuites: Set<String> = [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    ]

    static let appleOnlyRuleKinds: Set<RoutingRuleKind> = [
        .networkType,
        .networkIsExpensive,
        .networkIsConstrained,
        .wifiSSID,
        .wifiBSSID,
    ]

    static let profileAdvancedKeys: Set<String> = [
        "settings",
        "streamSettings",
        "proxySettings",
        "mux",
        "targetStrategy",
        "sendThrough",
    ]

    static let globalAdvancedKeys: Set<String> = [
        "dns",
        "fakeDns",
        "routing",
        "policy",
        "observatory",
        "version",
        "geodata",
    ]

    static let streamAdvancedKeys: Set<String> = [
        "tlsSettings",
        "realitySettings",
        "rawSettings",
        "tcpSettings",
        "xhttpSettings",
        "splithttpSettings",
        "kcpSettings",
        "grpcSettings",
        "wsSettings",
        "httpupgradeSettings",
        "hysteriaSettings",
        "finalmask",
        "sockopt",
    ]

    static let muxAdvancedKeys: Set<String> = ["enabled", "concurrency", "xudpConcurrency", "xudpProxyUDP443"]
    static let proxyAdvancedKeys: Set<String> = ["tag", "transportLayer"]
    // Security-critical TLS settings are typed so subscription review and
    // central validation cannot be bypassed by filling an otherwise-empty raw
    // field. These remaining long-tail settings cannot change trust policy.
    static let tlsAdvancedKeys: Set<String> = ["alpn", "enableSessionResumption", "echSockopt"]
    static let realityAdvancedKeys: Set<String> = ["fingerprint", "serverName", "password", "shortId", "mldsa65Verify", "spiderX"]
    static let finalMaskAdvancedKeys: Set<String> = ["tcp", "udp", "quicParams"]
    static let socketAdvancedKeys: Set<String> = [
        "mark", "tcpFastOpen", "tproxy", "domainStrategy", "dialerProxy",
        "tcpKeepAliveInterval", "tcpKeepAliveIdle", "tcpCongestion", "tcpWindowClamp", "tcpMaxSeg",
        "penetrate", "tcpUserTimeout", "v6only", "interface", "tcpMptcp",
        "addressPortStrategy", "happyEyeballs", "trustedXForwardedFor",
    ]

    static let forbiddenAdvancedKeys: Set<String> = [
        "allowInsecure",
        "api",
        "auth",
        "certificateFile",
        "echServerKeys",
        "inbounds",
        "keyFile",
        "listen",
        "masterKeyLog",
        "metrics",
        "pass",
        "password",
        "preSharedKey",
        "privateKey",
        "reverse",
        "seed",
        "secretKey",
        "statsInboundDownlink",
        "statsInboundUplink",
        "statsOutboundDownlink",
        "statsOutboundUplink",
        "statsUserDownlink",
        "statsUserOnline",
        "statsUserUplink",
        "transport",
        "url",
        "downloadSettings",
        "echConfigList",
    ]
    static let memorySensitiveKeys: Set<String> = [
        "concurrency", "xudpConcurrency", "maxConcurrency", "maxConnections",
        "scMaxBufferedPosts", "scMaxEachPostBytes", "uplinkChunkSize", "xPaddingBytes",
        "sessionIDLength", "bufferSize", "handshake", "connIdle", "uplinkOnly", "downlinkOnly", "initial_windows_size",
        "initStreamReceiveWindow", "maxStreamReceiveWindow",
        "initConnectionReceiveWindow", "maxConnectionReceiveWindow", "maxIncomingStreams",
        "rand", "length", "lengths", "maxSplit", "packetSize",
        "paddingMin", "paddingMax", "padding_min", "padding_max",
    ]
    static let positiveMemorySensitiveKeys: Set<String> = [
        "maxConnections", "scMaxBufferedPosts", "scMaxEachPostBytes",
        "handshake", "connIdle",
        "initStreamReceiveWindow", "maxStreamReceiveWindow",
        "initConnectionReceiveWindow", "maxConnectionReceiveWindow",
    ]
    static let policyLevelAdvancedKeys: Set<String> = [
        "bufferSize", "handshake", "connIdle", "uplinkOnly", "downlinkOnly",
    ]
    static let finalMaskGeneratedSizeKeys: Set<String> = [
        "rand", "length", "lengths", "maxSplit", "packetSize",
        "paddingMin", "paddingMax", "padding_min", "padding_max",
    ]

    func require(_ condition: @autoclosure () -> Bool, path: String, _ message: String) throws {
        guard condition() else {
            throw XrayConfigError.validationFailed([XrayValidationIssue(path: path, message: message)])
        }
    }

    func xrayLogLevel(_ level: ConfigLogLevel) -> String {
        switch level {
        case .debug:
            "debug"
        case .info:
            "info"
        case .warn:
            "warning"
        case .error:
            "error"
        }
    }

    func tunInboundDictionary(settings: AppSettings) -> JSONObject {
        var inbound: JSONObject = [
            "tag": .string("tun-in"),
            "protocol": .string("tun"),
            "settings": .object([
                "name": .string("hop0"),
                "mtu": .number(Double(XrayTunnelNetworkDefaults.mtu)),
                "gateway": .array([
                    .string(XrayTunnelNetworkDefaults.xrayIPv4CIDR),
                    .string(XrayTunnelNetworkDefaults.xrayIPv6CIDR),
                ]),
                "dns": .array(XrayTunnelNetworkDefaults.dnsServers.map(JSONValue.string)),
            ]),
        ]
        if settings.sniffTraffic {
            inbound["sniffing"] = .object([
                "enabled": .bool(true),
                "destOverride": .array([.string("http"), .string("tls"), .string("quic")]),
                "routeOnly": .bool(true),
            ])
        }
        return inbound
    }

    func dnsDictionary(settings: AppSettings) -> JSONObject {
        let server = switch settings.dnsPreset {
        case .cloudflare:
            "https://1.1.1.1/dns-query"
        case .google:
            "https://dns.google/dns-query"
        case .quad9:
            "https://dns.quad9.net/dns-query"
        case .system:
            "localhost"
        }
        let strategy = switch settings.dnsStrategy {
        case .preferIPv4, .ipv4Only:
            "UseIPv4"
        case .preferIPv6, .ipv6Only:
            "UseIPv6"
        }
        return [
            "servers": .array([.string(server)]),
            "queryStrategy": .string(strategy),
            "disableCache": .bool(true),
        ]
    }

    func outboundDictionary(for profile: ProxyProfile) throws -> JSONObject {
        try validate(profile)
        var outbound: JSONObject = [
            "tag": .string(Self.tag(for: profile)),
        ]
        var settings: JSONObject = [
            "address": .string(profile.endpoint.host),
            "port": .number(Double(profile.endpoint.port)),
        ]

        switch profile.options {
        case let .vless(options):
            outbound["protocol"] = .string("vless")
            settings["id"] = .string(options.uuid)
            settings["encryption"] = .string(options.normalizedEncryption ?? "none")
            insert(options.flow, key: "flow", into: &settings)
        case let .trojan(options):
            outbound["protocol"] = .string("trojan")
            settings["password"] = .string(options.password)
        case .tuic:
            preconditionFailure("TUIC was admitted after validation")
        case let .hysteria2(options):
            outbound["protocol"] = .string("hysteria")
            settings["version"] = .number(2)
            outbound["settings"] = .object(settings)
            outbound["streamSettings"] = try .object(hysteriaStreamDictionary(profile: profile, options: options))
            try applyProfileAdvanced(profile.xrayAdvanced, profile: profile, to: &outbound)
            return outbound
        case let .shadowsocks(options):
            outbound["protocol"] = .string("shadowsocks")
            settings["method"] = .string(options.method)
            settings["password"] = .string(options.password)
        case let .vmess(options):
            outbound["protocol"] = .string("vmess")
            settings["id"] = .string(options.uuid)
            settings["security"] = .string(options.security.lowercased())
        case let .http(options):
            outbound["protocol"] = .string("http")
            insert(options.username, key: "user", into: &settings)
            insert(options.password, key: "pass", into: &settings)
        case let .socks(options):
            outbound["protocol"] = .string("socks")
            insert(options.username, key: "user", into: &settings)
            insert(options.password, key: "pass", into: &settings)
        case let .wireGuard(options):
            outbound["protocol"] = .string("wireguard")
            settings = wireGuardSettings(profile: profile, options: options)
        case .anyTLS:
            preconditionFailure("AnyTLS was admitted after validation")
        }

        outbound["settings"] = .object(settings)
        if profile.proto != .wireGuard {
            outbound["streamSettings"] = try .object(streamDictionary(for: profile))
        }
        if let mux = profile.transport.mux {
            outbound["mux"] = .object(muxDictionary(mux))
        }
        try applyProfileAdvanced(profile.xrayAdvanced, profile: profile, to: &outbound)
        return outbound
    }

    func validate(_ profile: ProxyProfile) throws {
        let path = "/profiles/\(profile.id.uuidString.lowercased())"
        try require(!profile.endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, path: "\(path)/endpoint/host", "Server host is empty.")
        try require((1 ... 65535).contains(profile.endpoint.port), path: "\(path)/endpoint/port", "Server port must be between 1 and 65535.")
        try require(profile.transport.type != .quic, path: "\(path)/transport/type", "Legacy generic QUIC transport was removed; use XHTTP stream-one over H3.")
        try require(profile.proto != .tuic, path: "\(path)/protocol", "TUIC is not supported by Xray-core.")
        try require(profile.proto != .anyTLS, path: "\(path)/protocol", "AnyTLS is not supported by Xray-core.")

        if let tls = profile.security.tls {
            try require(!tls.allowInsecure, path: "\(path)/security/tls/allowInsecure", "Xray v26.6.27 removed allowInsecure. Use normal certificate validation or a SHA-256 certificate pin.")
            try validateCertificatePins(tls.pinnedPeerCertSHA256, path: "\(path)/security/tls/pinnedPeerCertSHA256")
            try validateTLSOptions(tls, path: "\(path)/security/tls")
        }

        if profile.security.layer == .reality {
            try require(
                [.tcp, .xhttp, .grpc].contains(profile.transport.type),
                path: "\(path)/transport/type",
                "REALITY supports only RAW, XHTTP, and gRPC transports.",
            )
        }

        switch profile.options {
        case let .vless(options):
            try validateVLESSEncryption(options.normalizedEncryption, path: "\(path)/options/encryption")
        case .trojan:
            break
        case let .hysteria2(options):
            try require(profile.security.layer == .tls, path: "\(path)/security", "Hysteria2 requires TLS.")
            try require(
                profile.transport.type == .tcp || profile.transport.type == .hysteria,
                path: "\(path)/transport/type",
                "Hysteria2 uses Xray's Hysteria transport and cannot be wrapped in another transport.",
            )
            if let interval = options.hopIntervalSeconds {
                try require((5 ... 3600).contains(interval), path: "\(path)/options/hopIntervalSeconds", "Hysteria2 hop interval must be between 5 and 3600 seconds.")
            }
            if let timeout = options.udpIdleTimeoutSeconds {
                try require((1 ... 3600).contains(timeout), path: "\(path)/options/udpIdleTimeoutSeconds", "Hysteria2 UDP idle timeout must be between 1 and 3600 seconds.")
            }
            if let ports = options.ports {
                let hops = ports.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
                try require(!hops.isEmpty && hops.count <= limits.maxHysteriaPortHops, path: "\(path)/options/ports", "Hysteria2 port hopping exceeds the iOS limit of \(limits.maxHysteriaPortHops) entries.")
                try require(hops.allSatisfy(validPortOrRange), path: "\(path)/options/ports", "Hysteria2 port hopping contains an invalid port or range.")
            }
            for (label, value) in [("up", options.up), ("down", options.down)] {
                if let value, let mbps = bandwidthMbps(value) {
                    try require(mbps <= Double(limits.maxHysteriaBandwidthMbps), path: "\(path)/options/\(label)", "Hysteria2 bandwidth exceeds the \(limits.maxHysteriaBandwidthMbps) Mbps iOS limit.")
                } else if value != nil {
                    try require(false, path: "\(path)/options/\(label)", "Hysteria2 bandwidth must use bps, kbps, mbps, or gbps.")
                }
            }
        case .tuic, .anyTLS:
            break
        case let .shadowsocks(options):
            try require(
                Self.secureShadowsocksMethods.contains(options.method.lowercased()),
                path: "\(path)/options/method",
                "Unsupported or insecure Shadowsocks cipher \(options.method).",
            )
        case let .vmess(options):
            try require(options.alterID == 0, path: "\(path)/options/alterID", "VMess alterID must be 0 (AEAD mode).")
            try require(
                Self.vmessSecurityValues.contains(options.security.lowercased()),
                path: "\(path)/options/security",
                "VMess security must be auto, aes-128-gcm, or chacha20-poly1305.",
            )
        case .http, .socks:
            break
        case let .wireGuard(options):
            try require(profile.security.layer == .none, path: "\(path)/security", "WireGuard cannot use an additional TLS or REALITY layer.")
            let peers = options.effectivePeers
            try require(!peers.isEmpty && peers.count <= limits.maxWireGuardPeers, path: "\(path)/options/peers", "WireGuard supports at most \(limits.maxWireGuardPeers) peers on iOS.")
            if options.peers != nil {
                try require(Set(peers.map(\.id)).count == peers.count, path: "\(path)/options/peers", "WireGuard peer IDs must be unique.")
            }
            for (index, peer) in peers.enumerated() {
                let peerPath = "\(path)/options/peers/\(index)"
                try require(!peer.publicKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, path: "\(peerPath)/publicKey", "WireGuard peer public key is required.")
                try require((peer.allowedIPs?.count ?? 2) <= 32, path: "\(peerPath)/allowedIPs", "Each WireGuard peer supports at most 32 allowed-IP entries on iOS.")
                if let endpoint = peer.endpoint {
                    try require(!endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, path: "\(peerPath)/endpoint/host", "WireGuard peer endpoint host is required.")
                    try require((1 ... 65535).contains(endpoint.port), path: "\(peerPath)/endpoint/port", "WireGuard peer endpoint port must be between 1 and 65535.")
                }
                if let keepAlive = peer.keepAliveSeconds {
                    try require((0 ... 65535).contains(keepAlive), path: "\(peerPath)/keepAliveSeconds", "WireGuard keepalive must be between 0 and 65535 seconds.")
                }
            }
            if let reserved = options.reserved {
                try require(reserved.count == 3, path: "\(path)/options/reserved", "WireGuard reserved must contain exactly 3 bytes.")
            }
            if let mtu = options.mtu {
                try require((576 ... 1500).contains(mtu), path: "\(path)/options/mtu", "WireGuard MTU must be between 576 and 1500 on iOS.")
            }
        }

        try validateTransport(profile.transport, profilePath: path)
        try validateProfileAdvanced(profile.xrayAdvanced, profile: profile, path: path)
    }

    func validateCertificatePins(_ pins: String?, path: String) throws {
        guard let pins, !pins.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        for pin in pins.split(separator: ",") {
            let normalized = pin.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: ":", with: "")
            try require(
                normalized.count == 64 && normalized.allSatisfy(\.isHexDigit),
                path: path,
                "Every certificate pin must be a 32-byte SHA-256 value in hexadecimal.",
            )
        }
    }

    func validateTLSOptions(_ tls: TLSOptions, path: String) throws {
        try require(
            tls.curvePreferences.allSatisfy { Self.tlsCurves.contains($0.lowercased()) },
            path: "\(path)/curvePreferences",
            "TLS curve is not supported by Xray-core \(Self.coreVersion).",
        )
        if let min = nonempty(tls.minVersion) {
            try require(Self.tlsVersions[min] != nil, path: "\(path)/minVersion", "Unsupported minimum TLS version.")
        }
        if let max = nonempty(tls.maxVersion) {
            try require(Self.tlsVersions[max] != nil, path: "\(path)/maxVersion", "Unsupported maximum TLS version.")
        }
        if let min = nonempty(tls.minVersion), let max = nonempty(tls.maxVersion),
           let minRank = Self.tlsVersions[min], let maxRank = Self.tlsVersions[max]
        {
            try require(minRank <= maxRank, path: "\(path)/minVersion", "Minimum TLS version cannot exceed the maximum.")
        }
        if let suites = nonempty(tls.cipherSuites) {
            let values = suites.split(separator: ":").map(String.init)
            try require(values.allSatisfy(Self.tlsCipherSuites.contains), path: "\(path)/cipherSuites", "TLS cipher suite is not supported by the pinned Go TLS runtime.")
        }
        if let ech = nonempty(tls.echConfigList) {
            try require(
                !ech.contains("://"),
                path: "\(path)/echConfigList",
                "Resolver-form ECH is not supported; use an inline base64 ECHConfigList.",
            )
            let normalized = ech.replacingOccurrences(of: "\r", with: "").replacingOccurrences(of: "\n", with: "")
            try require(
                Data(base64Encoded: normalized)?.isEmpty == false,
                path: "\(path)/echConfigList",
                "ECHConfigList must be valid standard base64.",
            )
        }
    }

    func validateVLESSEncryption(_ encryption: String?, path: String) throws {
        guard let encryption else { return }
        if encryption.hasPrefix("##HOP_SECRET:") {
            return
        }
        let parts = encryption.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        try require(
            parts.count >= 4 && parts[0].lowercased() == "mlkem768x25519plus",
            path: path,
            "Unsupported VLESS Encryption/Auth value.",
        )
        try require(["native", "xorpub", "random"].contains(parts[1].lowercased()), path: path, "Unsupported VLESS Encryption/Auth mode.")
        try require(["0rtt", "1rtt"].contains(parts[2].lowercased()), path: path, "Unsupported VLESS Encryption/Auth handshake mode.")
        var authenticationKeys = 0
        var padding = 0
        var paddingIsValid = true
        for value in parts.dropFirst(3) {
            let byteCount = rawBase64URLByteCount(value)
            if byteCount == 32 || byteCount == 1184 {
                authenticationKeys += 1
            }
            if value.count < 20 {
                padding += 1
                paddingIsValid = paddingIsValid && validVLESSPaddingDirective(value)
            }
        }
        try require(authenticationKeys > 0, path: path, "VLESS Encryption/Auth requires an X25519 or ML-KEM authentication key.")
        try require(paddingIsValid, path: path, "VLESS Encryption/Auth contains an invalid padding directive.")
        try require(authenticationKeys <= limits.maxVLESSAuthenticationKeys, path: path, "VLESS Encryption/Auth exceeds the \(limits.maxVLESSAuthenticationKeys)-key iOS limit.")
        try require(padding <= limits.maxVLESSPaddingDirectives, path: path, "VLESS Encryption/Auth exceeds the \(limits.maxVLESSPaddingDirectives)-directive iOS padding limit.")
    }

    func validateTransport(_ transport: TransportOptions, profilePath: String) throws {
        if let xhttpExtra = transport.xhttpExtra {
            if let object = xhttpExtra.objectValue,
               object.keys.contains(where: { jsonKeyEquals($0, "downloadSettings") })
            {
                try require(
                    false,
                    path: "\(profilePath)/transport/xhttpExtra/downloadSettings",
                    "XHTTP downloadSettings must use reviewed typed configuration.",
                )
            }
            try validateObject(xhttpExtra, allowed: transportAdvancedKeys(for: .xhttp), path: "\(profilePath)/transport/xhttpExtra")
            try validateForbiddenFields(xhttpExtra, path: "\(profilePath)/transport/xhttpExtra")
        }
        if let kcp = transport.kcp {
            if let mtu = kcp.mtu {
                try require((21 ... 1500).contains(mtu), path: "\(profilePath)/transport/kcp/mtu", "mKCP MTU must be between 21 and 1500.")
            }
            if let tti = kcp.tti {
                try require((10 ... 1000).contains(tti), path: "\(profilePath)/transport/kcp/tti", "mKCP TTI must be between 10 and 1000 ms.")
            }
            let mtu = kcp.mtu ?? 1350
            let window = kcp.maxSendingWindow ?? limits.maxKCPWriteBufferBytes
            try require(window >= mtu && window <= limits.maxKCPWriteBufferBytes, path: "\(profilePath)/transport/kcp/maxSendingWindow", "mKCP send window must be at least its MTU and no larger than the 1 MiB iOS buffer limit.")
            let cwndMultiplier = kcp.cwndMultiplier ?? 1
            try require((1 ... limits.maxKCPCongestionWindowMultiplier).contains(cwndMultiplier), path: "\(profilePath)/transport/kcp/cwndMultiplier", "mKCP congestion-window multiplier must be between 1 and \(limits.maxKCPCongestionWindowMultiplier) on iOS.")
            let tti = kcp.tti ?? 50
            let intervalsPerSecond = max(1, 1000 / tti)
            let bytesPerMiB = 1024 * 1024
            let maxUplinkCapacity = limits.maxKCPWriteBufferBytes * intervalsPerSecond / bytesPerMiB
            let maxDownlinkCapacity = limits.maxKCPReadBufferBytes * intervalsPerSecond / bytesPerMiB
            let uplinkCapacity = kcp.uplinkCapacity ?? 5
            let downlinkCapacity = kcp.downlinkCapacity ?? 20
            try require((0 ... maxUplinkCapacity).contains(uplinkCapacity), path: "\(profilePath)/transport/kcp/uplinkCapacity", "mKCP uplink in-flight data exceeds the 1 MiB iOS write-buffer limit.")
            try require((0 ... maxDownlinkCapacity).contains(downlinkCapacity), path: "\(profilePath)/transport/kcp/downlinkCapacity", "mKCP downlink in-flight data exceeds the 1 MiB iOS read-buffer limit.")
        }
        if let mux = transport.mux {
            try require(mux.concurrency <= limits.maxMuxConcurrency, path: "\(profilePath)/transport/mux/concurrency", "Mux concurrency exceeds the iOS limit of \(limits.maxMuxConcurrency).")
            try require(mux.xudpConcurrency <= limits.maxXUDPConcurrency, path: "\(profilePath)/transport/mux/xudpConcurrency", "XUDP concurrency exceeds the iOS limit of \(limits.maxXUDPConcurrency).")
        }
        if let finalMask = transport.finalMask {
            try validateFinalMask(finalMask, path: "\(profilePath)/transport/finalMask")
            try validateObject(finalMask, allowed: Self.finalMaskAdvancedKeys, path: "\(profilePath)/transport/finalMask")
            try validateForbiddenFields(finalMask, path: "\(profilePath)/transport/finalMask")
        }
        if let socketOptions = transport.socketOptions {
            try require(socketOptions.objectValue != nil, path: "\(profilePath)/transport/socketOptions", "Socket options must be a JSON object.")
            try validateObject(socketOptions, allowed: Self.socketAdvancedKeys, path: "\(profilePath)/transport/socketOptions")
            try validateForbiddenFields(socketOptions, path: "\(profilePath)/transport/socketOptions")
        }
    }

    func validateProfileAdvanced(_ advanced: XrayAdvancedDocument?, profile: ProxyProfile, path: String) throws {
        guard let advanced, !advanced.isEmpty else { return }
        try require(advanced.schemaVersion == Self.coreVersion, path: "\(path)/xrayAdvanced/schemaVersion", "Advanced JSON targets \(advanced.schemaVersion), but this build runs \(Self.coreVersion).")
        try require(advanced.encodedByteCount <= limits.maxProfileAdvancedBytes, path: "\(path)/xrayAdvanced", "Profile advanced JSON exceeds \(limits.maxProfileAdvancedBytes) bytes.")
        try validateKeys(advanced.values, allowed: Self.profileAdvancedKeys, path: "\(path)/xrayAdvanced")
        try validateForbiddenFields(.object(advanced.values), path: "\(path)/xrayAdvanced")

        if let settings = advanced.values["settings"] {
            let typedSettingKeys = typedProtocolSettingKeys(for: profile.proto)
            if let object = settings.objectValue,
               let collision = object.keys.sorted().first(where: typedSettingKeys.contains)
            {
                try require(false, path: "\(path)/xrayAdvanced/settings/\(collision)", "Advanced JSON collides with a typed or iOS-enforced field.")
            }
            try validateObject(settings, allowed: protocolAdvancedKeys(for: profile.proto), path: "\(path)/xrayAdvanced/settings")
        }
        if let mux = advanced.values["mux"] {
            try validateObject(mux, allowed: Self.muxAdvancedKeys, path: "\(path)/xrayAdvanced/mux")
        }
        if let proxy = advanced.values["proxySettings"] {
            try validateObject(proxy, allowed: Self.proxyAdvancedKeys, path: "\(path)/xrayAdvanced/proxySettings")
        }
        if let targetStrategy = advanced.values["targetStrategy"] {
            try require(targetStrategy.stringValue != nil, path: "\(path)/xrayAdvanced/targetStrategy", "targetStrategy must be a string.")
        }
        if let sendThrough = advanced.values["sendThrough"] {
            try require(sendThrough.stringValue != nil, path: "\(path)/xrayAdvanced/sendThrough", "sendThrough must be a string.")
        }

        if let stream = advanced.values["streamSettings"]?.objectValue {
            try validateKeys(stream, allowed: Self.streamAdvancedKeys, path: "\(path)/xrayAdvanced/streamSettings")
            try require(stream["network"] == nil && stream["security"] == nil, path: "\(path)/xrayAdvanced/streamSettings", "Transport and security selection belong to typed profile fields.")
            let selectedSetting = transportSettingsKey(for: profile.transport.type, protocol: profile.proto)
            for key in Self.streamAdvancedKeys where key.hasSuffix("Settings") && key != "tlsSettings" && key != "realitySettings" {
                if stream[key] != nil, key != selectedSetting {
                    try require(false, path: "\(path)/xrayAdvanced/streamSettings/\(key)", "Advanced JSON cannot configure an unselected transport.")
                }
            }
            if let tls = stream["tlsSettings"] {
                try validateObject(tls, allowed: Self.tlsAdvancedKeys, path: "\(path)/xrayAdvanced/streamSettings/tlsSettings")
            }
            if let reality = stream["realitySettings"] {
                try validateObject(reality, allowed: Self.realityAdvancedKeys, path: "\(path)/xrayAdvanced/streamSettings/realitySettings")
            }
            if let finalMask = stream["finalmask"] {
                try validateObject(finalMask, allowed: Self.finalMaskAdvancedKeys, path: "\(path)/xrayAdvanced/streamSettings/finalmask")
            }
            if let sockopt = stream["sockopt"] {
                try validateObject(sockopt, allowed: Self.socketAdvancedKeys, path: "\(path)/xrayAdvanced/streamSettings/sockopt")
            }
            if let selected = stream[selectedSetting] {
                try validateObject(selected, allowed: transportAdvancedKeys(for: profile.transport.type), path: "\(path)/xrayAdvanced/streamSettings/\(selectedSetting)")
                if profile.transport.type == .xhttp,
                   let extra = selected.objectValue?["extra"]
                {
                    try validateObject(extra, allowed: transportAdvancedKeys(for: .xhttp), path: "\(path)/xrayAdvanced/streamSettings/\(selectedSetting)/extra")
                }
            }
        } else if advanced.values["streamSettings"] != nil {
            try require(false, path: "\(path)/xrayAdvanced/streamSettings", "streamSettings must be a JSON object.")
        }
    }

    func validateGlobalAdvanced(_ advanced: XrayAdvancedDocument?) throws {
        guard let advanced, !advanced.isEmpty else { return }
        try require(advanced.schemaVersion == Self.coreVersion, path: "/settings/xrayAdvanced/schemaVersion", "Advanced JSON targets \(advanced.schemaVersion), but this build runs \(Self.coreVersion).")
        try require(advanced.encodedByteCount <= limits.maxGlobalAdvancedBytes, path: "/settings/xrayAdvanced", "Global advanced JSON exceeds \(limits.maxGlobalAdvancedBytes) bytes.")
        try validateKeys(advanced.values, allowed: Self.globalAdvancedKeys, path: "/settings/xrayAdvanced")
        try validateForbiddenFields(.object(advanced.values), path: "/settings/xrayAdvanced")
        if advanced.values["geodata"] != nil {
            try require(false, path: "/settings/xrayAdvanced/geodata", "Custom geodata requires a verified bundled-asset record and cannot be supplied as raw JSON.")
        }
        if let observatory = advanced.values["observatory"]?.objectValue,
           let probeURL = observatory["probeURL"]?.stringValue
        {
            try require(ImportPolicy.isAllowedProbeURL(probeURL), path: "/settings/xrayAdvanced/observatory/probeURL", "Observatory probe URL is not an allowed public HTTPS endpoint.")
        }
        try validateGlobalAdvancedSections(advanced.values)
    }

    func validateKeys(_ object: JSONObject, allowed: Set<String>, path: String) throws {
        if let unknown = object.keys.sorted().first(where: { !allowed.contains($0) }) {
            try require(false, path: "\(path)/\(unknown)", "Unknown or server-only Xray field.")
        }
    }

    func validateCaseInsensitiveKeys(_ object: JSONObject, allowed: Set<String>, path: String) throws {
        var seen: Set<String> = []
        for key in object.keys.sorted() {
            guard let canonical = allowed.first(where: { jsonKeyEquals(key, $0) }) else {
                try require(false, path: "\(path)/\(key)", "Unknown or server-only Xray field.")
                continue
            }
            try require(
                seen.insert(canonical).inserted,
                path: "\(path)/\(key)",
                "JSON object contains duplicate keys that differ only by case.",
            )
        }
    }

    func jsonKeyEquals(_ lhs: String, _ rhs: String) -> Bool {
        lhs.caseInsensitiveCompare(rhs) == .orderedSame
    }

    func validateObject(_ value: JSONValue, allowed: Set<String>, path: String) throws {
        guard let object = value.objectValue else {
            try require(false, path: path, "Xray section must be a JSON object.")
            return
        }
        try validateKeys(object, allowed: allowed, path: path)
    }

    func protocolAdvancedKeys(for proto: ProxyProtocol) -> Set<String> {
        switch proto {
        case .vless:
            ["email", "seed", "testpre", "testseed"]
        case .trojan, .shadowsocks:
            ["email"]
        case .vmess:
            ["email", "experiments"]
        case .http:
            ["email", "headers"]
        case .socks:
            ["email"]
        case .hysteria2, .wireGuard, .tuic, .anyTLS:
            []
        }
    }

    func typedProtocolSettingKeys(for proto: ProxyProtocol) -> Set<String> {
        switch proto {
        case .vless:
            ["address", "port", "id", "flow", "encryption"]
        case .trojan:
            ["address", "port", "password"]
        case .hysteria2:
            ["address", "port", "version"]
        case .shadowsocks:
            ["address", "port", "method", "password"]
        case .vmess:
            ["address", "port", "id", "security"]
        case .http, .socks:
            ["address", "port", "user", "pass"]
        case .wireGuard:
            ["noKernelTun", "secretKey", "address", "peers", "mtu", "reserved", "domainStrategy"]
        case .tuic, .anyTLS:
            []
        }
    }

    func transportAdvancedKeys(for type: TransportType) -> Set<String> {
        switch type {
        case .tcp:
            ["header"]
        case .websocket:
            ["host", "path", "headers", "heartbeatPeriod"]
        case .grpc:
            ["authority", "serviceName", "multiMode", "idle_timeout", "health_check_timeout", "permit_without_stream", "initial_windows_size", "user_agent"]
        case .httpUpgrade:
            ["host", "path", "headers"]
        case .xhttp:
            [
                "host", "path", "mode", "headers", "xPaddingBytes", "xPaddingObfsMode", "xPaddingKey",
                "xPaddingHeader", "xPaddingPlacement", "xPaddingMethod", "uplinkHTTPMethod", "sessionIDPlacement",
                "sessionIDKey", "sessionIDTable", "sessionIDLength", "seqPlacement", "seqKey", "uplinkDataPlacement",
                "uplinkDataKey", "uplinkChunkSize", "noGRPCHeader", "noSSEHeader", "scMaxEachPostBytes",
                "scMinPostsIntervalMs", "scMaxBufferedPosts", "scStreamUpServerSecs", "serverMaxHeaderBytes",
                "xmux", "extra",
            ]
        case .mKCP:
            ["mtu", "tti", "uplinkCapacity", "downlinkCapacity", "cwndMultiplier", "maxSendingWindow"]
        case .hysteria:
            ["version", "udpIdleTimeout"]
        case .quic:
            []
        }
    }

    func validateGlobalAdvancedSections(_ values: JSONObject) throws {
        let sections: [(String, Set<String>)] = [
            ("dns", ["servers", "hosts", "clientIp", "tag", "queryStrategy", "disableCache", "serveStale", "serveExpiredTTL", "disableFallback", "disableFallbackIfMatch", "enableParallelQuery", "useSystemHosts"]),
            ("routing", ["domainStrategy", "rules", "balancers"]),
            ("policy", ["levels", "system"]),
            ("observatory", ["subjectSelector", "probeURL", "probeInterval", "enableConcurrency"]),
            ("version", ["min", "max"]),
        ]
        for (key, allowed) in sections {
            if let value = values[key] {
                try validateObject(value, allowed: allowed, path: "/settings/xrayAdvanced/\(key)")
            }
        }
        if let policy = values["policy"]?.objectValue,
           let levelsValue = policy["levels"]
        {
            guard let levels = levelsValue.objectValue else {
                try require(false, path: "/settings/xrayAdvanced/policy/levels", "Policy levels must be a JSON object.")
                return
            }
            for rawLevel in levels.keys.sorted() {
                let path = "/settings/xrayAdvanced/policy/levels/\(rawLevel)"
                guard let level = UInt32(rawLevel), rawLevel == String(level) else {
                    try require(false, path: path, "Policy level keys must be canonical decimal UInt32 values.")
                    continue
                }
                try require(level != 0, path: path, "Advanced policy cannot replace the iOS-enforced level-0 policy.")
                if let value = levels[rawLevel] {
                    try validateObject(value, allowed: Self.policyLevelAdvancedKeys, path: path)
                }
            }
        }
        if let fakeDNS = values["fakeDns"] {
            let pools = fakeDNS.arrayValue ?? [fakeDNS]
            try require(pools.count <= 2, path: "/settings/xrayAdvanced/fakeDns", "At most two FakeDNS pools are allowed on iOS.")
            var totalEntries = 0
            for (index, pool) in pools.enumerated() {
                let path = "/settings/xrayAdvanced/fakeDns/\(index)"
                guard let object = pool.objectValue else {
                    try require(false, path: path, "Xray section must be a JSON object.")
                    continue
                }
                try validateCaseInsensitiveKeys(object, allowed: ["ipPool", "poolSize"], path: path)
                let rawEntries = try uniqueCaseInsensitiveValue("poolSize", in: object, path: path)
                if rawEntries != nil {
                    try require(
                        rawEntries?.integerValue != nil,
                        path: "\(path)/poolSize",
                        "FakeDNS pool size must be an in-range integer.",
                    )
                }
                let entries = rawEntries?.integerValue ?? 0
                try require(entries >= 0, path: "\(path)/poolSize", "FakeDNS pool size cannot be negative.")
                try require(entries <= limits.maxFakeDNSPoolEntries, path: "\(path)/poolSize", "FakeDNS pool size exceeds the \(limits.maxFakeDNSPoolEntries)-entry iOS limit.")
                totalEntries += entries
            }
            try require(totalEntries <= limits.maxFakeDNSPoolEntries, path: "/settings/xrayAdvanced/fakeDns", "FakeDNS exceeds the \(limits.maxFakeDNSPoolEntries)-entry iOS limit.")
        }
    }

    func validateForbiddenFields(_ value: JSONValue, path: String) throws {
        switch value {
        case let .object(object):
            for key in object.keys.sorted() {
                let childPath = "\(path)/\(key)"
                try require(
                    !Self.forbiddenAdvancedKeys.contains(where: { jsonKeyEquals(key, $0) }) || permittedClientSecretPath(childPath),
                    path: childPath,
                    "Security-sensitive, secret, or server-only fields cannot be supplied in advanced JSON.",
                )
                if let child = object[key] {
                    try validateForbiddenFields(child, path: childPath)
                }
            }
        case let .array(array):
            for (index, child) in array.enumerated() {
                try validateForbiddenFields(child, path: "\(path)/\(index)")
            }
        case .string, .number, .bool, .null:
            break
        }
    }

    func permittedClientSecretPath(_ path: String) -> Bool {
        // Sidecar rewriting recognizes ASCII field names. Keep permission
        // equally narrow: Unicode-folded lookalikes are forbidden above but
        // never admitted as persistable secret paths.
        let components = path.split(separator: "/").map { $0.lowercased() }
        if Array(components.suffix(3)) == ["xrayadvanced", "settings", "seed"] {
            return true
        }
        guard components.contains("finalmask"), components.count >= 4 else {
            return false
        }
        let suffix = Array(components.suffix(4))
        guard ["tcp", "udp"].contains(suffix[0]), Int(suffix[1]) != nil,
              suffix[2] == "settings"
        else { return false }
        if suffix[3] == "password" {
            return true
        }
        return suffix[0] == "udp" && suffix[3] == "url"
    }

    func streamDictionary(for profile: ProxyProfile) throws -> JSONObject {
        var stream: JSONObject = [
            "network": .string(networkName(for: profile.transport.type)),
        ]
        try addSecurity(profile.security, to: &stream)

        let key = transportSettingsKey(for: profile.transport.type, protocol: profile.proto)
        switch profile.transport.type {
        case .tcp:
            stream[key] = .object([:])
        case .websocket:
            stream[key] = .object(compactObject([
                "path": profile.transport.path.map(JSONValue.string),
                "host": profile.transport.host.map(JSONValue.string),
            ]))
        case .grpc:
            var grpc = compactObject([
                "serviceName": profile.transport.serviceName.map(JSONValue.string),
                "authority": profile.transport.host.map(JSONValue.string),
            ])
            grpc["initial_windows_size"] = .number(Double(limits.maxGRPCInitialWindowBytes))
            stream[key] = .object(grpc)
        case .httpUpgrade:
            stream[key] = .object(compactObject([
                "path": profile.transport.path.map(JSONValue.string),
                "host": profile.transport.host.map(JSONValue.string),
            ]))
        case .xhttp:
            stream[key] = try .object(xhttpDictionary(profile.transport))
        case .mKCP:
            stream[key] = .object(kcpDictionary(profile.transport.kcp))
        case .hysteria:
            try require(false, path: "/profiles/\(profile.id)/transport", "Typed Hysteria transport is reserved for Hysteria2 profiles.")
        case .quic:
            preconditionFailure("QUIC was admitted after validation")
        }

        if let finalMask = profile.transport.finalMask {
            stream["finalmask"] = try finalMaskWithSafeDefaults(finalMask)
        }
        if let socketOptions = profile.transport.socketOptions {
            stream["sockopt"] = socketOptions
        }
        return stream
    }

    func hysteriaStreamDictionary(profile: ProxyProfile, options: Hysteria2Options) throws -> JSONObject {
        var stream: JSONObject = [
            "network": .string("hysteria"),
            "hysteriaSettings": .object(compactObject([
                "version": .number(2),
                "auth": .string(options.password),
                "udpIdleTimeout": options.udpIdleTimeoutSeconds.map { .number(Double($0)) },
            ])),
        ]
        try addSecurity(profile.security, to: &stream)

        var finalMask = profile.transport.finalMask?.objectValue ?? [:]
        var quic = finalMask["quicParams"]?.objectValue ?? [:]
        if let up = options.up {
            quic["brutalUp"] = .string(up)
            quic["congestion"] = .string("brutal")
        }
        if let down = options.down {
            quic["brutalDown"] = .string(down)
            quic["congestion"] = .string("brutal")
        }
        if let ports = options.ports {
            var udpHop: JSONObject = ["ports": .string(ports)]
            if let interval = options.hopIntervalSeconds {
                udpHop["interval"] = .number(Double(interval))
            }
            quic["udpHop"] = .object(udpHop)
        }
        fillSafeQUICDefaults(into: &quic)
        finalMask["quicParams"] = .object(quic)

        if let obfs = options.obfs, !obfs.isEmpty {
            try require(obfs.lowercased() == "salamander", path: "/profiles/\(profile.id)/options/obfs", "Xray Hysteria2 supports Salamander obfuscation only.")
            guard let password = options.obfsPassword, !password.isEmpty else {
                try require(false, path: "/profiles/\(profile.id)/options/obfsPassword", "Salamander obfuscation requires a password.")
                return stream
            }
            finalMask["udp"] = .array([
                .object([
                    "type": .string("salamander"),
                    "settings": .object(["password": .string(password)]),
                ]),
            ])
        }
        let finalMaskValue = JSONValue.object(finalMask)
        try validateFinalMask(finalMaskValue, path: "/profiles/\(profile.id)/transport/finalMask")
        stream["finalmask"] = finalMaskValue
        if let socketOptions = profile.transport.socketOptions {
            stream["sockopt"] = socketOptions
        }
        return stream
    }

    func addSecurity(_ security: ProxySecurity, to stream: inout JSONObject) throws {
        switch security.layer {
        case .none:
            stream["security"] = .string("none")
        case .tls:
            guard let tls = security.tls else {
                try require(false, path: "/security/tls", "TLS is selected but its settings are missing.")
                return
            }
            stream["security"] = .string("tls")
            stream["tlsSettings"] = .object(tlsDictionary(tls))
        case .reality:
            guard let reality = security.reality else {
                try require(false, path: "/security/reality", "REALITY is selected but its settings are missing.")
                return
            }
            stream["security"] = .string("reality")
            stream["realitySettings"] = .object(realityDictionary(reality))
        }
    }

    func tlsDictionary(_ tls: TLSOptions) -> JSONObject {
        compactObject([
            "serverName": nonempty(tls.serverName).map(JSONValue.string),
            "alpn": tls.alpn.isEmpty ? nil : .array(tls.alpn.map(JSONValue.string)),
            "fingerprint": nonempty(tls.utlsFingerprint).map(JSONValue.string),
            "pinnedPeerCertSha256": nonempty(tls.pinnedPeerCertSHA256).map(JSONValue.string),
            "verifyPeerCertByName": nonempty(tls.verifyPeerCertByName).map(JSONValue.string),
            "echConfigList": nonempty(tls.echConfigList).map(JSONValue.string),
            "curvePreferences": tls.curvePreferences.isEmpty ? nil : .array(tls.curvePreferences.map(JSONValue.string)),
            "minVersion": nonempty(tls.minVersion).map(JSONValue.string),
            "maxVersion": nonempty(tls.maxVersion).map(JSONValue.string),
            "cipherSuites": nonempty(tls.cipherSuites).map(JSONValue.string),
            "enableSessionResumption": tls.enableSessionResumption ? .bool(true) : nil,
        ])
    }

    func realityDictionary(_ reality: RealityOptions) -> JSONObject {
        compactObject([
            "fingerprint": .string(reality.utlsFingerprint),
            "serverName": nonempty(reality.serverName).map(JSONValue.string),
            "password": .string(reality.publicKey),
            "shortId": nonempty(reality.shortID).map(JSONValue.string),
            "spiderX": nonempty(reality.spiderX).map(JSONValue.string),
            "mldsa65Verify": nonempty(reality.mldsa65Verify).map(JSONValue.string),
        ])
    }

    func networkName(for type: TransportType) -> String {
        switch type {
        case .tcp:
            "raw"
        case .websocket:
            "ws"
        case .grpc:
            "grpc"
        case .httpUpgrade:
            "httpupgrade"
        case .xhttp:
            "xhttp"
        case .mKCP:
            "mkcp"
        case .hysteria:
            "hysteria"
        case .quic:
            "quic"
        }
    }

    func transportSettingsKey(for type: TransportType, protocol proto: ProxyProtocol) -> String {
        if proto == .hysteria2 {
            return "hysteriaSettings"
        }
        return switch type {
        case .tcp:
            "rawSettings"
        case .websocket:
            "wsSettings"
        case .grpc:
            "grpcSettings"
        case .httpUpgrade:
            "httpupgradeSettings"
        case .xhttp:
            "xhttpSettings"
        case .mKCP:
            "kcpSettings"
        case .hysteria:
            "hysteriaSettings"
        case .quic:
            "quicSettings"
        }
    }

    func xhttpDictionary(_ transport: TransportOptions) throws -> JSONObject {
        var extra = transport.xhttpExtra?.objectValue ?? [:]
        try require(transport.xhttpExtra == nil || transport.xhttpExtra?.objectValue != nil, path: "/transport/xhttpExtra", "XHTTP extra must be a JSON object.")
        var xmux = extra["xmux"]?.objectValue ?? [:]
        fillIfMissing("maxConnections", value: .number(Double(limits.maxXHTTPConnections)), into: &xmux)
        extra["xmux"] = .object(xmux)
        fillIfMissing("scMaxBufferedPosts", value: .number(Double(limits.maxXHTTPBufferedPosts)), into: &extra)
        fillIfMissing("scMaxEachPostBytes", value: .number(Double(limits.maxXHTTPPostBytes)), into: &extra)
        return compactObject([
            "path": nonempty(transport.path).map(JSONValue.string),
            "host": nonempty(transport.host).map(JSONValue.string),
            "mode": nonempty(transport.xhttpMode).map(JSONValue.string),
            "extra": .object(extra),
        ])
    }

    func kcpDictionary(_ options: XrayKCPOptions?) -> JSONObject {
        let mtu = options?.mtu ?? 1350
        return compactObject([
            "mtu": .number(Double(mtu)),
            "tti": options?.tti.map { .number(Double($0)) },
            "uplinkCapacity": options?.uplinkCapacity.map { .number(Double($0)) },
            "downlinkCapacity": options?.downlinkCapacity.map { .number(Double($0)) },
            "cwndMultiplier": options?.cwndMultiplier.map { .number(Double($0)) },
            "maxSendingWindow": .number(Double(options?.maxSendingWindow ?? limits.maxKCPWriteBufferBytes)),
        ])
    }

    func muxDictionary(_ mux: XrayMuxOptions) -> JSONObject {
        compactObject([
            "enabled": .bool(mux.enabled),
            "concurrency": .number(Double(mux.concurrency)),
            "xudpConcurrency": .number(Double(mux.xudpConcurrency)),
            "xudpProxyUDP443": nonempty(mux.xudpProxyUDP443).map(JSONValue.string),
        ])
    }

    func wireGuardSettings(profile: ProxyProfile, options: WireGuardOptions) -> JSONObject {
        let peers = options.effectivePeers.map { peer -> JSONValue in
            let endpoint = peer.endpoint ?? profile.endpoint
            var value: JSONObject = [
                "publicKey": .string(peer.publicKey),
                "endpoint": .string(endpointString(host: endpoint.host, port: endpoint.port)),
                "allowedIPs": .array((peer.allowedIPs ?? ["0.0.0.0/0", "::/0"]).map(JSONValue.string)),
            ]
            insert(peer.preSharedKey, key: "preSharedKey", into: &value)
            if let keepAlive = peer.keepAliveSeconds {
                value["keepAlive"] = .number(Double(keepAlive))
            }
            return .object(value)
        }

        var result: JSONObject = [
            "noKernelTun": .bool(true),
            "secretKey": .string(options.privateKey),
            "address": .array(options.localAddress.map(JSONValue.string)),
            "peers": .array(peers),
            "mtu": .number(Double(options.mtu ?? 1280)),
        ]
        if let reserved = options.reserved {
            result["reserved"] = .array(reserved.map { .number(Double($0)) })
        }
        insert(options.domainStrategy, key: "domainStrategy", into: &result)
        return result
    }

    func endpointString(host: String, port: Int) -> String {
        host.contains(":") && !host.hasPrefix("[") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    func applyProfileAdvanced(_ advanced: XrayAdvancedDocument?, profile: ProxyProfile, to outbound: inout JSONObject) throws {
        if let advanced, !advanced.isEmpty {
            var copy = advanced.values
            if var stream = copy["streamSettings"]?.objectValue,
               let socketOptions = stream.removeValue(forKey: "socketOptions")
            {
                stream["sockopt"] = socketOptions
                copy["streamSettings"] = .object(stream)
            }
            try mergeAdvanced(copy, into: &outbound, path: "/profiles/\(profile.id.uuidString.lowercased())")
        }
        try finalizeMergedStreamSettings(in: &outbound, profile: profile)
    }

    func mergeAdvanced(_ advanced: JSONObject, into base: inout JSONObject, path: String) throws {
        for key in advanced.keys.sorted() {
            guard let newValue = advanced[key] else { continue }
            guard let existing = base[key] else {
                base[key] = newValue
                continue
            }
            if case var .object(existingObject) = existing,
               case let .object(newObject) = newValue
            {
                try mergeAdvanced(newObject, into: &existingObject, path: "\(path)/\(key)")
                base[key] = .object(existingObject)
            } else {
                try require(false, path: "\(path)/\(key)", "Advanced JSON collides with a typed or iOS-enforced field.")
            }
        }
    }

    func finalizeMergedStreamSettings(in outbound: inout JSONObject, profile: ProxyProfile) throws {
        guard var stream = outbound["streamSettings"]?.objectValue else { return }
        let path = "/profiles/\(profile.id.uuidString.lowercased())/streamSettings"
        let finalMaskKeys = stream.keys.filter { jsonKeyEquals($0, "finalmask") }
        try require(finalMaskKeys.count <= 1, path: "\(path)/finalmask", "JSON object contains duplicate protected keys that differ only by case.")
        if let key = finalMaskKeys.first,
           let finalMask = stream.removeValue(forKey: key)
        {
            stream["finalmask"] = try finalMaskWithSafeDefaults(finalMask)
        }
        let kcpKeys = stream.keys.filter { jsonKeyEquals($0, "kcpSettings") }
        try require(kcpKeys.count <= 1, path: "\(path)/kcpSettings", "JSON object contains duplicate protected keys that differ only by case.")
        if let key = kcpKeys.first,
           let kcp = stream.removeValue(forKey: key)
        {
            guard let settings = kcp.objectValue else {
                try require(false, path: "\(path)/kcpSettings", "mKCP settings must be a JSON object.")
                return
            }
            try validateMergedKCPSettings(settings, path: "\(path)/kcpSettings")
            stream["kcpSettings"] = kcp
        }
        outbound["streamSettings"] = .object(stream)
    }

    func validateMergedKCPSettings(_ settings: JSONObject, path: String) throws {
        let mtu = try integerValue("mtu", in: settings, default: 1350, path: path)
        let tti = try integerValue("tti", in: settings, default: 50, path: path)
        let uplinkCapacity = try integerValue("uplinkCapacity", in: settings, default: 5, path: path)
        let downlinkCapacity = try integerValue("downlinkCapacity", in: settings, default: 20, path: path)
        let cwndMultiplier = try integerValue("cwndMultiplier", in: settings, default: 1, path: path)
        let maxSendingWindow = try integerValue("maxSendingWindow", in: settings, default: limits.maxKCPWriteBufferBytes, path: path)

        try require((21 ... 1500).contains(mtu), path: "\(path)/mtu", "mKCP MTU must be between 21 and 1500.")
        try require((10 ... 1000).contains(tti), path: "\(path)/tti", "mKCP TTI must be between 10 and 1000 ms.")
        try require(maxSendingWindow >= mtu && maxSendingWindow <= limits.maxKCPWriteBufferBytes, path: "\(path)/maxSendingWindow", "mKCP send window must be at least its MTU and no larger than the 1 MiB iOS buffer limit.")
        try require((1 ... limits.maxKCPCongestionWindowMultiplier).contains(cwndMultiplier), path: "\(path)/cwndMultiplier", "mKCP congestion-window multiplier must be between 1 and \(limits.maxKCPCongestionWindowMultiplier) on iOS.")

        let intervalsPerSecond = max(1, 1000 / tti)
        let bytesPerMiB = 1024 * 1024
        let maxUplinkCapacity = limits.maxKCPWriteBufferBytes * intervalsPerSecond / bytesPerMiB
        let maxDownlinkCapacity = limits.maxKCPReadBufferBytes * intervalsPerSecond / bytesPerMiB
        try require((0 ... maxUplinkCapacity).contains(uplinkCapacity), path: "\(path)/uplinkCapacity", "mKCP uplink in-flight data exceeds the 1 MiB iOS write-buffer limit.")
        try require((0 ... maxDownlinkCapacity).contains(downlinkCapacity), path: "\(path)/downlinkCapacity", "mKCP downlink in-flight data exceeds the 1 MiB iOS read-buffer limit.")
    }

    func integerValue(_ key: String, in object: JSONObject, default defaultValue: Int, path: String) throws -> Int {
        guard let raw = object[key] else { return defaultValue }
        guard let value = raw.integerValue else {
            try require(false, path: "\(path)/\(key)", "mKCP setting must be an in-range integer.")
            return defaultValue
        }
        return value
    }

    func routingDictionary(
        mode: RoutingMode,
        rules: [RoutingRule],
        selected: XrayResolvedTarget,
        ruleDestinations: [XrayResolvedTarget],
        resolver: XrayReachabilityResolver,
        sniff: Bool,
    ) throws -> JSONObject {
        var resultRules: [JSONValue] = [
            .object([
                "type": .string("field"),
                "inboundTag": .array([.string("tun-in")]),
                "port": .number(53),
                "outboundTag": .string("dns-out"),
            ]),
        ]
        if mode == .rule {
            for (index, rule) in rules.enumerated() {
                try resultRules.append(.object(routingRuleDictionary(rule, index: index, destination: ruleDestinations[index], sniff: sniff)))
            }
        }

        var catchAll: JSONObject = [
            "type": .string("field"),
            "network": .string("tcp,udp"),
        ]
        setRouteTarget(mode == .direct ? .outbound("direct") : selected, in: &catchAll)
        resultRules.append(.object(catchAll))

        let needsDestinationIP = mode == .rule && rules.contains { [.geoIP, .ipIsPrivate].contains($0.kind) }
        var routing: JSONObject = [
            "domainStrategy": .string(needsDestinationIP ? "IPIfNonMatch" : "AsIs"),
            "rules": .array(resultRules),
        ]
        let urlGroups = resolver.urlGroups.values.sorted { $0.group.id.uuidString < $1.group.id.uuidString }
        if !urlGroups.isEmpty {
            routing["balancers"] = .array(urlGroups.map { resolved in
                .object([
                    "tag": .string(Self.tag(for: resolved.group)),
                    "selector": .array(resolved.memberTags.map(JSONValue.string)),
                    "strategy": .object(["type": .string("leastPing")]),
                ])
            })
        }
        return routing
    }

    func routingRuleDictionary(
        _ rule: RoutingRule,
        index: Int,
        destination: XrayResolvedTarget,
        sniff: Bool,
    ) throws -> JSONObject {
        let path = "/routing/rules/\(index)"
        try require(!Self.appleOnlyRuleKinds.contains(rule.kind), path: path, "\(rule.kind.displayName) is Apple-specific and cannot be reproduced by Xray routing.")
        if rule.kind == .protocolSniff {
            try require(sniff, path: path, "Protocol routing requires traffic sniffing.")
        }

        var result: JSONObject = ["type": .string("field")]
        setRouteTarget(destination, in: &result)
        let values = stringList(rule.value)

        switch rule.kind {
        case .final:
            result["network"] = .string("tcp,udp")
        case .domain:
            result["domain"] = .array(values.map { .string("full:\($0)") })
        case .domainSuffix:
            result["domain"] = .array(values.map { .string("domain:\($0)") })
        case .domainKeyword:
            result["domain"] = .array(values.map(JSONValue.string))
        case .domainRegex:
            try require(values.allSatisfy(ImportPolicy.isSafeRegexPattern), path: path, "Domain regex is too large or unsafe.")
            result["domain"] = .array(values.map { .string("regexp:\($0)") })
        case .ipCIDR:
            result["ip"] = .array(values.map(JSONValue.string))
        case .ipIsPrivate:
            try require(boolValue(rule.value) == true, path: path, "Xray cannot express the negated private-IP matcher.")
            result["ip"] = .array([.string("geoip:private")])
        case .sourceIPCIDR:
            result["sourceIP"] = .array(values.map(JSONValue.string))
        case .sourceIPIsPrivate:
            try require(boolValue(rule.value) == true, path: path, "Xray cannot express the negated private-source-IP matcher.")
            result["sourceIP"] = .array([.string("geoip:private")])
        case .port:
            result["port"] = .string(values.joined(separator: ","))
        case .portRange:
            result["port"] = .string(values.map(normalizedPortRange).joined(separator: ","))
        case .sourcePort:
            result["sourcePort"] = .string(values.joined(separator: ","))
        case .sourcePortRange:
            result["sourcePort"] = .string(values.map(normalizedPortRange).joined(separator: ","))
        case .network:
            try require(values.allSatisfy { ["tcp", "udp"].contains($0.lowercased()) }, path: path, "Xray TUN routing supports tcp and udp network matchers only.")
            result["network"] = .string(values.joined(separator: ","))
        case .protocolSniff:
            result["protocol"] = .array(values.map(JSONValue.string))
        case .geoSite:
            try require(values.allSatisfy(safeGeoCategory), path: path, "Unsafe GeoSite/GeoIP category; only letters, digits, hyphen, and underscore are allowed.")
            try require(values.allSatisfy { VerifiedXrayGeodata.geoSiteCategories.contains($0.lowercased()) }, path: path, "GeoSite category is not present in Hop's verified, memory-bounded local asset.")
            result["domain"] = .array(values.map { .string("geosite:\($0.lowercased())") })
        case .geoIP:
            try require(values.allSatisfy(safeGeoCategory), path: path, "Unsafe GeoSite/GeoIP category; only letters, digits, hyphen, and underscore are allowed.")
            try require(values.allSatisfy { VerifiedXrayGeodata.geoIPCategories.contains($0.lowercased()) }, path: path, "GeoIP category is not present in Hop's verified, memory-bounded local asset.")
            result["ip"] = .array(values.map { .string("geoip:\($0.lowercased())") })
        case .sourceGeoIP:
            try require(values.allSatisfy(safeGeoCategory), path: path, "Unsafe GeoSite/GeoIP category; only letters, digits, hyphen, and underscore are allowed.")
            try require(values.allSatisfy { VerifiedXrayGeodata.geoIPCategories.contains($0.lowercased()) }, path: path, "Source GeoIP category is not present in Hop's verified, memory-bounded local asset.")
            result["sourceIP"] = .array(values.map { .string("geoip:\($0.lowercased())") })
        case .networkType, .networkIsExpensive, .networkIsConstrained, .wifiSSID, .wifiBSSID:
            preconditionFailure("Apple-only rule was admitted after validation")
        }
        return result
    }

    func setRouteTarget(_ target: XrayResolvedTarget, in dictionary: inout JSONObject) {
        switch target {
        case let .outbound(tag):
            dictionary["outboundTag"] = .string(tag)
        case let .balancer(tag):
            dictionary["balancerTag"] = .string(tag)
        }
    }

    func validateURLGroups(_ groups: [XrayResolvedURLGroup]) throws {
        guard let first = groups.first else { return }
        let firstURL = effectiveProbeURL(first.group)
        let firstInterval = ImportPolicy.clampURLTestInterval(first.group.testOptions.intervalSeconds)
        for resolved in groups {
            let path = "/groups/\(resolved.group.id.uuidString.lowercased())"
            let url = effectiveProbeURL(resolved.group)
            try require(ImportPolicy.isAllowedProbeURL(url), path: "\(path)/testOptions/url", "URL-test probe must be an allowed public HTTPS URL.")
            try require(!resolved.memberTags.isEmpty, path: "\(path)/members", "URL-test group has no runnable Xray profiles.")
            try require(
                url == firstURL && ImportPolicy.clampURLTestInterval(resolved.group.testOptions.intervalSeconds) == firstInterval,
                path: path,
                "Xray has one observatory; active URL-test groups must share a probe URL and interval.",
            )
        }
    }

    func observatoryDictionary(from groups: [XrayResolvedURLGroup]) throws -> JSONObject? {
        guard let first = groups.first else { return nil }
        let tags = Array(Set(groups.flatMap(\.memberTags))).sorted()
        return [
            "subjectSelector": .array(tags.map(JSONValue.string)),
            "probeURL": .string(effectiveProbeURL(first.group)),
            "probeInterval": .string("\(ImportPolicy.clampURLTestInterval(first.group.testOptions.intervalSeconds))s"),
            "enableConcurrency": .bool(false),
        ]
    }

    func effectiveProbeURL(_ group: ProxyGroup) -> String {
        group.importedType == nil ? group.testOptions.url : ProxyGroupTestOptions.defaultURL
    }

    func validateHeavyOutboundCount(_ profiles: [ProxyProfile]) throws {
        let count = profiles.filter { profile in
            if profile.proto == .wireGuard || profile.proto == .hysteria2 {
                return true
            }
            return profile.transport.type == .xhttp && profile.security.tls?.alpn.contains(where: { $0.lowercased() == "h3" }) == true
        }.count
        try require(count <= limits.maxConcurrentHeavyOutbounds, path: "/outbounds", "Only one WireGuard, Hysteria2, or XHTTP-H3 outbound may be reachable on iOS.")
    }

    func validateRenderedLimits(_ root: JSONObject) throws {
        if let servers = root["dns"]?.objectValue?["servers"]?.arrayValue {
            try require(servers.count <= limits.maxDNSServers, path: "/dns/servers", "DNS server count exceeds the iOS limit of \(limits.maxDNSServers).")
        }
        if let subjects = root["observatory"]?.objectValue?["subjectSelector"]?.arrayValue {
            try require(subjects.count <= limits.maxObservatoryTargets, path: "/observatory/subjectSelector", "Observatory target count exceeds the iOS limit of \(limits.maxObservatoryTargets).")
        }
        if let subjects = root["burstObservatory"]?.objectValue?["subjectSelector"]?.arrayValue {
            try require(subjects.count <= limits.maxObservatoryTargets, path: "/burstObservatory/subjectSelector", "Burst-observatory target count exceeds the iOS limit of \(limits.maxObservatoryTargets).")
        }
        try validateMemorySensitiveValue(.object(root), path: "")
    }

    func enableFakeDNS(in root: inout JSONObject, sniff: Bool) throws {
        try require(sniff, path: "/fakeDns", "FakeDNS requires traffic sniffing to be enabled.")
        guard var dns = root["dns"]?.objectValue,
              var servers = dns["servers"]?.arrayValue,
              var inbounds = root["inbounds"]?.arrayValue,
              !inbounds.isEmpty,
              var inbound = inbounds[0].objectValue,
              var sniffing = inbound["sniffing"]?.objectValue,
              var overrides = sniffing["destOverride"]?.arrayValue
        else {
            try require(false, path: "/fakeDns", "FakeDNS could not attach to the typed DNS and TUN configuration.")
            return
        }
        if !servers.contains(.string("fakedns")) {
            servers.insert(.string("fakedns"), at: 0)
        }
        if !overrides.contains(.string("fakedns")) {
            overrides.append(.string("fakedns"))
        }
        dns["servers"] = .array(servers)
        sniffing["destOverride"] = .array(overrides)
        inbound["sniffing"] = .object(sniffing)
        inbounds[0] = .object(inbound)
        root["dns"] = .object(dns)
        root["inbounds"] = .array(inbounds)
    }

    func validateMemorySensitiveValue(_ value: JSONValue, path: String) throws {
        switch value {
        case let .object(object):
            var protectedKeys: Set<String> = []
            for key in object.keys.sorted() {
                guard let child = object[key] else { continue }
                let childPath = "\(path)/\(key)"
                let canonicalKey = Self.memorySensitiveKeys.first(where: { jsonKeyEquals(key, $0) })
                let isFinalMask = jsonKeyEquals(key, "finalmask")
                if let protectedKey = canonicalKey ?? (isFinalMask ? "finalmask" : nil) {
                    try require(
                        protectedKeys.insert(protectedKey).inserted,
                        path: childPath,
                        "JSON object contains duplicate protected keys that differ only by case.",
                    )
                }
                if let canonicalKey {
                    guard let bounds = numericBounds(child) else {
                        try require(false, path: childPath, "Memory-sensitive values must be numeric.")
                        continue
                    }
                    let maximum = memoryLimit(for: canonicalKey)
                    try require(bounds.lowerBound >= 0, path: childPath, "Memory-sensitive values cannot be negative.")
                    if Self.positiveMemorySensitiveKeys.contains(canonicalKey) {
                        try require(bounds.lowerBound > 0, path: childPath, "Zero would select an unsafe upstream memory default.")
                    }
                    try require(bounds.upperBound <= maximum, path: childPath, "Value \(bounds.upperBound) exceeds the iOS memory limit of \(maximum).")
                }
                if isFinalMask {
                    try validateFinalMask(child, path: childPath)
                }
                try validateMemorySensitiveValue(child, path: childPath)
            }
        case let .array(array):
            for (index, child) in array.enumerated() {
                try validateMemorySensitiveValue(child, path: "\(path)/\(index)")
            }
        case .string, .number, .bool, .null:
            break
        }
    }

    func memoryLimit(for canonicalKey: String) -> Int {
        switch canonicalKey {
        case "concurrency": limits.maxMuxConcurrency
        case "xudpConcurrency": limits.maxXUDPConcurrency
        case "maxConcurrency", "maxConnections": limits.maxXHTTPConnections
        case "scMaxBufferedPosts": limits.maxXHTTPBufferedPosts
        case "scMaxEachPostBytes", "uplinkChunkSize": limits.maxXHTTPPostBytes
        case "xPaddingBytes": limits.maxXHTTPPaddingBytes
        case "sessionIDLength": limits.maxXHTTPSessionIDLength
        case "bufferSize": limits.maxPolicyBufferSizeKiB
        case "handshake": limits.maxPolicyHandshakeSeconds
        case "connIdle": limits.maxPolicyConnectionIdleSeconds
        case "uplinkOnly", "downlinkOnly": limits.maxPolicyHalfCloseSeconds
        case "initial_windows_size": limits.maxGRPCInitialWindowBytes
        case "initStreamReceiveWindow", "maxStreamReceiveWindow": limits.maxQUICStreamWindowBytes
        case "initConnectionReceiveWindow", "maxConnectionReceiveWindow": limits.maxQUICConnectionWindowBytes
        case "maxIncomingStreams": limits.maxQUICIncomingStreams
        case "rand", "length", "lengths", "maxSplit", "packetSize",
             "paddingMin", "paddingMax", "padding_min", "padding_max":
            limits.maxFinalMaskGeneratedPayloadBytes
        default:
            preconditionFailure("Unregistered memory-sensitive JSON key: \(canonicalKey)")
        }
    }

    func validateFinalMask(_ value: JSONValue, path: String) throws {
        guard let object = value.objectValue else {
            try require(false, path: path, "FinalMask must be a JSON object.")
            return
        }
        let tcp = try uniqueCaseInsensitiveValue("tcp", in: object, path: path)
        let udp = try uniqueCaseInsensitiveValue("udp", in: object, path: path)
        let layers = (tcp?.arrayValue?.count ?? 0) + (udp?.arrayValue?.count ?? 0)
        try require(layers <= limits.maxFinalMaskLayers, path: path, "FinalMask exceeds the \(limits.maxFinalMaskLayers)-layer iOS limit.")
        let size = (try? JSONSerialization.data(withJSONObject: value.foundationValue, options: [])).map(\.count) ?? Int.max
        try require(size <= limits.maxFinalMaskGeneratedPayloadBytes, path: path, "FinalMask exceeds the \(limits.maxFinalMaskGeneratedPayloadBytes)-byte iOS payload limit.")
        try validateFinalMaskGeneratedPayload(value, path: path)
        try validateFinalMaskNetworkDestinations(udp, path: "\(path)/udp")
    }

    func validateFinalMaskNetworkDestinations(_ value: JSONValue?, path: String) throws {
        guard let value else { return }
        guard let layers = value.arrayValue else {
            try require(false, path: path, "FinalMask UDP layers must be an array.")
            return
        }

        for (index, layer) in layers.enumerated() {
            let layerPath = "\(path)/\(index)"
            guard let layerObject = layer.objectValue else {
                try require(false, path: layerPath, "FinalMask layers must be JSON objects.")
                continue
            }
            guard let typeValue = try uniqueCaseInsensitiveValue("type", in: layerObject, path: layerPath),
                  let type = typeValue.stringValue?.lowercased()
            else {
                try require(false, path: "\(layerPath)/type", "FinalMask layer type must be a string.")
                continue
            }

            let settingsValue = try uniqueCaseInsensitiveValue("settings", in: layerObject, path: layerPath)
            if type == "xdns" {
                try validateXDNSFinalMaskSettings(settingsValue, path: "\(layerPath)/settings")
            } else if type == "realm" {
                try validateRealmFinalMaskSettings(settingsValue, path: "\(layerPath)/settings")
            } else if let settings = settingsValue?.objectValue,
                      try uniqueCaseInsensitiveValue("url", in: settings, path: "\(layerPath)/settings") != nil
            {
                try require(false, path: "\(layerPath)/settings/url", "Only validated Realm layers may contain a control URL.")
            }
        }
    }

    func validateXDNSFinalMaskSettings(_ value: JSONValue?, path: String) throws {
        guard let settings = value?.objectValue else {
            try require(false, path: path, "XDNS settings must be a JSON object.")
            return
        }
        guard let resolverValue = try uniqueCaseInsensitiveValue("resolvers", in: settings, path: path),
              let resolvers = resolverValue.arrayValue,
              !resolvers.isEmpty
        else {
            try require(false, path: "\(path)/resolvers", "XDNS resolvers must be a nonempty array.")
            return
        }
        try require(
            resolvers.count <= limits.maxXDNSResolvers,
            path: "\(path)/resolvers",
            "XDNS exceeds the \(limits.maxXDNSResolvers)-resolver iOS limit.",
        )
        let legacyDomain = try uniqueCaseInsensitiveValue("domain", in: settings, path: path)
        let serverDomains = try uniqueCaseInsensitiveValue("domains", in: settings, path: path)
        if legacyDomain != nil || serverDomains != nil {
            try require(false, path: "\(path)/domains", "XDNS server domains cannot be supplied in a client configuration.")
        }
        for (index, resolver) in resolvers.enumerated() {
            let resolverPath = "\(path)/resolvers/\(index)"
            guard let raw = resolver.stringValue,
                  let host = xdnsResolverHost(raw),
                  ImportPolicy.isPublicIPAddressLiteral(host)
            else {
                try require(false, path: resolverPath, "XDNS resolvers must use a public IP literal and a port from 1 through 65535.")
                continue
            }
        }
    }

    func xdnsResolverHost(_ raw: String) -> String? {
        guard raw == raw.trimmingCharacters(in: .whitespacesAndNewlines),
              let separator = raw.range(of: "+udp://"),
              raw[separator.upperBound...].range(of: "+udp://") == nil
        else { return nil }

        let query = String(raw[..<separator.lowerBound])
        guard !query.isEmpty else { return nil }
        let queryParts = query.split(separator: ":", omittingEmptySubsequences: false)
        guard queryParts.count <= 2,
              !queryParts[0].isEmpty,
              queryParts.count == 1 || ["", "txt", "a", "aaaa"].contains(queryParts[1].lowercased())
        else { return nil }

        return splitHostPort(String(raw[separator.upperBound...]))?.host
    }

    func validateRealmFinalMaskSettings(_ value: JSONValue?, path: String) throws {
        guard let settings = value?.objectValue else {
            try require(false, path: path, "Realm settings must be a JSON object.")
            return
        }
        guard let urlValue = try uniqueCaseInsensitiveValue("url", in: settings, path: path),
              let rawURL = urlValue.stringValue
        else {
            try require(false, path: "\(path)/url", "Realm control URL must be a string.")
            return
        }
        if !rawURL.hasPrefix("##HOP_SECRET:") || !rawURL.hasSuffix("##") {
            guard let components = URLComponents(string: rawURL),
                  components.scheme?.lowercased() == "realm",
                  let user = components.user,
                  !user.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  components.password == nil,
                  let host = components.host,
                  allowedImportedSecondaryHost(host),
                  !components.path.trimmingCharacters(in: CharacterSet(charactersIn: "/")).isEmpty,
                  components.query == nil,
                  components.fragment == nil,
                  components.port.map({ (1 ... 65535).contains($0) }) ?? true
            else {
                try require(false, path: "\(path)/url", "Realm control URLs must use realm:// with a token, allowed host, optional valid port, and Realm ID.")
                return
            }
        }

        guard let stunValue = try uniqueCaseInsensitiveValue("stunServers", in: settings, path: path),
              let stunServers = stunValue.arrayValue,
              !stunServers.isEmpty
        else {
            try require(false, path: "\(path)/stunServers", "Realm STUN servers must be a nonempty array.")
            return
        }
        try require(
            stunServers.count <= limits.maxRealmSTUNServers,
            path: "\(path)/stunServers",
            "Realm exceeds the \(limits.maxRealmSTUNServers)-server iOS STUN limit.",
        )
        for (index, server) in stunServers.enumerated() {
            let serverPath = "\(path)/stunServers/\(index)"
            guard let raw = server.stringValue,
                  let endpoint = splitHostPort(raw),
                  ImportPolicy.isPublicIPAddressLiteral(endpoint.host)
            else {
                try require(false, path: serverPath, "Realm STUN servers must use a public IP literal and a port from 1 through 65535.")
                continue
            }
        }
    }

    func splitHostPort(_ raw: String) -> (host: String, port: Int)? {
        guard raw == raw.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else { return nil }
        let host: String
        let portString: String
        if raw.hasPrefix("[") {
            guard let close = raw.firstIndex(of: "]"),
                  raw.index(after: close) < raw.endIndex,
                  raw[raw.index(after: close)] == ":"
            else { return nil }
            host = String(raw[raw.index(after: raw.startIndex) ..< close])
            portString = String(raw[raw.index(close, offsetBy: 2)...])
        } else {
            guard let separator = raw.lastIndex(of: ":") else { return nil }
            host = String(raw[..<separator])
            portString = String(raw[raw.index(after: separator)...])
            guard !host.contains(":") else { return nil }
        }
        guard !host.isEmpty, let port = Int(portString), (1 ... 65535).contains(port) else { return nil }
        return (host, port)
    }

    func allowedImportedSecondaryHost(_ rawHost: String) -> Bool {
        let host = rawHost.hasPrefix("[") && rawHost.hasSuffix("]")
            ? String(rawHost.dropFirst().dropLast())
            : rawHost
        guard !host.isEmpty,
              !host.contains(where: \.isWhitespace),
              !ImportPolicy.isDisallowedRemoteHost(host),
              !ImportPolicy.resolvedAddressesAreDisallowed(host)
        else { return false }
        if ImportPolicy.isIPAddressLiteral(host) {
            return ImportPolicy.isPublicIPAddressLiteral(host)
        }
        return !host.contains(":") && !host.contains("%")
    }

    func uniqueCaseInsensitiveValue(_ name: String, in object: JSONObject, path: String) throws -> JSONValue? {
        var matchingKey: String?
        for key in object.keys where jsonKeyEquals(key, name) {
            try require(matchingKey == nil, path: "\(path)/\(name)", "JSON object contains duplicate keys that differ only by case.")
            matchingKey = key
        }
        return matchingKey.flatMap { object[$0] }
    }

    func validateFinalMaskGeneratedPayload(_ value: JSONValue, path: String) throws {
        switch value {
        case let .object(object):
            var seenGeneratedKeys: Set<String> = []
            for (key, child) in object {
                let childPath = "\(path)/\(key)"
                if let canonicalKey = Self.finalMaskGeneratedSizeKeys.first(where: { jsonKeyEquals(key, $0) }) {
                    try require(
                        seenGeneratedKeys.insert(canonicalKey).inserted,
                        path: childPath,
                        "FinalMask contains duplicate generated-size keys that differ only by case.",
                    )
                    if let upperBound = numericUpperBound(child) {
                        try require(upperBound <= limits.maxFinalMaskGeneratedPayloadBytes, path: childPath, "FinalMask may generate \(upperBound) bytes, above the \(limits.maxFinalMaskGeneratedPayloadBytes)-byte iOS limit.")
                    }
                }
                try validateFinalMaskGeneratedPayload(child, path: childPath)
            }
        case let .array(values):
            for (index, child) in values.enumerated() {
                try validateFinalMaskGeneratedPayload(child, path: "\(path)/\(index)")
            }
        case .string, .number, .bool, .null:
            break
        }
    }

    func finalMaskWithSafeDefaults(_ value: JSONValue) throws -> JSONValue {
        guard var object = value.objectValue else {
            try require(false, path: "/transport/finalMask", "FinalMask must be a JSON object.")
            return value
        }
        let quicKeys = object.keys.filter { jsonKeyEquals($0, "quicParams") }
        try require(quicKeys.count <= 1, path: "/transport/finalMask/quicParams", "JSON object contains duplicate protected keys that differ only by case.")
        if let key = quicKeys.first,
           let value = object.removeValue(forKey: key)
        {
            guard var quic = value.objectValue else {
                try require(false, path: "/transport/finalMask/quicParams", "QUIC parameters must be a JSON object.")
                return .object(object)
            }
            fillSafeQUICDefaults(into: &quic)
            object["quicParams"] = .object(quic)
        }
        return .object(object)
    }

    func fillSafeQUICDefaults(into quic: inout JSONObject) {
        fillIfMissing("initStreamReceiveWindow", value: .number(Double(limits.maxQUICStreamWindowBytes)), into: &quic)
        fillIfMissing("maxStreamReceiveWindow", value: .number(Double(limits.maxQUICStreamWindowBytes)), into: &quic)
        fillIfMissing("initConnectionReceiveWindow", value: .number(Double(limits.maxQUICConnectionWindowBytes)), into: &quic)
        fillIfMissing("maxConnectionReceiveWindow", value: .number(Double(limits.maxQUICConnectionWindowBytes)), into: &quic)
        fillIfMissing("maxIncomingStreams", value: .number(Double(limits.maxQUICIncomingStreams)), into: &quic)
    }

    func atomCount(in rule: RoutingRule) -> Int {
        rule.kind == .final ? 1 : max(1, stringList(rule.value).count)
    }

    func stringList(_ value: String) -> [String] {
        value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }

    func boolValue(_ value: String) -> Bool? {
        switch value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "true", "yes", "1": true
        case "false", "no", "0": false
        default: nil
        }
    }

    func normalizedPortRange(_ value: String) -> String {
        value.replacingOccurrences(of: ":", with: "-")
    }

    func validPortOrRange(_ value: String) -> Bool {
        let parts = value.replacingOccurrences(of: ":", with: "-").split(separator: "-", omittingEmptySubsequences: false)
        guard (1 ... 2).contains(parts.count),
              let first = Int(parts[0]), (1 ... 65535).contains(first)
        else { return false }
        guard parts.count == 2 else { return true }
        guard let last = Int(parts[1]), (first ... 65535).contains(last) else { return false }
        return true
    }

    func bandwidthMbps(_ value: String) -> Double? {
        let normalized = value.lowercased().filter { !$0.isWhitespace }
        let number = normalized.prefix { $0.isNumber || $0 == "." }
        guard !number.isEmpty, let amount = Double(number), amount >= 0 else { return nil }
        let unit = String(normalized.dropFirst(number.count))
        let multiplier: Double
        switch unit {
        case "", "b", "bps": multiplier = 1 / 1_000_000
        case "k", "kb", "kbps": multiplier = 1024 / 1_000_000
        case "m", "mb", "mbps": multiplier = 1_048_576 / 1_000_000
        case "g", "gb", "gbps": multiplier = 1_073_741_824 / 1_000_000
        case "t", "tb", "tbps": multiplier = 1_099_511_627_776 / 1_000_000
        default: return nil
        }
        return amount * multiplier
    }

    func rawBase64URLByteCount(_ value: String) -> Int? {
        var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        return Data(base64Encoded: base64)?.count
    }

    func validVLESSPaddingDirective(_ value: String) -> Bool {
        let components = value.split(separator: "-", omittingEmptySubsequences: false).compactMap { Int($0) }
        return components.count == 3 && components.allSatisfy { $0 >= 0 }
    }

    func safeGeoCategory(_ value: String) -> Bool {
        !value.isEmpty && value.allSatisfy { character in
            character.isASCII && (character.isLetter || character.isNumber || character == "-" || character == "_")
        }
    }

    func numericUpperBound(_ value: JSONValue) -> Int? {
        numericBounds(value)?.upperBound
    }

    func numericBounds(_ value: JSONValue) -> ClosedRange<Int>? {
        switch value {
        case let .number(number):
            guard let integer = value.integerValue else {
                return number < 0 ? Int.min ... 0 : 0 ... Int.max
            }
            return integer ... integer
        case let .string(string):
            let components = string.split(
                maxSplits: Int.max,
                omittingEmptySubsequences: false,
                whereSeparator: { $0 == "-" || $0 == ":" },
            )
            guard !components.isEmpty else { return nil }
            let values = components.map { Int($0.trimmingCharacters(in: .whitespaces)) }
            guard values.allSatisfy({ $0 != nil }) else { return Int.min ... Int.max }
            let integers = values.compactMap(\.self)
            guard let minimum = integers.min(), let maximum = integers.max() else { return nil }
            return minimum ... maximum
        case let .array(values):
            guard !values.isEmpty else { return nil }
            let bounds = values.map(numericBounds)
            guard bounds.allSatisfy({ $0 != nil }) else { return nil }
            return combinedNumericBounds(bounds.compactMap(\.self))
        case let .object(object):
            guard !object.isEmpty else { return nil }
            let bounds = object.values.map(numericBounds)
            guard bounds.allSatisfy({ $0 != nil }) else { return nil }
            return combinedNumericBounds(bounds.compactMap(\.self))
        case .bool, .null:
            return nil
        }
    }

    func combinedNumericBounds(_ bounds: [ClosedRange<Int>]) -> ClosedRange<Int>? {
        guard let minimum = bounds.map(\.lowerBound).min(),
              let maximum = bounds.map(\.upperBound).max()
        else { return nil }
        return minimum ... maximum
    }

    func nonempty(_ value: String?) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    func compactObject(_ values: [String: JSONValue?]) -> JSONObject {
        values.compactMapValues(\.self)
    }

    func insert(_ value: String?, key: String, into object: inout JSONObject) {
        if let value = nonempty(value) {
            object[key] = .string(value)
        }
    }

    func fillIfMissing(_ key: String, value: JSONValue, into object: inout JSONObject) {
        if object[key] == nil {
            object[key] = value
        }
    }

    static func tag(for profile: ProxyProfile) -> String {
        "proxy-\(profile.id.uuidString.lowercased())"
    }

    static func tag(for group: ProxyGroup) -> String {
        "group-\(group.id.uuidString.lowercased())"
    }
}

private enum XrayResolvedTarget: Hashable {
    case outbound(String)
    case balancer(String)
}

private struct XrayResolvedURLGroup {
    var group: ProxyGroup
    var memberTags: [String]
}

private final class XrayReachabilityResolver {
    let profiles: [ProxyProfile]
    let groups: [ProxyGroup]
    private let maxGroupDepth: Int
    private let maxResolutionSteps: Int
    private let profilesByID: [ProxyProfile.ID: ProxyProfile]
    private let groupsByID: [ProxyGroup.ID: ProxyGroup]
    private let profilesByName: [String: [ProxyProfile]]
    private let groupsByName: [String: [ProxyGroup]]
    private var resolutionSteps = 0
    private var budgetViolation: XrayValidationIssue?
    private var ambiguityViolation: XrayValidationIssue?

    private(set) var profileIDs: Set<ProxyProfile.ID> = []
    private(set) var urlGroups: [ProxyGroup.ID: XrayResolvedURLGroup] = [:]

    init(profiles: [ProxyProfile], groups: [ProxyGroup], limits: IOSRuntimeLimits) {
        self.profiles = profiles
        self.groups = groups
        maxGroupDepth = limits.maxProxyGroupDepth
        maxResolutionSteps = limits.maxProxyGroupResolutionSteps
        profilesByID = Dictionary(uniqueKeysWithValues: profiles.map { ($0.id, $0) })
        groupsByID = Dictionary(uniqueKeysWithValues: groups.map { ($0.id, $0) })
        profilesByName = Dictionary(grouping: profiles) { $0.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
        groupsByName = Dictionary(grouping: groups) { $0.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
    }

    func resolve(_ target: OutboundTarget) throws -> XrayResolvedTarget {
        var activeGroups: Set<ProxyGroup.ID> = []
        do {
            return try resolve(target, activeGroups: &activeGroups, groupDepth: 0)
        } catch {
            try rethrowFatalViolation()
            throw error
        }
    }

    private func resolve(
        _ target: OutboundTarget,
        activeGroups: inout Set<ProxyGroup.ID>,
        groupDepth: Int,
    ) throws -> XrayResolvedTarget {
        try consumeResolutionStep()
        switch target {
        case .selectedProxy:
            if let profile = profiles.first {
                return resolved(profile)
            }
            if let group = groups.first(where: \.isEnabled) {
                return try resolve(group, activeGroups: &activeGroups, groupDepth: groupDepth + 1)
            }
            return try fail("/selectedTarget", "No runnable proxy is available.")
        case .direct:
            return .outbound("direct")
        case .reject:
            return .outbound("reject")
        case let .profile(id):
            guard let profile = profilesByID[id] else {
                return try fail("/selectedTarget", "Referenced profile no longer exists.")
            }
            return resolved(profile)
        case let .group(id):
            guard let group = groupsByID[id] else {
                return try fail("/selectedTarget", "Referenced proxy group no longer exists.")
            }
            return try resolve(group, activeGroups: &activeGroups, groupDepth: groupDepth + 1)
        case let .named(name):
            let normalized = name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if normalized == "direct" {
                return .outbound("direct")
            }
            if normalized == "reject" {
                return .outbound("reject")
            }
            if normalized == "proxy" {
                return try resolve(.selectedProxy, activeGroups: &activeGroups, groupDepth: groupDepth)
            }
            let namedProfiles = profilesByName[normalized] ?? []
            let namedGroups = groupsByName[normalized] ?? []
            guard namedProfiles.count + namedGroups.count <= 1 else {
                let issue = XrayValidationIssue(
                    path: "/selectedTarget",
                    message: "Named target \(name) is ambiguous; use a UUID-bound profile or group target.",
                )
                ambiguityViolation = issue
                throw XrayConfigError.validationFailed([issue])
            }
            if let profile = namedProfiles.first {
                return resolved(profile)
            }
            if let group = namedGroups.first {
                return try resolve(group, activeGroups: &activeGroups, groupDepth: groupDepth + 1)
            }
            return try fail("/selectedTarget", "Named target \(name) does not exist.")
        }
    }

    private func resolve(
        _ group: ProxyGroup,
        activeGroups: inout Set<ProxyGroup.ID>,
        groupDepth: Int,
    ) throws -> XrayResolvedTarget {
        try requireGroupDepth(groupDepth)
        guard group.isEnabled else {
            return try fail("/groups/\(group.id)", "Proxy group is disabled.")
        }
        guard activeGroups.insert(group.id).inserted else {
            return try fail("/groups/\(group.id)", "Proxy group dependency cycle detected.")
        }
        defer { activeGroups.remove(group.id) }

        switch group.type {
        case .select:
            var attempted: Set<OutboundTarget> = []
            if let selected = group.defaultTarget {
                attempted.insert(deduplicationKey(for: selected))
                do {
                    return try resolve(selected, activeGroups: &activeGroups, groupDepth: groupDepth)
                } catch {
                    try rethrowFatalViolation()
                }
            }
            for member in group.members where attempted.insert(deduplicationKey(for: member)).inserted {
                do {
                    return try resolve(member, activeGroups: &activeGroups, groupDepth: groupDepth)
                } catch {
                    try rethrowFatalViolation()
                }
            }
            return try fail("/groups/\(group.id)/members", "Manual group has no runnable member.")
        case .urlTest:
            var tags: [String] = []
            var seenTags: Set<String> = []
            var attempted: Set<OutboundTarget> = []
            for member in group.members where attempted.insert(deduplicationKey(for: member)).inserted {
                let destination = try resolve(member, activeGroups: &activeGroups, groupDepth: groupDepth)
                guard case let .outbound(tag) = destination,
                      tag.hasPrefix("proxy-")
                else {
                    return try fail("/groups/\(group.id)/members", "URL-test groups may contain profile or manual-group profile members only.")
                }
                if seenTags.insert(tag).inserted {
                    tags.append(tag)
                }
            }
            guard !tags.isEmpty else {
                return try fail("/groups/\(group.id)/members", "URL-test group has no runnable profile.")
            }
            urlGroups[group.id] = XrayResolvedURLGroup(group: group, memberTags: tags)
            return .balancer(XrayConfigBuilder.tag(for: group))
        case .unsupported:
            return try fail("/groups/\(group.id)/type", "Unsupported proxy group cannot be represented by Xray.")
        }
    }

    private func deduplicationKey(for target: OutboundTarget) -> OutboundTarget {
        guard case let .named(name) = target else { return target }
        return .named(name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
    }

    private func resolved(_ profile: ProxyProfile) -> XrayResolvedTarget {
        profileIDs.insert(profile.id)
        return .outbound(XrayConfigBuilder.tag(for: profile))
    }

    private func fail<T>(_ path: String, _ message: String) throws -> T {
        throw XrayConfigError.validationFailed([XrayValidationIssue(path: path, message: message)])
    }

    private func consumeResolutionStep() throws {
        try rethrowFatalViolation()
        guard resolutionSteps < maxResolutionSteps else {
            let issue = XrayValidationIssue(
                path: "/groups",
                message: "Proxy-group resolution exceeds the iOS work limit of \(maxResolutionSteps) steps.",
            )
            budgetViolation = issue
            throw XrayConfigError.validationFailed([issue])
        }
        resolutionSteps += 1
    }

    private func requireGroupDepth(_ depth: Int) throws {
        try rethrowFatalViolation()
        guard depth <= maxGroupDepth else {
            let issue = XrayValidationIssue(
                path: "/groups",
                message: "Proxy-group dependency depth exceeds the iOS limit of \(maxGroupDepth).",
            )
            budgetViolation = issue
            throw XrayConfigError.validationFailed([issue])
        }
    }

    private func rethrowFatalViolation() throws {
        if let budgetViolation {
            throw XrayConfigError.validationFailed([budgetViolation])
        }
        if let ambiguityViolation {
            throw XrayConfigError.validationFailed([ambiguityViolation])
        }
    }
}
