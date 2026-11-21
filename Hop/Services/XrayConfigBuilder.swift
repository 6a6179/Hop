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
    static let coreVersion = XrayAdvancedDocument.currentSchemaVersion

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
        tokenizingSecretsWith nonce: String? = nil,
    ) throws -> String {
        try validateGlobalAdvanced(settings.xrayAdvanced)

        let activeRules: ArraySlice<RoutingRule> = if routingMode != .rule {
            []
        } else if let final = rules.firstIndex(where: { $0.kind == .final }) {
            rules[...final]
        } else {
            rules[...]
        }
        let resolver = XrayReachabilityResolver(profiles: profiles, groups: groups, limits: limits)
        let usesSelectedTarget = routingMode != .direct && (
            activeRules.last?.kind != .final || activeRules.contains { $0.target == .selectedProxy }
                || (settings.dnsPreset != .system && settings.proxyDNS)
        )
        let selectedDestination = try resolver.resolve(usesSelectedTarget ? selectedTarget : .direct)
        let ruleDestinations = try activeRules.map { rule in
            rule.target == .selectedProxy ? selectedDestination : try resolver.resolve(rule.target)
        }

        let routingAtoms = activeRules.reduce(0) { $0 + atomCount(in: $1) }
        try require(
            routingAtoms <= limits.maxRoutingAtoms,
            path: "/routing/rules",
            "Routing contains \(routingAtoms) atoms; iOS permits at most \(limits.maxRoutingAtoms).",
        )

        try validateURLGroups(Array(resolver.urlGroups.values))

        var outbounds = try reachableProfileOutbounds(resolver: resolver, tokenizingSecretsWith: nonce)
        try validateHeavyOutboundCount(outbounds)
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
        try validateOutboundReferences(outbounds)

        var root: JSONObject = try [
            "log": .object([
                "access": .string("none"),
                "dnsLog": .bool(false),
                "error": .string("none"),
                "logLevel": .string(xrayLogLevel(settings.logLevel)),
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
                rules: activeRules,
                selected: selectedDestination,
                ruleDestinations: ruleDestinations,
                resolver: resolver,
                settings: settings,
            )),
        ]

        if let observatory = observatoryDictionary(from: Array(resolver.urlGroups.values)) {
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
            return [XrayValidationIssue(path: "/", message: "\(error.localizedDescription)")]
        }
    }

    /// The form uses the runtime allowlists instead of maintaining a second policy.
    static func editorProtocolKeys(_ proto: ProxyProtocol) -> Set<String> {
        XrayConfigBuilder().protocolAdvancedKeys(for: proto)
    }

    static func editorTransportKeys(_ transport: TransportType) -> Set<String> {
        XrayConfigBuilder().transportAdvancedKeys(for: transport)
    }

    static var editorSocketKeys: Set<String> {
        socketAdvancedKeys
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
    static let tlsAdvancedKeys: Set<String> = ["alpn", "enableSessionResumption"]
    static let realityAdvancedKeys: Set<String> = ["fingerprint", "serverName", "password", "shortId", "mldsa65Verify", "spiderX"]
    static let finalMaskAdvancedKeys: Set<String> = ["tcp", "udp", "quicParams"]
    static let socketAdvancedKeys: Set<String> = [
        "tcpFastOpen", "domainStrategy", "dialerProxy", "tcpKeepAliveInterval", "tcpKeepAliveIdle",
        "penetrate", "interface", "addressPortStrategy", "happyEyeballs",
    ]

    static let forbiddenAdvancedKeys: Set<String> = [
        "script",
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
    static let memorySensitiveKeysByLowercase = Dictionary(uniqueKeysWithValues: memorySensitiveKeys.map { ($0.lowercased(), $0) })
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

    func require(_ condition: @autoclosure () -> Bool, path: String, _ message: @autoclosure () -> XrayValidationMessage) throws {
        guard condition() else {
            throw XrayConfigError.validationFailed([XrayValidationIssue(path: path, message: message())])
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
        case .automatic, .preferIPv4, .preferIPv6:
            "UseIP"
        case .ipv4Only:
            "UseIPv4"
        case .ipv6Only:
            "UseIPv6"
        }
        return [
            "tag": .string("dns-query"),
            "servers": .array([.string(server)]),
            "queryStrategy": .string(strategy),
            "disableCache": .bool(true),
        ]
    }

    /// Render each reachable profile once and follow the effective socket chain after
    /// typed and advanced settings have merged. Keep the user's stable outbound order.
    func reachableProfileOutbounds(resolver: XrayReachabilityResolver, tokenizingSecretsWith nonce: String?) throws -> [JSONObject] {
        var queue = resolver.profiles.filter { resolver.profileIDs.contains($0.id) }
        var discovered = resolver.profileIDs
        var rendered: [UUID: JSONObject] = [:]
        var index = 0
        while index < queue.count {
            try require(discovered.count + 3 <= limits.maxReachableOutbounds, path: "/outbounds", "The configuration exceeds the iOS limit of \(limits.maxReachableOutbounds) outbounds.")
            let profile = queue[index]
            index += 1
            let outbound = try outboundDictionary(for: profile, tokenizingSecretsWith: nonce)
            rendered[profile.id] = outbound
            if let tag = outbound["streamSettings"]?.objectValue?["sockopt"]?.objectValue?["dialerProxy"]?.stringValue,
               tag.hasPrefix("proxy-"), let id = UUID(uuidString: String(tag.dropFirst("proxy-".count))),
               let dependency = resolver.profilesByID[id], tag == Self.tag(for: dependency),
               discovered.insert(id).inserted
            {
                queue.append(dependency)
            }
        }
        return resolver.profiles.compactMap { rendered[$0.id] }
    }

    func outboundDictionary(for original: ProxyProfile, tokenizingSecretsWith nonce: String?) throws -> JSONObject {
        try validate(original)
        let runtime = try original.normalizingShadowsocks2022Keys()
        let profile = nonce.map { runtime.tokenizingSecrets(nonce: $0) } ?? runtime
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
            outbound["streamSettings"] = try .object(hysteriaStreamDictionary(profile: profile, options: options))
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
        if outbound["streamSettings"] == nil, profile.proto != .wireGuard {
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
                try require((2 ... 600).contains(timeout), path: "\(path)/options/udpIdleTimeoutSeconds", "Hysteria2 UDP idle timeout must be between 2 and 600 seconds.")
            }
        case .tuic, .anyTLS:
            break
        case let .shadowsocks(options):
            let method = options.method.lowercased()
            try require(
                Self.secureShadowsocksMethods.contains(method),
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
            if let strategy = nonempty(options.domainStrategy) {
                try require(
                    strategy.lowercased() == "forceip", path: "\(path)/options/domainStrategy",
                    "Xray no longer applies a WireGuard IP-family strategy to tunneled destinations. Clear the legacy domain strategy to use automatic address selection.",
                )
            }
            try require(wireGuardKeyHex(options.privateKey) != nil, path: "\(path)/options/privateKey", "WireGuard private key must encode 32 bytes.")
            try require(!options.localAddress.isEmpty, path: "\(path)/options/localAddress", "WireGuard requires a local IP address.")
            for (index, address) in options.localAddress.enumerated() {
                try require(Endpoint.ipAddressWidth(address) != nil || Endpoint.hostBits(inCIDR: address) != nil, path: "\(path)/options/localAddress/\(index)", "WireGuard local address must be an IPv4 or IPv6 address or CIDR prefix.")
            }
            let peers = options.effectivePeers
            try require(!peers.isEmpty && peers.count <= limits.maxWireGuardPeers, path: "\(path)/options/peers", "WireGuard supports at most \(limits.maxWireGuardPeers) peers on iOS.")
            if options.peers != nil {
                try require(Set(peers.map(\.id)).count == peers.count, path: "\(path)/options/peers", "WireGuard peer IDs must be unique.")
            }
            var peerKeys = Set<String>()
            for (index, peer) in peers.enumerated() {
                let peerPath = "\(path)/options/peers/\(index)"
                guard let publicKey = wireGuardKeyHex(peer.publicKey) else {
                    throw XrayConfigError.validationFailed([XrayValidationIssue(path: "\(peerPath)/publicKey", message: "WireGuard peer public key must encode 32 bytes.")])
                }
                try require(peerKeys.insert(publicKey).inserted, path: "\(peerPath)/publicKey", "WireGuard peer public keys must be unique.")
                if let key = peer.preSharedKey, !key.isEmpty {
                    try require(wireGuardKeyHex(key) != nil, path: "\(peerPath)/preSharedKey", "WireGuard preshared key must encode 32 bytes.")
                }
                try require((peer.allowedIPs?.count ?? 2) <= 32, path: "\(peerPath)/allowedIPs", "Each WireGuard peer supports at most 32 allowed-IP entries on iOS.")
                for (position, prefix) in (peer.allowedIPs ?? []).enumerated() {
                    try require(Endpoint.hostBits(inCIDR: prefix) != nil, path: "\(peerPath)/allowedIPs/\(position)", "WireGuard allowed IP must be an IPv4 or IPv6 CIDR prefix.")
                }
                let endpoint = peer.endpoint ?? profile.endpoint
                try require(Endpoint.isValidWireGuardHost(endpoint.host), path: "\(peerPath)/endpoint/host", "WireGuard peer endpoint must be an IP literal or a valid DNS name.")
                try require((1 ... 65535).contains(endpoint.port), path: "\(peerPath)/endpoint/port", "WireGuard peer endpoint port must be between 1 and 65535.")
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
        try require(transport.kcp == nil || transport.type == .mKCP, path: "\(profilePath)/transport/kcp", "mKCP options require the mKCP transport.")
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
        if let settings = advanced.values["settings"]?.objectValue {
            for key in settings.keys.sorted() {
                if jsonKeyEquals(key, "level") {
                    try require(false, path: "\(path)/xrayAdvanced/settings/\(key)", "Hop enforces policy level 0 for the iOS memory limit.")
                }
                if profile.proto == .vless, jsonKeyEquals(key, "seed") {
                    try require(false, path: "\(path)/xrayAdvanced/settings/\(key)", "The pinned Xray core ignores VLESS seed; use Encryption / Auth or Vision padding instead.")
                }
            }
        }
        try validateForbiddenFields(.object(advanced.values), path: "\(path)/xrayAdvanced")

        if let settings = advanced.values["settings"] {
            let typedSettingKeys = typedProtocolSettingKeys(for: profile.proto)
            if let object = settings.objectValue,
               let collision = object.keys.sorted().first(where: typedSettingKeys.contains)
            {
                try require(false, path: "\(path)/xrayAdvanced/settings/\(collision)", "Advanced JSON collides with a typed or iOS-enforced field.")
            }
            try validateObject(settings, allowed: protocolAdvancedKeys(for: profile.proto), path: "\(path)/xrayAdvanced/settings")
            if profile.proto == .vless, let object = settings.objectValue {
                if let preconnections = object["testpre"] {
                    try require(
                        preconnections.integerValue.map { (0 ... limits.maxVLESSPreconnections).contains($0) } == true,
                        path: "\(path)/xrayAdvanced/settings/testpre",
                        "VLESS preconnections must be between 0 and \(limits.maxVLESSPreconnections) on iOS.",
                    )
                }
                if let padding = object["testseed"] {
                    let values = padding.arrayValue?.compactMap(\.integerValue) ?? []
                    try require(
                        values.count == 4 && padding.arrayValue?.count == 4 && values.allSatisfy { (0 ... 8192).contains($0) },
                        path: "\(path)/xrayAdvanced/settings/testseed",
                        "Vision padding requires four integers between 0 and 8192.",
                    )
                    // The pinned core calls rand.Int on entries 1/3 and extends
                    // its 8192-byte buffer by random + base - content length.
                    try require(
                        values[1] > 0 && values[3] > 0 && values[2] >= values[0] - 1,
                        path: "\(path)/xrayAdvanced/settings/testseed",
                        "Vision padding random ranges must be positive, and base must be at least threshold minus one.",
                    )
                }
            }
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
                try require(profile.security.layer == .tls, path: "\(path)/xrayAdvanced/streamSettings/tlsSettings", "Advanced JSON cannot configure an unselected security layer.")
                try validateObject(tls, allowed: Self.tlsAdvancedKeys, path: "\(path)/xrayAdvanced/streamSettings/tlsSettings")
            }
            if let reality = stream["realitySettings"] {
                try require(profile.security.layer == .reality, path: "\(path)/xrayAdvanced/streamSettings/realitySettings", "Advanced JSON cannot configure an unselected security layer.")
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
            ["email", "testpre", "testseed"]
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
            ["noKernelTun", "secretKey", "address", "peers", "mtu", "reserved"]
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
                "uplinkDataKey", "uplinkChunkSize", "noGRPCHeader", "scMaxEachPostBytes",
                "scMinPostsIntervalMs",
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
            try require(!pools.isEmpty, path: "/settings/xrayAdvanced/fakeDns", "FakeDNS requires at least one pool.")
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
                guard let entries = rawEntries?.integerValue, entries > 0 else {
                    throw XrayConfigError.validationFailed([XrayValidationIssue(path: "\(path)/poolSize", message: "FakeDNS pool size must be a positive in-range integer.")])
                }
                try require(entries <= limits.maxFakeDNSPoolEntries, path: "\(path)/poolSize", "FakeDNS pool size exceeds the \(limits.maxFakeDNSPoolEntries)-entry iOS limit.")
                let rawCIDR = try uniqueCaseInsensitiveValue("ipPool", in: object, path: path)
                guard let cidr = rawCIDR?.stringValue, let hostBits = Endpoint.hostBits(inCIDR: cidr) else {
                    throw XrayConfigError.validationFailed([XrayValidationIssue(path: "\(path)/ipPool", message: "FakeDNS requires an IPv4 or IPv6 CIDR prefix.")])
                }
                // The core requires the pool size to be strictly below 2^hostBits.
                try require(Int.bitWidth - entries.leadingZeroBitCount <= hostBits, path: "\(path)/poolSize", "FakeDNS pool size must be smaller than its subnet.")
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
            stream[key] = .object(compactObject([
                "serviceName": profile.transport.serviceName.map(JSONValue.string),
                "authority": profile.transport.host.map(JSONValue.string),
            ]))
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
            stream["finalmask"] = finalMask
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
        guard var quic = (finalMask["quicParams"] ?? .object([:])).objectValue else {
            throw XrayConfigError.validationFailed([XrayValidationIssue(path: "/transport/finalMask/quicParams", message: "QUIC parameters must be a JSON object.")])
        }
        for (key, isTyped) in [
            ("brutalUp", options.up != nil),
            ("brutalDown", options.down != nil),
            ("congestion", options.up != nil || options.down != nil),
            ("udpHop", options.ports != nil),
        ] where isTyped {
            try require(
                !quic.keys.contains(where: { jsonKeyEquals($0, key) }),
                path: "/profiles/\(profile.id)/transport/finalMask/quicParams/\(key)",
                "Advanced QUIC parameters collide with typed Hysteria2 options; configure one or the other.",
            )
        }
        if let up = options.up {
            quic["brutalUp"] = .string(up)
            quic["congestion"] = .string("brutal")
        }
        if let down = options.down {
            quic["brutalDown"] = .string(down)
            quic["congestion"] = .string("brutal")
        }
        if let ports = options.ports {
            // Keep the same intermediate shape as persisted advanced profiles.
            // Finalization converts it to the current UDP mask after merging
            // all layers, so typed and advanced forms share collision checks.
            var udpHop: JSONObject = ["ports": .string(ports.replacingOccurrences(of: ":", with: "-"))]
            if let interval = options.hopIntervalSeconds {
                udpHop["interval"] = .number(Double(interval))
            }
            quic["udpHop"] = .object(udpHop)
        }
        finalMask["quicParams"] = .object(quic)

        if let obfs = options.obfs, !obfs.isEmpty {
            try require(obfs.lowercased() == "salamander", path: "/profiles/\(profile.id)/options/obfs", "Xray Hysteria2 supports Salamander obfuscation only.")
            guard let password = options.obfsPassword, !password.isEmpty else {
                try require(false, path: "/profiles/\(profile.id)/options/obfsPassword", "Salamander obfuscation requires a password.")
                return stream
            }
            try require(
                !finalMask.keys.contains(where: { jsonKeyEquals($0, "udp") }),
                path: "/profiles/\(profile.id)/transport/finalMask/udp",
                "Advanced FinalMask udp layers cannot be combined with typed Salamander obfuscation; configure one or the other.",
            )
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
            "useSystemCA": .bool(true),
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
        let extra = transport.xhttpExtra?.objectValue ?? [:]
        try require(transport.xhttpExtra == nil || transport.xhttpExtra?.objectValue != nil, path: "/transport/xhttpExtra", "XHTTP extra must be a JSON object.")
        return compactObject([
            "path": nonempty(transport.path).map(JSONValue.string),
            "host": nonempty(transport.host).map(JSONValue.string),
            "mode": nonempty(transport.xhttpMode).map(JSONValue.string),
            "extra": .object(extra),
        ])
    }

    func finalizedXHTTPSettings(_ settings: JSONObject, path: String) throws -> JSONObject {
        var result = settings
        var extra = settings["extra"]?.objectValue ?? [:]
        try require(settings["extra"] == nil || settings["extra"]?.objectValue != nil, path: "\(path)/extra", "XHTTP extra must be a JSON object.")
        let outerKeys: Set = ["host", "path", "mode", "extra"]
        for key in extra.keys.sorted() where outerKeys.contains(key) {
            try require(false, path: "\(path)/extra/\(key)", "XHTTP \(key) belongs outside extra; the core ignores it here.")
        }
        // The core replaces the outer settings with extra, retaining only host,
        // path and mode. Normalize before adding defaults so no field is lost.
        for key in result.keys.sorted() where !outerKeys.contains(key) {
            if let value = result.removeValue(forKey: key) {
                try mergeAdvanced([key: value], into: &extra, path: "\(path)/extra")
            }
        }
        var xmux = extra["xmux"]?.objectValue ?? [:]
        try require(extra["xmux"] == nil || extra["xmux"]?.objectValue != nil, path: "\(path)/extra/xmux", "XHTTP xmux must be a JSON object.")
        if let concurrency = try uniqueCaseInsensitiveValue("maxConcurrency", in: xmux, path: "\(path)/extra/xmux") {
            // Xray treats these limits as mutually exclusive. A concurrency target
            // alone can create more connections than the extension can afford.
            try require(numericBounds(concurrency) == 0 ... 0, path: "\(path)/extra/xmux/maxConcurrency", "XHTTP requires a fixed connection limit on iOS. Remove maxConcurrency or set it to zero.")
        }
        fillIfMissing("maxConnections", value: .number(Double(limits.maxXHTTPConnections)), into: &xmux)
        extra["xmux"] = .object(xmux)
        fillIfMissing("scMaxBufferedPosts", value: .number(Double(limits.maxXHTTPBufferedPosts)), into: &extra)
        fillIfMissing("scMaxEachPostBytes", value: .number(Double(limits.maxXHTTPPostBytes)), into: &extra)
        result["extra"] = .object(extra)
        return result
    }

    func kcpDictionary(_ options: XrayKCPOptions?) -> JSONObject {
        compactObject([
            "mtu": options?.mtu.map { .number(Double($0)) },
            "tti": options?.tti.map { .number(Double($0)) },
            "uplinkCapacity": options?.uplinkCapacity.map { .number(Double($0)) },
            "downlinkCapacity": options?.downlinkCapacity.map { .number(Double($0)) },
            "cwndMultiplier": options?.cwndMultiplier.map { .number(Double($0)) },
            "maxSendingWindow": options?.maxSendingWindow.map { .number(Double($0)) },
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

    /// Xray accepts hex, standard base64, and URL-safe base64. WireGuard identifies
    /// peers by the decoded bytes, even when two rows use different encodings.
    func wireGuardKeyHex(_ value: String) -> String? {
        if value.utf8.count == 64, value.allSatisfy({ $0.isASCII && $0.isHexDigit }) {
            return value.lowercased()
        }
        var raw = value
        if raw.hasSuffix("=") {
            raw.removeLast()
        }
        raw = raw.replacingOccurrences(of: "\r", with: "").replacingOccurrences(of: "\n", with: "")
        guard raw.utf8.count == 43 else { return nil }
        if !raw.contains("+"), !raw.contains("/") {
            raw = raw.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        }
        guard let bytes = Data(base64Encoded: raw + "="), bytes.count == 32 else { return nil }
        return bytes.map { String(format: "%02x", $0) }.joined()
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
        return result
    }

    func endpointString(host: String, port: Int) -> String {
        host.contains(":") && !host.hasPrefix("[") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    func applyProfileAdvanced(_ advanced: XrayAdvancedDocument?, profile: ProxyProfile, to outbound: inout JSONObject) throws {
        if let advanced, !advanced.isEmpty {
            var copy = advanced.values
            if let proxy = copy.removeValue(forKey: "proxySettings")?.objectValue {
                let path = "/profiles/\(profile.id)/proxySettings"
                try require(proxy["transportLayer"] == .bool(true), path: path, "Protocol-layer chaining was removed. Review this chain and choose a socket dialer proxy before connecting.")
                guard let tag = proxy["tag"]?.stringValue, !tag.isEmpty else {
                    throw XrayConfigError.validationFailed([XrayValidationIssue(path: path, message: "The outbound chain needs a proxy tag.")])
                }
                var stream = copy["streamSettings"]?.objectValue ?? [:]
                var socket = stream["sockopt"]?.objectValue ?? [:]
                try require(socket["dialerProxy"] == nil, path: path, "proxySettings.tag conflicts with sockopt.dialerProxy.")
                socket["dialerProxy"] = .string(tag)
                stream["sockopt"] = .object(socket)
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
        if let xhttp = stream["xhttpSettings"]?.objectValue {
            stream["xhttpSettings"] = try .object(finalizedXHTTPSettings(xhttp, path: "\(path)/xhttpSettings"))
        }
        if var grpc = stream["grpcSettings"]?.objectValue {
            fillIfMissing("initial_windows_size", value: .number(Double(limits.maxGRPCInitialWindowBytes)), into: &grpc)
            stream["grpcSettings"] = .object(grpc)
        }
        let finalMaskKeys = stream.keys.filter { jsonKeyEquals($0, "finalmask") }
        try require(finalMaskKeys.count <= 1, path: "\(path)/finalmask", "JSON object contains duplicate protected keys that differ only by case.")
        if let key = finalMaskKeys.first,
           let finalMask = stream.removeValue(forKey: key)
        {
            stream["finalmask"] = try finalMaskForPinnedCore(
                finalMask, stream: stream, path: "\(path)/finalmask",
            )
        }
        if isXHTTPH3(stream) {
            var finalMask = stream["finalmask"]?.objectValue ?? [:]
            var quic = finalMask["quicParams"]?.objectValue ?? [:]
            fillSafeQUICDefaults(into: &quic)
            finalMask["quicParams"] = .object(quic)
            stream["finalmask"] = .object(finalMask)
        }
        if let quic = stream["finalmask"]?.objectValue?["quicParams"]?.objectValue {
            try validateQUICBandwidth(quic, path: "\(path)/finalmask/quicParams")
        }
        let kcpKeys = stream.keys.filter { jsonKeyEquals($0, "kcpSettings") }
        try require(kcpKeys.count <= 1, path: "\(path)/kcpSettings", "JSON object contains duplicate protected keys that differ only by case.")
        if let key = kcpKeys.first,
           let kcp = stream.removeValue(forKey: key)
        {
            guard var settings = kcp.objectValue else {
                try require(false, path: "\(path)/kcpSettings", "mKCP settings must be a JSON object.")
                return
            }
            // Only explicit typed fields take part in collision checks. Apply the
            // iOS send-window cap after the accepted advanced settings are merged.
            fillIfMissing("mtu", value: .number(1350), into: &settings)
            fillIfMissing("maxSendingWindow", value: .number(Double(limits.maxKCPWriteBufferBytes)), into: &settings)
            try validateMergedKCPSettings(settings, path: "\(path)/kcpSettings")
            stream["kcpSettings"] = .object(settings)
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
        rules: ArraySlice<RoutingRule>,
        selected: XrayResolvedTarget,
        ruleDestinations: [XrayResolvedTarget],
        resolver: XrayReachabilityResolver,
        settings: AppSettings,
    ) throws -> JSONObject {
        var resultRules: [JSONValue] = [
            .object([
                "type": .string("field"),
                "inboundTag": .array([.string("tun-in")]),
                "port": .number(53),
                "outboundTag": .string("dns-out"),
            ]),
        ]
        if settings.dnsPreset != .system {
            var dnsRoute: JSONObject = [
                "type": .string("field"),
                "inboundTag": .array([.string("dns-query")]),
            ]
            setRouteTarget(settings.proxyDNS && mode != .direct ? selected : .outbound("direct"), in: &dnsRoute)
            resultRules.append(.object(dnsRoute))
        }
        for (index, rule) in rules.enumerated() {
            try resultRules.append(.object(routingRuleDictionary(rule, index: index, destination: ruleDestinations[index], settings: settings)))
        }

        if rules.last?.kind != .final {
            var catchAll: JSONObject = [
                "type": .string("field"),
                "network": .string("tcp,udp"),
            ]
            setRouteTarget(selected, in: &catchAll)
            resultRules.append(.object(catchAll))
        }

        // IPIfNonMatch never retries DNS once our TCP/UDP catch-all matches.
        let needsDestinationIP = mode == .rule && rules.contains { [.geoIP, .ipIsPrivate, .ipCIDR].contains($0.kind) }
        var routing: JSONObject = [
            "domainStrategy": .string(needsDestinationIP ? "IPOnDemand" : "AsIs"),
            "rules": .array(resultRules),
        ]
        let urlGroups = resolver.urlGroups.values.sorted { $0.group.id.uuidString < $1.group.id.uuidString }
        if !urlGroups.isEmpty {
            routing["balancers"] = .array(urlGroups.map { resolved in
                .object([
                    "tag": .string(Self.tag(for: resolved.group)),
                    "selector": .array(resolved.memberTags.map(JSONValue.string)),
                    "strategy": .object(["type": .string("leastPing")]),
                    // Without a fallback Xray uses the global first outbound when
                    // no member is healthy, even if it belongs to another group.
                    "fallbackTag": .string("reject"),
                ])
            })
        }
        return routing
    }

    func routingRuleDictionary(
        _ rule: RoutingRule,
        index: Int,
        destination: XrayResolvedTarget,
        settings: AppSettings,
    ) throws -> JSONObject {
        let path = "/routing/rules/\(index)"
        try require(rule.kind.isAvailableInXray, path: path, "\(rule.kind.displayName) is Apple-specific and cannot be reproduced by Xray routing.")
        if !settings.sniffTraffic, let requirement = rule.kind.sniffingRequirement {
            try require(false, path: path, XrayValidationMessage(stringLiteral: requirement))
        }

        var result: JSONObject = ["type": .string("field")]
        setRouteTarget(destination, in: &result)
        let values = rule.kind == .domainRegex ? [rule.value] : stringList(rule.value)

        switch rule.kind {
        case .final:
            result["network"] = .string("tcp,udp")
        case .domain:
            result["domain"] = .array(values.map { .string("full:\($0)") })
        case .domainSuffix:
            result["domain"] = .array(values.map { .string("domain:\($0)") })
        case .domainKeyword:
            result["domain"] = .array(values.map { .string("keyword:\($0)") })
        case .domainRegex:
            try require(values.allSatisfy(ImportPolicy.isSafeRegexPattern), path: path, "Domain regex is too large or unsafe.")
            result["domain"] = .array(values.map { .string("regexp:\($0)") })
        case .ipCIDR, .sourceIPCIDR:
            try require(!values.isEmpty && values.allSatisfy { Endpoint.ipAddressWidth($0) != nil || Endpoint.hostBits(inCIDR: $0) != nil }, path: path, "Enter an IP address or a CIDR prefix.")
            result[rule.kind == .ipCIDR ? "ip" : "sourceIP"] = .array(values.map(JSONValue.string))
        case .ipIsPrivate:
            try require(boolValue(rule.value) == true, path: path, "Xray cannot express the negated private-IP matcher.")
            result["ip"] = .array([.string("geoip:private")])
        case .sourceIPIsPrivate:
            try require(boolValue(rule.value) == true, path: path, "Xray cannot express the negated private-source-IP matcher.")
            result["sourceIP"] = .array([.string("geoip:private")])
        case .port:
            result["port"] = .string(values.joined(separator: ","))
        case .portRange:
            result["port"] = try .string(routingPortRanges(values, path: path))
        case .sourcePort:
            result["sourcePort"] = .string(values.joined(separator: ","))
        case .sourcePortRange:
            result["sourcePort"] = try .string(routingPortRanges(values, path: path))
        case .network:
            try require(values.allSatisfy { ["tcp", "udp"].contains($0.lowercased()) }, path: path, "Xray TUN routing supports tcp and udp network matchers only.")
            result["network"] = .string(values.joined(separator: ","))
        case .protocolSniff:
            let protocols = values.map { $0.lowercased() }
            var supported: Set = ["http", "http1", "tls", "quic", "bittorrent"]
            if settings.xrayAdvanced?.values["fakeDns"] != nil {
                supported.insert("fakedns")
            }
            try require(!protocols.isEmpty && protocols.allSatisfy(supported.contains), path: path, "Choose a protocol the tunnel can identify: \(supported.sorted().joined(separator: ", ")).")
            result["protocol"] = .array(protocols.map(JSONValue.string))
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

    func observatoryDictionary(from groups: [XrayResolvedURLGroup]) -> JSONObject? {
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

    func validateHeavyOutboundCount(_ outbounds: [JSONObject]) throws {
        let count = outbounds.filter { outbound in
            if outbound["protocol"] == .string("wireguard") || outbound["protocol"] == .string("hysteria") {
                return true
            }
            return isXHTTPH3(outbound["streamSettings"]?.objectValue)
        }.count
        try require(count <= limits.maxConcurrentHeavyOutbounds, path: "/outbounds", "Only one WireGuard, Hysteria2, or XHTTP-H3 outbound may be reachable on iOS.")
    }

    func isXHTTPH3(_ stream: JSONObject?) -> Bool {
        let alpn = stream?["tlsSettings"]?.objectValue?["alpn"]
        return stream?["network"] == .string("xhttp") && stream?["security"] == .string("tls")
            && (alpn == .array([.string("h3")]) || alpn == .string("h3"))
    }

    func validateOutboundReferences(_ outbounds: [JSONObject]) throws {
        let tags = Set(outbounds.compactMap { $0["tag"]?.stringValue })
        var nextByTag: [String: String] = [:]
        for (index, outbound) in outbounds.enumerated() {
            guard let tag = outbound["tag"]?.stringValue else { continue }
            guard let reference = outbound["streamSettings"]?.objectValue?["sockopt"]?.objectValue?["dialerProxy"]?.stringValue,
                  !reference.isEmpty else { continue }
            try require(tags.contains(reference), path: "/outbounds/\(index)", "Outbound chain references an unavailable outbound: \(reference).")
            nextByTag[tag] = reference
        }
        // ponytail: at most 32 outbounds; use a shared DFS if that cap grows.
        for tag in nextByTag.keys.sorted() {
            var visited: Set<String> = []
            var current: String? = tag
            while let target = current {
                try require(visited.insert(target).inserted, path: "/outbounds", "Outbound chain contains a dependency cycle.")
                current = nextByTag[target]
            }
        }
    }

    func validateRenderedLimits(_ root: JSONObject) throws {
        if let servers = root["dns"]?.objectValue?["servers"]?.arrayValue {
            try require(servers.count <= limits.maxDNSServers, path: "/dns/servers", "DNS server count exceeds the iOS limit of \(limits.maxDNSServers).")
        }
        if let subjects = root["observatory"]?.objectValue?["subjectSelector"]?.arrayValue {
            let path = "/observatory/subjectSelector"
            try require(subjects.count <= limits.maxObservatoryTargets, path: path, "Observatory exceeds the \(limits.maxObservatoryTargets)-target iOS limit.")
            // Xray expands each selector as a tag prefix and probes a matching outbound only once.
            let selectors = subjects.compactMap(\.stringValue)
            let tags = root["outbounds"]?.arrayValue?.compactMap { $0.objectValue?["tag"]?.stringValue } ?? []
            let matched = tags.filter { tag in selectors.contains(where: tag.hasPrefix) }
            try require(matched.count <= limits.maxObservatoryTargets, path: path, "Observatory exceeds the \(limits.maxObservatoryTargets)-target iOS limit.")
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
                let canonicalKey = key.utf8.allSatisfy { $0 < 128 }
                    ? Self.memorySensitiveKeysByLowercase[key.lowercased()]
                    : Self.memorySensitiveKeys.first(where: { jsonKeyEquals(key, $0) })
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
        for layer in (tcp?.arrayValue ?? []) + (udp?.arrayValue ?? []) {
            if let object = layer.objectValue,
               let type = try uniqueCaseInsensitiveValue("type", in: object, path: path)?.stringValue?.lowercased()
            {
                try require(type != "filter" && type != "xmc", path: path, "The \(type) mask is unavailable in the iOS client.")
            }
        }
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
                _ = try normalizedXDNS(settingsValue, path: "\(layerPath)/settings")
            } else if type == "realm" {
                try validateRealmFinalMaskSettings(settingsValue, path: "\(layerPath)/settings")
            } else if let settings = settingsValue?.objectValue,
                      try uniqueCaseInsensitiveValue("url", in: settings, path: "\(layerPath)/settings") != nil
            {
                try require(false, path: "\(layerPath)/settings/url", "Only validated Realm layers may contain a control URL.")
            }
        }
    }

    /// Canonicalize Go's case-insensitive JSON keys without accepting duplicates.
    func maskObject(_ value: JSONValue?, keys: Set<String>, path: String) throws -> JSONObject {
        guard let object = value?.objectValue else {
            throw XrayConfigError.validationFailed([XrayValidationIssue(path: path, message: "Expected a FinalMask settings object.")])
        }
        try validateCaseInsensitiveKeys(object, allowed: keys, path: path)
        var result: JSONObject = [:]
        for name in keys {
            result[name] = try uniqueCaseInsensitiveValue(name, in: object, path: path)
        }
        return result
    }

    func normalizedXDNS(_ value: JSONValue?, path: String) throws -> JSONObject {
        var settings = try maskObject(value, keys: ["domain", "domains", "resolvers"], path: path)
        let resolvers = settings["resolvers"]?.arrayValue ?? []
        try require(!resolvers.isEmpty, path: path, "XDNS resolvers must be a nonempty array.")
        try require(resolvers.count <= limits.maxXDNSResolvers, path: path, "XDNS exceeds the \(limits.maxXDNSResolvers)-resolver iOS limit.")
        try require(settings["domain"] == nil, path: path, "Legacy XDNS server domains cannot be used in a client.")
        if resolvers.contains(where: { $0.stringValue != nil }) {
            try require(settings["domains"] == nil, path: path, "Legacy XDNS server domains cannot be combined with client resolver strings.")
            return try convertedXDNSResolverStrings(resolvers, path: path)
        }
        let domains = settings["domains"]?.arrayValue ?? []
        try require(!domains.isEmpty && domains.count <= limits.maxXDNSResolvers, path: path, "XDNS needs between one and \(limits.maxXDNSResolvers) domain entries.")
        var domainCount = 0
        settings["domains"] = try .array(domains.map { domain in
            var config = try maskObject(domain, keys: ["names", "types"], path: "\(path)/domains")
            let names = config["names"]?.arrayValue ?? []
            domainCount += names.count
            try require(!names.isEmpty && domainCount <= limits.maxXDNSResolvers && names.allSatisfy { $0.stringValue.map(validXDNSDomain) == true }, path: path, "Invalid or excessive XDNS domain names.")
            config["names"] = .array(names.compactMap(\.stringValue).map { .string($0.hasSuffix(".") ? String($0.dropLast()) : $0) })
            if let types = config["types"] {
                let queryTypes = types.arrayValue ?? []
                try require(!queryTypes.isEmpty && queryTypes.count <= 3 && queryTypes.allSatisfy { [1, 16, 28].contains($0.integerValue) }, path: path, "XDNS query types must be A, TXT or AAAA.")
            }
            return .object(config)
        })
        var addressCount = 0
        settings["resolvers"] = try .array(resolvers.map { resolver in
            let config = try maskObject(resolver, keys: ["addrs"], path: "\(path)/resolvers")
            let addresses = config["addrs"]?.arrayValue ?? []
            addressCount += addresses.count
            try require(!addresses.isEmpty && addressCount <= limits.maxXDNSResolvers && addresses.allSatisfy { $0.stringValue.map(validXDNSAddress) == true }, path: path, "XDNS resolvers require bounded public UDP IP literals with explicit ports.")
            return .object(config)
        })
        return settings
    }

    func convertedXDNSResolverStrings(_ resolvers: [JSONValue], path: String) throws -> JSONObject {
        var domains: [JSONValue] = []
        var addresses: [String] = []
        var originalPairs: [JSONValue: Set<String>] = [:]
        for resolver in resolvers {
            let parts = resolver.stringValue?.components(separatedBy: "+udp://") ?? []
            guard parts.count == 2 else { throw invalidXDNSResolver(path) }
            let query = parts[0].components(separatedBy: ":")
            let methods = ["": 16, "txt": 16, "a": 1, "aaaa": 28]
            guard query.count <= 2, let name = query.first, validXDNSDomain(name),
                  let type = methods[query.count == 2 ? query[1].lowercased() : ""],
                  !parts[1].contains("://"), validXDNSAddress(parts[1])
            else { throw invalidXDNSResolver(path) }
            let domain = JSONValue.object(["names": .array([.string(name.hasSuffix(".") ? String(name.dropLast()) : name)]), "types": .array([.number(Double(type))])])
            if originalPairs[domain] == nil {
                domains.append(domain)
            }
            originalPairs[domain, default: []].insert(parts[1])
            if !addresses.contains(parts[1]) {
                addresses.append(parts[1])
            }
        }
        // The new client selects domains and resolvers independently. Converting
        // a partial matrix would send queries to resolvers the profile didn't select.
        let allowed = Set(addresses)
        try require(originalPairs.values.allSatisfy { $0 == allowed }, path: path, "Review XDNS domains and resolvers. This core cannot preserve the original domain-to-resolver pairings.")
        return ["domains": .array(domains), "resolvers": .array([.object(["addrs": .array(addresses.map(JSONValue.string))])])]
    }

    func invalidXDNSResolver(_ path: String) -> XrayConfigError {
        .validationFailed([XrayValidationIssue(path: path, message: "XDNS resolvers require a domain, supported query type and public UDP IP literal with a port.")])
    }

    func validXDNSDomain(_ name: String) -> Bool {
        let domain = name.hasSuffix(".") ? name.dropLast() : name[...]
        let labels = domain.split(separator: ".", omittingEmptySubsequences: false)
        return !name.isEmpty && name.utf8.count <= 253 && !labels.isEmpty && labels.allSatisfy { label in
            (1 ... 63).contains(label.utf8.count) && label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }
        }
    }

    func validXDNSAddress(_ value: String) -> Bool {
        let address = value.hasPrefix("udp://") ? String(value.dropFirst(6)) : value
        guard let endpoint = splitHostPort(address) else { return false }
        return ImportPolicy.isPublicIPAddressLiteral(endpoint.host)
    }

    func validateRealmFinalMaskSettings(_ value: JSONValue?, path: String) throws {
        guard let settings = value?.objectValue else {
            try require(false, path: path, "Realm settings must be a JSON object.")
            return
        }
        try validateCaseInsensitiveKeys(settings, allowed: ["url", "stunServers", "tlsConfig"], path: path)
        let tlsConfig = try uniqueCaseInsensitiveValue("tlsConfig", in: settings, path: path)
        try require(
            tlsConfig == nil,
            path: "\(path)/tlsConfig",
            "Realm TLS overrides require typed trust validation and are not supported.",
        )
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

    func finalMaskForPinnedCore(_ value: JSONValue, stream: JSONObject, path: String) throws -> JSONValue {
        var mask = try maskObject(value, keys: Self.finalMaskAdvancedKeys, path: path)
        var layers = mask["udp"]?.arrayValue ?? []
        if let rawQUIC = mask["quicParams"] {
            try require(rawQUIC.objectValue != nil, path: "\(path)/quicParams", "QUIC parameters must be a JSON object.")
            let allowed: Set = [
                "congestion", "debug", "bbrProfile", "brutalUp", "brutalDown", "udpHop",
                "initStreamReceiveWindow", "maxStreamReceiveWindow", "initConnectionReceiveWindow",
                "maxConnectionReceiveWindow", "maxIdleTimeout", "keepAlivePeriod", "disablePathMTUDiscovery", "maxIncomingStreams",
            ]
            var quic = try maskObject(rawQUIC, keys: allowed, path: "\(path)/quicParams")
            fillSafeQUICDefaults(into: &quic)
            try require(quic["debug"] == nil || quic["debug"] == .bool(false), path: "\(path)/quicParams/debug", "QUIC debug logging is unavailable in the tunnel.")
            if let old = quic.removeValue(forKey: "udpHop") {
                let hopPath = "\(path)/quicParams/udpHop"
                // Older cores used this field only on Hysteria and XHTTP/3.
                // Moving it blindly would activate formerly ignored hopping on mKCP.
                try require(stream["network"] == .string("hysteria") || isXHTTPH3(stream), path: hopPath, "Legacy QUIC port hopping requires Hysteria or XHTTP with HTTP/3. Review the UDP mask for this transport.")
                let oldSettings = try maskObject(old, keys: ["ports", "interval"], path: hopPath)
                var settings: JSONObject = ["mode": .string("intervalLocal,intervalRemote")]
                settings["remotePorts"] = oldSettings["ports"]
                settings["interval"] = oldSettings["interval"]
                try validateHopPorts(settings, path: hopPath)
                layers.append(.object(["type": .string("udphop"), "settings": .object(settings)]))
            }
            mask["quicParams"] = .object(quic)
        }
        if mask["udp"] != nil || !layers.isEmpty {
            try require(mask["udp"] == nil || mask["udp"]?.arrayValue != nil, path: path, "FinalMask UDP layers must be an array.")
            mask["udp"] = try .array(layers.enumerated().map { index, layer in
                let layerPath = "\(path)/udp/\(index)"
                var object = try maskObject(layer, keys: ["type", "settings"], path: layerPath)
                let type = object["type"]?.stringValue?.lowercased()
                if ["udphop", "xdns", "xicmp"].contains(type) {
                    try require(index == layers.count - 1, path: layerPath, "A UDP layer that opens its own socket must be last and cannot share the socket with another dialer.")
                }
                if type == "xdns" {
                    object["type"] = .string("xdns")
                    object["settings"] = try .object(normalizedXDNS(object["settings"], path: layerPath))
                } else if type == "udphop" {
                    let settings = try maskObject(object["settings"], keys: ["mode", "interval", "remotePorts"], path: layerPath)
                    let modes = settings["mode"]?.stringValue?.lowercased().components(separatedBy: ",") ?? []
                    let allowed = ["intervallocal", "intervalremote", "perconnremote"]
                    try require(!modes.isEmpty && modes.allSatisfy(allowed.contains), path: layerPath, "Unsupported UDP hopping mode.")
                    if modes.contains("intervalremote") || modes.contains("perconnremote") {
                        try validateHopPorts(settings, path: layerPath)
                    } else {
                        try require(settings["remotePorts"] == nil, path: layerPath, "A remote hopping mode is required for remotePorts.")
                        try validateHopInterval(settings["interval"], path: layerPath)
                    }
                    // The core's chained UDP connection has a synthetic peer address.
                    // Subsequent dials would hop to 0.0.0.0 instead of the configured server.
                    let chained = stream["sockopt"]?.objectValue?["dialerProxy"]?.stringValue
                    try require(chained?.isEmpty != false || Set(modes) == ["perconnremote"], path: layerPath, "Interval UDP hopping cannot use a socket dialer proxy. Choose per-connection remote hopping or remove the chain.")
                    object["type"] = .string("udphop")
                    object["settings"] = .object(settings)
                }
                return .object(object)
            })
        }
        return .object(mask)
    }

    func fillSafeQUICDefaults(into quic: inout JSONObject) {
        fillIfMissing("initStreamReceiveWindow", value: .number(Double(limits.maxQUICStreamWindowBytes)), into: &quic)
        fillIfMissing("maxStreamReceiveWindow", value: .number(Double(limits.maxQUICStreamWindowBytes)), into: &quic)
        fillIfMissing("initConnectionReceiveWindow", value: .number(Double(limits.maxQUICConnectionWindowBytes)), into: &quic)
        fillIfMissing("maxConnectionReceiveWindow", value: .number(Double(limits.maxQUICConnectionWindowBytes)), into: &quic)
        fillIfMissing("maxIncomingStreams", value: .number(Double(limits.maxQUICIncomingStreams)), into: &quic)
    }

    func atomCount(in rule: RoutingRule) -> Int {
        rule.kind == .final || rule.kind == .domainRegex ? 1 : max(1, stringList(rule.value).count)
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

    func routingPortRanges(_ values: [String], path: String) throws -> String {
        try require(!values.isEmpty, path: path, "Routing port range is empty.")
        return try values.map { value in
            var normalized = value
            if value.hasPrefix(":") {
                normalized = "0" + normalized
            }
            if value.hasSuffix(":") {
                normalized += "65535"
            }
            normalized = normalized.replacingOccurrences(of: ":", with: "-")
            try require(value != ":" && portRange(normalized) != nil, path: path, "Invalid routing port range.")
            return normalized
        }.joined(separator: ",")
    }

    func portRange(_ value: String) -> ClosedRange<Int>? {
        let parts = value.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false)
        guard let first = parts.first.flatMap({ UInt16($0) }),
              let last = parts.last.flatMap({ UInt16($0) }), first <= last
        else { return nil }
        return Int(first) ... Int(last)
    }

    func validateQUICBandwidth(_ quic: JSONObject, path: String) throws {
        for key in ["brutalUp", "brutalDown"] {
            if let value = try uniqueCaseInsensitiveValue(key, in: quic, path: path) {
                let bytesPerSecond = value.stringValue.flatMap(quicBandwidthBytesPerSecond)
                let maxBytesPerSecond = UInt64(limits.maxHysteriaBandwidthMbps) * 1_000_000 / 8
                try require(
                    bytesPerSecond.map { $0 == 0 || (65536 ... maxBytesPerSecond).contains($0) } == true,
                    path: "\(path)/\(key)", "QUIC bandwidth must be zero or between 65536 bytes/s and \(limits.maxHysteriaBandwidthMbps) Mbps.",
                )
            }
        }
    }

    func validateHopInterval(_ interval: JSONValue?, path: String) throws {
        if let interval {
            let range = (interval.stringValue ?? interval.integerValue.map(String.init)).flatMap(portRange)
            try require(range.map { $0.lowerBound >= 5 && $0.upperBound <= 3600 } == true, path: "\(path)/interval", "UDP hopping interval must be between 5 and 3600 seconds.")
        }
    }

    func validateHopPorts(_ settings: JSONObject, path: String) throws {
        try validateHopInterval(settings["interval"], path: path)
        guard let ports = settings["remotePorts"] else {
            throw XrayConfigError.validationFailed([XrayValidationIssue(path: path, message: "UDP hopping needs remotePorts on the profile endpoint.")])
        }
        let ranges = stringList(ports.stringValue ?? ports.integerValue.map(String.init) ?? "")
        let portPath = "\(path)/remotePorts"
        try require(!ranges.isEmpty, path: portPath, "UDP port hopping needs a port or range.")
        var count = 0
        for value in ranges {
            guard let range = portRange(value), range.lowerBound > 0 else {
                throw XrayConfigError.validationFailed([XrayValidationIssue(path: portPath, message: "Invalid UDP hop port or range.")])
            }
            // Xray expands each range, including overlaps, before opening a socket.
            count += range.count
            try require(count <= limits.maxHysteriaPortHops, path: portPath, "UDP hopping exceeds the iOS limit of \(limits.maxHysteriaPortHops) expanded ports.")
        }
    }

    func quicBandwidthBytesPerSecond(_ value: String) -> UInt64? {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if normalized.isEmpty {
            return 0
        }
        let number = normalized.prefix { $0.isASCII && ($0.isNumber || $0 == ".") }
        guard let amount = Double(number) else { return nil }
        let unit = normalized.dropFirst(number.count).trimmingCharacters(in: .whitespacesAndNewlines)
        let multiplier: Double
        switch unit {
        case "", "b", "bps": multiplier = 1
        case "k", "kb", "kbps": multiplier = 1024
        case "m", "mb", "mbps": multiplier = 1_048_576
        case "g", "gb", "gbps": multiplier = 1_073_741_824
        case "t", "tb", "tbps": multiplier = 1_099_511_627_776
        default: return nil
        }
        // Match Xray Bandwidth.Bps: binary unit multipliers, then whole bytes.
        return UInt64(exactly: (amount * multiplier).rounded(.towardZero)).map { $0 / 8 }
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
    let profilesByID: [ProxyProfile.ID: ProxyProfile]
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

        let originalProfileIDs = profileIDs
        let originalURLGroups = urlGroups
        var succeeded = false
        defer {
            if !succeeded {
                profileIDs = originalProfileIDs
                urlGroups = originalURLGroups
            }
        }

        switch group.type {
        case .select:
            var attempted: Set<OutboundTarget> = []
            if let selected = group.effectiveDefaultTarget {
                attempted.insert(deduplicationKey(for: selected))
                do {
                    let destination = try resolve(selected, activeGroups: &activeGroups, groupDepth: groupDepth)
                    succeeded = true
                    return destination
                } catch {
                    try rethrowFatalViolation()
                }
            }
            for member in group.members where attempted.insert(deduplicationKey(for: member)).inserted {
                do {
                    let destination = try resolve(member, activeGroups: &activeGroups, groupDepth: groupDepth)
                    succeeded = true
                    return destination
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
            succeeded = true
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

    private func fail<T>(_ path: String, _ message: XrayValidationMessage) throws -> T {
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
