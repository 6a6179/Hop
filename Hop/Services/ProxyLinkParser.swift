import Foundation

enum ProxyLinkParseError: LocalizedError {
    case unsupportedScheme(String)
    case invalidURL
    case missingCredentials
    case missingHost
    case missingPort
    case noImportableItems
    case insecureSubscriptionURL
    case disallowedSubscriptionHost
    case payloadTooLarge
    case subscriptionUnavailable

    var errorDescription: String? {
        switch self {
        case let .unsupportedScheme(scheme):
            "Unsupported proxy scheme: \(scheme)"
        case .invalidURL:
            "The proxy link is not a valid URL."
        case .missingCredentials:
            "The proxy link is missing credentials."
        case .missingHost:
            "The proxy link is missing a host."
        case .missingPort:
            "The proxy link is missing a port."
        case .noImportableItems:
            "No importable profiles, groups, or rules were found."
        case .insecureSubscriptionURL:
            "Subscription URLs must use HTTPS."
        case .disallowedSubscriptionHost:
            "Subscription URLs cannot point to local, private, or metadata addresses."
        case .payloadTooLarge:
            "The import payload is too large to process safely."
        case .subscriptionUnavailable:
            "The subscription could not be downloaded."
        }
    }
}

struct ProxyLinkParser {
    private let service = ProxyImportService()

    func parse(_ rawValue: String) throws -> ProxyProfile {
        guard let profile = try service.importText(rawValue).profiles.first else {
            throw ProxyLinkParseError.noImportableItems
        }
        return profile
    }
}

struct ProxyImportService {
    /// Session configuration for subscription fetches; tests substitute one
    /// with a stub `URLProtocol` to exercise the transfer policy offline.
    var subscriptionSessionConfiguration: URLSessionConfiguration = .ephemeral

    func importText(_ rawValue: String) throws -> ImportResult {
        guard rawValue.utf8.count <= ImportPolicy.maxPayloadBytes else {
            throw ProxyLinkParseError.payloadTooLarge
        }
        return try importText(rawValue, depth: 0)
    }

    private func importText(_ rawValue: String, depth: Int) throws -> ImportResult {
        let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw ProxyLinkParseError.invalidURL
        }

        if looksLikeShadowrocketConfig(trimmed) {
            return parseShadowrocketConfig(trimmed).truncated(to: ImportPolicy.maxImportedItems)
        }

        let decoded = decodeBase64String(trimmed)
        if let decoded, looksLikeShadowrocketConfig(decoded) {
            return parseShadowrocketConfig(decoded).truncated(to: ImportPolicy.maxImportedItems)
        }

        let lines = importLines(from: decoded ?? trimmed)
        var result = ImportResult()

        for line in lines {
            do {
                let profile = try parseProfileLink(line)
                result.profiles.append(profile)
                appendRuntimeWarnings(for: profile, label: ImportPolicy.redactForLog(line), to: &result)
                if profile.security.tls?.allowInsecure == true {
                    result.warnings.append(ImportWarning(
                        message: "\(ImportPolicy.redactForLog(line)) disables TLS certificate verification (allow-insecure).",
                    ))
                }
            } catch {
                result.warnings.append(ImportWarning(
                    message: "\(ImportPolicy.redactForLog(line)): \(error.localizedDescription)",
                ))
            }
        }

        if result.isEmpty, let decoded, decoded != trimmed, depth < ImportPolicy.maxDecodeDepth {
            return try importText(decoded, depth: depth + 1)
        }

        if result.isEmpty {
            throw ProxyLinkParseError.noImportableItems
        }

        return result.truncated(to: ImportPolicy.maxImportedItems)
    }

    func importSubscription(url: URL) async throws -> ImportResult {
        try ImportPolicy.validateSubscriptionURL(url)

        var request = URLRequest(url: url)
        request.timeoutInterval = ImportPolicy.subscriptionRequestTimeout
        request.cachePolicy = .reloadIgnoringLocalCacheData

        // A dedicated fetcher rather than `URLSession.shared`: it re-validates
        // every redirect target (which would otherwise bypass the up-front
        // `validateSubscriptionURL` check) and enforces the payload cap
        // mid-stream so peak memory stays bounded. See `SubscriptionFetcher`.
        let data = try await SubscriptionFetcher.fetch(request, configuration: subscriptionSessionConfiguration)
        guard let text = String(data: data, encoding: .utf8) else {
            throw ProxyLinkParseError.invalidURL
        }
        return try importText(text)
    }

    private func parseProfileLink(_ rawValue: String) throws -> ProxyProfile {
        let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: trimmed), let scheme = components.scheme?.lowercased() else {
            throw ProxyLinkParseError.invalidURL
        }

        switch scheme {
        case "vless":
            return try parseVLESS(components: components)
        case "trojan":
            return try parseTrojan(components: components)
        case "hysteria2", "hy2":
            return try parseHysteria2(components: components)
        case "tuic":
            return try parseTUIC(components: components)
        case "ss":
            return try parseShadowsocks(rawValue: trimmed, components: components)
        case "vmess":
            return try parseVMess(rawValue: trimmed, components: components)
        case "http", "https":
            return try parseHTTP(components: components, isTLS: scheme == "https")
        case "socks", "socks5", "socks5+tls":
            return try parseSOCKS(components: components, isTLS: scheme == "socks5+tls")
        case "ssr", "snell":
            throw ProxyLinkParseError.unsupportedScheme("\(scheme) is imported as an unsupported warning because sing-box mapping is not wired yet")
        default:
            throw ProxyLinkParseError.unsupportedScheme(scheme)
        }
    }

    private func parseVLESS(components: URLComponents) throws -> ProxyProfile {
        let uuid = try requiredUser(components)
        let endpoint = try endpoint(from: components)
        let query = Query(components)
        let security = parseSecurity(query: query, fallbackServerName: endpoint.host)

        return ProxyProfile(
            name: displayName(from: components, fallback: "VLESS \(endpoint.host)"),
            endpoint: endpoint,
            proto: .vless,
            options: .vless(VLESSOptions(uuid: uuid, flow: query["flow"], encryption: query["encryption"])),
            security: security,
            transport: parseTransport(query: query),
        )
    }

    private func parseTrojan(components: URLComponents) throws -> ProxyProfile {
        let password = try requiredUser(components)
        let endpoint = try endpoint(from: components)
        let query = Query(components)
        let security = parseSecurity(query: query, fallbackServerName: endpoint.host)

        return ProxyProfile(
            name: displayName(from: components, fallback: "Trojan \(endpoint.host)"),
            endpoint: endpoint,
            proto: .trojan,
            options: .trojan(TrojanOptions(password: password)),
            security: security.layer == .none ? .tls(TLSOptions(serverName: endpoint.host)) : security,
            transport: parseTransport(query: query),
        )
    }

    private func parseHysteria2(components: URLComponents) throws -> ProxyProfile {
        let password = try requiredUser(components)
        let endpoint = try endpoint(from: components)
        let query = Query(components)

        return ProxyProfile(
            name: displayName(from: components, fallback: "Hysteria2 \(endpoint.host)"),
            endpoint: endpoint,
            proto: .hysteria2,
            options: .hysteria2(
                Hysteria2Options(
                    password: password,
                    obfs: query["obfs"],
                    obfsPassword: query["obfs-password"] ?? query["obfs_password"] ?? query["obfsParam"],
                ),
            ),
            security: parseSecurity(query: query, fallbackServerName: endpoint.host),
            transport: .tcp,
        )
    }

    private func parseTUIC(components: URLComponents) throws -> ProxyProfile {
        let uuid = try requiredUser(components)
        guard let password = components.password?.removingPercentEncoding, !password.isEmpty else {
            throw ProxyLinkParseError.missingCredentials
        }
        let endpoint = try endpoint(from: components)
        let query = Query(components)

        return ProxyProfile(
            name: displayName(from: components, fallback: "TUIC \(endpoint.host)"),
            endpoint: endpoint,
            proto: .tuic,
            options: .tuic(
                TUICOptions(
                    uuid: uuid,
                    password: password,
                    congestionControl: query["congestion_control"] ?? query["congestionControl"],
                ),
            ),
            security: parseSecurity(query: query, fallbackServerName: endpoint.host),
            transport: .tcp,
        )
    }

    private func parseShadowsocks(rawValue: String, components: URLComponents) throws -> ProxyProfile {
        if let legacyProfile = try legacyShadowsocksProfile(rawValue: rawValue, components: components) {
            return legacyProfile
        }

        let endpoint = try endpoint(from: components)
        let query = Query(components)
        let name = displayName(from: components, fallback: "Shadowsocks \(endpoint.host)")

        let userInfo = try shadowsocksUserInfo(rawValue: rawValue, components: components)
        let parts = userInfo.split(separator: ":", maxSplits: 1).map(String.init)
        guard parts.count == 2 else {
            throw ProxyLinkParseError.missingCredentials
        }

        return ProxyProfile(
            name: name,
            endpoint: endpoint,
            proto: .shadowsocks,
            options: .shadowsocks(ShadowsocksOptions(method: parts[0], password: parts[1])),
            security: parseSecurity(query: query, fallbackServerName: endpoint.host),
            transport: .tcp,
        )
    }

    private func legacyShadowsocksProfile(rawValue: String, components: URLComponents) throws -> ProxyProfile? {
        let payload = rawValue.dropFirst("ss://".count)
        let withoutFragment = payload.split(separator: "#", maxSplits: 1).first.map(String.init) ?? String(payload)
        let withoutQuery = withoutFragment.split(separator: "?", maxSplits: 1).first.map(String.init) ?? withoutFragment

        guard !withoutQuery.contains("@"),
              let decoded = decodeBase64String(withoutQuery),
              decoded.contains("@")
        else {
            return nil
        }

        let name = displayName(from: components, fallback: "Shadowsocks")
        let userAndServer = decoded.split(separator: "@", maxSplits: 1).map(String.init)
        guard userAndServer.count == 2 else {
            throw ProxyLinkParseError.missingCredentials
        }

        let credentials = userAndServer[0].split(separator: ":", maxSplits: 1).map(String.init)
        guard credentials.count == 2 else {
            throw ProxyLinkParseError.missingCredentials
        }

        let server = userAndServer[1].split(separator: ":", maxSplits: 1).map(String.init)
        guard server.count == 2, let port = Int(server[1]), (1 ... 65535).contains(port) else {
            throw ProxyLinkParseError.missingPort
        }

        return ProxyProfile(
            name: name,
            endpoint: Endpoint(host: server[0], port: port),
            proto: .shadowsocks,
            options: .shadowsocks(ShadowsocksOptions(method: credentials[0], password: credentials[1])),
            security: .none,
            transport: .tcp,
        )
    }

    private func parseVMess(rawValue: String, components: URLComponents) throws -> ProxyProfile {
        let payload = String(rawValue.dropFirst("vmess://".count))
        if let json = decodeBase64String(payload),
           let data = json.data(using: .utf8),
           let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        {
            let host = try stringValue(object["add"], error: .missingHost)
            let port = try intValue(object["port"], error: .missingPort)
            // Match the port validation every other parser applies; an
            // out-of-range port would otherwise reach the generated config as
            // `server_port: 0`, failing the tunnel with no useful diagnostic.
            guard (1 ... 65535).contains(port) else { throw ProxyLinkParseError.missingPort }
            let uuid = try stringValue(object["id"], error: .missingCredentials)
            let network = (object["net"] as? String) ?? "tcp"
            let tlsValue = ((object["tls"] as? String) ?? "").lowercased()
            let sni = (object["sni"] as? String) ?? (object["host"] as? String)
            let security: ProxySecurity = tlsValue == "tls" ? .tls(TLSOptions(
                serverName: sni ?? host,
                alpn: alpnValues(from: object["alpn"] as? String),
                allowInsecure: boolValue(from: object["allowInsecure"]) ?? boolValue(from: object["skip-cert-verify"]) ?? false,
                utlsFingerprint: (object["fp"] as? String) ?? (object["fingerprint"] as? String) ?? "chrome",
            )) : .none
            let transport = transportFromVMess(network: network, path: object["path"] as? String, host: object["host"] as? String)

            return ProxyProfile(
                name: (object["ps"] as? String)?.nilIfEmpty ?? "VMess \(host)",
                endpoint: Endpoint(host: host, port: port),
                proto: .vmess,
                options: .vmess(
                    VMessOptions(
                        uuid: uuid,
                        security: (object["scy"] as? String)?.nilIfEmpty ?? (object["type"] as? String)?.nilIfEmpty ?? "auto",
                        alterID: intValueOrZero(object["aid"]),
                    ),
                ),
                security: security,
                transport: transport,
            )
        }

        let endpoint = try endpoint(from: components)
        let query = Query(components)
        return try ProxyProfile(
            name: displayName(from: components, fallback: "VMess \(endpoint.host)"),
            endpoint: endpoint,
            proto: .vmess,
            options: .vmess(
                VMessOptions(
                    uuid: requiredUser(components),
                    security: query.first("encryption", "scy", "method") ?? "auto",
                    alterID: Int(query["alterId"] ?? query["alter_id"] ?? "0") ?? 0,
                ),
            ),
            security: parseSecurity(query: query, fallbackServerName: endpoint.host),
            transport: parseTransport(query: query),
        )
    }

    private func parseHTTP(components: URLComponents, isTLS: Bool) throws -> ProxyProfile {
        let endpoint = try endpoint(from: components)
        let username = components.user?.removingPercentEncoding
        let password = components.password?.removingPercentEncoding
        return ProxyProfile(
            name: displayName(from: components, fallback: "\(isTLS ? "HTTPS" : "HTTP") \(endpoint.host)"),
            endpoint: endpoint,
            proto: .http,
            options: .http(HTTPOptions(username: username, password: password)),
            security: isTLS ? .tls(TLSOptions(serverName: endpoint.host)) : .none,
        )
    }

    private func parseSOCKS(components: URLComponents, isTLS: Bool) throws -> ProxyProfile {
        let endpoint = try endpoint(from: components)
        let username = components.user?.removingPercentEncoding
        let password = components.password?.removingPercentEncoding
        return ProxyProfile(
            name: displayName(from: components, fallback: "SOCKS \(endpoint.host)"),
            endpoint: endpoint,
            proto: .socks,
            options: .socks(SOCKSOptions(username: username, password: password)),
            security: isTLS ? .tls(TLSOptions(serverName: endpoint.host)) : .none,
        )
    }

    func appendRuntimeWarnings(for profile: ProxyProfile, label: String, to result: inout ImportResult) {
        for warning in profile.importRuntimeWarnings {
            result.warnings.append(ImportWarning(message: "\(label): \(warning)"))
        }
    }

    private func parseSecurity(query: Query, fallbackServerName: String) -> ProxySecurity {
        let security = (query.first("security", "tls") ?? "").lowercased()
        let serverName = query.first("sni", "serverName", "server_name", "server-name", "peer") ?? fallbackServerName
        let alpn = alpnValues(from: query.first("alpn"))
        let fingerprint = query.first("fp", "fingerprint", "utlsFingerprint", "utls_fingerprint", "utls-fingerprint", "clientFingerprint", "client_fingerprint", "client-fingerprint") ?? "chrome"
        let allowInsecure = boolOption(query.first("allowInsecure", "allow_insecure", "allow-insecure", "insecure", "skipCertVerify", "skip_cert_verify", "skip-cert-verify"))

        if security == "reality" {
            return ProxySecurity(
                layer: .reality,
                tls: TLSOptions(
                    serverName: serverName,
                    alpn: alpn,
                    allowInsecure: false,
                    utlsFingerprint: fingerprint,
                ),
                reality: RealityOptions(
                    publicKey: query.first("pbk", "publicKey", "public_key", "public-key", "password") ?? "",
                    shortID: query.first("sid", "shortId", "short_id", "short-id"),
                    serverName: serverName,
                    spiderX: query.first("spx", "spiderX", "spider_x", "spider-x", "spider"),
                    mldsa65Verify: query.first("pqv", "mldsa65Verify", "mldsa65_verify", "mldsa65-verify"),
                    utlsFingerprint: fingerprint,
                ),
            )
        }

        if security == "tls" || boolOption(query["tls"]) || query["sni"] != nil || query["alpn"] != nil {
            return .tls(
                TLSOptions(
                    serverName: serverName,
                    alpn: alpn,
                    allowInsecure: allowInsecure,
                    utlsFingerprint: fingerprint,
                ),
            )
        }

        return .none
    }

    private func parseTransport(query: Query) -> TransportOptions {
        switch (query["type"] ?? query["net"] ?? "").lowercased() {
        case "ws", "websocket":
            TransportOptions(type: .websocket, path: query["path"], host: query["host"], serviceName: nil)
        case "grpc":
            TransportOptions(type: .grpc, path: nil, host: nil, serviceName: query["serviceName"] ?? query["service_name"])
        case "httpupgrade", "http-upgrade":
            TransportOptions(type: .httpUpgrade, path: query["path"], host: query["host"], serviceName: nil)
        case "quic":
            TransportOptions(type: .quic)
        default:
            .tcp
        }
    }

    private func transportFromVMess(network: String, path: String?, host: String?) -> TransportOptions {
        switch network.lowercased() {
        case "ws", "websocket":
            TransportOptions(type: .websocket, path: path, host: host, serviceName: nil)
        case "grpc":
            TransportOptions(type: .grpc, path: nil, host: nil, serviceName: path)
        case "h2", "http":
            TransportOptions(type: .httpUpgrade, path: path, host: host, serviceName: nil)
        default:
            .tcp
        }
    }

    private func endpoint(from components: URLComponents) throws -> Endpoint {
        guard let host = components.host?.removingPercentEncoding, !host.isEmpty else {
            throw ProxyLinkParseError.missingHost
        }
        // URLComponents accepts ports like 0 or 99999; reject them here so the
        // generated config never carries an invalid server_port.
        guard let port = components.port, (1 ... 65535).contains(port) else {
            throw ProxyLinkParseError.missingPort
        }
        return Endpoint(host: host, port: port)
    }

    private func requiredUser(_ components: URLComponents) throws -> String {
        guard let user = components.user?.removingPercentEncoding, !user.isEmpty else {
            throw ProxyLinkParseError.missingCredentials
        }
        return user
    }

    private func displayName(from components: URLComponents, fallback: String) -> String {
        components.fragment?.removingPercentEncoding.nilIfEmpty ?? fallback
    }

    private func shadowsocksUserInfo(rawValue: String, components: URLComponents) throws -> String {
        if let user = components.user?.removingPercentEncoding, !user.isEmpty {
            if let decoded = decodeBase64String(user), decoded.contains(":") {
                return decoded
            }
            return user
        }

        let payload = rawValue.dropFirst("ss://".count)
        let withoutFragment = payload.split(separator: "#", maxSplits: 1).first.map(String.init) ?? String(payload)
        let withoutQuery = withoutFragment.split(separator: "?", maxSplits: 1).first.map(String.init) ?? withoutFragment
        let encodedUser = withoutQuery.split(separator: "@", maxSplits: 1).first.map(String.init) ?? withoutQuery

        if let decoded = decodeBase64String(encodedUser), decoded.contains(":") {
            return decoded
        }

        throw ProxyLinkParseError.missingCredentials
    }

    private func importLines(from text: String) -> [String] {
        text.components(separatedBy: .newlines)
            .prefix(ImportPolicy.maxLines)
            .flatMap { $0.components(separatedBy: CharacterSet(charactersIn: " \t")) }
            // Re-cap after whitespace tokenization: a single newline-free line
            // packed with spaces yields one "line" that explodes into millions
            // of tokens, each then fed to URLComponents (CPU/memory DoS).
            .prefix(ImportPolicy.maxLines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .filter { URLComponents(string: $0)?.scheme != nil }
    }

    private func looksLikeShadowrocketConfig(_ text: String) -> Bool {
        text.contains("[Proxy]") || text.contains("[Proxy Group]") || text.contains("[Rule]")
    }

    private func decodeBase64String(_ value: String) -> String? {
        // Strip all whitespace (not just leading/trailing) before computing
        // padding: RFC 2045-style wrapped base64 carries internal newlines that
        // would otherwise inflate the count and mis-pad unpadded payloads.
        let compacted = value.filter { !$0.isWhitespace }
        let normalized = compacted
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padded = normalized.padding(toLength: ((normalized.count + 3) / 4) * 4, withPad: "=", startingAt: 0)
        guard let data = Data(base64Encoded: padded, options: [.ignoreUnknownCharacters]),
              data.count <= ImportPolicy.maxDecodedBytes
        else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    func boolOption(_ value: String?) -> Bool {
        guard let value else {
            return false
        }
        return switch value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "true", "yes", "1", "tls":
            true
        default:
            false
        }
    }

    private func boolValue(from value: String?) -> Bool? {
        guard let value else {
            return nil
        }
        return switch value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "true", "yes", "1", "tls":
            true
        case "false", "no", "0", "none":
            false
        default:
            nil
        }
    }

    private func boolValue(from value: Any?) -> Bool? {
        if let value = value as? Bool {
            return value
        }
        if let value = value as? NSNumber {
            return value.boolValue
        }
        return boolValue(from: value as? String)
    }

    func alpnValues(from value: String?) -> [String] {
        guard let value else {
            return []
        }
        return value
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    private func stringValue(_ value: Any?, error: ProxyLinkParseError) throws -> String {
        if let value = value as? String, !value.isEmpty {
            return value
        }
        if let number = value as? NSNumber {
            return number.stringValue
        }
        throw error
    }

    private func intValue(_ value: Any?, error: ProxyLinkParseError) throws -> Int {
        if let value = value as? Int {
            return value
        }
        if let value = value as? String, let intValue = Int(value) {
            return intValue
        }
        if let value = value as? NSNumber {
            return value.intValue
        }
        throw error
    }

    private func intValueOrZero(_ value: Any?) -> Int {
        (try? intValue(value, error: .missingCredentials)) ?? 0
    }
}

private struct Query {
    private var values: [String: String] = [:]

    init(_ components: URLComponents) {
        for item in components.queryItems ?? [] {
            guard let value = item.value?.removingPercentEncoding else {
                continue
            }
            values[item.name] = value
            values[item.name.lowercased()] = value
        }
    }

    subscript(_ key: String) -> String? {
        values[key] ?? values[key.lowercased()]
    }

    func first(_ keys: String...) -> String? {
        for key in keys {
            if let value = self[key] {
                return value
            }
        }
        return nil
    }
}

private extension String {
    var nilIfEmpty: String? {
        isEmpty ? nil : self
    }
}

private extension String? {
    var nilIfEmpty: String? {
        guard let self, !self.isEmpty else {
            return nil
        }
        return self
    }
}
