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

/// Re-applies `ImportPolicy.validateSubscriptionURL` to every redirect target so
/// a subscription server cannot bounce the fetch to a cleartext or
/// private/loopback destination. Refusing a redirect (`completionHandler(nil)`)
/// lets the task complete with the 3xx response, which then fails the 2xx check.
private final class SubscriptionRedirectValidator: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _: URLSession,
        task _: URLSessionTask,
        willPerformHTTPRedirection _: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void,
    ) {
        guard let url = request.url, (try? ImportPolicy.validateSubscriptionURL(url)) != nil else {
            completionHandler(nil)
            return
        }
        completionHandler(request)
    }
}

struct ProxyImportService {
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

        // A dedicated session with a redirect validator. `URLSession.shared`
        // follows 3xx automatically, which would let a benign-looking HTTPS URL
        // bounce to http:// or to a private/loopback/metadata host, bypassing the
        // up-front `validateSubscriptionURL` check (SSRF, CWE-918).
        let session = URLSession(configuration: .ephemeral, delegate: SubscriptionRedirectValidator(), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        // Stream the body with a hard byte cap rather than buffering it whole.
        // `session.data(for:)` materializes the entire response in memory before
        // any size check, letting a malicious subscription server force a large
        // allocation; capping mid-stream bounds peak memory to maxPayloadBytes.
        let (bytes, response) = try await session.bytes(for: request)
        if let http = response as? HTTPURLResponse, !(200 ..< 300).contains(http.statusCode) {
            throw ProxyLinkParseError.subscriptionUnavailable
        }
        if response.expectedContentLength > Int64(ImportPolicy.maxPayloadBytes) {
            throw ProxyLinkParseError.payloadTooLarge
        }
        var data = Data()
        for try await byte in bytes {
            data.append(byte)
            if data.count > ImportPolicy.maxPayloadBytes {
                throw ProxyLinkParseError.payloadTooLarge
            }
        }
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

    private func parseShadowrocketConfig(_ text: String) -> ImportResult {
        var result = ImportResult()
        var section = ""

        for rawLine in text.components(separatedBy: .newlines).prefix(ImportPolicy.maxLines) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty, !line.hasPrefix("#"), !line.hasPrefix(";") else {
                continue
            }

            if line.hasPrefix("["), line.hasSuffix("]") {
                section = String(line.dropFirst().dropLast()).lowercased()
                continue
            }

            switch section {
            case "proxy":
                parseShadowrocketProxyLine(line, into: &result)
            case "proxy group":
                parseShadowrocketGroupLine(line, into: &result)
            case "rule":
                parseShadowrocketRuleLine(line, into: &result)
            default:
                continue
            }
        }

        return result
    }

    private func parseShadowrocketProxyLine(_ line: String, into result: inout ImportResult) {
        let parts = csvParts(line)
        guard let nameAndType = parts.first?.split(separator: "=", maxSplits: 1).map({ $0.trimmingCharacters(in: .whitespacesAndNewlines) }),
              nameAndType.count == 2
        else {
            result.warnings.append(ImportWarning(message: "Skipped malformed proxy line: \(ImportPolicy.redactForLog(line))"))
            return
        }

        let name = nameAndType[0]
        let type = nameAndType[1].lowercased()
        let values = Array(parts.dropFirst())
        let keyed = keyedOptions(values)

        guard values.count >= 2,
              let port = Int(values[1].trimmingCharacters(in: .whitespacesAndNewlines)),
              (1 ... 65535).contains(port)
        else {
            result.warnings.append(ImportWarning(message: "Skipped \(name): missing or out-of-range port."))
            return
        }

        let host = values[0].trimmingCharacters(in: .whitespacesAndNewlines)
        let security = shadowrocketSecurity(keyed: keyed, host: host, type: type)

        let profile: ProxyProfile?
        switch type {
        case "ss", "shadowsocks":
            guard let password = keyed["password"] ?? values[safe: 3],
                  let method = keyed["method"] ?? keyed["encrypt-method"] ?? values[safe: 2]
            else {
                result.warnings.append(ImportWarning(message: "Skipped \(name): Shadowsocks requires method and password."))
                return
            }
            profile = ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), proto: .shadowsocks, options: .shadowsocks(ShadowsocksOptions(method: method, password: password)), security: security)
        case "vmess":
            guard let password = keyed["password"] ?? values[safe: 3] else {
                result.warnings.append(ImportWarning(message: "Skipped \(name): VMess requires password UUID."))
                return
            }
            profile = ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), proto: .vmess, options: .vmess(VMessOptions(uuid: password, security: keyed["method"] ?? values[safe: 2] ?? "auto", alterID: Int(keyed["alterid"] ?? keyed["alter-id"] ?? "0") ?? 0)), security: security, transport: shadowrocketTransport(keyed: keyed))
        case "vless":
            guard let password = keyed["password"] ?? keyed["uuid"] ?? values[safe: 2] else {
                result.warnings.append(ImportWarning(message: "Skipped \(name): VLESS requires password UUID."))
                return
            }
            profile = ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), proto: .vless, options: .vless(VLESSOptions(uuid: password, flow: keyed["flow"], encryption: keyed["encryption"])), security: security, transport: shadowrocketTransport(keyed: keyed))
        case "trojan":
            guard let password = keyed["password"] ?? values[safe: 2] else {
                result.warnings.append(ImportWarning(message: "Skipped \(name): Trojan requires password."))
                return
            }
            profile = ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), proto: .trojan, options: .trojan(TrojanOptions(password: password)), security: security.layer == .none ? .tls(TLSOptions(serverName: host)) : security, transport: shadowrocketTransport(keyed: keyed))
        case "hysteria", "hysteria2":
            guard let auth = keyed["auth"] ?? keyed["password"] ?? values[safe: 2] else {
                result.warnings.append(ImportWarning(message: "Skipped \(name): Hysteria2 requires auth/password."))
                return
            }
            profile = ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), proto: .hysteria2, options: .hysteria2(Hysteria2Options(password: auth, obfs: keyed["obfs"], obfsPassword: keyedValue(keyed, "obfsparam", "obfs-param", "obfs_password", "obfs-password"))), security: security.layer == .none ? .tls(TLSOptions(serverName: host)) : security)
        case "tuic":
            guard let password = keyed["password"] ?? values[safe: 3],
                  let user = keyed["user"] ?? keyed["uuid"] ?? values[safe: 2]
            else {
                result.warnings.append(ImportWarning(message: "Skipped \(name): TUIC requires user and password."))
                return
            }
            profile = ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), proto: .tuic, options: .tuic(TUICOptions(uuid: user, password: password, congestionControl: keyedValue(keyed, "congestion-control", "congestion_control", "congestioncontrol"))), security: security.layer == .none ? .tls(TLSOptions(serverName: host)) : security)
        case "http", "https":
            profile = ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), proto: .http, options: .http(HTTPOptions(username: values[safe: 2], password: values[safe: 3])), security: security)
        case "socks5", "socks5-tls":
            profile = ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), proto: .socks, options: .socks(SOCKSOptions(username: values[safe: 2], password: values[safe: 3])), security: security)
        default:
            result.warnings.append(ImportWarning(message: "Imported unsupported proxy \(name) with type \(type) as a warning."))
            profile = nil
        }

        if let profile {
            result.profiles.append(profile)
            appendRuntimeWarnings(for: profile, label: name, to: &result)
            if profile.security.tls?.allowInsecure == true {
                result.warnings.append(ImportWarning(message: "\(name) disables TLS certificate verification (allow-insecure)."))
            }
        }
    }

    private func appendRuntimeWarnings(for profile: ProxyProfile, label: String, to result: inout ImportResult) {
        for warning in profile.importRuntimeWarnings {
            result.warnings.append(ImportWarning(message: "\(label): \(warning)"))
        }
    }

    private func parseShadowrocketGroupLine(_ line: String, into result: inout ImportResult) {
        let parts = csvParts(line)
        guard let first = parts.first?.split(separator: "=", maxSplits: 1).map({ $0.trimmingCharacters(in: .whitespacesAndNewlines) }),
              first.count == 2
        else {
            result.warnings.append(ImportWarning(message: "Skipped malformed proxy group: \(ImportPolicy.redactForLog(line))"))
            return
        }

        let name = first[0]
        let importedType = first[1].lowercased()
        let values = Array(parts.dropFirst())
        let keyed = keyedOptions(values)
        let memberNames = values.filter { !$0.contains("=") }
        let members = memberNames.map { OutboundTarget.named($0.trimmingCharacters(in: .whitespacesAndNewlines)) }

        switch importedType {
        case "select":
            result.groups.append(
                ProxyGroup(
                    name: name,
                    type: .select,
                    members: members,
                    defaultTarget: keyed["policy-select-name"].map(OutboundTarget.named) ?? members.first,
                    importedType: importedType,
                ),
            )
        case "url-test", "urltest":
            var resolvedMembers = members
            var groupWarning: String?
            if let filter = keyed["policy-regex-filter"] {
                if ImportPolicy.isSafeRegexPattern(filter) {
                    if resolvedMembers.isEmpty {
                        resolvedMembers = result.profiles
                            // Bound the input length too: the filter passed the
                            // nested-quantifier check, but cap match cost regardless.
                            .filter { $0.name.count <= 256 && $0.name.range(of: filter, options: .regularExpression) != nil }
                            .map { .profile($0.id) }
                    }
                    groupWarning = "Members matched by regex: \(filter)"
                } else {
                    result.warnings.append(ImportWarning(message: "Group \(name): ignored unsafe policy-regex-filter."))
                    groupWarning = "Ignored unsafe policy-regex-filter."
                }
            }

            let requestedURL = keyed["url"] ?? ProxyGroupTestOptions.defaultURL
            let probeURL: String
            if ImportPolicy.isAllowedProbeURL(requestedURL) {
                probeURL = requestedURL
            } else {
                probeURL = ProxyGroupTestOptions.defaultURL
                result.warnings.append(ImportWarning(message: "Group \(name): replaced disallowed URL-test URL with the default."))
            }

            result.groups.append(
                ProxyGroup(
                    name: name,
                    type: .urlTest,
                    members: resolvedMembers,
                    defaultTarget: resolvedMembers.first,
                    testOptions: ProxyGroupTestOptions(
                        url: probeURL,
                        intervalSeconds: ImportPolicy.clampURLTestInterval(Int(keyed["interval"] ?? "600") ?? 600),
                        toleranceMilliseconds: ImportPolicy.clampURLTestTolerance(Int(keyed["tolerance"] ?? "50") ?? 50),
                    ),
                    importedType: importedType,
                    warning: groupWarning,
                ),
            )
        default:
            result.groups.append(
                ProxyGroup(
                    name: name,
                    type: .unsupported,
                    members: members,
                    isEnabled: false,
                    importedType: importedType,
                    warning: "Unsupported Shadowrocket group type: \(importedType)",
                ),
            )
            result.warnings.append(ImportWarning(message: "Group \(name) uses unsupported type \(importedType)."))
        }
    }

    private func parseShadowrocketRuleLine(_ line: String, into result: inout ImportResult) {
        let parts = csvParts(line)
        guard parts.count >= 2 else {
            result.warnings.append(ImportWarning(message: "Skipped malformed rule: \(ImportPolicy.redactForLog(line))"))
            return
        }

        let kindName = parts[0].trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        let value: String
        let targetName: String

        if kindName == "FINAL" || kindName == "MATCH" {
            value = "*"
            targetName = parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            guard parts.count >= 3 else {
                result.warnings.append(ImportWarning(message: "Skipped malformed rule: \(ImportPolicy.redactForLog(line))"))
                return
            }
            value = parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
            targetName = parts[2].trimmingCharacters(in: .whitespacesAndNewlines)
        }

        guard let kind = shadowrocketRuleKind(kindName) else {
            result.warnings.append(ImportWarning(message: "Skipped unsupported rule type \(kindName)."))
            return
        }

        if kind == .domainRegex, !ImportPolicy.isSafeRegexPattern(value) {
            result.warnings.append(ImportWarning(message: "Skipped DOMAIN-REGEX rule with an unsafe or oversized pattern."))
            return
        }

        result.rules.append(RoutingRule(kind: kind, value: value, target: shadowrocketTarget(targetName)))
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

    private func shadowrocketSecurity(keyed: [String: String], host: String, type: String) -> ProxySecurity {
        let security = (keyedValue(keyed, "security", "tls") ?? "").lowercased()
        let serverName = keyedValue(keyed, "peer", "sni", "servername", "server_name", "server-name") ?? host
        let alpn = alpnValues(from: keyedValue(keyed, "alpn"))
        let fingerprint = keyedValue(keyed, "fingerprint", "fp", "utlsfingerprint", "utls_fingerprint", "utls-fingerprint", "clientfingerprint", "client_fingerprint", "client-fingerprint") ?? "chrome"
        let hasRealityFields = keyedValue(keyed, "pbk", "publickey", "public_key", "public-key", "sid", "shortid", "short_id", "short-id", "spx", "spiderx", "spider_x", "spider-x", "pqv", "mldsa65verify", "mldsa65_verify", "mldsa65-verify") != nil
        let isReality = type == "vless" && (security == "reality" || boolOption(keyedValue(keyed, "reality")) || hasRealityFields)

        if isReality {
            return ProxySecurity(
                layer: .reality,
                tls: TLSOptions(
                    serverName: serverName,
                    alpn: alpn,
                    allowInsecure: false,
                    utlsFingerprint: fingerprint,
                ),
                reality: RealityOptions(
                    publicKey: keyedValue(keyed, "pbk", "publickey", "public_key", "public-key", "password") ?? "",
                    shortID: keyedValue(keyed, "sid", "shortid", "short_id", "short-id"),
                    serverName: serverName,
                    spiderX: keyedValue(keyed, "spx", "spiderx", "spider_x", "spider-x", "spider"),
                    mldsa65Verify: keyedValue(keyed, "pqv", "mldsa65verify", "mldsa65_verify", "mldsa65-verify"),
                    utlsFingerprint: fingerprint,
                ),
            )
        }

        let isTLS = security == "tls" || boolOption(keyedValue(keyed, "tls")) || type == "https" || type == "socks5-tls"
        guard isTLS else {
            return .none
        }

        return .tls(
            TLSOptions(
                serverName: serverName,
                alpn: alpn,
                allowInsecure: boolOption(keyedValue(keyed, "allowinsecure", "allow_insecure", "allow-insecure", "skip-common-name-verify", "skipcertverify", "skip_cert_verify", "skip-cert-verify")),
                utlsFingerprint: fingerprint,
            ),
        )
    }

    private func shadowrocketTransport(keyed: [String: String]) -> TransportOptions {
        switch (keyed["obfs"] ?? keyed["type"] ?? "").lowercased() {
        case "websocket", "ws":
            TransportOptions(type: .websocket, path: keyed["path"] ?? keyed["obfs-uri"], host: keyed["host"] ?? keyed["obfs-host"], serviceName: nil)
        case "grpc":
            TransportOptions(type: .grpc, serviceName: keyedValue(keyed, "service-name", "service_name", "servicename", "grpc-service-name", "grpc_service_name"))
        case "http", "httpupgrade", "http-upgrade":
            TransportOptions(type: .httpUpgrade, path: keyed["path"], host: keyed["host"], serviceName: nil)
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

    private func csvParts(_ line: String) -> [String] {
        var result: [String] = []
        var current = ""
        var isQuoted = false

        for character in line {
            if character == "\"" {
                isQuoted.toggle()
            } else if character == ",", !isQuoted {
                result.append(current.trimmingCharacters(in: .whitespacesAndNewlines))
                current = ""
            } else {
                current.append(character)
            }
        }

        result.append(current.trimmingCharacters(in: .whitespacesAndNewlines))
        return result.filter { !$0.isEmpty }
    }

    private func keyedOptions(_ values: [String]) -> [String: String] {
        values.reduce(into: [:]) { result, value in
            let parts = value.split(separator: "=", maxSplits: 1).map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            guard parts.count == 2 else {
                return
            }
            result[parts[0].lowercased()] = parts[1]
        }
    }

    private func shadowrocketRuleKind(_ value: String) -> RoutingRuleKind? {
        switch value {
        case "DOMAIN":
            .domain
        case "DOMAIN-SUFFIX":
            .domainSuffix
        case "DOMAIN-KEYWORD":
            .domainKeyword
        case "DOMAIN-REGEX":
            .domainRegex
        case "IP-CIDR", "IP-CIDR6":
            .ipCIDR
        case "GEOIP":
            .geoIP
        case "GEOSITE":
            .geoSite
        case "USER-AGENT":
            nil
        case "FINAL", "MATCH":
            .final
        default:
            nil
        }
    }

    private func shadowrocketTarget(_ value: String) -> OutboundTarget {
        switch value.lowercased() {
        case "direct":
            .direct
        case "reject", "reject-tinygif", "reject-dict":
            .reject
        case "proxy":
            .selectedProxy
        default:
            .named(value)
        }
    }

    private func boolOption(_ value: String?) -> Bool {
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

    private func alpnValues(from value: String?) -> [String] {
        guard let value else {
            return []
        }
        return value
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    private func keyedValue(_ values: [String: String], _ keys: String...) -> String? {
        for key in keys {
            if let value = values[key.lowercased()] {
                return value
            }
        }
        return nil
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

private extension Array {
    subscript(safe index: Int) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}
