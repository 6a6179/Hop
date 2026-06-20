import Foundation

/// Shadowrocket `.conf` parsing: `[Proxy]`, `[Proxy Group]`, and `[Rule]`
/// sections. Split from the share-link parsing in `ProxyLinkParser.swift`;
/// `importText` routes here when the payload looks like a config file.
extension ProxyImportService {
    func parseShadowrocketConfig(_ text: String) -> ImportResult {
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
            profile = ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), options: .shadowsocks(ShadowsocksOptions(method: method, password: password)), security: security)
        case "vmess":
            guard let password = keyed["password"] ?? values[safe: 3] else {
                result.warnings.append(ImportWarning(message: "Skipped \(name): VMess requires password UUID."))
                return
            }
            profile = ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), options: .vmess(VMessOptions(uuid: password, security: keyed["method"] ?? values[safe: 2] ?? "auto", alterID: Int(keyed["alterid"] ?? keyed["alter-id"] ?? "0") ?? 0)), security: security, transport: shadowrocketTransport(keyed: keyed))
        case "vless":
            guard let password = keyed["password"] ?? keyed["uuid"] ?? values[safe: 2] else {
                result.warnings.append(ImportWarning(message: "Skipped \(name): VLESS requires password UUID."))
                return
            }
            profile = ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), options: .vless(VLESSOptions(uuid: password, flow: keyed["flow"], encryption: keyed["encryption"])), security: security, transport: shadowrocketTransport(keyed: keyed))
        case "trojan":
            guard let password = keyed["password"] ?? values[safe: 2] else {
                result.warnings.append(ImportWarning(message: "Skipped \(name): Trojan requires password."))
                return
            }
            profile = ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), options: .trojan(TrojanOptions(password: password)), security: security.layer == .none ? .tls(TLSOptions(serverName: host)) : security, transport: shadowrocketTransport(keyed: keyed))
        case "hysteria", "hysteria2":
            guard let auth = keyed["auth"] ?? keyed["password"] ?? values[safe: 2] else {
                result.warnings.append(ImportWarning(message: "Skipped \(name): Hysteria2 requires auth/password."))
                return
            }
            profile = ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), options: .hysteria2(Hysteria2Options(password: auth, obfs: keyed["obfs"], obfsPassword: keyedValue(keyed, "obfsparam", "obfs-param", "obfs_password", "obfs-password"))), security: security.layer == .none ? .tls(TLSOptions(serverName: host)) : security)
        case "tuic":
            guard let password = keyed["password"] ?? values[safe: 3],
                  let user = keyed["user"] ?? keyed["uuid"] ?? values[safe: 2]
            else {
                result.warnings.append(ImportWarning(message: "Skipped \(name): TUIC requires user and password."))
                return
            }
            profile = ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), options: .tuic(TUICOptions(uuid: user, password: password, congestionControl: keyedValue(keyed, "congestion-control", "congestion_control", "congestioncontrol"))), security: security.layer == .none ? .tls(TLSOptions(serverName: host)) : security)
        case "http", "https":
            profile = ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), options: .http(HTTPOptions(username: values[safe: 2], password: values[safe: 3])), security: security)
        case "socks5", "socks5-tls":
            profile = ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), options: .socks(SOCKSOptions(username: values[safe: 2], password: values[safe: 3])), security: security)
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
        let members = memberNames.map { shadowrocketTarget($0.trimmingCharacters(in: .whitespacesAndNewlines)) }

        switch importedType {
        case "select":
            result.groups.append(
                ProxyGroup(
                    name: name,
                    type: .select,
                    members: members,
                    defaultTarget: keyed["policy-select-name"].map(shadowrocketTarget) ?? members.first,
                    importedType: importedType,
                ),
            )
        case "url-test", "urltest":
            var resolvedMembers = members
            var groupWarning: String?
            if let filter = keyed["policy-regex-filter"] {
                let literalFilter = filter.trimmingCharacters(in: .whitespacesAndNewlines)
                if !literalFilter.isEmpty, literalFilter.utf8.count <= ImportPolicy.maxRegexPatternLength {
                    if resolvedMembers.isEmpty {
                        // Do not evaluate import-supplied regex with ICU here:
                        // even conservative pattern checks miss ambiguous
                        // alternations such as `(a|aa)+$`. Treat the imported
                        // filter as a bounded literal substring instead.
                        resolvedMembers = result.profiles
                            .filter { $0.name.count <= 256 && $0.name.localizedCaseInsensitiveContains(literalFilter) }
                            .map { .profile($0.id) }
                    }
                    groupWarning = "Members matched by literal filter: \(literalFilter)"
                } else {
                    result.warnings.append(ImportWarning(message: "Group \(name): ignored unsafe policy-regex-filter."))
                    groupWarning = "Ignored unsafe policy-regex-filter."
                }
            }

            let probeURL = ProxyGroupTestOptions.defaultURL
            if keyed["url"] != nil {
                // A subscription/conf author controls this URL, and the engine
                // resolves/probes it later. Pre-resolving here cannot defeat DNS
                // rebinding, so imported custom probe URLs are ignored instead
                // of becoming an SSRF/LAN-scan primitive in the tunnel.
                result.warnings.append(ImportWarning(message: "Group \(name): ignored imported URL-test URL and used the default."))
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

    /// Splits a Shadowrocket line on commas, honoring double-quoted segments.
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

    private func keyedValue(_ values: [String: String], _ keys: String...) -> String? {
        for key in keys {
            if let value = values[key.lowercased()] {
                return value
            }
        }
        return nil
    }
}

private extension Array {
    subscript(safe index: Int) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}
