import Foundation

/// Compatible `.conf` parsing for `[Proxy]`, `[Proxy Group]`, and `[Rule]`
/// sections. Split from the share-link parsing in `ProxyLinkParser.swift`;
/// `importText` routes here when the payload looks like a config file.
extension ProxyImportService {
    func parseProxyConfiguration(_ text: String) -> ImportResult {
        var result = ImportResult()
        var section = ""
        var sawInventorySection = false
        var sawRuleSection = false
        var attemptedInventoryItem = false
        var remainingGroupMembers = ImportPolicy.maxImportedGroupMembers
        var groupFilters = GroupFilterCache()

        func parseLine(_ rawLine: Substring) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty, !line.hasPrefix("#"), !line.hasPrefix(";") else {
                return
            }

            if line.hasPrefix("["), line.hasSuffix("]") {
                section = String(line.dropFirst().dropLast()).lowercased()
                if section == "proxy" || section == "proxy group" {
                    sawInventorySection = true
                } else if section == "rule" {
                    sawRuleSection = true
                }
                return
            }

            switch section {
            case "proxy":
                attemptedInventoryItem = true
                let count = result.profiles.count
                do {
                    try parseProxyLine(line, into: &result)
                } catch {
                    result.warnings.append(ImportWarning(message: error.localizedDescription))
                }
                if result.profiles.count == count {
                    result.incompleteSubscriptionInventory = true
                }
            case "proxy group":
                attemptedInventoryItem = true
                let count = result.groups.count
                parseProxyGroupLine(line, into: &result, remainingMembers: &remainingGroupMembers, groupFilters: &groupFilters)
                if result.groups.count == count {
                    result.incompleteSubscriptionInventory = true
                }
            case "rule":
                parseProxyRuleLine(line, into: &result)
            default:
                return
            }
        }

        let wasTruncated = scanConfigurationLines(text) { line in
            parseLine(line)
            return true
        }

        if wasTruncated {
            result.incompleteSubscriptionInventory = true
            result.warnings.insert(ImportWarning(message: "The configuration exceeded the line limit; only the first part was read."), at: 0)
        }

        if sawInventorySection,
           !sawRuleSection,
           !attemptedInventoryItem,
           !wasTruncated,
           result.profiles.isEmpty,
           result.groups.isEmpty,
           result.rules.isEmpty,
           result.warnings.isEmpty
        {
            result.validatedEmptySubscriptionSnapshot = true
        }

        return result
    }

    func looksLikeProxyConfiguration(_ text: String) -> Bool {
        guard text.contains("[") else { return false }
        var found = false
        _ = scanConfigurationLines(text) { line in
            let header = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if header.first == "[", header.last == "]" {
                found = ["[proxy]", "[proxy group]", "[rule]"].contains(header.lowercased())
            }
            return !found
        }
        return found
    }

    /// Shares newline semantics and the line budget between detection and parsing.
    /// A false visit result ends the scan early. The return value indicates truncation.
    private func scanConfigurationLines(_ text: String, visit: (Substring) -> Bool) -> Bool {
        let scalars = text.unicodeScalars
        var lineStart = scalars.startIndex
        var lineCount = 0
        for index in scalars.indices where CharacterSet.newlines.contains(scalars[index]) {
            guard visit(text[lineStart ..< index]) else { return false }
            lineCount += 1
            guard lineCount < ImportPolicy.maxLines else { return true }
            lineStart = scalars.index(after: index)
        }
        _ = visit(text[lineStart...])
        return false
    }

    private func parseProxyLine(_ line: String, into result: inout ImportResult) throws {
        let parts = csvFields(line)
        guard let nameAndType = parts.first?.text.split(separator: "=", maxSplits: 1).map({ $0.trimmingCharacters(in: .whitespacesAndNewlines) }),
              nameAndType.count == 2
        else {
            result.warnings.append(ImportWarning(message: "Skipped malformed proxy line: \(ImportPolicy.redactForLog(line))"))
            return
        }

        let name = nameAndType[0]
        let type = nameAndType[1].lowercased()
        let values = parts.dropFirst()
        guard let host = values.first?.text, !host.isEmpty,
              let portText = values.dropFirst().first?.text,
              let port = Int(portText), (1 ... 65535).contains(port)
        else {
            result.warnings.append(ImportWarning(message: "Skipped \(name): missing host or out-of-range port."))
            return
        }
        let arguments = values.dropFirst(2)
        let keyed = keyedOptions(arguments.filter(\.isNamed).map(\.text))
        var positional = arguments.filter { !$0.isNamed }.map(\.text)[...]
        let security = try configurationSecurity(keyed: keyed, host: host, type: type)

        let profile: ProxyProfile?
        switch type {
        case "ss", "shadowsocks":
            // A positional SS2022 password can contain base64 padding.
            var fields = arguments.filter { !$0.isNamed || $0.isPaddedBase64 }.map(\.text)[...]
            guard let method = keyed["method"] ?? keyed["encrypt-method"] ?? fields.popFirst(), !method.isEmpty, !method.contains("="),
                  let password = keyed["password"] ?? fields.popFirst(), !password.isEmpty
            else {
                result.warnings.append(ImportWarning(message: "Skipped \(name): Shadowsocks requires method and password."))
                return
            }
            profile = try ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), options: .shadowsocks(ShadowsocksOptions(method: method, password: password)), security: security, transport: configurationTransport(keyed: keyed))
        case "vmess":
            let hasPositionalMethod = keyed["password"] != nil || positional.count > 1
            let method = keyed["method"] ?? (hasPositionalMethod ? positional.popFirst() : nil) ?? "auto"
            guard let password = keyed["password"] ?? positional.popFirst(), !password.isEmpty else {
                result.warnings.append(ImportWarning(message: "Skipped \(name): VMess requires password UUID."))
                return
            }
            profile = try ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), options: .vmess(VMessOptions(uuid: password, security: method, alterID: Int(keyed["alterid"] ?? keyed["alter-id"] ?? "0") ?? 0)), security: security, transport: configurationTransport(keyed: keyed))
        case "vless":
            guard let password = keyed["password"] ?? keyed["uuid"] ?? positional.popFirst(), !password.isEmpty else {
                result.warnings.append(ImportWarning(message: "Skipped \(name): VLESS requires password UUID."))
                return
            }
            profile = try ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), options: .vless(VLESSOptions(uuid: password, flow: keyed["flow"], encryption: keyed["encryption"])), security: security, transport: configurationTransport(keyed: keyed))
        case "trojan":
            guard let password = keyed["password"] ?? positional.popFirst(), !password.isEmpty else {
                result.warnings.append(ImportWarning(message: "Skipped \(name): Trojan requires password."))
                return
            }
            profile = try ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), options: .trojan(TrojanOptions(password: password)), security: security, transport: configurationTransport(keyed: keyed))
        case "hysteria", "hysteria2":
            guard let auth = keyed["auth"] ?? keyed["password"] ?? positional.popFirst(), !auth.isEmpty else {
                result.warnings.append(ImportWarning(message: "Skipped \(name): Hysteria2 requires auth/password."))
                return
            }
            profile = ProxyProfile(
                name: name,
                endpoint: Endpoint(host: host, port: port),
                options: .hysteria2(Hysteria2Options(
                    password: auth,
                    obfs: keyed["obfs"],
                    obfsPassword: keyedValue(keyed, "obfsparam", "obfs-param", "obfs_password", "obfs-password"),
                    up: keyedValue(keyed, "up", "upmbps"),
                    down: keyedValue(keyed, "down", "downmbps"),
                    ports: keyed["ports"],
                    hopIntervalSeconds: Int(keyedValue(keyed, "hop-interval", "hop_interval") ?? ""),
                    udpIdleTimeoutSeconds: Int(keyedValue(keyed, "udp-idle-timeout", "udp_idle_timeout") ?? ""),
                )),
                security: security,
                transport: TransportOptions(type: .hysteria),
            )
        case "tuic":
            result.warnings.append(ImportWarning(message: "Skipped \(name): TUIC is not supported by Xray-core \(XrayAdvancedDocument.currentSchemaVersion)."))
            profile = nil
        case "http", "https", "socks5", "socks5-tls":
            // Never shift a later positional password into a missing username slot.
            let username = keyed["username"] ?? arguments.first?.positionalValue
            let password = keyed["password"] ?? (keyed["username"] == nil
                ? arguments.dropFirst().first?.positionalValue : positional.first)
            let options: ProtocolOptions = ["http", "https"].contains(type)
                ? .http(HTTPOptions(username: username, password: password))
                : .socks(SOCKSOptions(username: username, password: password))
            profile = try ProxyProfile(name: name, endpoint: Endpoint(host: host, port: port), options: options, security: security, transport: configurationTransport(keyed: keyed))
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

    private func parseProxyGroupLine(_ line: String, into result: inout ImportResult, remainingMembers: inout Int, groupFilters: inout GroupFilterCache) {
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
        guard memberNames.count <= remainingMembers else {
            result.warnings.append(ImportWarning(message: "Skipped group \(ImportPolicy.sanitizeImportedName(name)): group member limit exceeded."))
            return
        }
        let members = memberNames.map { configurationTarget($0.trimmingCharacters(in: .whitespacesAndNewlines)) }
        remainingMembers -= members.count

        switch importedType {
        case "select":
            result.groups.append(
                ProxyGroup(
                    name: name,
                    type: .select,
                    members: members,
                    defaultTarget: keyed["policy-select-name"].map(configurationTarget) ?? members.first,
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
                        do {
                            resolvedMembers = try groupFilters.members(matching: literalFilter, in: result.profiles, limit: remainingMembers)
                        } catch {
                            result.warnings.append(ImportWarning(message: "Skipped group \(ImportPolicy.sanitizeImportedName(name)): \(error.rawValue)."))
                            return
                        }
                        remainingMembers -= resolvedMembers.count
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
                    warning: "Unsupported proxy group type: \(importedType)",
                ),
            )
            result.warnings.append(ImportWarning(message: "Group \(name) uses unsupported type \(importedType)."))
        }
    }

    private func parseProxyRuleLine(_ line: String, into result: inout ImportResult) {
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

        guard let kind = configurationRuleKind(kindName) else {
            result.warnings.append(ImportWarning(message: "Skipped unsupported rule type \(kindName)."))
            return
        }

        if kind == .domainRegex, !ImportPolicy.isSafeRegexPattern(value) {
            result.warnings.append(ImportWarning(message: "Skipped DOMAIN-REGEX rule with an unsafe or oversized pattern."))
            return
        }

        result.rules.append(RoutingRule(kind: kind, value: value, target: configurationTarget(targetName)))
    }

    private func configurationSecurity(keyed: [String: String], host: String, type: String) throws -> ProxySecurity {
        let requiresSecurity = ["https", "socks5-tls", "hysteria", "hysteria2"].contains(type)
        let inferredLayer: SecurityLayer = requiresSecurity || type == "trojan" ? .tls : .none
        let layer = try importedSecurityLayer(keyed["security"], tls: keyed["tls"], defaultLayer: inferredLayer)
        guard layer != .none || !requiresSecurity, layer != .reality || type == "vless" else {
            throw ProxyLinkParseError.invalidSecurity
        }
        let serverName = keyedValue(keyed, "peer", "sni", "servername", "server_name", "server-name") ?? host
        let alpn = alpnValues(from: keyedValue(keyed, "alpn"))
        let fingerprint = keyedValue(keyed, "fingerprint", "fp", "utlsfingerprint", "utls_fingerprint", "utls-fingerprint", "clientfingerprint", "client_fingerprint", "client-fingerprint") ?? "chrome"
        let hasRealityFields = keyedValue(keyed, "pbk", "publickey", "public_key", "public-key", "sid", "shortid", "short_id", "short-id", "spx", "spiderx", "spider_x", "spider-x", "pqv", "mldsa65verify", "mldsa65_verify", "mldsa65-verify") != nil
        let isReality = type == "vless" && (layer == .reality || boolOption(keyedValue(keyed, "reality")) || hasRealityFields)

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

        guard layer == .tls else {
            return .none
        }

        return .tls(
            TLSOptions(
                serverName: serverName,
                alpn: alpn,
                allowInsecure: boolOption(keyedValue(keyed, "allowinsecure", "allow_insecure", "allow-insecure", "skip-common-name-verify", "skipcertverify", "skip_cert_verify", "skip-cert-verify")),
                utlsFingerprint: fingerprint,
                pinnedPeerCertSHA256: keyedValue(keyed, "pcs", "pinnedpeercertsha256", "pinned_peer_cert_sha256", "pinned-peer-cert-sha256"),
                verifyPeerCertByName: keyedValue(keyed, "vcn", "verifypeercertbyname", "verify_peer_cert_by_name", "verify-peer-cert-by-name"),
                echConfigList: keyedValue(keyed, "ech", "echconfiglist", "ech_config_list", "ech-config-list"),
                curvePreferences: alpnValues(from: keyedValue(keyed, "curves", "curvepreferences", "curve_preferences", "curve-preferences")),
                minVersion: keyedValue(keyed, "minver", "minversion", "min_version", "min-version"),
                maxVersion: keyedValue(keyed, "maxver", "maxversion", "max_version", "max-version"),
                cipherSuites: keyedValue(keyed, "ciphers", "ciphersuites", "cipher_suites", "cipher-suites"),
                enableSessionResumption: boolOption(keyedValue(keyed, "sessionresumption", "session_resumption", "session-resumption")),
            ),
        )
    }

    private func configurationTransport(keyed: [String: String]) throws -> TransportOptions {
        switch (keyed["obfs"] ?? keyed["type"])?.lowercased() {
        case nil, "none", "raw", "tcp":
            .tcp
        case "websocket", "ws":
            TransportOptions(type: .websocket, path: keyed["path"] ?? keyed["obfs-uri"], host: keyed["host"] ?? keyed["obfs-host"], serviceName: nil)
        case "grpc":
            TransportOptions(
                type: .grpc,
                host: keyedValue(keyed, "authority", "grpc-authority", "grpc_authority"),
                serviceName: keyedValue(keyed, "service-name", "service_name", "servicename", "grpc-service-name", "grpc_service_name"),
            )
        case "http", "httpupgrade", "http-upgrade":
            TransportOptions(type: .httpUpgrade, path: keyed["path"], host: keyed["host"], serviceName: nil)
        case "xhttp", "splithttp":
            TransportOptions(type: .xhttp, path: keyed["path"], host: keyed["host"], xhttpMode: keyed["mode"])
        case "kcp", "mkcp":
            TransportOptions(type: .mKCP)
        case "hysteria":
            TransportOptions(type: .hysteria)
        default:
            throw ProxyLinkParseError.invalidTransport
        }
    }

    private func configurationRuleKind(_ value: String) -> RoutingRuleKind? {
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

    private func configurationTarget(_ value: String) -> OutboundTarget {
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

    private struct CSVField {
        let text: String
        let isNamed: Bool

        var positionalValue: String? {
            isNamed ? nil : text
        }

        var isPaddedBase64: Bool {
            guard text.contains("=") else { return false }
            return text.split(separator: ":", omittingEmptySubsequences: false).allSatisfy { key in
                guard let data = Data(base64Encoded: String(key)) else { return false }
                return !data.isEmpty && data.base64EncodedString() == key
            }
        }
    }

    private func csvParts(_ line: String) -> [String] {
        csvFields(line).map(\.text).filter { !$0.isEmpty }
    }

    /// Keep empty slots and distinguish a quoted literal ("a=b") from an option (password="a=b").
    private func csvFields(_ line: String) -> [CSVField] {
        var result: [CSVField] = []
        var current = ""
        var isQuoted = false
        var hasUnquotedEquals = false

        func finishField() {
            let text = current.trimmingCharacters(in: .whitespacesAndNewlines)
            result.append(CSVField(text: text, isNamed: hasUnquotedEquals))
            current = ""
            hasUnquotedEquals = false
        }
        for character in line {
            if character == "\"" {
                isQuoted.toggle()
            } else if character == ",", !isQuoted {
                finishField()
            } else {
                if character == "=", !isQuoted {
                    hasUnquotedEquals = true
                }
                current.append(character)
            }
        }
        finishField()
        return result
    }

    private func keyedOptions(_ values: [String]) -> [String: String] {
        values.reduce(into: [:]) { result, value in
            let parts = value.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false).map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
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

/// The inventory only grows during a parse. A repeated filter reuses matches
/// from earlier sections and scans the newly appended profiles in order.
private struct GroupFilterCache {
    enum Limit: String, Error {
        case work = "group filter work limit exceeded"
        case members = "group member limit exceeded"
    }

    private var matches: [String: (scanned: Int, members: [OutboundTarget])] = [:]
    private var remainingWork = ImportPolicy.maxGroupFilterComparisons

    mutating func members(matching filter: String, in profiles: [ProxyProfile], limit: Int) throws(Limit) -> [OutboundTarget] {
        let cached = matches[filter] ?? (scanned: 0, members: [])
        guard cached.members.count <= limit else { throw .members }
        guard cached.scanned < profiles.count else { return cached.members }
        guard profiles.count - cached.scanned <= remainingWork else { throw .work }

        var members = cached.members
        for profile in profiles[cached.scanned...] {
            // One comparison covers up to 256 bytes. Charge longer names
            // proportionally, including multi-scalar grapheme clusters, before
            // counting characters or invoking the localized substring search.
            let cost = max(1, (profile.name.utf8.count + 255) / 256)
            guard cost <= remainingWork else { throw .work }
            remainingWork -= cost
            if profile.name.count <= 256, profile.name.localizedCaseInsensitiveContains(filter) {
                guard members.count < limit else { throw .members }
                members.append(.profile(profile.id))
            }
        }
        matches[filter] = (profiles.count, members)
        return members
    }
}
