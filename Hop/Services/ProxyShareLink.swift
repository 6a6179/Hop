import Foundation

/// Builds the canonical share link for a profile — the inverse of
/// `ProxyImportService`'s link parsing, used by the node export UI (copy,
/// share sheet, QR). Returns nil for protocols without an interoperable link
/// form the parser can round-trip (WireGuard, AnyTLS).
///
/// Links embed the node's credentials by design — that is what sharing a node
/// means — so the UI only produces them from an explicit user action.
enum ProxyShareLink {
    static func shareLink(for profile: ProxyProfile) -> String? {
        switch profile.options {
        case let .vless(options):
            var query = securityQuery(profile.security)
            query += transportQuery(profile.transport)
            if let flow = options.flow, !flow.isEmpty {
                query.append(("flow", flow))
            }
            if let encryption = options.normalizedEncryption {
                query.append(("encryption", encryption))
            }
            return link(scheme: "vless", userInfo: options.uuid, profile: profile, query: query)

        case let .trojan(options):
            var query = securityQuery(profile.security)
            query += transportQuery(profile.transport)
            return link(scheme: "trojan", userInfo: options.password, profile: profile, query: query)

        case let .hysteria2(options):
            var query = securityQuery(profile.security, omitLayerKey: true)
            if let obfs = options.obfs, !obfs.isEmpty {
                query.append(("obfs", obfs))
                if let obfsPassword = options.obfsPassword, !obfsPassword.isEmpty {
                    query.append(("obfs-password", obfsPassword))
                }
            }
            return link(scheme: "hysteria2", userInfo: options.password, profile: profile, query: query)

        case let .tuic(options):
            var query = securityQuery(profile.security, omitLayerKey: true)
            if let congestionControl = options.congestionControl, !congestionControl.isEmpty {
                query.append(("congestion_control", congestionControl))
            }
            return link(scheme: "tuic", userInfo: "\(encoded(options.uuid)):\(encoded(options.password))", profile: profile, query: query, userInfoIsEncoded: true)

        case let .shadowsocks(options):
            // SIP002: base64url(method:password) as the userinfo.
            let userInfo = Data("\(options.method):\(options.password)".utf8)
                .base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
            return link(scheme: "ss", userInfo: userInfo, profile: profile, query: securityQuery(profile.security), userInfoIsEncoded: true)

        case let .vmess(options):
            return vmessLink(options: options, profile: profile)

        case let .http(options):
            let scheme = profile.security.layer == .none ? "http" : "https"
            return link(scheme: scheme, userInfo: userInfo(options.username, options.password), profile: profile, query: [], userInfoIsEncoded: true)

        case let .socks(options):
            let scheme = profile.security.layer == .none ? "socks" : "socks5+tls"
            return link(scheme: scheme, userInfo: userInfo(options.username, options.password), profile: profile, query: [], userInfoIsEncoded: true)

        case .wireGuard, .anyTLS:
            return nil
        }
    }

    // MARK: - Link assembly

    private static func link(
        scheme: String,
        userInfo: String?,
        profile: ProxyProfile,
        query: [(String, String)],
        userInfoIsEncoded: Bool = false,
    ) -> String {
        var result = "\(scheme)://"
        if let userInfo, !userInfo.isEmpty {
            result += (userInfoIsEncoded ? userInfo : encoded(userInfo)) + "@"
        }
        result += bracketedHost(profile.endpoint.host) + ":\(profile.endpoint.port)"
        if !query.isEmpty {
            result += "?" + query.map { "\($0.0)=\(encoded($0.1))" }.joined(separator: "&")
        }
        result += "#" + encoded(profile.name)
        return result
    }

    private static func vmessLink(options: VMessOptions, profile: ProxyProfile) -> String? {
        // v2rayN JSON form — the shape the importer (and most clients) accept.
        var object: [String: Any] = [
            "v": "2",
            "ps": profile.name,
            "add": profile.endpoint.host,
            "port": "\(profile.endpoint.port)",
            "id": options.uuid,
            "aid": "\(options.alterID)",
            "scy": options.security,
            "net": vmessNetwork(profile.transport),
            "type": "none",
        ]
        switch profile.transport.type {
        case .websocket, .httpUpgrade:
            object["path"] = profile.transport.path ?? ""
            object["host"] = profile.transport.host ?? ""
        case .grpc:
            object["path"] = profile.transport.serviceName ?? ""
        case .tcp, .quic:
            break
        }
        if profile.security.layer != .none, let tls = profile.security.tls {
            object["tls"] = "tls"
            if let serverName = tls.serverName, !serverName.isEmpty {
                object["sni"] = serverName
            }
            if !tls.alpn.isEmpty {
                object["alpn"] = tls.alpn.joined(separator: ",")
            }
            if let fingerprint = tls.utlsFingerprint, !fingerprint.isEmpty {
                object["fp"] = fingerprint
            }
            if tls.allowInsecure {
                object["allowInsecure"] = true
            }
        }
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else {
            return nil
        }
        return "vmess://" + data.base64EncodedString()
    }

    private static func vmessNetwork(_ transport: TransportOptions) -> String {
        switch transport.type {
        case .tcp:
            "tcp"
        case .websocket:
            "ws"
        case .grpc:
            "grpc"
        case .httpUpgrade:
            "h2"
        case .quic:
            "quic"
        }
    }

    // MARK: - Query fragments

    /// `omitLayerKey` is for QUIC-based schemes (hysteria2/tuic) where TLS is
    /// implied and links conventionally carry only sni/alpn/insecure.
    private static func securityQuery(_ security: ProxySecurity, omitLayerKey: Bool = false) -> [(String, String)] {
        var query: [(String, String)] = []
        switch security.layer {
        case .none:
            return []
        case .tls:
            if !omitLayerKey {
                query.append(("security", "tls"))
            }
        case .reality:
            query.append(("security", "reality"))
        }

        if let tls = security.tls {
            if let serverName = tls.serverName, !serverName.isEmpty {
                query.append(("sni", serverName))
            }
            if !tls.alpn.isEmpty {
                query.append(("alpn", tls.alpn.joined(separator: ",")))
            }
            if let fingerprint = tls.utlsFingerprint, !fingerprint.isEmpty {
                query.append(("fp", fingerprint))
            }
            if tls.allowInsecure {
                query.append(("insecure", "1"))
            }
        }

        if security.layer == .reality, let reality = security.reality {
            query.append(("pbk", reality.publicKey))
            if let shortID = reality.shortID, !shortID.isEmpty {
                query.append(("sid", shortID))
            }
            if let spiderX = reality.spiderX, !spiderX.isEmpty {
                query.append(("spx", spiderX))
            }
            if let mldsa65Verify = reality.mldsa65Verify, !mldsa65Verify.isEmpty {
                query.append(("pqv", mldsa65Verify))
            }
        }
        return query
    }

    private static func transportQuery(_ transport: TransportOptions) -> [(String, String)] {
        switch transport.type {
        case .tcp:
            return []
        case .websocket, .httpUpgrade:
            var query = [("type", transport.type == .websocket ? "ws" : "httpupgrade")]
            if let path = transport.path, !path.isEmpty {
                query.append(("path", path))
            }
            if let host = transport.host, !host.isEmpty {
                query.append(("host", host))
            }
            return query
        case .grpc:
            var query = [("type", "grpc")]
            if let serviceName = transport.serviceName, !serviceName.isEmpty {
                query.append(("serviceName", serviceName))
            }
            return query
        case .quic:
            return [("type", "quic")]
        }
    }

    // MARK: - Encoding helpers

    private static func userInfo(_ username: String?, _ password: String?) -> String? {
        guard let username, !username.isEmpty else {
            return nil
        }
        guard let password, !password.isEmpty else {
            return encoded(username)
        }
        return "\(encoded(username)):\(encoded(password))"
    }

    private static func bracketedHost(_ host: String) -> String {
        guard host.contains(":"), !host.hasPrefix("[") else {
            return host
        }
        return "[\(host)]"
    }

    /// Conservative percent-encoding: everything outside unreserved characters
    /// is escaped, so credentials and names survive userinfo, query, and
    /// fragment positions unambiguously.
    private static func encoded(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: .shareLinkUnreserved) ?? value
    }
}

private extension CharacterSet {
    /// RFC 3986 unreserved characters, ASCII only — `CharacterSet.alphanumerics`
    /// would leave non-ASCII letters (e.g. CJK names) unescaped, and
    /// `URLComponents(string:)` rejects URLs containing them.
    static let shareLinkUnreserved = CharacterSet(
        charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
    )
}
