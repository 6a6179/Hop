import Foundation

/// Builds the canonical share link for a profile — the inverse of
/// `ProxyImportService`'s link parsing, used by the node export UI (copy,
/// share sheet, QR). Returns nil for protocols without an interoperable link
/// form the parser can round-trip (AnyTLS). WireGuard uses Hop's explicit
/// `wireguard://` client-link extension because no single interoperable form
/// carries all Xray peer fields.
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
            query += transportQuery(profile.transport)
            if let obfs = options.obfs, !obfs.isEmpty {
                query.append(("obfs", obfs))
                if let obfsPassword = options.obfsPassword, !obfsPassword.isEmpty {
                    query.append(("obfs-password", obfsPassword))
                }
            }
            if let up = options.up, !up.isEmpty {
                query.append(("up", up))
            }
            if let down = options.down, !down.isEmpty {
                query.append(("down", down))
            }
            if let ports = options.ports, !ports.isEmpty {
                query.append(("ports", ports))
            }
            if let interval = options.hopIntervalSeconds {
                query.append(("hop-interval", String(interval)))
            }
            if let timeout = options.udpIdleTimeoutSeconds {
                query.append(("udp-idle-timeout", String(timeout)))
            }
            return link(scheme: "hysteria2", userInfo: options.password, profile: profile, query: query)

        case let .shadowsocks(options):
            // SIP002: base64url(method:password) as the userinfo.
            let userInfo = Data("\(options.method):\(options.password)".utf8)
                .base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
            return link(
                scheme: "ss",
                userInfo: userInfo,
                profile: profile,
                query: securityQuery(profile.security) + transportQuery(profile.transport),
                userInfoIsEncoded: true,
            )

        case let .vmess(options):
            return vmessLink(options: options, profile: profile)

        case let .http(options):
            let scheme = profile.security.layer == .none ? "http" : "https"
            return link(
                scheme: scheme,
                userInfo: userInfo(options.username, options.password),
                profile: profile,
                query: securityQuery(profile.security, omitLayerKey: true) + transportQuery(profile.transport),
                userInfoIsEncoded: true,
            )

        case let .socks(options):
            let scheme = profile.security.layer == .none ? "socks" : "socks5+tls"
            return link(
                scheme: scheme,
                userInfo: userInfo(options.username, options.password),
                profile: profile,
                query: securityQuery(profile.security, omitLayerKey: true) + transportQuery(profile.transport),
                userInfoIsEncoded: true,
            )

        case let .wireGuard(options):
            let firstPeer = options.effectivePeers[0]
            var query: [(String, String)] = [
                ("publickey", firstPeer.publicKey),
                ("address", options.localAddress.joined(separator: ",")),
            ]
            if let value = firstPeer.preSharedKey, !value.isEmpty {
                query.append(("presharedkey", value))
            }
            if let value = firstPeer.allowedIPs, !value.isEmpty {
                query.append(("allowedips", value.joined(separator: ",")))
            }
            if let value = options.reserved, !value.isEmpty {
                query.append(("reserved", value.map(String.init).joined(separator: ",")))
            }
            if let value = firstPeer.keepAliveSeconds {
                query.append(("keepalive", String(value)))
            }
            if let value = options.mtu {
                query.append(("mtu", String(value)))
            }
            if let value = options.domainStrategy, !value.isEmpty {
                query.append(("domainStrategy", value))
            }
            appendEncodedJSON(options.peers, key: "peers", to: &query)
            return link(scheme: "wireguard", userInfo: options.privateKey, profile: profile, query: query)

        case .tuic, .anyTLS:
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
        case .tcp, .mKCP, .hysteria, .quic:
            break
        case .xhttp:
            object["path"] = profile.transport.path ?? ""
            object["host"] = profile.transport.host ?? ""
        }
        if profile.security.layer != .none, let tls = profile.security.tls {
            object["tls"] = profile.security.layer == .reality ? "reality" : "tls"
            if let serverName = tls.serverName, !serverName.isEmpty {
                object["sni"] = serverName
            }
            if !tls.alpn.isEmpty {
                object["alpn"] = tls.alpn.joined(separator: ",")
            }
            if let fingerprint = tls.utlsFingerprint, !fingerprint.isEmpty {
                object["fp"] = fingerprint
            }
            if let pins = tls.pinnedPeerCertSHA256 {
                object["pcs"] = pins
            }
            if let names = tls.verifyPeerCertByName {
                object["vcn"] = names
            }
            if let ech = tls.echConfigList {
                object["ech"] = ech
            }
            if !tls.curvePreferences.isEmpty {
                object["curves"] = tls.curvePreferences.joined(separator: ",")
            }
            if let value = tls.minVersion {
                object["minver"] = value
            }
            if let value = tls.maxVersion {
                object["maxver"] = value
            }
            if let value = tls.cipherSuites {
                object["ciphers"] = value
            }
            if tls.enableSessionResumption {
                object["sessionResumption"] = "1"
            }
        }
        if let reality = profile.security.reality {
            object["pbk"] = reality.publicKey
            if let value = reality.shortID {
                object["sid"] = value
            }
            if let value = reality.spiderX {
                object["spx"] = value
            }
            if let value = reality.mldsa65Verify {
                object["pqv"] = value
            }
        }
        addTransportExtensions(profile.transport, to: &object)
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
            if let pins = tls.pinnedPeerCertSHA256, !pins.isEmpty {
                query.append(("pcs", pins))
            }
            if let names = tls.verifyPeerCertByName, !names.isEmpty {
                query.append(("vcn", names))
            }
            if let ech = tls.echConfigList, !ech.isEmpty {
                query.append(("ech", ech))
            }
            if !tls.curvePreferences.isEmpty {
                query.append(("curves", tls.curvePreferences.joined(separator: ",")))
            }
            if let minVersion = tls.minVersion, !minVersion.isEmpty {
                query.append(("minver", minVersion))
            }
            if let maxVersion = tls.maxVersion, !maxVersion.isEmpty {
                query.append(("maxver", maxVersion))
            }
            if let ciphers = tls.cipherSuites, !ciphers.isEmpty {
                query.append(("ciphers", ciphers))
            }
            if tls.enableSessionResumption {
                query.append(("sessionResumption", "1"))
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
        var query: [(String, String)] = []
        switch transport.type {
        case .tcp:
            break
        case .websocket, .httpUpgrade:
            query = [("type", transport.type == .websocket ? "ws" : "httpupgrade")]
            if let path = transport.path, !path.isEmpty {
                query.append(("path", path))
            }
            if let host = transport.host, !host.isEmpty {
                query.append(("host", host))
            }
        case .grpc:
            query = [("type", "grpc")]
            if let serviceName = transport.serviceName, !serviceName.isEmpty {
                query.append(("serviceName", serviceName))
            }
        case .xhttp:
            query = [("type", "xhttp")]
            if let path = transport.path, !path.isEmpty {
                query.append(("path", path))
            }
            if let host = transport.host, !host.isEmpty {
                query.append(("host", host))
            }
            if let mode = transport.xhttpMode, !mode.isEmpty {
                query.append(("mode", mode))
            }
        case .mKCP:
            query = [("type", "mkcp")]
        case .hysteria:
            query = [("type", "hysteria")]
        case .quic:
            query = [("type", "quic")]
        }
        appendEncodedJSON(transport.xhttpExtra, key: "xhttpExtra", to: &query)
        appendEncodedJSON(transport.kcp, key: "kcp", to: &query)
        appendEncodedJSON(transport.finalMask, key: "finalmask", to: &query)
        appendEncodedJSON(transport.mux, key: "mux", to: &query)
        appendEncodedJSON(transport.socketOptions, key: "sockopt", to: &query)
        return query
    }

    private static func addTransportExtensions(_ transport: TransportOptions, to object: inout [String: Any]) {
        object["xhttpExtra"] = encodedJSON(transport.xhttpExtra)
        object["kcp"] = encodedJSON(transport.kcp)
        object["finalmask"] = encodedJSON(transport.finalMask)
        object["mux"] = encodedJSON(transport.mux)
        object["sockopt"] = encodedJSON(transport.socketOptions)
    }

    private static func appendEncodedJSON(_ value: (some Encodable)?, key: String, to query: inout [(String, String)]) {
        if let encoded = encodedJSON(value) {
            query.append((key, encoded))
        }
    }

    private static func encodedJSON(_ value: (some Encodable)?) -> String? {
        guard let value, let data = try? JSONEncoder().encode(value) else { return nil }
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
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
