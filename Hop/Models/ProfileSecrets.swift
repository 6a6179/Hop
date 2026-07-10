import Foundation

/// The secret-bearing fields of a profile that are stored in the Keychain
/// rather than in the on-disk JSON / generated config.
enum ProfileSecretField: String, CaseIterable {
    case uuid
    case vlessEncryption
    case password
    case obfsPassword
    case privateKey
    case preSharedKey
    case realityPublicKey
    case realityShortID
    case realityMLDSA65Verify
}

extension SubscriptionSource {
    var keychainURLItem: (key: String, value: String)? {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        return (HopSecret.subscriptionURLKey(subscriptionID: id), trimmed)
    }

    func redactingSecrets() -> SubscriptionSource {
        var copy = self
        copy.url = ""
        return copy
    }

    func hydratingSecrets(from store: SecretStore) -> SubscriptionSource {
        hydratingSecrets { store.value(forKey: $0) }
    }

    /// Bulk-hydration path used by app-state loading after taking one
    /// Keychain snapshot for every profile and subscription.
    func hydratingSecrets(from values: [String: String]) -> SubscriptionSource {
        hydratingSecrets { values[$0] }
    }

    private func hydratingSecrets(valueForKey: (String) -> String?) -> SubscriptionSource {
        var copy = self
        copy.url = valueForKey(HopSecret.subscriptionURLKey(subscriptionID: id)) ?? url
        return copy
    }

    var redactedDisplayURL: String {
        guard let components = URLComponents(string: url),
              let scheme = components.scheme,
              let host = components.host,
              !host.isEmpty
        else {
            return url.isEmpty ? "Subscription URL unavailable" : "Subscription URL stored securely"
        }

        let port = components.port.map { ":\($0)" } ?? ""
        return "\(scheme)://\(host)\(port) (stored securely)"
    }
}

extension ProxyProfile {
    /// Non-empty secret values currently set on this profile.
    var secretFieldValues: [ProfileSecretField: String] {
        var values: [ProfileSecretField: String] = [:]
        switch options {
        case let .vless(options):
            values[.uuid] = options.uuid
            values[.vlessEncryption] = options.normalizedEncryption
        case let .trojan(options):
            values[.password] = options.password
        case let .hysteria2(options):
            values[.password] = options.password
            values[.obfsPassword] = options.obfsPassword
        case let .tuic(options):
            values[.uuid] = options.uuid
            values[.password] = options.password
        case let .shadowsocks(options):
            values[.password] = options.password
        case let .vmess(options):
            values[.uuid] = options.uuid
        case let .http(options):
            values[.password] = options.password
        case let .socks(options):
            values[.password] = options.password
        case let .wireGuard(options):
            values[.privateKey] = options.privateKey
            values[.preSharedKey] = options.preSharedKey
        case let .anyTLS(options):
            values[.password] = options.password
        }
        if let reality = security.reality {
            values[.realityPublicKey] = reality.publicKey
            values[.realityShortID] = reality.shortID
            values[.realityMLDSA65Verify] = reality.mldsa65Verify
        }
        return values.filter { !$0.value.isEmpty }
    }

    /// Keychain (account, value) items for this profile's secrets.
    var keychainSecretItems: [(key: String, value: String)] {
        var items = secretFieldValues.map { (HopSecret.key(profileID: id, fieldRaw: $0.key.rawValue), $0.value) }
        if case let .wireGuard(options) = options, let peers = options.peers {
            items += peers.compactMap { peer in
                guard let value = peer.preSharedKey, !value.isEmpty else { return nil }
                return (HopSecret.key(profileID: id, fieldRaw: peer.preSharedKeyFieldRaw), value)
            }
        }
        items += xraySecretSidecar.valuesByJSONPointer.map { pointer, value in
            (HopSecret.key(profileID: id, fieldRaw: XrayAdvancedSecret.fieldRaw(for: pointer)), value)
        }
        return items
    }

    /// Advanced client credentials found at schema-reviewed JSON pointers.
    /// This sidecar is derived on demand and never encoded into app state.
    var xraySecretSidecar: XraySecretSidecar {
        var values: [String: String] = [:]
        visitAdvancedSecretStrings { pointer, value in
            guard !value.isEmpty,
                  !XrayAdvancedSecret.isPersistentReference(value),
                  !value.hasPrefix("##HOP_SECRET:")
            else { return }
            values[pointer] = value
        }
        return XraySecretSidecar(valuesByJSONPointer: values)
    }

    /// A copy with all secret fields blanked, for writing to JSON.
    func redactingSecrets() -> ProxyProfile {
        rewritingSecrets { _, _ in "" }
            .rewritingAdvancedSecrets { pointer, _ in
                XrayAdvancedSecret.persistentReference(
                    fieldRaw: XrayAdvancedSecret.fieldRaw(for: pointer),
                )
            }
    }

    /// A copy with each present secret replaced by a resolvable token, for the
    /// generated tunnel config. `nonce` binds the tokens to one tunnel start so
    /// untrusted fields can't forge a token that resolves another profile's
    /// secret (see `HopSecret`).
    func tokenizingSecrets(nonce: String) -> ProxyProfile {
        let id = id
        return rewritingSecrets { fieldRaw, value in
            value.isEmpty ? "" : HopSecret.token(forKey: HopSecret.key(profileID: id, fieldRaw: fieldRaw), nonce: nonce)
        }.rewritingAdvancedSecrets { pointer, value in
            let fieldRaw = XrayAdvancedSecret.fieldRaw(for: pointer)
            return value.isEmpty ? "" : HopSecret.token(
                forKey: HopSecret.key(profileID: id, fieldRaw: fieldRaw),
                nonce: nonce,
            )
        }
    }

    /// A copy with secret fields filled from the Keychain (used on load). Fields
    /// absent from the store keep their decoded value.
    func hydratingSecrets(from store: SecretStore) -> ProxyProfile {
        hydratingSecrets { store.value(forKey: $0) }
    }

    /// Bulk-hydration path used by app-state loading after taking one
    /// Keychain snapshot for every profile and subscription.
    func hydratingSecrets(from values: [String: String]) -> ProxyProfile {
        hydratingSecrets { values[$0] }
    }

    private func hydratingSecrets(valueForKey: (String) -> String?) -> ProxyProfile {
        let id = id
        return rewritingSecrets { fieldRaw, value in
            valueForKey(HopSecret.key(profileID: id, fieldRaw: fieldRaw)) ?? value
        }.rewritingAdvancedSecrets { pointer, value in
            let key = HopSecret.key(profileID: id, fieldRaw: XrayAdvancedSecret.fieldRaw(for: pointer))
            if let stored = valueForKey(key) {
                return stored
            }
            return XrayAdvancedSecret.isPersistentReference(value) ? "" : value
        }
    }

    /// Rebuilds the profile applying `transform(fieldRaw, currentValue)` to every
    /// secret field. Optional secret fields stay `nil` when originally `nil`.
    private func rewritingSecrets(_ transform: (String, String) -> String) -> ProxyProfile {
        var copy = self

        switch options {
        case let .vless(options):
            copy.options = .vless(VLESSOptions(
                uuid: transform(ProfileSecretField.uuid.rawValue, options.uuid),
                flow: options.flow,
                encryption: options.shouldRewriteEncryptionSecret ? transform(ProfileSecretField.vlessEncryption.rawValue, options.encryption ?? "") : options.encryption,
            ))
        case let .trojan(options):
            copy.options = .trojan(TrojanOptions(password: transform(ProfileSecretField.password.rawValue, options.password)))
        case let .hysteria2(options):
            copy.options = .hysteria2(Hysteria2Options(
                password: transform(ProfileSecretField.password.rawValue, options.password),
                obfs: options.obfs,
                obfsPassword: options.obfsPassword.map { transform(ProfileSecretField.obfsPassword.rawValue, $0) },
                up: options.up,
                down: options.down,
                ports: options.ports,
                hopIntervalSeconds: options.hopIntervalSeconds,
                udpIdleTimeoutSeconds: options.udpIdleTimeoutSeconds,
            ))
        case let .tuic(options):
            copy.options = .tuic(TUICOptions(
                uuid: transform(ProfileSecretField.uuid.rawValue, options.uuid),
                password: transform(ProfileSecretField.password.rawValue, options.password),
                congestionControl: options.congestionControl,
            ))
        case let .shadowsocks(options):
            copy.options = .shadowsocks(ShadowsocksOptions(method: options.method, password: transform(ProfileSecretField.password.rawValue, options.password)))
        case let .vmess(options):
            copy.options = .vmess(VMessOptions(uuid: transform(ProfileSecretField.uuid.rawValue, options.uuid), security: options.security, alterID: options.alterID))
        case let .http(options):
            copy.options = .http(HTTPOptions(username: options.username, password: options.password.map { transform(ProfileSecretField.password.rawValue, $0) }))
        case let .socks(options):
            copy.options = .socks(SOCKSOptions(username: options.username, password: options.password.map { transform(ProfileSecretField.password.rawValue, $0) }))
        case let .wireGuard(options):
            let peers = options.peers?.map { peer in
                var copy = peer
                copy.preSharedKey = peer.preSharedKey.map { transform(peer.preSharedKeyFieldRaw, $0) }
                return copy
            }
            copy.options = .wireGuard(WireGuardOptions(
                privateKey: transform(ProfileSecretField.privateKey.rawValue, options.privateKey),
                peerPublicKey: options.peerPublicKey,
                preSharedKey: options.preSharedKey.map { transform(ProfileSecretField.preSharedKey.rawValue, $0) },
                localAddress: options.localAddress,
                allowedIPs: options.allowedIPs,
                reserved: options.reserved,
                keepAliveSeconds: options.keepAliveSeconds,
                mtu: options.mtu,
                domainStrategy: options.domainStrategy,
                peers: peers,
            ))
        case let .anyTLS(options):
            copy.options = .anyTLS(AnyTLSOptions(password: transform(ProfileSecretField.password.rawValue, options.password)))
        }

        if var reality = copy.security.reality {
            reality.publicKey = transform(ProfileSecretField.realityPublicKey.rawValue, reality.publicKey)
            reality.shortID = reality.shortID.map { transform(ProfileSecretField.realityShortID.rawValue, $0) }
            reality.mldsa65Verify = reality.mldsa65Verify.map { transform(ProfileSecretField.realityMLDSA65Verify.rawValue, $0) }
            copy.security.reality = reality
        }

        return copy
    }

    private func visitAdvancedSecretStrings(_ visit: (String, String) -> Void) {
        _ = rewritingAdvancedSecrets { pointer, value in
            visit(pointer, value)
            return value
        }
    }

    private func rewritingAdvancedSecrets(_ transform: (String, String) -> String) -> ProxyProfile {
        var copy = self
        if var advanced = copy.xrayAdvanced {
            advanced.values = XrayAdvancedSecret.rewrite(
                .object(advanced.values),
                path: ["xrayAdvanced"],
                transform: transform,
            ).objectValue ?? advanced.values
            copy.xrayAdvanced = advanced
        }
        copy.transport.xhttpExtra = copy.transport.xhttpExtra.map {
            XrayAdvancedSecret.rewrite($0, path: ["transport", "xhttpExtra"], transform: transform)
        }
        copy.transport.finalMask = copy.transport.finalMask.map {
            XrayAdvancedSecret.rewrite($0, path: ["transport", "finalMask"], transform: transform)
        }
        copy.transport.socketOptions = copy.transport.socketOptions.map {
            XrayAdvancedSecret.rewrite($0, path: ["transport", "socketOptions"], transform: transform)
        }
        return copy
    }
}

private enum XrayAdvancedSecret {
    private static let referencePrefix = "##HOP_XRAY_SECRET_REF:"
    private static let sensitiveHeaderNames: Set<String> = [
        "authorization", "cookie", "proxy-authorization", "set-cookie", "x-api-key",
    ]

    static func rewrite(
        _ value: JSONValue,
        path: [String],
        transform: (String, String) -> String,
    ) -> JSONValue {
        switch value {
        case let .object(object):
            .object(Dictionary(uniqueKeysWithValues: object.map { key, child in
                (key, rewrite(child, path: path + [key], transform: transform))
            }))
        case let .array(values):
            .array(values.enumerated().map { index, child in
                rewrite(child, path: path + [String(index)], transform: transform)
            })
        case let .string(string) where isSecret(path):
            .string(transform(jsonPointer(path), string))
        case .string, .number, .bool, .null:
            value
        }
    }

    static func fieldRaw(for pointer: String) -> String {
        let encoded = Data(pointer.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "xray.\(encoded)"
    }

    static func persistentReference(fieldRaw: String) -> String {
        "\(referencePrefix)\(fieldRaw)##"
    }

    static func isPersistentReference(_ value: String) -> Bool {
        value.hasPrefix(referencePrefix) && value.hasSuffix("##")
    }

    private static func isSecret(_ path: [String]) -> Bool {
        let lower = path.map { $0.lowercased() }
        guard let keyIndex = lower.lastIndex(where: { Int($0) == nil }) else { return false }
        let key = lower[keyIndex]

        if lower.contains("headers"), sensitiveHeaderNames.contains(key) {
            return true
        }
        if lower.contains("xrayadvanced"), lower.contains("settings"),
           ["encryption", "id", "pass", "password", "presharedkey", "secretkey", "seed"].contains(key)
        {
            return true
        }
        if lower.contains("finalmask"), lower.contains("settings") {
            return key == "password" || (key == "url" && lower.contains("udp"))
        }
        if lower.contains("hysteriasettings"), key == "auth" {
            return true
        }
        if lower.contains("realitysettings"), ["mldsa65seed", "privatekey"].contains(key) {
            return true
        }
        if lower.contains("tlssettings"), ["echserverkeys", "key", "keyfile"].contains(key) {
            return true
        }
        return false
    }

    private static func jsonPointer(_ path: [String]) -> String {
        "/" + path.map {
            $0.replacingOccurrences(of: "~", with: "~0").replacingOccurrences(of: "/", with: "~1")
        }.joined(separator: "/")
    }
}
