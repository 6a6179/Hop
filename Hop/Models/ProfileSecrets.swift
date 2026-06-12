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
        secretFieldValues.map { (HopSecret.key(profileID: id, fieldRaw: $0.key.rawValue), $0.value) }
    }

    /// A copy with all secret fields blanked, for writing to JSON.
    func redactingSecrets() -> ProxyProfile {
        rewritingSecrets { _, _ in "" }
    }

    /// A copy with each present secret replaced by a resolvable token, for the
    /// generated tunnel config. `nonce` binds the tokens to one tunnel start so
    /// untrusted fields can't forge a token that resolves another profile's
    /// secret (see `HopSecret`).
    func tokenizingSecrets(nonce: String) -> ProxyProfile {
        let id = id
        return rewritingSecrets { field, value in
            value.isEmpty ? "" : HopSecret.token(forKey: HopSecret.key(profileID: id, fieldRaw: field.rawValue), nonce: nonce)
        }
    }

    /// A copy with secret fields filled from the Keychain (used on load). Fields
    /// absent from the store keep their decoded value.
    func hydratingSecrets(from store: SecretStore) -> ProxyProfile {
        let id = id
        return rewritingSecrets { field, value in
            store.value(forKey: HopSecret.key(profileID: id, fieldRaw: field.rawValue)) ?? value
        }
    }

    /// Rebuilds the profile applying `transform(field, currentValue)` to every
    /// secret field. Optional secret fields stay `nil` when originally `nil`.
    private func rewritingSecrets(_ transform: (ProfileSecretField, String) -> String) -> ProxyProfile {
        var copy = self

        switch options {
        case let .vless(options):
            copy.options = .vless(VLESSOptions(
                uuid: transform(.uuid, options.uuid),
                flow: options.flow,
                encryption: options.shouldRewriteEncryptionSecret ? transform(.vlessEncryption, options.encryption ?? "") : options.encryption,
            ))
        case let .trojan(options):
            copy.options = .trojan(TrojanOptions(password: transform(.password, options.password)))
        case let .hysteria2(options):
            copy.options = .hysteria2(Hysteria2Options(
                password: transform(.password, options.password),
                obfs: options.obfs,
                obfsPassword: options.obfsPassword.map { transform(.obfsPassword, $0) },
            ))
        case let .tuic(options):
            copy.options = .tuic(TUICOptions(
                uuid: transform(.uuid, options.uuid),
                password: transform(.password, options.password),
                congestionControl: options.congestionControl,
            ))
        case let .shadowsocks(options):
            copy.options = .shadowsocks(ShadowsocksOptions(method: options.method, password: transform(.password, options.password)))
        case let .vmess(options):
            copy.options = .vmess(VMessOptions(uuid: transform(.uuid, options.uuid), security: options.security, alterID: options.alterID))
        case let .http(options):
            copy.options = .http(HTTPOptions(username: options.username, password: options.password.map { transform(.password, $0) }))
        case let .socks(options):
            copy.options = .socks(SOCKSOptions(username: options.username, password: options.password.map { transform(.password, $0) }))
        case let .wireGuard(options):
            copy.options = .wireGuard(WireGuardOptions(
                privateKey: transform(.privateKey, options.privateKey),
                peerPublicKey: options.peerPublicKey,
                preSharedKey: options.preSharedKey.map { transform(.preSharedKey, $0) },
                localAddress: options.localAddress,
            ))
        case let .anyTLS(options):
            copy.options = .anyTLS(AnyTLSOptions(password: transform(.password, options.password)))
        }

        if var reality = copy.security.reality {
            reality.publicKey = transform(.realityPublicKey, reality.publicKey)
            reality.shortID = reality.shortID.map { transform(.realityShortID, $0) }
            reality.mldsa65Verify = reality.mldsa65Verify.map { transform(.realityMLDSA65Verify, $0) }
            copy.security.reality = reality
        }

        return copy
    }
}
