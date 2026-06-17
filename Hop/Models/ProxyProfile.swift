import Foundation

struct ProxyProfile: Identifiable, Hashable, Codable {
    var id: UUID
    var name: String
    var endpoint: Endpoint
    var options: ProtocolOptions
    var security: ProxySecurity
    var transport: TransportOptions

    init(
        id: UUID = UUID(),
        name: String,
        endpoint: Endpoint,
        options: ProtocolOptions,
        security: ProxySecurity,
        transport: TransportOptions = .tcp,
    ) {
        self.id = id
        self.name = name
        self.endpoint = endpoint
        self.options = options
        self.security = security
        self.transport = transport
    }

    var proto: ProxyProtocol {
        options.proto
    }

    var displaySecurity: String {
        switch security.layer {
        case .none:
            "No transport security"
        case .tls:
            "TLS"
        case .reality:
            "REALITY"
        }
    }

    var vlessOptions: VLESSOptions? {
        guard case let .vless(options) = options else {
            return nil
        }
        return options
    }

    var vlessEncryptionRuntimeWarning: String? {
        guard proto == .vless,
              let options = vlessOptions,
              options.normalizedEncryption != nil
        else {
            return nil
        }
        return "\(options.encryptionAuthLabel) is preserved, but the bundled sing-box/libbox engine cannot run Xray VLESS Encryption/Auth yet."
    }

    var realityMLDSA65RuntimeWarning: String? {
        guard security.reality?.mldsa65Verify?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false else {
            return nil
        }
        return "REALITY ML-DSA-65 verification is preserved, but the bundled sing-box/libbox engine cannot enforce pqv yet."
    }

    /// The config builder only emits Hysteria2 obfuscation when both the type
    /// and password are present; an obfs type without a password is silently
    /// unusable at runtime, so it surfaces as a warning instead.
    var hysteria2ObfsRuntimeWarning: String? {
        guard case let .hysteria2(options) = options,
              let obfs = options.obfs, !obfs.isEmpty,
              options.obfsPassword?.isEmpty != false
        else {
            return nil
        }
        return "Hysteria2 \(obfs) obfuscation has no obfs password, so it is left out of the generated config."
    }

    var importRuntimeWarnings: [String] {
        [vlessEncryptionRuntimeWarning, realityMLDSA65RuntimeWarning, hysteria2ObfsRuntimeWarning].compactMap(\.self)
    }
}
