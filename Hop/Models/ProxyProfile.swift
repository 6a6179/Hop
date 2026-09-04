import Foundation

struct ProxyProfile: Identifiable, Hashable, Codable {
    var id: UUID
    var name: String
    var endpoint: Endpoint
    var options: ProtocolOptions
    var security: ProxySecurity
    var transport: TransportOptions
    var subscriptionID: UUID?
    var xrayAdvanced: XrayAdvancedDocument?

    init(
        id: UUID = UUID(),
        name: String,
        endpoint: Endpoint,
        options: ProtocolOptions,
        security: ProxySecurity,
        transport: TransportOptions = .tcp,
        subscriptionID: UUID? = nil,
        xrayAdvanced: XrayAdvancedDocument? = nil,
    ) {
        self.id = id
        self.name = name
        self.endpoint = endpoint
        self.options = options
        self.security = security
        self.transport = transport
        self.subscriptionID = subscriptionID
        self.xrayAdvanced = xrayAdvanced
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

    /// Import can preserve an incomplete node for editing; the builder rejects
    /// missing obfuscation credentials rather than silently dropping the layer.
    var hysteria2ObfsRuntimeWarning: String? {
        guard case let .hysteria2(options) = options,
              let obfs = options.obfs, !obfs.isEmpty,
              options.obfsPassword?.isEmpty != false
        else {
            return nil
        }
        return "Hysteria2 \(obfs) needs an obfuscation password before connecting."
    }

    var importRuntimeWarnings: [String] {
        [hysteria2ObfsRuntimeWarning].compactMap(\.self)
    }
}
