import Foundation

struct ProxyProfile: Identifiable, Hashable, Codable {
    var id: UUID
    var name: String
    var endpoint: Endpoint
    var proto: ProxyProtocol
    var options: ProtocolOptions
    var security: ProxySecurity
    var transport: TransportOptions

    init(
        id: UUID = UUID(),
        name: String,
        endpoint: Endpoint,
        proto: ProxyProtocol,
        options: ProtocolOptions,
        security: ProxySecurity,
        transport: TransportOptions = .tcp,
    ) {
        self.id = id
        self.name = name
        self.endpoint = endpoint
        self.proto = proto
        self.options = options
        self.security = security
        self.transport = transport
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
}
