enum TransportType: String, CaseIterable, Codable, Identifiable {
    case tcp
    case websocket
    case grpc
    case httpUpgrade
    case quic

    var id: String {
        rawValue
    }

    var displayName: String {
        switch self {
        case .tcp:
            "TCP"
        case .websocket:
            "WebSocket"
        case .grpc:
            "gRPC"
        case .httpUpgrade:
            "HTTP Upgrade"
        case .quic:
            "QUIC"
        }
    }

    var singBoxType: String? {
        switch self {
        case .tcp:
            nil
        case .websocket:
            "ws"
        case .grpc:
            "grpc"
        case .httpUpgrade:
            "httpupgrade"
        case .quic:
            "quic"
        }
    }
}

struct TransportOptions: Hashable, Codable {
    var type: TransportType
    var path: String?
    var host: String?
    var serviceName: String?

    static let tcp = TransportOptions(type: .tcp)
}
