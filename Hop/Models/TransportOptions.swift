enum TransportType: String, CaseIterable, Codable, Identifiable {
    case tcp
    case websocket
    case grpc
    case httpUpgrade
    case xhttp
    case mKCP
    case hysteria
    /// Decodes legacy profiles so migration can explain why they cannot run.
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
        case .xhttp:
            "XHTTP"
        case .mKCP:
            "mKCP"
        case .hysteria:
            "Hysteria"
        case .quic:
            "QUIC"
        }
    }
}

struct TransportOptions: Hashable, Codable {
    var type: TransportType
    var path: String?
    var host: String?
    var serviceName: String?
    var xhttpMode: String?
    var xhttpExtra: JSONValue?
    var kcp: XrayKCPOptions?
    var finalMask: JSONValue?
    var mux: XrayMuxOptions?
    var socketOptions: JSONValue?

    init(
        type: TransportType,
        path: String? = nil,
        host: String? = nil,
        serviceName: String? = nil,
        xhttpMode: String? = nil,
        xhttpExtra: JSONValue? = nil,
        kcp: XrayKCPOptions? = nil,
        finalMask: JSONValue? = nil,
        mux: XrayMuxOptions? = nil,
        socketOptions: JSONValue? = nil,
    ) {
        self.type = type
        self.path = path
        self.host = host
        self.serviceName = serviceName
        self.xhttpMode = xhttpMode
        self.xhttpExtra = xhttpExtra
        self.kcp = kcp
        self.finalMask = finalMask
        self.mux = mux
        self.socketOptions = socketOptions
    }

    static let tcp = TransportOptions(type: .tcp)
}
