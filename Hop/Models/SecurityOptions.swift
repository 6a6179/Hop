enum SecurityLayer: String, CaseIterable, Codable, Identifiable {
    case none
    case tls
    case reality

    var id: String {
        rawValue
    }

    var displayName: String {
        switch self {
        case .none:
            "None"
        case .tls:
            "TLS"
        case .reality:
            "REALITY"
        }
    }
}

struct TLSOptions: Hashable, Codable {
    var serverName: String?
    var alpn: [String]
    var allowInsecure: Bool
    var utlsFingerprint: String?

    init(
        serverName: String? = nil,
        alpn: [String] = [],
        allowInsecure: Bool = false,
        utlsFingerprint: String? = "chrome",
    ) {
        self.serverName = serverName
        self.alpn = alpn
        self.allowInsecure = allowInsecure
        self.utlsFingerprint = utlsFingerprint
    }
}

struct RealityOptions: Hashable, Codable {
    var publicKey: String
    var shortID: String?
    var serverName: String?
    var spiderX: String?
    var mldsa65Verify: String?
    var utlsFingerprint: String

    init(
        publicKey: String,
        shortID: String? = nil,
        serverName: String? = nil,
        spiderX: String? = nil,
        mldsa65Verify: String? = nil,
        utlsFingerprint: String = "chrome",
    ) {
        self.publicKey = publicKey
        self.shortID = shortID
        self.serverName = serverName
        self.spiderX = spiderX
        self.mldsa65Verify = mldsa65Verify
        self.utlsFingerprint = utlsFingerprint
    }
}

struct ProxySecurity: Hashable, Codable {
    var layer: SecurityLayer
    var tls: TLSOptions?
    var reality: RealityOptions?

    static let none = ProxySecurity(layer: .none, tls: nil, reality: nil)

    static func tls(_ options: TLSOptions) -> ProxySecurity {
        ProxySecurity(layer: .tls, tls: options, reality: nil)
    }

    static func reality(_ options: RealityOptions) -> ProxySecurity {
        reality(options, alpn: [])
    }

    static func reality(_ options: RealityOptions, alpn: [String]) -> ProxySecurity {
        ProxySecurity(
            layer: .reality,
            tls: TLSOptions(
                serverName: options.serverName,
                alpn: alpn,
                allowInsecure: false,
                utlsFingerprint: options.utlsFingerprint,
            ),
            reality: options,
        )
    }
}
