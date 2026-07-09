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
    /// Kept only to decode/import legacy profiles. Xray v26.6.27 rejects it.
    var allowInsecure: Bool
    var utlsFingerprint: String?
    var pinnedPeerCertSHA256: String?
    var verifyPeerCertByName: String?
    var echConfigList: String?
    var curvePreferences: [String]
    var minVersion: String?
    var maxVersion: String?
    var cipherSuites: String?
    var enableSessionResumption: Bool

    init(
        serverName: String? = nil,
        alpn: [String] = [],
        allowInsecure: Bool = false,
        utlsFingerprint: String? = "chrome",
        pinnedPeerCertSHA256: String? = nil,
        verifyPeerCertByName: String? = nil,
        echConfigList: String? = nil,
        curvePreferences: [String] = [],
        minVersion: String? = nil,
        maxVersion: String? = nil,
        cipherSuites: String? = nil,
        enableSessionResumption: Bool = false,
    ) {
        self.serverName = serverName
        self.alpn = alpn
        self.allowInsecure = allowInsecure
        self.utlsFingerprint = utlsFingerprint
        self.pinnedPeerCertSHA256 = pinnedPeerCertSHA256
        self.verifyPeerCertByName = verifyPeerCertByName
        self.echConfigList = echConfigList
        self.curvePreferences = curvePreferences
        self.minVersion = minVersion
        self.maxVersion = maxVersion
        self.cipherSuites = cipherSuites
        self.enableSessionResumption = enableSessionResumption
    }
}

extension TLSOptions {
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        serverName = try container.decodeIfPresent(String.self, forKey: .serverName)
        alpn = try container.decodeIfPresent([String].self, forKey: .alpn) ?? []
        allowInsecure = try container.decodeIfPresent(Bool.self, forKey: .allowInsecure) ?? false
        utlsFingerprint = try container.decodeIfPresent(String.self, forKey: .utlsFingerprint)
        pinnedPeerCertSHA256 = try container.decodeIfPresent(String.self, forKey: .pinnedPeerCertSHA256)
        verifyPeerCertByName = try container.decodeIfPresent(String.self, forKey: .verifyPeerCertByName)
        echConfigList = try container.decodeIfPresent(String.self, forKey: .echConfigList)
        curvePreferences = try container.decodeIfPresent([String].self, forKey: .curvePreferences) ?? []
        minVersion = try container.decodeIfPresent(String.self, forKey: .minVersion)
        maxVersion = try container.decodeIfPresent(String.self, forKey: .maxVersion)
        cipherSuites = try container.decodeIfPresent(String.self, forKey: .cipherSuites)
        enableSessionResumption = try container.decodeIfPresent(Bool.self, forKey: .enableSessionResumption) ?? false
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
