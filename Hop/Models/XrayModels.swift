import Foundation

enum XrayAdvancedDocumentError: LocalizedError {
    case rootMustBeObject
    case invalidUTF8

    var errorDescription: String? {
        switch self {
        case .rootMustBeObject:
            "Advanced Xray JSON must contain one object at its root."
        case .invalidUTF8:
            "Advanced Xray JSON is not valid UTF-8."
        }
    }
}

/// A schema-pinned advanced override. `jsonString` intentionally represents
/// only the editable Xray object; schema metadata remains in persisted Codable.
struct XrayAdvancedDocument: Hashable, Codable, Sendable {
    static let currentSchemaVersion = XrayBridgeRequest.coreVersion

    var schemaVersion: String
    var values: [String: JSONValue]

    init(
        schemaVersion: String = XrayAdvancedDocument.currentSchemaVersion,
        values: [String: JSONValue] = [:],
    ) {
        self.schemaVersion = schemaVersion
        self.values = values
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let storedVersion = try container.decode(String.self, forKey: .schemaVersion)
        // Only these released schemas have a reviewed compatibility path in
        // the builder. A future core bump must explicitly review November.
        switch storedVersion {
        case "v26.6.27", "v26.7.28":
            schemaVersion = "v26.11.9"
        default:
            schemaVersion = storedVersion
        }
        values = try container.decode([String: JSONValue].self, forKey: .values)
    }

    init(
        _ object: [String: JSONValue],
        schemaVersion: String = XrayAdvancedDocument.currentSchemaVersion,
    ) {
        self.init(schemaVersion: schemaVersion, values: object)
    }

    init(jsonString: String, schemaVersion: String = XrayAdvancedDocument.currentSchemaVersion) throws {
        guard let data = jsonString.data(using: .utf8) else {
            throw XrayAdvancedDocumentError.invalidUTF8
        }
        let value = try JSONDecoder().decode(JSONValue.self, from: data)
        guard case let .object(object) = value else {
            throw XrayAdvancedDocumentError.rootMustBeObject
        }
        self.init(schemaVersion: schemaVersion, values: object)
    }

    var jsonString: String {
        encodedData.flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
    }

    var encodedByteCount: Int {
        encodedData?.count ?? 2
    }

    private var encodedData: Data? {
        try? JSONSerialization.data(
            withJSONObject: JSONValue.object(values).foundationValue,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes],
        )
    }

    var isEmpty: Bool {
        values.isEmpty
    }
}

/// Runtime-only secret values. Persist only token strings in advanced JSON;
/// raw sidecar values must follow the existing SecretStore path.
struct XraySecretSidecar: Hashable, Sendable {
    var valuesByJSONPointer: [String: String] = [:]
}

/// Compiler-authored literals are safe for the connection UI. String
/// interpolations can contain imported names, JSON keys or credentials.
struct XrayValidationMessage: ExpressibleByStringInterpolation {
    let detail: String
    let publicReason: String

    init(stringLiteral value: String) {
        detail = value
        publicReason = value
    }

    init(stringInterpolation: StringInterpolation) {
        detail = stringInterpolation.detail
        publicReason = stringInterpolation.publicReason
    }

    struct StringInterpolation: StringInterpolationProtocol {
        var detail = ""
        var publicReason = ""

        init(literalCapacity: Int, interpolationCount _: Int) {
            detail.reserveCapacity(literalCapacity)
            publicReason.reserveCapacity(literalCapacity)
        }

        mutating func appendLiteral(_ literal: String) {
            detail += literal
            publicReason += literal
        }

        mutating func appendInterpolation(_ number: Int) {
            appendLiteral(String(number))
        }

        mutating func appendInterpolation(_ value: some Any) {
            detail += String(describing: value)
            publicReason += "“…”"
        }
    }
}

struct XrayValidationIssue: Identifiable, Hashable, Codable, Sendable {
    enum Severity: String, Hashable, Codable, Sendable {
        case error
        case warning
    }

    var path: String
    var message: String
    var publicReason: String?
    var severity: Severity = .error

    init(path: String, message: XrayValidationMessage, severity: Severity = .error) {
        self.path = path
        self.message = message.detail
        publicReason = message.publicReason
        self.severity = severity
    }

    /// Only use known field labels. Unknown JSON keys can themselves be secret.
    var publicField: String {
        let parts = path.split(separator: "/")
        switch parts.first {
        case "profiles":
            switch parts.dropFirst(2).first {
            case "endpoint": return "Server endpoint"
            case "transport", "streamSettings": return "Profile transport"
            case "security", "tlsSettings", "realitySettings": return "Profile security"
            case "options": return "Protocol options"
            default: return "Profile"
            }
        case "observatory": return "URL-test groups"
        case "groups": return "Proxy groups"
        case "selectedTarget", "outbounds": return "Outbound selection"
        case "routing": return "Routing rules"
        case "dns", "fakeDns": return "DNS settings"
        case "settings": return "Advanced settings"
        default: return "Configuration"
        }
    }

    var id: String {
        "\(severity.rawValue):\(path):\(message)"
    }
}

struct XrayKCPOptions: Hashable, Codable, Sendable {
    var mtu: Int?
    var tti: Int?
    var uplinkCapacity: Int?
    var downlinkCapacity: Int?
    var cwndMultiplier: Int?
    var maxSendingWindow: Int?

    init(
        mtu: Int? = nil,
        tti: Int? = nil,
        uplinkCapacity: Int? = nil,
        downlinkCapacity: Int? = nil,
        cwndMultiplier: Int? = nil,
        maxSendingWindow: Int? = nil,
    ) {
        self.mtu = mtu
        self.tti = tti
        self.uplinkCapacity = uplinkCapacity
        self.downlinkCapacity = downlinkCapacity
        self.cwndMultiplier = cwndMultiplier
        self.maxSendingWindow = maxSendingWindow
    }
}

struct XrayMuxOptions: Hashable, Codable, Sendable {
    var enabled: Bool
    var concurrency: Int
    var xudpConcurrency: Int
    var xudpProxyUDP443: String?

    init(
        enabled: Bool = false,
        concurrency: Int = 8,
        xudpConcurrency: Int = 16,
        xudpProxyUDP443: String? = nil,
    ) {
        self.enabled = enabled
        self.concurrency = concurrency
        self.xudpConcurrency = xudpConcurrency
        self.xudpProxyUDP443 = xudpProxyUDP443
    }
}

/// iOS Network Extensions are jetsammed around 50 MiB. These values are a
/// configuration admission envelope, not tuning suggestions.
struct IOSRuntimeLimits: Hashable, Sendable {
    static let `default` = IOSRuntimeLimits()

    let goHeapBytes = 30 * 1024 * 1024
    let goGCPercent = 10
    let maxRenderedConfigBytes = TunnelMemoryPolicy.maximumConfigurationBytes
    let maxProfileAdvancedBytes = 64 * 1024
    let maxGlobalAdvancedBytes = 256 * 1024
    let maxReachableOutbounds = 32
    let maxProxyGroupDepth = 32
    let maxProxyGroupResolutionSteps = 8192
    let maxRoutingAtoms = 4096
    let maxDNSServers = 8
    let maxFakeDNSPoolEntries = 4096
    let maxObservatoryTargets = 16
    let maxVLESSAuthenticationKeys = 4
    let maxVLESSPaddingDirectives = 16
    let maxVLESSPreconnections = 8
    let maxMuxConcurrency = 8
    let maxXUDPConcurrency = 16
    let maxKCPReadBufferBytes = 1 * 1024 * 1024
    let maxKCPWriteBufferBytes = 1 * 1024 * 1024
    let maxKCPCongestionWindowMultiplier = 16
    let maxGRPCInitialWindowBytes = 0
    let maxXHTTPConnections = 1
    let maxXHTTPBufferedPosts = 1
    let maxXHTTPPostBytes = 128 * 1024
    let maxXHTTPPaddingBytes = 16 * 1024
    let maxXHTTPSessionIDLength = 128
    let maxPolicyBufferSizeKiB = 16
    let maxPolicyHandshakeSeconds = 15
    let maxPolicyConnectionIdleSeconds = 120
    let maxPolicyHalfCloseSeconds = 1
    let maxQUICStreamWindowBytes = 512 * 1024
    let maxQUICConnectionWindowBytes = 2 * 1024 * 1024
    let maxQUICIncomingStreams = 0
    let maxHysteriaBandwidthMbps = 1000
    let maxHysteriaPortHops = 64
    let maxFinalMaskLayers = 4
    let maxFinalMaskGeneratedPayloadBytes = 64 * 1024
    let maxXDNSResolvers = 4
    let maxRealmSTUNServers = 4
    let maxWireGuardPeers = 4
    let maxConcurrentHeavyOutbounds = 1
    let memoryCollectionThresholdBytes = Int(TunnelMemoryPolicy.softLimitBytes)
    let memoryStopThresholdBytes = Int(TunnelMemoryPolicy.hardLimitBytes)
}
