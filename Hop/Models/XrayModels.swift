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
    static let currentSchemaVersion = "v26.6.27"

    var schemaVersion: String
    var values: [String: JSONValue]

    init(
        schemaVersion: String = XrayAdvancedDocument.currentSchemaVersion,
        values: [String: JSONValue] = [:],
    ) {
        self.schemaVersion = schemaVersion
        self.values = values
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

struct XrayClientOverrides: Hashable, Codable, Sendable {
    var protocolSettings: [String: JSONValue] = [:]
    var streamSettings: [String: JSONValue] = [:]
    var proxySettings: [String: JSONValue] = [:]
    var mux: [String: JSONValue] = [:]
    var targetStrategy: String?
}

/// Runtime-only secret values. Persist only token strings in advanced JSON;
/// raw sidecar values must follow the existing SecretStore path.
struct XraySecretSidecar: Hashable, Sendable {
    var valuesByJSONPointer: [String: String] = [:]
}

struct XrayValidationIssue: Identifiable, Hashable, Codable, Sendable {
    enum Severity: String, Hashable, Codable, Sendable {
        case error
        case warning
    }

    var path: String
    var message: String
    var severity: Severity = .error

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
    let maxRenderedConfigBytes = 1 * 1024 * 1024
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
    let maxMuxConcurrency = 8
    let maxXUDPConcurrency = 16
    let maxKCPReadBufferBytes = 1 * 1024 * 1024
    let maxKCPWriteBufferBytes = 1 * 1024 * 1024
    let maxGRPCInitialWindowBytes = 1 * 1024 * 1024
    let maxXHTTPConnections = 2
    let maxXHTTPBufferedPosts = 2
    let maxXHTTPPostBytes = 256 * 1024
    let maxPolicyBufferSizeKiB = 256
    let maxQUICStreamWindowBytes = 1 * 1024 * 1024
    let maxQUICConnectionWindowBytes = 4 * 1024 * 1024
    let maxQUICIncomingStreams = 16
    let maxHysteriaBandwidthMbps = 1000
    let maxHysteriaPortHops = 64
    let maxFinalMaskLayers = 4
    let maxFinalMaskGeneratedPayloadBytes = 64 * 1024
    let maxXDNSResolvers = 4
    let maxRealmSTUNServers = 4
    let maxWireGuardPeers = 4
    let maxConcurrentHeavyOutbounds = 1
    let memoryCollectionThresholdBytes = 42 * 1024 * 1024
    let memoryStopThresholdBytes = 46 * 1024 * 1024
}
