import Foundation

enum TunnelConnectionState: Equatable {
    case disconnected
    case connecting
    case connected
    case disconnecting
    case failed

    var title: String {
        switch self {
        case .disconnected:
            "Disconnected"
        case .connecting:
            "Connecting"
        case .connected:
            "Connected"
        case .disconnecting:
            "Disconnecting"
        case .failed:
            "Failed"
        }
    }

    var isConnected: Bool {
        self == .connected
    }
}

struct TrafficCounters: Equatable {
    var uplinkBytes: Int64
    var downlinkBytes: Int64
    var uplinkBytesPerSecond: Int64 = 0
    var downlinkBytesPerSecond: Int64 = 0

    static let zero = TrafficCounters(uplinkBytes: 0, downlinkBytes: 0)
}

struct TunnelConnectionSnapshot: Identifiable, Equatable {
    var id: String
    var network: String
    var source: String
    var destination: String
    var domain: String
    var displayDestination: String
    var protocolName: String
    var inbound: String
    var inboundType: String
    var outbound: String
    var outboundType: String
    var createdAt: Date
    var closedAt: Date?
    var uplinkBytesPerSecond: Int64
    var downlinkBytesPerSecond: Int64
    var uplinkTotalBytes: Int64
    var downlinkTotalBytes: Int64
    var rule: String
    var chain: [String]

    var isActive: Bool {
        closedAt == nil
    }

    var searchableText: String {
        [
            network,
            source,
            destination,
            domain,
            displayDestination,
            protocolName,
            inbound,
            inboundType,
            outbound,
            outboundType,
            rule,
            chain.joined(separator: " "),
        ]
        .joined(separator: " ")
        .lowercased()
    }
}
