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
