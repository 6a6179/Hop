import Foundation

#if canImport(Libbox)
    import Libbox

    final class TunnelTelemetryClient: @unchecked Sendable {
        var onStatus: ((TrafficCounters) -> Void)?
        var onConnections: (([TunnelConnectionSnapshot]) -> Void)?
        var onConnectionStateChanged: ((Bool, String?) -> Void)?

        private var commandClient: LibboxCommandClient?
        private var isConnecting = false
        private var activeToken: UInt64 = 0
        private var connectionsStore: LibboxConnections?
        private let connectionsLock = NSLock()

        func start() {
            guard commandClient == nil, !isConnecting else {
                return
            }

            isConnecting = true
            activeToken &+= 1
            let token = activeToken

            DispatchQueue.global(qos: .utility).async { [weak self] in
                guard let self else {
                    return
                }

                let options = LibboxCommandClientOptions()
                options.addCommand(LibboxCommandStatus)
                options.addCommand(LibboxCommandConnections)
                options.statusInterval = Int64(NSEC_PER_SEC)

                guard let client = LibboxNewCommandClient(TunnelTelemetryHandler(client: self, token: token), options) else {
                    DispatchQueue.main.async { [weak self] in
                        self?.finishStart(token: token, client: nil, error: "libbox returned no command client")
                    }
                    return
                }

                do {
                    try client.connect()
                    DispatchQueue.main.async { [weak self] in
                        self?.finishStart(token: token, client: client, error: nil)
                    }
                } catch {
                    DispatchQueue.main.async { [weak self] in
                        self?.finishStart(token: token, client: nil, error: error.localizedDescription)
                    }
                }
            }
        }

        func stop(resetValues: Bool = true) {
            activeToken &+= 1
            isConnecting = false
            if let commandClient {
                try? commandClient.disconnect()
            }
            commandClient = nil
            connectionsLock.lock()
            connectionsStore = nil
            connectionsLock.unlock()
            onConnectionStateChanged?(false, nil)
            if resetValues {
                onStatus?(.zero)
                onConnections?([])
            }
        }

        func closeAllConnections() {
            DispatchQueue.global(qos: .utility).async {
                try? LibboxNewStandaloneCommandClient()?.closeConnections()
            }
        }

        func closeConnection(id: String) {
            DispatchQueue.global(qos: .utility).async {
                try? LibboxNewStandaloneCommandClient()?.closeConnection(id)
            }
        }

        private func finishStart(token: UInt64, client: LibboxCommandClient?, error: String?) {
            defer {
                isConnecting = false
            }

            guard token == activeToken else {
                if let client {
                    try? client.disconnect()
                }
                return
            }

            if let client {
                commandClient = client
            } else {
                onConnectionStateChanged?(false, error)
            }
        }

        fileprivate func handleConnected(token: UInt64) {
            DispatchQueue.main.async { [weak self] in
                guard let self, token == activeToken else {
                    return
                }
                onConnectionStateChanged?(true, nil)
            }
        }

        fileprivate func handleDisconnected(token: UInt64, message: String?) {
            DispatchQueue.main.async { [weak self] in
                guard let self, token == activeToken else {
                    return
                }
                commandClient = nil
                connectionsLock.lock()
                connectionsStore = nil
                connectionsLock.unlock()
                onConnectionStateChanged?(false, message)
            }
        }

        fileprivate func handleStatus(token: UInt64, message: LibboxStatusMessage?) {
            guard let message else {
                return
            }
            let counters = TrafficCounters(
                uplinkBytes: max(0, message.uplinkTotal),
                downlinkBytes: max(0, message.downlinkTotal),
                uplinkBytesPerSecond: message.trafficAvailable ? max(0, message.uplink) : 0,
                downlinkBytesPerSecond: message.trafficAvailable ? max(0, message.downlink) : 0,
            )

            DispatchQueue.main.async { [weak self] in
                guard let self, token == activeToken else {
                    return
                }
                onStatus?(counters)
            }
        }

        fileprivate func handleConnectionEvents(token: UInt64, events: LibboxConnectionEvents?) {
            guard let events else {
                return
            }

            let snapshots: [TunnelConnectionSnapshot] = {
                connectionsLock.lock()
                defer {
                    connectionsLock.unlock()
                }
                if connectionsStore == nil {
                    connectionsStore = LibboxNewConnections()
                }
                guard let connectionsStore else {
                    return []
                }
                connectionsStore.apply(events)
                connectionsStore.sortByDate()
                return Self.snapshots(from: connectionsStore)
            }()

            DispatchQueue.main.async { [weak self] in
                guard let self, token == activeToken else {
                    return
                }
                onConnections?(snapshots)
            }
        }

        private static func snapshots(from store: LibboxConnections) -> [TunnelConnectionSnapshot] {
            guard let iterator = store.iterator() else {
                return []
            }

            var snapshots: [TunnelConnectionSnapshot] = []
            while iterator.hasNext() {
                guard let connection = iterator.next(), connection.outboundType != "dns" else {
                    continue
                }
                snapshots.append(snapshot(from: connection))
            }
            return snapshots
        }

        private static func snapshot(from connection: LibboxConnection) -> TunnelConnectionSnapshot {
            TunnelConnectionSnapshot(
                id: connection.id_,
                network: connection.network,
                source: connection.source,
                destination: connection.destination,
                domain: connection.domain,
                displayDestination: connection.displayDestination(),
                protocolName: connection.protocol,
                inbound: connection.inbound,
                inboundType: connection.inboundType,
                outbound: connection.outbound,
                outboundType: connection.outboundType,
                createdAt: date(millisecondsSince1970: connection.createdAt) ?? .now,
                closedAt: date(millisecondsSince1970: connection.closedAt),
                uplinkBytesPerSecond: max(0, connection.uplink),
                downlinkBytesPerSecond: max(0, connection.downlink),
                uplinkTotalBytes: max(0, connection.uplinkTotal),
                downlinkTotalBytes: max(0, connection.downlinkTotal),
                rule: connection.rule,
                chain: stringArray(from: connection.chain()),
            )
        }

        private static func date(millisecondsSince1970 milliseconds: Int64) -> Date? {
            guard milliseconds > 0 else {
                return nil
            }
            return Date(timeIntervalSince1970: Double(milliseconds) / 1000)
        }

        private static func stringArray(from iterator: (any LibboxStringIteratorProtocol)?) -> [String] {
            guard let iterator else {
                return []
            }

            var values: [String] = []
            while iterator.hasNext() {
                let value = iterator.next()
                if !value.isEmpty {
                    values.append(value)
                }
            }
            return values
        }
    }

    private final class TunnelTelemetryHandler: NSObject, LibboxCommandClientHandlerProtocol {
        private weak var client: TunnelTelemetryClient?
        private let token: UInt64

        init(client: TunnelTelemetryClient, token: UInt64) {
            self.client = client
            self.token = token
        }

        func connected() {
            client?.handleConnected(token: token)
        }

        func disconnected(_ message: String?) {
            client?.handleDisconnected(token: token, message: message)
        }

        func writeStatus(_ message: LibboxStatusMessage?) {
            client?.handleStatus(token: token, message: message)
        }

        func write(_ events: LibboxConnectionEvents?) {
            client?.handleConnectionEvents(token: token, events: events)
        }

        func clearLogs() {}
        func setDefaultLogLevel(_: Int32) {}
        func writeLogs(_: (any LibboxLogIteratorProtocol)?) {}
        func writeGroups(_: (any LibboxOutboundGroupIteratorProtocol)?) {}
        func initializeClashMode(_: (any LibboxStringIteratorProtocol)?, currentMode _: String?) {}
        func updateClashMode(_: String?) {}
    }
#else
    final class TunnelTelemetryClient {
        var onStatus: ((TrafficCounters) -> Void)?
        var onConnections: (([TunnelConnectionSnapshot]) -> Void)?
        var onConnectionStateChanged: ((Bool, String?) -> Void)?

        func start() {
            onConnectionStateChanged?(false, "Libbox is unavailable in this build.")
        }

        func stop(resetValues: Bool = true) {
            onConnectionStateChanged?(false, nil)
            if resetValues {
                onStatus?(.zero)
                onConnections?([])
            }
        }

        func closeAllConnections() {}
        func closeConnection(id _: String) {}
    }
#endif
