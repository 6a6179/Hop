import Foundation

#if canImport(Libbox)
    @preconcurrency import Libbox

    /// Live telemetry from the tunnel's libbox command server, split into two
    /// independent subscriptions:
    ///
    /// - a **status** stream (traffic counters + live connection counts) that
    ///   runs for the whole tunnel session and doubles as the telemetry health
    ///   signal, and
    /// - a **connections** stream (per-connection events) that is much heavier
    ///   — libbox pushes event batches every interval and each one is
    ///   re-extracted over the gomobile bridge — so callers start it only
    ///   while a connections UI is actually visible.
    ///
    /// The class is `@MainActor`: every stored property is main-isolated and
    /// the libbox callback handlers are separate per-session objects that
    /// convert bridge payloads into value types on the callback thread before
    /// hopping over (see `StatusCommandHandler` / `ConnectionsCommandHandler`).
    /// Stale-session callbacks are dropped by per-stream tokens.
    @MainActor
    final class TunnelTelemetryClient {
        var onStatus: ((TrafficCounters) -> Void)?
        var onConnections: (([TunnelConnectionSnapshot]) -> Void)?
        var onConnectionStateChanged: ((Bool, String?) -> Void)?

        private let libboxRuntime = LibboxCommandRuntime()

        private var statusClient: LibboxCommandClient?
        private var statusConnecting = false
        private var statusToken: UInt64 = 0

        private var connectionsClient: LibboxCommandClient?
        private var connectionsConnecting = false
        private var connectionsToken: UInt64 = 0

        // MARK: - Status stream

        /// Starts the per-second status subscription. Idempotent.
        func start() {
            guard statusClient == nil, !statusConnecting else {
                return
            }
            statusConnecting = true
            statusToken &+= 1
            let token = statusToken
            let runtime = libboxRuntime

            Task.detached(priority: .utility) { [weak self] in
                guard let self else {
                    return
                }
                do {
                    let client = try Self.establishClient(
                        runtime: runtime,
                        commands: [LibboxCommandStatus],
                        handler: StatusCommandHandler(client: self, token: token),
                    )
                    let transfer = LibboxClientTransfer(client)
                    await finishStatusStart(token: token, client: transfer.value, error: nil)
                } catch {
                    await finishStatusStart(token: token, client: nil, error: error.localizedDescription)
                }
            }
        }

        /// Stops both streams and publishes zeroed values, e.g. on tunnel
        /// disconnect.
        func stop() {
            statusToken &+= 1
            statusConnecting = false
            if let statusClient {
                try? statusClient.disconnect()
            }
            statusClient = nil

            stopConnections()

            onConnectionStateChanged?(false, nil)
            onStatus?(.zero)
            onConnections?([])
        }

        private func finishStatusStart(token: UInt64, client: LibboxCommandClient?, error: String?) {
            guard token == statusToken else {
                // A stop()/restart superseded this connect; dispose quietly and
                // leave the current session's `connecting` flag alone.
                if let client {
                    try? client.disconnect()
                }
                return
            }

            statusConnecting = false
            if let client {
                statusClient = client
            } else {
                onConnectionStateChanged?(false, error)
            }
        }

        fileprivate func handleStatusConnected(token: UInt64) {
            guard token == statusToken else {
                return
            }
            onConnectionStateChanged?(true, nil)
        }

        fileprivate func handleStatusDisconnected(token: UInt64, message: String?) {
            guard token == statusToken else {
                return
            }
            // Bump so stragglers from this dead session can't publish after
            // the disconnect notification.
            statusToken &+= 1
            statusClient = nil
            onConnectionStateChanged?(false, message)
        }

        fileprivate func handleStatus(token: UInt64, counters: TrafficCounters) {
            guard token == statusToken else {
                return
            }
            onStatus?(counters)
        }

        // MARK: - Connections stream

        /// Starts the per-connection event subscription. Idempotent; safe to
        /// call regardless of whether the status stream is up.
        func startConnections() {
            guard connectionsClient == nil, !connectionsConnecting else {
                return
            }
            connectionsConnecting = true
            connectionsToken &+= 1
            let token = connectionsToken
            let runtime = libboxRuntime

            Task.detached(priority: .utility) { [weak self] in
                guard let self else {
                    return
                }
                do {
                    let client = try Self.establishClient(
                        runtime: runtime,
                        commands: [LibboxCommandConnections],
                        handler: ConnectionsCommandHandler(client: self, token: token),
                    )
                    let transfer = LibboxClientTransfer(client)
                    await finishConnectionsStart(token: token, client: transfer.value)
                } catch {
                    // Best-effort stream: the status stream is the telemetry
                    // health signal, so a connections-subscribe failure only
                    // means the list stays empty until the next attempt.
                    await finishConnectionsStart(token: token, client: nil)
                }
            }
        }

        /// Stops the connections stream only. The last published list is kept;
        /// resubscribing receives a full reset batch that replaces it.
        func stopConnections() {
            connectionsToken &+= 1
            connectionsConnecting = false
            if let connectionsClient {
                try? connectionsClient.disconnect()
            }
            connectionsClient = nil
        }

        private func finishConnectionsStart(token: UInt64, client: LibboxCommandClient?) {
            guard token == connectionsToken else {
                if let client {
                    try? client.disconnect()
                }
                return
            }

            connectionsConnecting = false
            connectionsClient = client
        }

        fileprivate func handleConnectionsDisconnected(token: UInt64) {
            guard token == connectionsToken else {
                return
            }
            connectionsToken &+= 1
            connectionsClient = nil
        }

        fileprivate func handleConnections(token: UInt64, snapshots: [TunnelConnectionSnapshot]) {
            guard token == connectionsToken else {
                return
            }
            onConnections?(snapshots)
        }

        // MARK: - One-shot commands

        func closeAllConnections() {
            let runtime = libboxRuntime
            Task.detached(priority: .utility) {
                try? runtime.ensureConfigured()
                try? LibboxNewStandaloneCommandClient()?.closeConnections()
            }
        }

        func closeConnection(id: String) {
            let runtime = libboxRuntime
            Task.detached(priority: .utility) {
                try? runtime.ensureConfigured()
                try? LibboxNewStandaloneCommandClient()?.closeConnection(id)
            }
        }

        // MARK: - Worker-side plumbing

        /// Configures the runtime and connects a command client subscribed to
        /// `commands`. Runs on the connect worker; the returned client is
        /// handed to the main actor exactly once via `LibboxClientTransfer`.
        private nonisolated static func establishClient(
            runtime: LibboxCommandRuntime,
            commands: [Int32],
            handler: any LibboxCommandClientHandlerProtocol,
        ) throws -> LibboxCommandClient {
            try runtime.ensureConfigured()

            let options = LibboxCommandClientOptions()
            for command in commands {
                options.addCommand(command)
            }
            options.statusInterval = Int64(NSEC_PER_SEC)

            guard let client = LibboxNewCommandClient(handler, options) else {
                throw TunnelTelemetryError.commandClientUnavailable
            }
            try client.connect()
            return client
        }

        // MARK: - Bridge value extraction (callback-thread safe)

        nonisolated static func counters(from message: LibboxStatusMessage) -> TrafficCounters {
            TrafficCounters(
                uplinkBytes: max(0, message.uplinkTotal),
                downlinkBytes: max(0, message.downlinkTotal),
                uplinkBytesPerSecond: message.trafficAvailable ? max(0, message.uplink) : 0,
                downlinkBytesPerSecond: message.trafficAvailable ? max(0, message.downlink) : 0,
                activeConnections: Int(max(0, message.connectionsIn)),
            )
        }

        nonisolated static func snapshots(
            from store: LibboxConnections,
            reusing cache: inout [String: TunnelConnectionSnapshot],
        ) -> [TunnelConnectionSnapshot] {
            guard let iterator = store.iterator() else {
                cache = [:]
                return []
            }

            var snapshots: [TunnelConnectionSnapshot] = []
            var rebuiltCache: [String: TunnelConnectionSnapshot] = [:]
            rebuiltCache.reserveCapacity(cache.count)
            while iterator.hasNext() {
                guard let connection = iterator.next(), connection.outboundType != "dns" else {
                    continue
                }
                let snapshot = snapshot(from: connection, cache: cache)
                rebuiltCache[snapshot.id] = snapshot
                snapshots.append(snapshot)
            }
            cache = rebuiltCache // entries for vanished connections drop out here
            return snapshots
        }

        /// Reuses the cached snapshot when none of the connection's mutable
        /// numeric fields moved. Traffic rates/totals and `closedAt` are the
        /// only fields libbox updates after creation without traffic flowing;
        /// anything else (sniffed domain/protocol, routing rule, chain) is
        /// settled while handshake bytes move the totals, which forces a fresh
        /// extraction anyway.
        nonisolated static func snapshot(from connection: LibboxConnection, cache: [String: TunnelConnectionSnapshot]) -> TunnelConnectionSnapshot {
            let id = connection.id_
            if let cached = cache[id],
               cached.closedAt == date(millisecondsSince1970: connection.closedAt),
               cached.uplinkBytesPerSecond == max(0, connection.uplink),
               cached.downlinkBytesPerSecond == max(0, connection.downlink),
               cached.uplinkTotalBytes == max(0, connection.uplinkTotal),
               cached.downlinkTotalBytes == max(0, connection.downlinkTotal)
            {
                return cached
            }

            return TunnelConnectionSnapshot(
                id: id,
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

        private nonisolated static func date(millisecondsSince1970 milliseconds: Int64) -> Date? {
            guard milliseconds > 0 else {
                return nil
            }
            return Date(timeIntervalSince1970: Double(milliseconds) / 1000)
        }

        private nonisolated static func stringArray(from iterator: (any LibboxStringIteratorProtocol)?) -> [String] {
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

    /// One-shot, single-owner handoff of a non-Sendable libbox object from the
    /// connect worker to the main actor. The worker boxes the object as its
    /// last touch, so there is never concurrent access — the narrow
    /// `@unchecked Sendable` this file still needs.
    private struct LibboxClientTransfer: @unchecked Sendable {
        let value: LibboxCommandClient

        init(_ value: LibboxCommandClient) {
            self.value = value
        }
    }

    /// All-no-op `LibboxCommandClientHandlerProtocol` base. libbox invokes
    /// these from its Go-side read loops; subclasses extract value types there
    /// and hop to the main-actor client, dropping stale sessions by token.
    private class TelemetryCommandHandler: NSObject, LibboxCommandClientHandlerProtocol {
        func connected() {}
        func disconnected(_: String?) {}
        func writeStatus(_: LibboxStatusMessage?) {}
        func write(_: LibboxConnectionEvents?) {}
        func clearLogs() {}
        func setDefaultLogLevel(_: Int32) {}
        func writeLogs(_: (any LibboxLogIteratorProtocol)?) {}
        func writeGroups(_: (any LibboxOutboundGroupIteratorProtocol)?) {}
        func initializeClashMode(_: (any LibboxStringIteratorProtocol)?, currentMode _: String?) {}
        func updateClashMode(_: String?) {}
    }

    /// Handler for the status subscription; also the telemetry health signal
    /// (its connected/disconnected drive `onConnectionStateChanged`).
    private final class StatusCommandHandler: TelemetryCommandHandler {
        private weak var client: TunnelTelemetryClient?
        private let token: UInt64

        init(client: TunnelTelemetryClient?, token: UInt64) {
            self.client = client
            self.token = token
        }

        override func connected() {
            let token = token
            Task { @MainActor [weak client] in
                client?.handleStatusConnected(token: token)
            }
        }

        override func disconnected(_ message: String?) {
            let token = token
            Task { @MainActor [weak client] in
                client?.handleStatusDisconnected(token: token, message: message)
            }
        }

        override func writeStatus(_ message: LibboxStatusMessage?) {
            guard let message else {
                return
            }
            let counters = TunnelTelemetryClient.counters(from: message)
            let token = token
            Task { @MainActor [weak client] in
                client?.handleStatus(token: token, counters: counters)
            }
        }
    }

    /// Handler for the connections subscription. Owns the libbox connections
    /// store for its session: only `write(_:)` touches it, and libbox delivers
    /// those sequentially from the subscription's single read loop, so no lock
    /// is needed — the store dies with the handler when the session ends.
    private final class ConnectionsCommandHandler: TelemetryCommandHandler {
        private weak var client: TunnelTelemetryClient?
        private let token: UInt64
        private let connectionsStore = LibboxNewConnections()
        private var snapshotCache: [String: TunnelConnectionSnapshot] = [:]
        private var publishedSnapshots: [TunnelConnectionSnapshot]?

        init(client: TunnelTelemetryClient?, token: UInt64) {
            self.client = client
            self.token = token
        }

        override func disconnected(_: String?) {
            let token = token
            Task { @MainActor [weak client] in
                client?.handleConnectionsDisconnected(token: token)
            }
        }

        override func write(_ events: LibboxConnectionEvents?) {
            guard let events, let connectionsStore else {
                return
            }
            connectionsStore.apply(events)
            connectionsStore.sortByDate()
            let rebuilt = TunnelTelemetryClient.snapshots(from: connectionsStore, reusing: &snapshotCache)
            // Skip the main-actor hop when nothing changed, so an idle tunnel
            // doesn't trigger observation/SwiftUI work every interval.
            guard rebuilt != publishedSnapshots else {
                return
            }
            publishedSnapshots = rebuilt
            let token = token
            Task { @MainActor [weak client] in
                client?.handleConnections(token: token, snapshots: rebuilt)
            }
        }
    }

    private final class LibboxCommandRuntime: @unchecked Sendable {
        private let lock = NSLock()
        private var isConfigured = false

        func ensureConfigured() throws {
            lock.lock()
            defer {
                lock.unlock()
            }

            guard !isConfigured else {
                return
            }

            guard let container = RuntimeEnvironment.appGroupContainerURL else {
                throw TunnelTelemetryError.appGroupUnavailable(RuntimeEnvironment.appGroupIdentifier)
            }

            let workingPath = container.appendingPathComponent("Working", isDirectory: true)
            let tempPath = container.appendingPathComponent("Temp", isDirectory: true)
            try FileManager.default.createDirectory(at: workingPath, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: tempPath, withIntermediateDirectories: true)

            let setup = LibboxSetupOptions()
            setup.basePath = container.path
            setup.workingPath = workingPath.path
            setup.tempPath = tempPath.path
            setup.logMaxLines = 3000
            // Present the same shared-Keychain token the extension's command
            // server requires, so the live status/connections feed authenticates.
            setup.commandServerSecret = SecretStore.runtime.commandServerSecret()

            var setupError: NSError?
            LibboxSetup(setup, &setupError)
            if let setupError {
                throw setupError
            }

            isConfigured = true
        }
    }

    private enum TunnelTelemetryError: LocalizedError {
        case appGroupUnavailable(String)
        case commandClientUnavailable

        var errorDescription: String? {
            switch self {
            case let .appGroupUnavailable(appGroup):
                "App Group \(appGroup) is unavailable; live telemetry requires Hop and HopTunnel to be signed with the same App Group entitlement."
            case .commandClientUnavailable:
                "libbox returned no command client"
            }
        }
    }
#else
    @MainActor
    final class TunnelTelemetryClient {
        var onStatus: ((TrafficCounters) -> Void)?
        var onConnections: (([TunnelConnectionSnapshot]) -> Void)?
        var onConnectionStateChanged: ((Bool, String?) -> Void)?

        func start() {
            onConnectionStateChanged?(false, "Libbox is unavailable in this build.")
        }

        func stop() {
            onConnectionStateChanged?(false, nil)
            onStatus?(.zero)
            onConnections?([])
        }

        func startConnections() {}
        func stopConnections() {}
        func closeAllConnections() {}
        func closeConnection(id _: String) {}
    }
#endif
