import Foundation
@preconcurrency import NetworkExtension
import Observation

@MainActor
@Observable
final class TunnelController {
    var state: TunnelConnectionState = .disconnected
    var counters: TrafficCounters = .zero
    var connections: [TunnelConnectionSnapshot] = []
    var telemetryIsConnected = false
    var telemetryError: String?
    var logs: [String]
    var maximumLogEntries: Int

    @ObservationIgnored var onLogsChanged: (() -> Void)?

    private let configBuilder = SingBoxConfigBuilder()
    private let sharedConfigStore = SharedTunnelConfigurationStore()
    private let sharedLogStore = SharedTunnelLogStore()
    private let secretStore = SecretStore.shared
    private let telemetryClient = TunnelTelemetryClient()
    @ObservationIgnored private var diagnosticsTask: Task<Void, Never>?
    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var importedExtensionLogLines: Set<String> = []
    private var lastObservedStatus: NEVPNStatus?
    private var startInProgress = false
    private var loggedStartupStop = false

    init(logs: [String] = SampleData.logs, maximumLogEntries: Int = LogRetention.fiveHundred.rawValue) {
        self.logs = logs
        self.maximumLogEntries = maximumLogEntries
        telemetryClient.onStatus = { [weak self] counters in
            self?.counters = counters
        }
        telemetryClient.onConnections = { [weak self] connections in
            self?.connections = connections
        }
        telemetryClient.onConnectionStateChanged = { [weak self] isConnected, error in
            self?.telemetryIsConnected = isConnected
            self?.telemetryError = error
            if let error, self?.state.isConnected == true {
                self?.appendLog("Telemetry unavailable: \(error)")
            }
        }
    }

    func connect(
        target: OutboundTarget,
        profiles: [ProxyProfile],
        groups: [ProxyGroup],
        routingMode: RoutingMode,
        rules: [RoutingRule],
        settings: AppSettings,
    ) async {
        diagnosticsTask?.cancel()
        importedExtensionLogLines.removeAll()
        lastObservedStatus = nil
        loggedStartupStop = false
        startInProgress = true
        state = .connecting
        counters = .zero
        connections = []
        telemetryError = nil
        appendLog("Connect requested for \(target.id)")
        appendLog("Resolved App Group: \(RuntimeEnvironment.appGroupIdentifier)")
        appendLog("Shared container: \(RuntimeEnvironment.sharedContainerURL.path)")
        appendLog("Tunnel extension bundle ID: \(RuntimeEnvironment.tunnelProviderBundleIdentifier)")

        do {
            try sharedLogStore.clear()
            appendLog("Cleared extension log at \(RuntimeEnvironment.tunnelLogFileURL.path)")
        } catch {
            appendLog("Unable to clear extension log: \(error.diagnosticDescription)")
        }

        do {
            appendLog("Preparing tunnel with \(profiles.count) nodes, \(groups.count) groups, \(rules.count) rules")
            // Ensure secrets are in the shared Keychain, then build a config that
            // references them by token so no credentials are written to disk or
            // passed through IPC/provider configuration. The per-start nonce
            // makes the tokens unforgeable from untrusted import data.
            for item in profiles.flatMap(\.keychainSecretItems) {
                secretStore.setValue(item.value, forKey: item.key)
            }
            let secretNonce = UUID().uuidString
            let configContent = try configBuilder.build(
                profiles: profiles.map { $0.tokenizingSecrets(nonce: secretNonce) },
                groups: groups,
                selectedTarget: target,
                routingMode: routingMode,
                rules: rules,
                settings: settings,
                logOutputPath: RuntimeEnvironment.tunnelLogFileURL.path,
            )
            try sharedConfigStore.writeConfig(configContent)

            let manager = try await configuredManager(secretNonce: secretNonce)
            observeStatus(for: manager.connection)
            appendLog("Starting NetworkExtension tunnel")
            try manager.connection.startVPNTunnel(options: [
                "configPath": RuntimeEnvironment.configFileURL.path as NSString,
                "appGroup": RuntimeEnvironment.appGroupIdentifier as NSString,
                "secretNonce": secretNonce as NSString,
            ])
            appendLog("startVPNTunnel returned; current status is \(manager.connection.status.displayName)")
            syncExtensionLogs()
            updateState(from: manager.connection.status, source: "startVPNTunnel return")
            if state == .connecting {
                appendLog("VPN start requested. Waiting for NetworkExtension status.")
            }
            schedulePostStartDiagnostics()
        } catch {
            state = .failed
            startInProgress = false
            syncExtensionLogs()
            appendLog("Tunnel start failed: \(error.diagnosticDescription)")
            if let diagnosticHint = error.networkExtensionDiagnosticHint {
                appendLog("Diagnostic: \(diagnosticHint)")
            }
        }
    }

    func disconnect() async {
        guard state.isConnected || state == .connecting else {
            state = .disconnected
            return
        }

        state = .disconnecting
        startInProgress = false
        diagnosticsTask?.cancel()
        stopTelemetry()
        do {
            let manager = try await loadManager()
            manager.connection.stopVPNTunnel()
            syncExtensionLogs()
            updateState(from: manager.connection.status, source: "disconnect")
            appendLog("Tunnel disconnect requested")
        } catch {
            state = .failed
            appendLog("Tunnel disconnect failed: \(error.diagnosticDescription)")
            if let diagnosticHint = error.networkExtensionDiagnosticHint {
                appendLog("Diagnostic: \(diagnosticHint)")
            }
        }
    }

    func appendLog(_ message: String) {
        let timestamp = Date.now.formatted(date: .omitted, time: .standard)
        logs.insert("[\(timestamp)] \(message)", at: 0)
        if logs.count > maximumLogEntries {
            logs.removeLast(logs.count - maximumLogEntries)
        }
        onLogsChanged?()
    }

    func clearLogs() {
        logs.removeAll()
        importedExtensionLogLines.removeAll()
        try? sharedLogStore.clear()
        onLogsChanged?()
    }

    func syncExtensionLogs() {
        do {
            for line in try sharedLogStore.readLines() where importedExtensionLogLines.insert(line).inserted {
                appendLog("Extension \(line)")
            }
        } catch {
            appendLog("Unable to read extension logs: \(error.diagnosticDescription)")
        }
    }

    private func configuredManager(secretNonce: String) async throws -> NETunnelProviderManager {
        let manager = try await loadManager()
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = RuntimeEnvironment.tunnelProviderBundleIdentifier
        tunnelProtocol.serverAddress = "Hop"
        // `secretNonce` lets an iOS-initiated restart (start options absent)
        // still resolve the tokens written to the shared config file. It is not
        // a secret — only unpredictable to import data — so persisting it in the
        // provider configuration alongside the non-secret paths is fine.
        tunnelProtocol.providerConfiguration = [
            "configPath": RuntimeEnvironment.configFileURL.path,
            "appGroup": RuntimeEnvironment.appGroupIdentifier,
            "secretNonce": secretNonce,
        ]

        manager.localizedDescription = "Hop"
        manager.protocolConfiguration = tunnelProtocol
        manager.isEnabled = true
        try await save(manager)
        try await manager.loadFromPreferences()
        self.manager = manager
        appendLog("Installed tunnel manager for \(RuntimeEnvironment.tunnelProviderBundleIdentifier)")
        appendLog("Manager enabled=\(manager.isEnabled), status=\(manager.connection.status.displayName)")
        return manager
    }

    private func loadManager() async throws -> NETunnelProviderManager {
        if let manager {
            return manager
        }

        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        appendLog("Loaded \(managers.count) tunnel manager(s) from preferences")
        let manager = managers.first { $0.localizedDescription == "Hop" } ?? NETunnelProviderManager()
        self.manager = manager
        return manager
    }

    private func save(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    private func observeStatus(for connection: NEVPNConnection) {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: connection,
            queue: .main,
        ) { [weak self, weak connection] _ in
            guard let connection else {
                return
            }
            Task { @MainActor in
                self?.syncExtensionLogs()
                self?.updateState(from: connection.status, source: "status notification")
            }
        }
    }

    private func schedulePostStartDiagnostics() {
        diagnosticsTask?.cancel()
        diagnosticsTask = Task { [weak self] in
            for delaySeconds in [1, 3, 6] {
                do {
                    try await Task.sleep(for: .seconds(delaySeconds))
                } catch {
                    return
                }
                guard !Task.isCancelled else {
                    return
                }
                self?.runPostStartDiagnostic(delaySeconds: delaySeconds)
            }
        }
    }

    private func runPostStartDiagnostic(delaySeconds: Int) {
        syncExtensionLogs()
        guard let status = manager?.connection.status else {
            appendLog("Post-start diagnostic +\(delaySeconds)s: no tunnel manager connection available")
            return
        }
        appendLog("Post-start diagnostic +\(delaySeconds)s: status=\(status.displayName)")
        updateState(from: status, source: "post-start diagnostic")
    }

    private func updateState(from status: NEVPNStatus, source: String) {
        if lastObservedStatus != status {
            appendLog("NetworkExtension status: \(status.displayName) (\(source))")
            lastObservedStatus = status
        }

        let wasConnected = state == .connected
        switch status {
        case .connected:
            state = .connected
            startInProgress = false
            loggedStartupStop = false
            diagnosticsTask?.cancel()
            startTelemetry()
            if !wasConnected {
                appendLog("Tunnel connected")
            }
        case .connecting, .reasserting:
            state = .connecting
        case .disconnecting:
            state = .disconnecting
        case .disconnected, .invalid:
            if startInProgress || state == .connecting {
                state = .failed
                if !loggedStartupStop {
                    loggedStartupStop = true
                    appendLog("Tunnel stopped before connecting. If this happened immediately, the packet tunnel extension failed during startup.")
                    appendLog("If no Extension lines appear here, iOS did not launch the tunnel extension; check Network Extension/App Group entitlements and the embedded .appex.")
                }
                syncExtensionLogs()
            } else {
                state = .disconnected
            }
            stopTelemetry()
        @unknown default:
            state = .failed
            stopTelemetry()
            appendLog("NetworkExtension reported an unknown status")
        }
    }

    private func startTelemetry() {
        telemetryClient.start()
    }

    private func stopTelemetry() {
        telemetryClient.stop()
        telemetryIsConnected = false
        telemetryError = nil
    }

    func closeAllConnections() {
        telemetryClient.closeAllConnections()
        appendLog("Requested close for all active connections")
    }

    func closeConnection(id: String) {
        telemetryClient.closeConnection(id: id)
        appendLog("Requested close for connection \(id)")
    }
}

private extension NEVPNStatus {
    var displayName: String {
        switch self {
        case .invalid:
            "invalid"
        case .disconnected:
            "disconnected"
        case .connecting:
            "connecting"
        case .connected:
            "connected"
        case .reasserting:
            "reasserting"
        case .disconnecting:
            "disconnecting"
        @unknown default:
            "unknown"
        }
    }
}

private extension Error {
    var diagnosticDescription: String {
        let nsError = self as NSError
        return "\(localizedDescription) [domain=\(nsError.domain), code=\(nsError.code)]"
    }

    var networkExtensionDiagnosticHint: String? {
        let nsError = self as NSError
        guard nsError.domain == "NEVPNErrorDomain" else {
            return nil
        }

        return switch nsError.code {
        case 5:
            "NetworkExtension IPC failed, so iOS could not talk to the tunnel extension. Check that the signer preserved Packet Tunnel + App Group entitlements and embedded HopTunnel.appex."
        default:
            "NetworkExtension rejected the tunnel start. Check VPN permission, signing entitlements, App Group access, and the embedded HopTunnel.appex bundle ID."
        }
    }
}
