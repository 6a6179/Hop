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
    /// Whether a connections UI is currently visible. The per-connection event
    /// stream is heavy (libbox pushes batches every interval), so it runs only
    /// while something displays it; the always-on status stream keeps counters
    /// and the live connection count.
    private(set) var isMonitoringConnections = false

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
        appendLog(RuntimeEnvironment.appGroupResolutionDiagnostic)
        appendLog("Shared container: \(RuntimeEnvironment.sharedContainerURL.path)")
        appendLog("Tunnel extension bundle ID: \(RuntimeEnvironment.tunnelProviderBundleIdentifier)")
        if !RuntimeEnvironment.tunnelExtensionIsEmbedded {
            appendLog("No .appex bundle exists inside Hop.app/PlugIns — the installer or signer stripped the tunnel extension, so iOS has nothing to launch. Reinstall with app extensions included.")
        }

        let useInlineResolvedConfig = RuntimeEnvironment.usesInlineResolvedTunnelConfiguration
        if useInlineResolvedConfig {
            appendLog("Shared App Group with HopTunnel.appex is not confirmed; using one-shot inline tunnel config. If startup still disconnects immediately, re-sign Hop.app and HopTunnel.appex with the Packet Tunnel entitlement.")
        } else {
            do {
                try RuntimeEnvironment.requireAppGroupAccess()
            } catch {
                state = .failed
                startInProgress = false
                appendLog("Tunnel preflight failed: \(error.diagnosticDescription)")
                if let diagnosticHint = error.networkExtensionDiagnosticHint {
                    appendLog("Diagnostic: \(diagnosticHint)")
                }
                return
            }
        }

        do {
            try sharedLogStore.clear()
            appendLog("Cleared extension log at \(RuntimeEnvironment.tunnelLogFileURL.path)")
        } catch {
            appendLog("Unable to clear extension log: \(error.diagnosticDescription)")
        }

        do {
            appendLog("Preparing tunnel with \(profiles.count) nodes, \(groups.count) groups, \(rules.count) rules")
            // Ensure secrets are in the shared Keychain for the normal tokenized
            // config path. If signing does not expose a verifiable shared App
            // Group, startup falls back to an inline one-shot resolved config so
            // the extension does not need to read shared storage.
            for item in profiles.flatMap(\.keychainSecretItems) {
                secretStore.setValue(item.value, forKey: item.key)
            }
            // Ensure the command-server auth token exists before the extension
            // starts; the extension and telemetry client read the same shared
            // Keychain value to gate/authenticate the command socket.
            SecretStore.runtime.ensureCommandServerSecret()
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
            let inlineConfigContent: String? = if useInlineResolvedConfig {
                try configBuilder.build(
                    profiles: profiles,
                    groups: groups,
                    selectedTarget: target,
                    routingMode: routingMode,
                    rules: rules,
                    settings: settings,
                )
            } else {
                nil
            }
            try sharedConfigStore.writeConfig(configContent)

            let manager = try await configuredManager(secretNonce: secretNonce, killSwitch: settings.killSwitch)
            observeStatus(for: manager.connection)
            appendLog("Starting NetworkExtension tunnel with sing-box engine")
            var startOptions: [String: NSObject] = [
                "appGroup": RuntimeEnvironment.appGroupIdentifier as NSString,
                "secretNonce": secretNonce as NSString,
                "includeAllNetworks": (settings.killSwitch ? "true" : "false") as NSString,
            ]
            if let inlineConfigContent {
                startOptions["configContent"] = inlineConfigContent as NSString
                startOptions["configSecrets"] = "resolved" as NSString
            } else {
                startOptions["configPath"] = RuntimeEnvironment.configFileURL.path as NSString
            }
            try manager.connection.startVPNTunnel(options: startOptions)
            appendLog("startVPNTunnel returned; current status is \(manager.connection.status.displayName)")
            syncExtensionLogs()
            // The synchronous status read here is almost always still
            // `disconnected` — the connecting transition arrives via the status
            // notification. Feeding it into `updateState` would misreport a
            // startup failure before the extension was even launched.
            if manager.connection.status != .disconnected, manager.connection.status != .invalid {
                updateState(from: manager.connection.status, source: "startVPNTunnel return")
            }
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

    private func configuredManager(secretNonce: String, killSwitch: Bool) async throws -> NETunnelProviderManager {
        let manager = try await loadManager()
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = RuntimeEnvironment.tunnelProviderBundleIdentifier
        tunnelProtocol.serverAddress = "Hop"
        // `secretNonce` lets an iOS-initiated restart (start options absent)
        // still resolve the tokens written to the shared config file. It is not
        // a secret — only unpredictable to import data — so persisting it in the
        // provider configuration alongside the non-secret paths is fine. The
        // kill-switch flag is mirrored here so an OS-initiated restart preserves
        // it without the app's start options.
        tunnelProtocol.providerConfiguration = [
            "configPath": RuntimeEnvironment.configFileURL.path,
            "appGroup": RuntimeEnvironment.appGroupIdentifier,
            "secretNonce": secretNonce,
            "includeAllNetworks": killSwitch ? "true" : "false",
        ]
        // Kill switch: when on, iOS forces every flow through the tunnel and
        // drops traffic if the extension dies (fail-closed) instead of leaking
        // to the default interface. Only diverge from system defaults when it's
        // enabled so the off state matches prior behavior exactly; pairing it
        // with excludeLocalNetworks keeps LAN/captive portals reachable.
        tunnelProtocol.includeAllNetworks = killSwitch
        if killSwitch {
            tunnelProtocol.excludeLocalNetworks = true
        }

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
                startInProgress = false
                if !loggedStartupStop {
                    loggedStartupStop = true
                    appendLog("Tunnel stopped before connecting. If this happened immediately, the packet tunnel extension failed during startup.")
                    appendLog("If no Extension lines appear here, iOS rejected or killed HopTunnel.appex before PacketTunnelProvider could write logs. Check the App Group diagnostic above and that the embedded .appex was re-signed with Hop.app.")
                    logLastDisconnectError()
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

    /// iOS records why the tunnel last went down — including the error the
    /// provider handed its start completion handler and system-side launch
    /// failures (rejected/killed .appex) that the app can't observe any other
    /// way. Without a shared App Group this is the only channel that carries
    /// the extension's failure reason back to the app.
    private func logLastDisconnectError() {
        guard let connection = manager?.connection else {
            return
        }
        connection.fetchLastDisconnectError { [weak self] error in
            let message = error.map { "Last disconnect error: \($0.diagnosticDescription)" }
            let hint = error?.networkExtensionDiagnosticHint
            Task { @MainActor in
                guard let self else {
                    return
                }
                guard let message else {
                    self.appendLog("iOS reported no disconnect error for the last tunnel stop.")
                    return
                }
                self.appendLog(message)
                if let hint {
                    self.appendLog("Diagnostic: \(hint)")
                }
            }
        }
    }

    private func startTelemetry() {
        telemetryClient.start()
        if isMonitoringConnections {
            telemetryClient.startConnections()
        }
    }

    private func stopTelemetry() {
        telemetryClient.stop()
        telemetryIsConnected = false
        telemetryError = nil
    }

    /// Called when a connections UI appears/disappears; subscribes to the
    /// per-connection event stream only while it is actually displayed.
    func beginConnectionsMonitoring() {
        isMonitoringConnections = true
        if state.isConnected {
            telemetryClient.startConnections()
        }
    }

    func endConnectionsMonitoring() {
        isMonitoringConnections = false
        telemetryClient.stopConnections()
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
        if nsError.domain == "Hop.RuntimeEnvironmentError" || self is RuntimeEnvironmentError {
            return "Hop.app and HopTunnel.appex must share the selected App Group and keychain access group, and HopTunnel.appex must keep the Packet Tunnel entitlement. Re-sign both bundles with the same groups, then reinstall."
        }
        if nsError.domain == NEVPNConnectionErrorDomain {
            return switch NEVPNConnectionError(rawValue: nsError.code) {
            case .pluginFailed:
                "iOS launched HopTunnel.appex but it exited during startup — usually a thrown provider error or a crash. Any Extension lines above carry the provider's own reason."
            case .pluginDisabled:
                "iOS refused to launch HopTunnel.appex. The re-signed .appex is missing the Packet Tunnel entitlement or a provisioning profile that allows it; re-sign with app extensions enabled."
            case .configurationFailed, .configurationNotFound:
                "The saved VPN configuration is invalid or gone. Toggle the Hop VPN profile in Settings > VPN, or reconnect to rebuild it."
            default:
                nil
            }
        }
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
