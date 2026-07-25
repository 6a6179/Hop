import Foundation
@preconcurrency import NetworkExtension
import Observation

@MainActor
@Observable
final class TunnelController {
    var state: TunnelConnectionState = .disconnected
    var logs: [String]
    var maximumLogEntries: Int

    @ObservationIgnored var onLogsChanged: (() -> Void)?
    @ObservationIgnored var onLegacyExtensionLogPurgeCompleted: (() -> Void)?
    @ObservationIgnored var requiresLegacyExtensionLogPurge: Bool

    private let sharedConfigStore = SharedTunnelConfigurationStore()
    private let sharedLogStore: SharedTunnelLogStore
    private let secretStore = SecretStore.shared
    @ObservationIgnored private var diagnosticsTask: Task<Void, Never>?
    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var importedExtensionLogLines: Set<String> = []
    private var lastObservedStatus: NEVPNStatus?
    private var startInProgress = false
    private var loggedStartupStop = false
    init(
        logs: [String] = [],
        maximumLogEntries: Int = LogRetention.fiveHundred.rawValue,
        sharedLogStore: SharedTunnelLogStore = SharedTunnelLogStore(),
        requiresLegacyExtensionLogPurge: Bool = false,
    ) {
        self.logs = logs
        self.maximumLogEntries = maximumLogEntries
        self.sharedLogStore = sharedLogStore
        self.requiresLegacyExtensionLogPurge = requiresLegacyExtensionLogPurge
    }

    func connect(
        target: OutboundTarget,
        profiles: [ProxyProfile],
        groups: [ProxyGroup],
        routingMode: RoutingMode,
        rules: [RoutingRule],
        settings: AppSettings,
    ) async {
        guard !startInProgress else {
            appendLog("Connect ignored: a tunnel start is already in progress")
            return
        }
        diagnosticsTask?.cancel()
        importedExtensionLogLines.removeAll()
        lastObservedStatus = nil
        loggedStartupStop = false
        startInProgress = true
        state = .connecting
        appendLog("Connect requested for \(target.id)")
        appendLog(RuntimeEnvironment.installedBundleDiagnostic)
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
            completeLegacyExtensionLogPurgeIfNeeded()
            appendLog("Cleared extension log at \(RuntimeEnvironment.tunnelLogFileURL.path)")
        } catch {
            appendLog("Unable to clear extension log: \(error.diagnosticDescription)")
        }

        do {
            appendLog("Preparing tunnel with \(profiles.count) nodes, \(groups.count) groups, \(rules.count) rules")
            let buildSnapshot = XrayConfigBuildSnapshot(
                profiles: profiles,
                groups: groups,
                selectedTarget: target,
                routingMode: routingMode,
                rules: rules,
                settings: settings,
            )

            // Build once with hydrated values for exact pinned-core validation.
            // The app never starts an instance; `validate` parses and closes it.
            let resolvedConfig = try await Task.detached(priority: .userInitiated) {
                try buildSnapshot.build()
            }.value
            guard startInProgress else {
                appendLog("Tunnel start cancelled during config validation")
                return
            }
            appendLog("Validating settings with Xray-core \(XrayConfigBuilder.coreVersion)")
            try await XrayCoreClient.validate(configJSON: resolvedConfig)
            guard startInProgress else {
                appendLog("Tunnel start cancelled during Xray validation")
                return
            }

            let secretNonce = UUID().uuidString
            let inlineConfigContent: String?
            if useInlineResolvedConfig {
                // This fallback is intentionally one-shot: the extension cannot
                // read the app-only config container on a later OS restart, so
                // avoid generating and persisting an unusable tokenized copy.
                inlineConfigContent = resolvedConfig
            } else {
                let configContent = try await Task.detached(priority: .userInitiated) {
                    try buildSnapshot.build(tokenizingSecretsWith: secretNonce)
                }.value
                guard startInProgress else {
                    appendLog("Tunnel start cancelled during tokenized config preparation")
                    return
                }

                let preparation = SharedTunnelConfigPreparation(
                    config: configContent,
                    nonce: secretNonce,
                    profiles: profiles,
                    secretStore: secretStore,
                    configStore: sharedConfigStore,
                )
                try await Task.detached(priority: .userInitiated) {
                    try preparation.write()
                }.value
                guard startInProgress else {
                    // No manager or tunnel is launched for this nonce. The file
                    // contains references rather than plaintext credentials,
                    // and a later connect atomically replaces it.
                    appendLog("Tunnel start cancelled during shared config preparation")
                    return
                }
                inlineConfigContent = nil
            }

            let manager = try await configuredManager(secretNonce: secretNonce, onDemand: settings.connectOnDemand, killSwitch: settings.killSwitch)
            // The manager round-trip suspends; a disconnect() issued meanwhile
            // cleared `startInProgress`, and starting anyway would override the
            // user's explicit stop with a stale connect.
            guard startInProgress else {
                appendLog("Tunnel start cancelled before launch")
                await disarmOnDemandIfNeeded(context: "start cancelled")
                return
            }
            observeStatus(for: manager.connection)
            appendLog("Starting NetworkExtension tunnel with Xray-core \(XrayConfigBuilder.coreVersion)")
            var startOptions: [String: NSObject] = [
                "appGroup": RuntimeEnvironment.appGroupIdentifier as NSString,
                "secretNonce": secretNonce as NSString,
                "includeAllNetworks": (settings.killSwitch ? "true" : "false") as NSString,
                "dnsServers": XrayTunnelNetworkDefaults.dnsServers.joined(separator: ",") as NSString,
                "tunnelMTU": String(XrayTunnelNetworkDefaults.mtu) as NSString,
            ]
            if let inlineConfigContent {
                startOptions["configContent"] = inlineConfigContent as NSString
                startOptions["configSecrets"] = "resolved" as NSString
            } else {
                startOptions["configPath"] = RuntimeEnvironment.configFileURL.path as NSString
            }
            try manager.connection.startVPNTunnel(options: startOptions)
            appendLog("startVPNTunnel returned; current status is \(manager.connection.status.displayName)")
            await syncExtensionLogs()
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
            await syncExtensionLogs()
            appendTunnelStartFailure(error)
            await disarmOnDemandIfNeeded(context: "tunnel start failed")
        }
    }

    /// Best-effort removal of the on-demand rule when a start did not stick.
    /// Without this, a failed connect leaves the rule armed in the system
    /// configuration and iOS keeps relaunching a tunnel the app shows as
    /// failed — a loop the user could otherwise only break from iOS Settings.
    /// The setting itself is untouched; the next manual connect re-arms it.
    private func disarmOnDemandIfNeeded(context: String) async {
        guard let manager, manager.isOnDemandEnabled else {
            return
        }
        manager.isOnDemandEnabled = false
        do {
            try await save(manager)
            appendLog("On-demand connect disabled (\(context))")
        } catch {
            appendLog("Could not disable on-demand connect (\(context)): \(error.diagnosticDescription)")
        }
    }

    func disconnect() async {
        guard state.isConnected || state == .connecting else {
            state = .disconnected
            // A failed session can leave the on-demand rule armed (the start
            // saved it before failing); clear it so iOS stops relaunching a
            // tunnel the UI shows as down.
            await disarmOnDemandIfNeeded(context: "disconnect while not connected")
            return
        }

        state = .disconnecting
        startInProgress = false
        diagnosticsTask?.cancel()
        do {
            let manager = try await loadManager()
            // With on-demand rules active, iOS would immediately relaunch the
            // tunnel after stopVPNTunnel; disable them before stopping so a
            // manual disconnect sticks until the next connect re-arms them.
            if manager.isOnDemandEnabled {
                manager.isOnDemandEnabled = false
                try await save(manager)
                appendLog("On-demand connect disabled until the next manual connect")
            }
            manager.connection.stopVPNTunnel()
            await syncExtensionLogs()
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
        appendLogs([message])
    }

    /// A start error can be derived from the resolved configuration, so its
    /// localized description is not safe to persist. Xray errors already expose
    /// a stable code-only summary; all other errors retain only domain and code.
    func appendTunnelStartFailure(_ error: Error) {
        if let error = error as? XrayCoreClientError {
            appendLog("Tunnel start failed: \(error.localizedDescription)")
        } else {
            let error = error as NSError
            appendLog("Tunnel start failed [domain=\(error.domain), code=\(error.code)]")
        }
        if let diagnosticHint = error.networkExtensionDiagnosticHint {
            appendLog("Diagnostic: \(diagnosticHint)")
        }
    }

    /// `NEVPNConnection` may retain a provider error across app upgrades, so
    /// never persist its localized description. Pre-fix provider errors could
    /// include values echoed from the resolved configuration.
    func appendLastDisconnectError(_ error: Error?) {
        guard let error else {
            appendLog("iOS reported no recent disconnect error.")
            return
        }
        let nsError = error as NSError
        appendLog("Most recent disconnect error (may predate this start) [domain=\(nsError.domain), code=\(nsError.code)]")
        if let diagnosticHint = error.networkExtensionDiagnosticHint {
            appendLog("Diagnostic: \(diagnosticHint)")
        }
    }

    /// Appends a chronological batch as one array mutation and one persist
    /// callback, instead of one per line — extension log syncs deliver bursts.
    /// One call is one visual entry: line breaks collapse to spaces so
    /// messages embedding remote-controlled text (import warnings, engine
    /// errors) can't forge extra timestamped entries in the app log. This
    /// mirrors `PacketTunnelProvider.writeTunnelLog`.
    func appendLogs(_ messages: [String]) {
        guard !messages.isEmpty else {
            return
        }
        let timestamp = Date.now.formatted(date: .omitted, time: .standard)
        let entries = messages.map { message in
            "[\(timestamp)] \(message.components(separatedBy: .newlines).joined(separator: " "))"
        }
        // Newest-first display order: the last message of the batch lands at
        // index 0, matching what per-line inserts would have produced.
        logs.insert(contentsOf: entries.reversed(), at: 0)
        if logs.count > maximumLogEntries {
            logs.removeLast(logs.count - maximumLogEntries)
        }
        onLogsChanged?()
    }

    func clearLogs() {
        logs.removeAll()
        importedExtensionLogLines.removeAll()
        if (try? sharedLogStore.clear()) != nil {
            completeLegacyExtensionLogPurgeIfNeeded()
        }
        onLogsChanged?()
    }

    /// Clears only the shared extension log for the pre-v3 migration gate.
    /// App-side logs remain untouched, and a failure leaves the gate pending.
    func purgeLegacyExtensionLogIfNeeded() throws {
        guard requiresLegacyExtensionLogPurge else {
            return
        }
        try sharedLogStore.clear()
        importedExtensionLogLines.removeAll()
        completeLegacyExtensionLogPurgeIfNeeded()
    }

    private func completeLegacyExtensionLogPurgeIfNeeded() {
        guard requiresLegacyExtensionLogPurge else {
            return
        }
        requiresLegacyExtensionLogPurge = false
        onLegacyExtensionLogPurgeCompleted?()
    }

    /// Reads the shared tunnel log file off the main actor — the read is up to
    /// 512 KB of file I/O, and it runs on hot paths (status notifications, the
    /// post-start diagnostics, the Logs tab refresh).
    func syncExtensionLogs() async {
        if requiresLegacyExtensionLogPurge {
            let purgeResult: Result<Void, Error> = await Task.detached(priority: .utility) { [sharedLogStore] in
                do {
                    try sharedLogStore.clear()
                    return .success(())
                } catch {
                    return .failure(error)
                }
            }.value
            switch purgeResult {
            case .success:
                importedExtensionLogLines.removeAll()
                completeLegacyExtensionLogPurgeIfNeeded()
            case let .failure(error):
                let error = error as NSError
                appendLog("Unable to clear legacy extension logs [domain=\(error.domain), code=\(error.code)]")
            }
            // A successful purge intentionally imports nothing from the old
            // file; a failed purge remains gated and retries on the next sync.
            return
        }

        let result: Result<[String], Error> = await Task.detached(priority: .utility) { [sharedLogStore] in
            do {
                return try .success(sharedLogStore.readLines())
            } catch {
                return .failure(error)
            }
        }.value

        switch result {
        case let .success(lines):
            let newLines = lines.filter { !importedExtensionLogLines.contains($0) }
            appendLogs(newLines.map { "Extension \($0)" })
            // Rebuild rather than accumulate: the shared file only appends and
            // the reader only sees its bounded tail, so a line absent from
            // `lines` can never be read again — retaining it would grow the
            // dedup set without bound over a long session.
            importedExtensionLogLines = Set(lines)
        case let .failure(error):
            appendLog("Unable to read extension logs: \(error.diagnosticDescription)")
        }
    }

    private func configuredManager(secretNonce: String, onDemand: Bool, killSwitch: Bool) async throws -> NETunnelProviderManager {
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
            "dnsServers": XrayTunnelNetworkDefaults.dnsServers.joined(separator: ","),
            "tunnelMTU": String(XrayTunnelNetworkDefaults.mtu),
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
        // On-demand: iOS starts the tunnel whenever any network is reachable
        // and restarts it if the extension stops. A manual disconnect clears
        // the flag first (see `disconnect`), so the user's explicit stop is
        // never fought by the system.
        manager.isOnDemandEnabled = onDemand
        manager.onDemandRules = onDemand ? [NEOnDemandRuleConnect()] : nil
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
                await self?.syncExtensionLogs()
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
                await self?.runPostStartDiagnostic(delaySeconds: delaySeconds)
            }
        }
    }

    private func runPostStartDiagnostic(delaySeconds: Int) async {
        await syncExtensionLogs()
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
                    appendLog("If no Extension lines appear here, HopTunnel.appex may not have reached shared-log setup. Check the installed-bundle and App Group diagnostics above, then remove the saved Hop VPN and reinstall the latest build. If it persists, inspect the final re-signed .appex and its own provisioning profile.")
                    logLastDisconnectError()
                    // A startup failure repeats identically on every on-demand
                    // relaunch; disarm so iOS doesn't loop a broken config.
                    Task { await self.disarmOnDemandIfNeeded(context: "tunnel failed during startup") }
                }
                Task { await syncExtensionLogs() }
            } else if state != .failed {
                // A failed start stays visibly failed: the post-start
                // diagnostics and late status notifications re-read
                // `.disconnected` seconds after the failure and would
                // otherwise quietly wash the red failure state away.
                state = .disconnected
            }
        @unknown default:
            state = .failed
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
            Task { @MainActor in
                guard let self else {
                    return
                }
                self.appendLastDisconnectError(error)
            }
        }
    }
}

/// A tightly scoped immutable value snapshot for config work that must not run
/// on `TunnelController`'s main actor. Every stored model is value-semantic;
/// the detached task only reads it and creates its own builder instance.
private struct XrayConfigBuildSnapshot: @unchecked Sendable {
    let profiles: [ProxyProfile]
    let groups: [ProxyGroup]
    let selectedTarget: OutboundTarget
    let routingMode: RoutingMode
    let rules: [RoutingRule]
    let settings: AppSettings

    func build(tokenizingSecretsWith nonce: String? = nil) throws -> String {
        try XrayConfigBuilder().build(
            profiles: nonce.map { nonce in profiles.map { $0.tokenizingSecrets(nonce: nonce) } } ?? profiles,
            groups: groups,
            selectedTarget: selectedTarget,
            routingMode: routingMode,
            rules: rules,
            settings: settings,
        )
    }
}

/// Performs secure-store and authenticated-file I/O without blocking the main
/// actor. Inputs are immutable value snapshots; `SecretStore` wraps a Sendable
/// backend and `SharedTunnelConfigurationStore` is stateless.
private struct SharedTunnelConfigPreparation: @unchecked Sendable {
    let config: String
    let nonce: String
    let profiles: [ProxyProfile]
    let secretStore: SecretStore
    let configStore: SharedTunnelConfigurationStore

    func write() throws {
        var missingKeys = SecretResolver.referencedKeys(in: config, nonce: nonce)
        for profile in profiles where !missingKeys.isEmpty {
            for item in profile.keychainSecretItems where missingKeys.remove(item.key) != nil {
                // Do not skip equal values: writing also repairs legacy items
                // whose Keychain accessibility class is weaker than required.
                guard secretStore.setValue(item.value, forKey: item.key) else {
                    throw TunnelSecretPreparationError.writeFailed
                }
            }
        }
        guard missingKeys.isEmpty else {
            throw TunnelSecretPreparationError.missingReference
        }
        try configStore.writeConfig(config)
    }
}

private enum TunnelSecretPreparationError: Error {
    case missingReference
    case writeFailed
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
                "iOS reports HopTunnel.appex is unavailable or needs an update. Remove the saved Hop VPN, uninstall the old app, then install this newer build and reconnect. If it persists, verify that the final re-signed .appex bundle ID matches the logged provider ID and that its own provisioning profile authorizes Packet Tunnel, the shared App Group, and keychain group."
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
