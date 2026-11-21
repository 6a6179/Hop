import Foundation
@preconcurrency import NetworkExtension
import Observation

struct InstalledTunnelConnection: Equatable {
    let targetName: String
    let routingMode: RoutingMode

    init(targetName: String, routingMode: RoutingMode) {
        self.targetName = routingMode == .direct ? "Direct" : targetName
        self.routingMode = routingMode
    }

    init?(manager: NETunnelProviderManager?) {
        guard let configuration = (manager?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
              let name = configuration["targetDisplayName"] as? String,
              let mode = configuration["routingMode"] as? String,
              let routingMode = RoutingMode(rawValue: mode)
        else { return nil }
        self.init(targetName: name, routingMode: routingMode)
    }
}

@MainActor
@Observable
final class TunnelController {
    var state: TunnelConnectionState = .disconnected
    private(set) var installedConnection: InstalledTunnelConnection?
    var logs: [String]
    var maximumLogEntries: Int {
        didSet { trimLogsToLimit() }
    }

    @ObservationIgnored var onLogsChanged: (() -> Void)?
    @ObservationIgnored var onLegacyExtensionLogPurgeCompleted: (() -> Void)?
    @ObservationIgnored var requiresLegacyExtensionLogPurge: Bool

    private let sharedConfigStore = SharedTunnelConfigurationStore()
    private let sharedLogStore: SharedTunnelLogStore
    private let secretStore = SecretStore.runtime
    @ObservationIgnored private var diagnosticsTask: Task<Void, Never>?
    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var statusObservationID = UUID()
    private var statusRefreshID = UUID()
    @ObservationIgnored private(set) var extensionLogCursor: ExtensionLogCursor?
    @ObservationIgnored private var extensionLogReadID = UUID()
    private var lastObservedStatus: NEVPNStatus?
    private var startInProgress = false
    private var stopInProgress = false
    private var currentActionID = UUID()
    private let preferenceGate = TunnelPreferenceGate()
    private(set) var configurationFailureHint: String?
    private var loggedStartupStop = false
    init(
        logs: [String] = [],
        extensionLogCursor: ExtensionLogCursor? = nil,
        maximumLogEntries: Int = LogRetention.fiveHundred.rawValue,
        sharedLogStore: SharedTunnelLogStore = SharedTunnelLogStore(),
        requiresLegacyExtensionLogPurge: Bool = false,
    ) {
        self.logs = logs
        // Older app state saved the displayed entries without a file position.
        // Recover its newest imported line for the first incremental read.
        self.extensionLogCursor = extensionLogCursor ?? logs.lazy.compactMap { entry -> ExtensionLogCursor? in
            guard let timestampEnd = entry.firstIndex(of: "]") else { return nil }
            let message = entry[entry.index(after: timestampEnd)...]
            let prefix = " Extension "
            guard message.hasPrefix(prefix) else { return nil }
            return ExtensionLogCursor(file: nil, offset: 0, lastLine: String(message.dropFirst(prefix.count)))
        }.first
        self.maximumLogEntries = maximumLogEntries
        self.sharedLogStore = sharedLogStore
        self.requiresLegacyExtensionLogPurge = requiresLegacyExtensionLogPurge
    }

    /// Inspect the installed VPN without creating or saving a configuration.
    func refreshStatus(
        loadManagers: @MainActor () async throws -> [NETunnelProviderManager] = {
            try await NETunnelProviderManager.loadAllFromPreferences()
        },
    ) async {
        guard !startInProgress, !stopInProgress, !preferenceGate.isLocked, state != .disconnecting else { return }
        let refreshID = UUID()
        statusRefreshID = refreshID
        do {
            let managers = try await loadManagers()
            // A newer refresh or manual connection action wins this round-trip.
            guard statusRefreshID == refreshID, !Task.isCancelled else { return }
            manager = Self.existingManager(in: managers)
            installedConnection = InstalledTunnelConnection(manager: manager)
            observeStatus(for: manager?.connection)
            updateState(from: manager?.connection.status ?? .disconnected, source: "saved VPN")
        } catch {
            guard statusRefreshID == refreshID, !Task.isCancelled else { return }
            appendLog("Unable to read VPN status: \(error.diagnosticDescription)")
        }
    }

    func connect(
        target: OutboundTarget,
        targetName: String,
        profiles: [ProxyProfile],
        groups: [ProxyGroup],
        routingMode: RoutingMode,
        rules: [RoutingRule],
        settings: AppSettings,
        loadManagers: @MainActor () async throws -> [NETunnelProviderManager] = {
            try await NETunnelProviderManager.loadAllFromPreferences()
        },
    ) async {
        guard !startInProgress, !stopInProgress, state != .disconnecting else {
            appendLog("Connect ignored: a tunnel action is already in progress")
            return
        }
        let actionID = UUID()
        currentActionID = actionID
        statusRefreshID = actionID
        configurationFailureHint = nil
        // The saved connection can still emit old status changes while the
        // new configuration is being validated. Observe again at launch.
        observeStatus(for: nil)
        defer {
            // Preflight can fail before launch installs the new observer.
            // Do not leave an existing VPN unobserved, or rebind over a newer action.
            if currentActionID == actionID, statusObserver == nil {
                observeStatus(for: manager?.connection)
            }
        }
        diagnosticsTask?.cancel()
        extensionLogReadID = UUID()
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
            appendLog("Missing tunnel extension in Hop.app/PlugIns. Reinstall with app extensions included.")
        }

        let useInlineResolvedConfig = RuntimeEnvironment.usesInlineResolvedTunnelConfiguration
        if useInlineResolvedConfig {
            appendLog("Shared App Group unconfirmed; using one-shot config. If startup fails, re-sign Hop.app and HopTunnel.appex with Packet Tunnel enabled.")
            if settings.connectOnDemand {
                appendLog("On-demand disabled: automatic restarts cannot reuse one-shot config.")
            }
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
            extensionLogCursor = nil
            completeLegacyExtensionLogPurgeIfNeeded()
            appendLog("Cleared extension log at \(RuntimeEnvironment.tunnelLogFileURL.path)")
        } catch {
            appendLog("Unable to clear extension log: \(error.diagnosticDescription)")
        }

        var attemptedNonce: String?
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
            guard currentActionID == actionID, startInProgress else {
                appendLog("Tunnel start cancelled during config validation")
                return
            }
            appendLog("Validating settings with Xray-core \(XrayConfigBuilder.coreVersion)")
            try await XrayCoreClient.validate(configJSON: resolvedConfig)
            guard currentActionID == actionID, startInProgress else {
                appendLog("Tunnel start cancelled during Xray validation")
                return
            }

            // The snapshot files, runtime Keychain and VPN preferences form one
            // transaction. A stop or erase waits for an in-flight write before
            // it reads or changes the installed manager.
            await preferenceGate.acquire()
            defer { preferenceGate.release() }
            guard currentActionID == actionID else { return }

            // A failed/ambiguous save can leave the cached manager mutated.
            // Only persisted preferences may decide which snapshots are live.
            let existingManager = try await loadManager(reload: true, loadManagers: loadManagers)
            guard currentActionID == actionID else { return }
            let existingConfiguration = (existingManager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
            let previousNonce = existingConfiguration?["secretNonce"] as? String
            let retainedNonces = Set([previousNonce, existingConfiguration?["previousSecretNonce"] as? String].compactMap(\.self))
            let secretNonce = UUID().uuidString
            let configURL = sharedConfigStore.snapshotURL(nonce: secretNonce)
            let inlineConfigContent: String?
            let preparation: SharedTunnelConfigPreparation?
            if useInlineResolvedConfig {
                // This fallback is intentionally one-shot: the extension cannot
                // read the app-only config container on a later OS restart, so
                // avoid generating and persisting an unusable tokenized copy.
                inlineConfigContent = resolvedConfig
                preparation = nil
            } else {
                let configContent = try await Task.detached(priority: .userInitiated) {
                    try buildSnapshot.build(tokenizingSecretsWith: secretNonce)
                }.value
                guard currentActionID == actionID, startInProgress else {
                    appendLog("Tunnel start cancelled during tokenized config preparation")
                    return
                }

                let snapshot = SharedTunnelConfigPreparation(
                    config: configContent,
                    nonce: secretNonce,
                    profiles: profiles,
                    secretStore: secretStore,
                    configStore: sharedConfigStore,
                )
                try await Task.detached(priority: .userInitiated) {
                    try snapshot.write(keeping: retainedNonces)
                }.value
                guard currentActionID == actionID, startInProgress else {
                    // No manager or tunnel is launched for this nonce. The file
                    // contains references rather than plaintext credentials,
                    // and the next connect prunes this abandoned snapshot.
                    appendLog("Tunnel start cancelled during shared config preparation")
                    return
                }
                inlineConfigContent = nil
                preparation = snapshot
            }

            attemptedNonce = secretNonce
            let manager = try await configuredManager(
                existingManager,
                secretNonce: secretNonce,
                connection: InstalledTunnelConnection(targetName: targetName, routingMode: routingMode),
                onDemand: settings.connectOnDemand,
                killSwitch: settings.killSwitch,
                usesInlineResolvedConfig: useInlineResolvedConfig,
                configURL: configURL,
                previousNonce: previousNonce,
            )
            guard currentActionID == actionID else { return }
            if let preparation {
                let installedNonces = Set([secretNonce, previousNonce].compactMap(\.self))
                try await Task.detached(priority: .utility) {
                    try preparation.pruneSnapshots(keeping: installedNonces)
                }.value
            }
            // The manager round-trip suspends; a disconnect() issued meanwhile
            // cleared `startInProgress`, and starting anyway would override the
            // user's explicit stop with a stale connect.
            guard currentActionID == actionID, startInProgress else {
                appendLog("Tunnel start cancelled before launch")
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
                startOptions["configPath"] = configURL.path as NSString
            }
            try manager.connection.startVPNTunnel(options: startOptions)
            appendLog("startVPNTunnel returned; current status is \(manager.connection.status.displayName)")
            await syncExtensionLogs()
            guard currentActionID == actionID else { return }
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
            schedulePostStartDiagnostics(actionID: actionID)
        } catch {
            guard currentActionID == actionID else { return }
            state = .failed
            startInProgress = false
            appendTunnelStartFailure(error)
            if let attemptedNonce {
                await disarmOnDemandIfNeeded(
                    context: "tunnel start failed", actionID: actionID,
                    installedNonce: attemptedNonce, loadManagers: loadManagers,
                )
            }
            guard currentActionID == actionID else { return }
            await syncExtensionLogs()
        }
    }

    /// Best-effort removal of the on-demand rule when a start did not stick.
    /// Without this, a failed connect leaves the rule armed in the system
    /// configuration and iOS keeps relaunching a tunnel the app shows as
    /// failed — a loop the user could otherwise only break from iOS Settings.
    /// The setting itself is untouched; the next manual connect re-arms it.
    private func disarmOnDemandIfNeeded(
        context: String, actionID: UUID, installedNonce: String? = nil,
        loadManagers: @MainActor () async throws -> [NETunnelProviderManager] = {
            try await NETunnelProviderManager.loadAllFromPreferences()
        },
    ) async {
        await preferenceGate.acquire()
        defer { preferenceGate.release() }
        guard currentActionID == actionID else { return }
        do {
            if let installedNonce {
                // A rejected or ambiguous install leaves the in-memory manager
                // mutated. Saving it again could install the rejected protocol.
                manager = nil
                installedConnection = nil
                observeStatus(for: nil)
                let managers = try await loadManagers()
                guard currentActionID == actionID else { return }
                manager = Self.existingManager(in: managers)
                installedConnection = InstalledTunnelConnection(manager: manager)
                observeStatus(for: manager?.connection)
                let configuration = (manager?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
                guard configuration?["secretNonce"] as? String == installedNonce else { return }
            }
            guard let manager, manager.isOnDemandEnabled else { return }
            try await disableOnDemand(manager)
            appendLog("On-demand connect disabled (\(context))")
        } catch {
            appendLog("Could not disable on-demand connect (\(context)): \(error.diagnosticDescription)")
        }
    }

    private func disableOnDemand(_ manager: NETunnelProviderManager) async throws {
        guard manager.isOnDemandEnabled else { return }
        manager.isOnDemandEnabled = false
        do {
            try await save(manager)
        } catch {
            // The persisted flag can still be enabled. A retry must save it.
            manager.isOnDemandEnabled = true
            throw error
        }
    }

    func disconnect(
        loadManagers: @MainActor () async throws -> [NETunnelProviderManager] = {
            try await NETunnelProviderManager.loadAllFromPreferences()
        },
    ) async {
        guard !stopInProgress else { return }
        let actionID = UUID()
        currentActionID = actionID
        statusRefreshID = actionID
        let interruptedStart = startInProgress
        let shouldStop = interruptedStart || state.isConnected || state == .connecting
        startInProgress = false
        stopInProgress = true
        defer {
            if currentActionID == actionID {
                stopInProgress = false
            }
        }
        diagnosticsTask?.cancel()
        if shouldStop {
            state = .disconnecting
        }
        observeStatus(for: nil)
        await preferenceGate.acquire()
        defer { preferenceGate.release() }
        guard currentActionID == actionID else { return }
        do {
            guard shouldStop else {
                if let manager {
                    try await disableOnDemand(manager)
                }
                observeStatus(for: manager?.connection)
                state = .disconnected
                return
            }
            let manager = try await loadManager(reload: interruptedStart, loadManagers: loadManagers)
            guard currentActionID == actionID else { return }
            if manager.isOnDemandEnabled {
                try await disableOnDemand(manager)
                appendLog("On-demand connect disabled until the next manual connect")
            }
            guard currentActionID == actionID else { return }
            observeStatus(for: manager.connection)
            manager.connection.stopVPNTunnel()
            await syncExtensionLogs()
            guard currentActionID == actionID else { return }
            updateState(from: manager.connection.status, source: "disconnect")
            appendLog("Tunnel disconnect requested")
        } catch {
            let saved = try? await loadManagers()
            guard currentActionID == actionID else { return }
            if let saved {
                manager = Self.existingManager(in: saved)
                installedConnection = InstalledTunnelConnection(manager: manager)
            }
            observeStatus(for: manager?.connection)
            updateState(from: manager?.connection.status ?? .disconnected, source: "disconnect failure")
            appendLog("Tunnel disconnect failed: \(error.diagnosticDescription)")
            if let diagnosticHint = error.networkExtensionDiagnosticHint {
                appendLog("Diagnostic: \(diagnosticHint)")
            }
        }
    }

    /// Erase can be retried after any failed preference or file operation.
    /// Keep disabled managers as a record of their containers until cleanup succeeds.
    func eraseInstalledTunnel(
        loadManagers: @MainActor () async throws -> [NETunnelProviderManager] = {
            try await NETunnelProviderManager.loadAllFromPreferences()
        },
        eraseSnapshots: @escaping @Sendable (Set<URL>) throws -> Void = { containers in
            for container in containers {
                try SharedTunnelConfigurationStore.eraseAllSnapshots(in: container)
            }
            guard SecretStore.runtime.pruneTunnelSnapshots(keeping: []) else {
                throw TunnelSecretPreparationError.writeFailed
            }
        },
    ) async throws {
        let actionID = UUID()
        currentActionID = actionID
        statusRefreshID = actionID
        startInProgress = false
        stopInProgress = true
        defer {
            if currentActionID == actionID {
                stopInProgress = false
            }
        }
        diagnosticsTask?.cancel()
        observeStatus(for: nil)
        await preferenceGate.acquire()
        defer { preferenceGate.release() }
        guard currentActionID == actionID else { throw CancellationError() }
        let managers = try await loadManagers().filter(Self.isHopManager)
        var containers: Set = [RuntimeEnvironment.sharedContainerURL]
        for manager in managers {
            if let configuration = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
               configuration["configPath"] != nil, let group = configuration["appGroup"] as? String
            {
                guard let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) else {
                    throw RuntimeEnvironmentError.appGroupUnavailable(group)
                }
                containers.insert(url)
            }
            if manager.isEnabled || manager.isOnDemandEnabled {
                let enabled = manager.isEnabled
                let onDemand = manager.isOnDemandEnabled
                manager.isEnabled = false
                manager.isOnDemandEnabled = false
                do {
                    try await save(manager)
                } catch {
                    manager.isEnabled = enabled
                    manager.isOnDemandEnabled = onDemand
                    throw error
                }
            }
            let session = manager.connection
            if session.status != .disconnected, session.status != .invalid {
                session.stopVPNTunnel()
                let deadline = ContinuousClock.now + .seconds(10)
                while session.status != .disconnected, session.status != .invalid {
                    guard ContinuousClock.now < deadline else { throw TunnelEraseError.stopTimedOut }
                    try await Task.sleep(for: .milliseconds(100))
                }
            }
        }
        let snapshotContainers = containers
        try await Task.detached(priority: .userInitiated) { try eraseSnapshots(snapshotContainers) }.value
        for manager in managers {
            try await manager.removeFromPreferences()
        }
        manager = nil
        installedConnection = nil
        state = .disconnected
    }

    func appendLog(_ message: String) {
        appendLogs([message])
    }

    /// A start error can be derived from the resolved configuration, so its
    /// localized description is not safe to persist. Xray errors already expose
    /// a stable code-only summary; all other errors retain only domain and code.
    func appendTunnelStartFailure(_ error: Error) {
        if let error = error as? XrayConfigError, case let .validationFailed(issues) = error,
           let issue = issues.first
        {
            configurationFailureHint = "\(issue.publicField). \(issue.publicReason ?? "Review the settings before reconnecting.")"
        }
        if let error = error as? XrayCoreClientError {
            configurationFailureHint = error.localizedDescription
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
        trimLogsToLimit()
        onLogsChanged?()
    }

    private func trimLogsToLimit() {
        let limit = max(0, maximumLogEntries)
        if logs.count > limit {
            logs.removeLast(logs.count - limit)
        }
    }

    func clearLogs() {
        extensionLogReadID = UUID()
        extensionLogCursor = nil
        logs.removeAll()
        do {
            try sharedLogStore.clear()
            completeLegacyExtensionLogPurgeIfNeeded()
        } catch {
            // Keep the import gate closed across relaunch until deletion works.
            requiresLegacyExtensionLogPurge = true
            appendLog("Unable to clear the shared extension log; Hop will retry.")
            return
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
        extensionLogReadID = UUID()
        extensionLogCursor = nil
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
    func syncExtensionLogs(
        read: @MainActor (SharedTunnelLogStore, ExtensionLogCursor?) async throws -> ExtensionLogBatch = { store, cursor in
            try await Task.detached(priority: .utility) { try store.readBatch(after: cursor) }.value
        },
    ) async {
        if requiresLegacyExtensionLogPurge {
            do {
                try purgeLegacyExtensionLogIfNeeded()
            } catch {
                let error = error as NSError
                appendLog("Unable to clear legacy extension logs [domain=\(error.domain), code=\(error.code)]")
            }
            return
        }

        let readID = UUID()
        extensionLogReadID = readID
        do {
            let batch = try await read(sharedLogStore, extensionLogCursor)
            guard readID == extensionLogReadID else { return }
            let cursorChanged = extensionLogCursor != batch.cursor
            extensionLogCursor = batch.cursor
            if !batch.lines.isEmpty {
                appendLogs(batch.lines.map { "Extension \($0)" })
            } else if cursorChanged {
                onLogsChanged?()
            }
        } catch {
            guard readID == extensionLogReadID else { return }
            appendLog("Unable to read extension logs: \(error.diagnosticDescription)")
        }
    }

    private func configuredManager(_ manager: NETunnelProviderManager, secretNonce: String, connection: InstalledTunnelConnection, onDemand: Bool, killSwitch: Bool, usesInlineResolvedConfig: Bool, configURL: URL, previousNonce: String?) async throws -> NETunnelProviderManager {
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
            "appGroup": RuntimeEnvironment.appGroupIdentifier,
            "secretNonce": secretNonce,
            "oneShot": usesInlineResolvedConfig,
            "targetDisplayName": connection.targetName,
            "routingMode": connection.routingMode.rawValue,
            "includeAllNetworks": killSwitch ? "true" : "false",
            "dnsServers": XrayTunnelNetworkDefaults.dnsServers.joined(separator: ","),
            "tunnelMTU": String(XrayTunnelNetworkDefaults.mtu),
        ]
        if !usesInlineResolvedConfig {
            tunnelProtocol.providerConfiguration?["configPath"] = configURL.path
        }
        // Keep the previous installed snapshot while an in-flight OS restart
        // can still be resolving it. Older/abandoned snapshots are pruned.
        tunnelProtocol.providerConfiguration?["previousSecretNonce"] = previousNonce
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
        Self.configureOnDemand(manager, requested: onDemand, usesInlineResolvedConfig: usesInlineResolvedConfig)
        try await save(manager)
        try await manager.loadFromPreferences()
        self.manager = manager
        installedConnection = InstalledTunnelConnection(manager: manager)
        appendLog("Installed tunnel manager for \(RuntimeEnvironment.tunnelProviderBundleIdentifier)")
        appendLog("Manager enabled=\(manager.isEnabled), status=\(manager.connection.status.displayName)")
        return manager
    }

    static func configureOnDemand(_ manager: NETunnelProviderManager, requested: Bool, usesInlineResolvedConfig: Bool) {
        let enabled = requested && !usesInlineResolvedConfig
        manager.isOnDemandEnabled = enabled
        manager.onDemandRules = enabled ? [NEOnDemandRuleConnect()] : nil
    }

    private static func existingManager(in managers: [NETunnelProviderManager]) -> NETunnelProviderManager? {
        managers.first(where: isHopManager)
    }

    private nonisolated static func isHopManager(_ manager: NETunnelProviderManager) -> Bool {
        (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
            == RuntimeEnvironment.tunnelProviderBundleIdentifier
    }

    func loadManager(
        reload: Bool = false,
        loadManagers: @MainActor () async throws -> [NETunnelProviderManager] = {
            try await NETunnelProviderManager.loadAllFromPreferences()
        },
    ) async throws -> NETunnelProviderManager {
        if !reload, let manager {
            return manager
        }

        let managers = try await loadManagers()
        appendLog("Loaded \(managers.count) tunnel manager(s) from preferences")
        let manager = Self.existingManager(in: managers) ?? NETunnelProviderManager()
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

    private func observeStatus(for connection: NEVPNConnection?) {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
            self.statusObserver = nil
        }
        let observationID = UUID()
        statusObservationID = observationID
        guard let connection else { return }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: connection,
            queue: .main,
        ) { [weak self, weak connection] _ in
            guard let connection else {
                return
            }
            Task { @MainActor in
                guard let controller = self, controller.statusObservationID == observationID else { return }
                controller.updateState(from: connection.status, source: "status notification")
                await controller.syncExtensionLogs()
            }
        }
    }

    private func schedulePostStartDiagnostics(actionID: UUID) {
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
                await self?.runPostStartDiagnostic(delaySeconds: delaySeconds, actionID: actionID)
            }
        }
    }

    private func runPostStartDiagnostic(delaySeconds: Int, actionID: UUID) async {
        await syncExtensionLogs()
        guard currentActionID == actionID, !Task.isCancelled else { return }
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
            if startInProgress {
                state = .failed
                startInProgress = false
                if !loggedStartupStop {
                    loggedStartupStop = true
                    appendLog("Tunnel stopped before connecting; an immediate stop suggests extension startup failure.")
                    appendLog("No Extension logs? Check bundle/App Group diagnostics, remove the saved VPN, and reinstall. If it persists, check HopTunnel.appex signing and provisioning.")
                    logLastDisconnectError()
                    // A startup failure repeats identically on every on-demand
                    // relaunch; disarm so iOS doesn't loop a broken config.
                    let actionID = currentActionID
                    Task { await self.disarmOnDemandIfNeeded(context: "tunnel failed during startup", actionID: actionID) }
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

/// Transfers ownership of the entire preferences/snapshot transaction across
/// suspension points. Main-actor isolation alone only serializes individual steps.
@MainActor
private final class TunnelPreferenceGate {
    private(set) var isLocked = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func acquire() async {
        if isLocked {
            await withCheckedContinuation { waiters.append($0) }
        } else {
            isLocked = true
        }
    }

    func release() {
        if waiters.isEmpty {
            isLocked = false
        } else {
            waiters.removeFirst().resume()
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
            profiles: profiles,
            groups: groups,
            selectedTarget: selectedTarget,
            routingMode: routingMode,
            rules: rules,
            settings: settings,
            tokenizingSecretsWith: nonce,
        )
    }
}

/// Performs secure-store and authenticated-file I/O without blocking the main
/// actor. Inputs are immutable value snapshots; `SecretStore` wraps a Sendable
/// backend and `SharedTunnelConfigurationStore` is stateless.
struct SharedTunnelConfigPreparation: @unchecked Sendable {
    let config: String
    let nonce: String
    let profiles: [ProxyProfile]
    let secretStore: SecretStore
    let configStore: SharedTunnelConfigurationStore

    func write(keeping existingNonces: Set<String>) throws {
        // Clean abandoned attempts before staging; a failed cleanup aborts
        // without accumulating another generation of credentials or files.
        try pruneSnapshots(keeping: existingNonces)
        do {
            try writeReferencedSecrets()
            // A fresh path keeps the installed config/signature usable even
            // if this write or the following manager save fails.
            try configStore.writeConfig(config, nonce: nonce)
        } catch {
            try? pruneSnapshots(keeping: existingNonces)
            throw error
        }
    }

    func writeReferencedSecrets() throws {
        var missingKeys = SecretResolver.referencedKeys(in: config, nonce: nonce)
        let keyPrefix = HopSecret.runtimeKeyPrefix(nonce: nonce)
        for profile in profiles where !missingKeys.isEmpty {
            let passwordKey = HopSecret.key(profileID: profile.id, fieldRaw: ProfileSecretField.password.rawValue)
            let runtime = try missingKeys.contains(passwordKey) ? profile.normalizingShadowsocks2022Keys() : profile
            for item in runtime.keychainSecretItems where missingKeys.remove(item.key) != nil {
                guard secretStore.setValue(item.value, forKey: keyPrefix + item.key) else {
                    throw TunnelSecretPreparationError.writeFailed
                }
            }
        }
        guard missingKeys.isEmpty else {
            throw TunnelSecretPreparationError.missingReference
        }
    }

    func pruneSnapshots(keeping nonces: Set<String>) throws {
        try configStore.pruneSnapshots(keeping: nonces)
        guard secretStore.pruneTunnelSnapshots(keeping: nonces) else {
            throw TunnelSecretPreparationError.writeFailed
        }
    }
}

private enum TunnelEraseError: Error {
    case stopTimedOut
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
            return "Re-sign both bundles with matching App Group/keychain groups and Packet Tunnel enabled, then reinstall."
        }
        if nsError.domain == NEVPNConnectionErrorDomain {
            return switch NEVPNConnectionError(rawValue: nsError.code) {
            case .pluginFailed:
                "HopTunnel.appex exited during startup. Check Extension logs for the cause."
            case .pluginDisabled:
                "Tunnel extension unavailable or outdated. Remove the saved Hop VPN and reinstall. If it persists, check the extension's bundle ID and provisioning profile for Packet Tunnel, App Group, and keychain access."
            case .configurationFailed, .configurationNotFound:
                "Saved VPN configuration is invalid or missing. Reconnect to rebuild it."
            default:
                nil
            }
        }
        guard nsError.domain == "NEVPNErrorDomain" else {
            return nil
        }

        return switch nsError.code {
        case 5:
            "NetworkExtension IPC failed. Check HopTunnel.appex embedding and Packet Tunnel/App Group entitlements."
        default:
            "Tunnel start rejected. Check VPN permission, signing, App Group, and HopTunnel.appex bundle ID."
        }
    }
}
