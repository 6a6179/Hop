import Foundation
import NetworkExtension

#if canImport(Libbox)
    @preconcurrency import Libbox
#endif

/// The provider is handed from NetworkExtension's callback thread to a worker
/// queue after start options are snapshotted into value types.
final class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
    private var logURL: URL?
    /// Serializes log appends: lines arrive from the start worker, NE
    /// callbacks, and libbox Go threads, and concurrent seek-to-end + write
    /// pairs on separate file handles would interleave mid-line.
    private let tunnelLogLock = NSLock()

    // Bound the shared tunnel log so a noisy/malicious proxy condition can't
    // grow it without limit and later exhaust disk or freeze the log UI.
    private static let maxTunnelLogBytes = 1_048_576 // 1 MB
    private static let tunnelLogTrimBytes = 262_144 // keep ~256 KB tail on rotation

    /// Costly to construct, so one per provider instead of one per log line;
    /// only touched under `tunnelLogLock`.
    private let tunnelLogDateFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    #if canImport(Libbox)
        private lazy var platformInterface = HopPlatformInterface(provider: self)
        /// Guards the libbox service state below. It is written by the start
        /// worker, cleared from the NE callback thread in `stopTunnel`, and read
        /// by `reloadService` on libbox's Go command-server thread — three
        /// uncoordinated threads under `@unchecked Sendable`.
        private let serviceStateLock = NSLock()
        private var commandServer: LibboxCommandServer?
        // Retain the last config + nonce for reloads. Normal shared-file starts
        // keep a tokenized config and resolve credentials in memory; degraded
        // inline starts may keep an already-resolved config, but only in the
        // extension process, not in providerConfiguration or on disk.
        private var lastRawConfig: String?
        private var configSecretNonce: String?
        private var lastConfigSecretsAreResolved = false
    #endif

    /// iOS kill-switch setting threaded from the app. When true, the engine is
    /// told to include all networks so the OS drops traffic if the tunnel dies.
    private(set) var includeAllNetworksSetting = false

    override func startTunnel(options startOptions: [String: NSObject]?, completionHandler: @escaping @Sendable (Error?) -> Void) {
        let request = TunnelStartRequest(
            options: startOptions,
            providerConfiguration: (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
        )

        // libbox starts the engine synchronously, and during start it calls back
        // into `openTun`, which blocks on `setTunnelNetworkSettings`. Running
        // that on the NE callback thread can deadlock, so hop to a worker thread.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.startTunnelOnWorker(request: request, completionHandler: completionHandler)
        }
    }

    private func startTunnelOnWorker(request: TunnelStartRequest, completionHandler: @escaping @Sendable (Error?) -> Void) {
        do {
            configureLogURL(request: request)
            writeTunnelLog("PacketTunnelProvider.startTunnel invoked")
            writeTunnelLog("Start option keys: \(request.visibleOptionKeys.joined(separator: ", "))")

            includeAllNetworksSetting = request.includeAllNetworks

            let rawConfig = try loadConfig(request: request)
            // Normal generated configs carry secret *references*, not
            // credentials. The nonce gates which tokens are resolvable so
            // import-supplied fields can't forge one. Degraded inline starts
            // mark the config as already resolved and skip token resolution.
            let nonce = request.secretNonce
            guard !nonce.isEmpty else { throw TunnelProviderError.missingSecretNonce }

            #if canImport(Libbox)
                try startService(rawConfig: rawConfig, nonce: nonce, request: request)
                writeTunnelLog("sing-box service started")
                completionHandler(nil)
            #else
                writeTunnelLog("Startup failed: \(TunnelProviderError.libboxUnavailable.localizedDescription)")
                completionHandler(TunnelProviderError.libboxUnavailable)
            #endif
        } catch {
            writeTunnelLog("Startup failed: \(error.diagnosticDescription)")
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        writeTunnelLog("PacketTunnelProvider.stopTunnel reason=\(reason.rawValue)")
        #if canImport(Libbox)
            // Take and clear the service state BEFORE closing anything, so a
            // concurrent `reloadService` on the libbox Go thread sees nil and
            // no-ops instead of reloading a server that is being torn down.
            // (The libbox calls themselves stay outside the lock: closeService
            // can call back into command-server handlers, and re-entering the
            // lock from those would deadlock.)
            serviceStateLock.lock()
            let server = commandServer
            commandServer = nil
            lastRawConfig = nil
            configSecretNonce = nil
            lastConfigSecretsAreResolved = false
            serviceStateLock.unlock()
            do {
                try server?.closeService()
            } catch {
                writeTunnelLog("stopService error: \(error.diagnosticDescription)")
            }
            platformInterface.reset()
            server?.close()
        #endif
        completionHandler()
    }

    #if canImport(Libbox)
        private func startService(rawConfig: String, nonce: String, request: TunnelStartRequest) throws {
            // Resolve secrets up front so we fail closed before touching the
            // engine. `resolved` stays a local — handed to libbox and then
            // released — so credentials don't linger on the provider for the
            // tunnel's lifetime.
            let resolved = try resolveConfig(rawConfig: rawConfig, nonce: nonce, secretsAreResolved: request.configSecretsAreResolved)
            writeTunnelLog("Loaded tunnel settings (\(resolved.utf8.count) bytes)")

            let container = appGroupContainer(request: request)
            let workingPath = container.appendingPathComponent("Working", isDirectory: true)
            let tempPath = container.appendingPathComponent("Temp", isDirectory: true)
            try? FileManager.default.createDirectory(at: workingPath, withIntermediateDirectories: true)
            try? FileManager.default.createDirectory(at: tempPath, withIntermediateDirectories: true)

            let setup = LibboxSetupOptions()
            setup.basePath = container.path
            setup.workingPath = workingPath.path
            setup.tempPath = tempPath.path
            setup.logMaxLines = 3000
            // Require this token on every command-socket call. The app's
            // telemetry client reads the same shared-Keychain value, so a
            // process with only App Group container access (enough to reach the
            // unix socket) still can't drive the tunnel without it.
            let commandServerSecret = SecretStore.runtime.commandServerSecret()
            if commandServerSecret.isEmpty {
                // The app side generates this before starting the tunnel, so an
                // empty read here means the shared Keychain is unreachable — the
                // server will then reject the app's authenticated telemetry
                // client. Name the root cause instead of failing silently.
                writeTunnelLog("WARNING: command-server secret not readable from the shared Keychain; telemetry will be rejected. Check the keychain-access-groups entitlement on both Hop.app and HopTunnel.appex.")
            }
            setup.commandServerSecret = commandServerSecret

            var setupError: NSError?
            LibboxSetup(setup, &setupError)
            if let setupError { throw setupError }

            var stderrError: NSError?
            LibboxRedirectStderr(tempPath.appendingPathComponent("stderr.log").path, &stderrError)
            if let stderrError {
                writeTunnelLog("Could not redirect stderr: \(stderrError.localizedDescription)")
            }

            // Packet tunnel extensions run under a tight memory ceiling.
            LibboxSetMemoryLimit(true)

            var serverError: NSError?
            let server = LibboxNewCommandServer(platformInterface, platformInterface, &serverError)
            if let serverError { throw serverError }
            guard let server else { throw HopTunnelError("libbox returned a nil command server") }
            try server.start()
            serviceStateLock.lock()
            commandServer = server
            lastRawConfig = rawConfig
            configSecretNonce = nonce
            lastConfigSecretsAreResolved = request.configSecretsAreResolved
            serviceStateLock.unlock()
            try server.startOrReloadService(resolved, options: LibboxOverrideOptions())
        }

        /// Resolves secret tokens from the shared Keychain in memory and fails
        /// closed if any nonce-matching token is unresolvable — that means the
        /// shared Keychain is unreachable (e.g. the keychain-access-groups
        /// entitlement was dropped during signing), and starting anyway would
        /// run the tunnel with blank credentials.
        func stopService() {
            serviceStateLock.lock()
            let server = commandServer
            serviceStateLock.unlock()
            do {
                try server?.closeService()
            } catch {
                writeTunnelLog("stopService error: \(error.diagnosticDescription)")
            }
            platformInterface.reset()
        }

        /// Invoked by libbox on its Go command-server thread.
        func reloadService() throws {
            serviceStateLock.lock()
            let server = commandServer
            let rawConfig = lastRawConfig
            let nonce = configSecretNonce
            let secretsAreResolved = lastConfigSecretsAreResolved
            serviceStateLock.unlock()
            guard let server, let rawConfig, let nonce else { return }
            setReasserting(true)
            defer { setReasserting(false) }
            // Re-resolve tokenized configs for reloads; inline-resolved configs
            // are already marked and returned unchanged.
            let resolved = try resolveConfig(rawConfig: rawConfig, nonce: nonce, secretsAreResolved: secretsAreResolved)
            try server.startOrReloadService(resolved, options: LibboxOverrideOptions())
        }

        /// `reasserting` is a KVO-published NE property; mutating it from the
        /// libbox Go thread is an unsynchronized ObjC property write. The main
        /// queue is serial, so the true→false order is preserved.
        private func setReasserting(_ value: Bool) {
            DispatchQueue.main.async { [weak self] in
                self?.reasserting = value
            }
        }
    #endif

    private func resolveConfig(rawConfig: String, nonce: String, secretsAreResolved: Bool) throws -> String {
        guard !secretsAreResolved else {
            return rawConfig
        }

        let (config, unresolvedSecrets) = SecretResolver.resolve(rawConfig, nonce: nonce)
        if unresolvedSecrets > 0 {
            throw TunnelProviderError.unresolvedSecrets(unresolvedSecrets)
        }
        return config
    }

    private func loadConfig(request: TunnelStartRequest) throws -> String {
        if let configContent = request.optionConfigContent {
            writeTunnelLog("Using inline tunnel settings from start options")
            return configContent
        }

        if let configPath = request.optionConfigPath {
            guard isWithinAppGroupContainer(configPath, request: request) else {
                throw TunnelProviderError.configPathOutsideContainer
            }
            writeTunnelLog("Reading tunnel settings from shared storage")
            return try String(contentsOfFile: configPath, encoding: .utf8)
        }

        if let configContent = request.providerConfigContent {
            writeTunnelLog("Using inline tunnel settings from provider configuration")
            return configContent
        }

        if let configPath = request.providerConfigPath {
            guard isWithinAppGroupContainer(configPath, request: request) else {
                throw TunnelProviderError.configPathOutsideContainer
            }
            writeTunnelLog("Reading tunnel settings from provider configuration")
            return try String(contentsOfFile: configPath, encoding: .utf8)
        }

        if let appGroup = request.appGroup,
           let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
        {
            writeTunnelLog("Reading tunnel settings from App Group container")
            return try String(contentsOf: container.appendingPathComponent("hop-sing-box.json"), encoding: .utf8)
        }

        throw TunnelProviderError.missingConfig
    }

    private func appGroupContainer(request: TunnelStartRequest) -> URL {
        if let appGroup = request.appGroup,
           let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
        {
            return container
        }
        // Engine still runs; shared state/logs just won't reach the app.
        return FileManager.default.temporaryDirectory
    }

    /// Confirms a config path handed to us via start options / provider
    /// configuration resolves inside the App Group container before we read it,
    /// so a tampered app-side state can't point the extension at an arbitrary
    /// file (path traversal). The legitimate path is always
    /// `RuntimeEnvironment.configFileURL`, which lives in this container.
    private func isWithinAppGroupContainer(_ path: String, request: TunnelStartRequest) -> Bool {
        guard let appGroup = request.appGroup,
              let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
        else {
            return false
        }
        let resolved = URL(fileURLWithPath: path).standardizedFileURL.path
        let base = container.standardizedFileURL.path
        return resolved == base || resolved.hasPrefix(base + "/")
    }

    private func configureLogURL(request: TunnelStartRequest) {
        if let appGroup = request.appGroup,
           let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
        {
            logURL = container.appendingPathComponent("hop-tunnel.log")
            return
        }

        if let configPath = request.optionConfigPath ?? request.providerConfigPath {
            logURL = URL(fileURLWithPath: configPath).deletingLastPathComponent().appendingPathComponent("hop-tunnel.log")
        }
    }

    func writeTunnelLog(_ message: String) {
        guard let logURL else {
            return
        }

        // Collapse line breaks so one call is one log line. Messages can carry
        // remote-proxy-controlled text (libbox debug output), and an embedded
        // newline would let a malicious server forge timestamped entries in the
        // log the app displays (log injection).
        let sanitized = message
            .components(separatedBy: .newlines)
            .joined(separator: " ")

        tunnelLogLock.lock()
        defer { tunnelLogLock.unlock() }

        do {
            try FileManager.default.createDirectory(at: logURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            rotateTunnelLogIfNeeded(at: logURL)

            let line = "[\(tunnelLogDateFormatter.string(from: Date()))] \(sanitized)\n"
            let data = Data(line.utf8)

            if FileManager.default.fileExists(atPath: logURL.path) {
                let handle = try FileHandle(forWritingTo: logURL)
                defer {
                    try? handle.close()
                }
                try handle.seekToEnd()
                try handle.write(contentsOf: data)
            } else {
                try data.write(to: logURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            }
        } catch {
            NSLog("Hop tunnel log write failed: %@", error.localizedDescription)
        }
    }

    /// Keeps only the most recent tail once the shared log passes its size cap,
    /// dropping the partial leading line so the rotated file starts cleanly.
    private func rotateTunnelLogIfNeeded(at logURL: URL) {
        let attributes = try? FileManager.default.attributesOfItem(atPath: logURL.path)
        guard let size = attributes?[.size] as? Int, size > Self.maxTunnelLogBytes else {
            return
        }

        do {
            let tail: Data
            let handle = try FileHandle(forReadingFrom: logURL)
            do {
                defer { try? handle.close() }
                try handle.seek(toOffset: UInt64(size - Self.tunnelLogTrimBytes))
                tail = try handle.readToEnd() ?? Data()
            }

            let trimmed: Data = if let newline = tail.firstIndex(of: 0x0A) {
                tail.suffix(from: tail.index(after: newline))
            } else {
                tail
            }
            try trimmed.write(to: logURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } catch {
            // If rotation fails, truncate so growth is still bounded.
            try? Data().write(to: logURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        }
    }
}

private struct TunnelStartRequest {
    let optionConfigContent: String?
    let optionConfigPath: String?
    let providerConfigContent: String?
    let providerConfigPath: String?
    let appGroup: String?
    let secretNonce: String
    let configSecretsAreResolved: Bool
    let includeAllNetworks: Bool
    let visibleOptionKeys: [String]

    init(options: [String: NSObject]?, providerConfiguration: [String: Any]?) {
        optionConfigContent = options?["configContent"] as? String
        optionConfigPath = options?["configPath"] as? String
        providerConfigContent = providerConfiguration?["configContent"] as? String
        providerConfigPath = providerConfiguration?["configPath"] as? String
        appGroup = (options?["appGroup"] as? String) ?? (providerConfiguration?["appGroup"] as? String)
        secretNonce = (options?["secretNonce"] as? String) ?? (providerConfiguration?["secretNonce"] as? String) ?? ""
        configSecretsAreResolved = ((options?["configSecrets"] as? String) ?? (providerConfiguration?["configSecrets"] as? String)) == "resolved"
        includeAllNetworks = ((options?["includeAllNetworks"] as? String) ?? (providerConfiguration?["includeAllNetworks"] as? String)) == "true"

        let hiddenKeys: Set = ["configContent", "configPath"]
        let keys = options?.keys.filter { !hiddenKeys.contains($0) }.sorted() ?? []
        visibleOptionKeys = keys.isEmpty ? ["none"] : keys
    }
}

private enum TunnelProviderError: LocalizedError {
    case missingConfig
    case missingSecretNonce
    case configPathOutsideContainer
    case unresolvedSecrets(Int)
    case libboxUnavailable

    var errorDescription: String? {
        switch self {
        case .missingConfig:
            "The Hop tunnel extension could not find the tunnel settings."
        case .missingSecretNonce:
            "The Hop tunnel extension received no secret nonce, so credentials cannot be resolved safely. Reconnect from the app."
        case .configPathOutsideContainer:
            "The Hop tunnel extension was handed a config path outside the shared App Group container and refused to read it."
        case let .unresolvedSecrets(count):
            "\(count) credential reference(s) could not be resolved from the shared Keychain. Verify the keychain-access-groups entitlement is present on both the app and the tunnel extension."
        case .libboxUnavailable:
            "Libbox.xcframework is not linked yet. Run scripts/build-libbox.sh, then regenerate the project."
        }
    }
}

private extension Error {
    var diagnosticDescription: String {
        let nsError = self as NSError
        return "\(localizedDescription) [domain=\(nsError.domain), code=\(nsError.code)]"
    }
}
