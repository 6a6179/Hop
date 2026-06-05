import Foundation
import NetworkExtension

#if canImport(Libbox)
    import Libbox
#endif

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var logURL: URL?

    // Bound the shared tunnel log so a noisy/malicious proxy condition can't
    // grow it without limit and later exhaust disk or freeze the log UI.
    private static let maxTunnelLogBytes = 1_048_576 // 1 MB
    private static let tunnelLogTrimBytes = 262_144 // keep ~256 KB tail on rotation

    #if canImport(Libbox)
        private lazy var platformInterface = HopPlatformInterface(provider: self)
        private var commandServer: LibboxCommandServer?
        private var lastConfigContent: String?
    #endif

    override func startTunnel(options startOptions: [String: NSObject]?, completionHandler: @escaping @Sendable (Error?) -> Void) {
        // libbox starts the engine synchronously, and during start it calls back
        // into `openTun`, which blocks on `setTunnelNetworkSettings`. Running
        // that on the NE callback thread can deadlock, so hop to a worker thread.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.startTunnelOnWorker(options: startOptions, completionHandler: completionHandler)
        }
    }

    private func startTunnelOnWorker(options startOptions: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        do {
            configureLogURL(options: startOptions)
            writeTunnelLog("PacketTunnelProvider.startTunnel invoked")
            writeTunnelLog("Start option keys: \(visibleStartOptionKeys(startOptions).joined(separator: ", "))")

            let rawConfig = try loadConfig(options: startOptions)
            // Generated config carries secret references, not credentials. Resolve
            // them from the shared Keychain here, in memory, just before starting.
            // The nonce (passed via start options, or the persisted provider
            // configuration on an iOS-initiated restart) gates which tokens are
            // resolvable, so import-supplied fields can't forge one.
            let nonce = secretNonce(options: startOptions)
            guard !nonce.isEmpty else { throw TunnelProviderError.missingSecretNonce }
            let (config, unresolvedSecrets) = SecretResolver.resolve(rawConfig, nonce: nonce)
            writeTunnelLog("Loaded tunnel settings (\(config.utf8.count) bytes)")
            // Fail closed: every emitted token has a matching Keychain item, so a
            // non-zero count means the shared Keychain is unreachable (e.g. the
            // keychain-access-groups entitlement was dropped during signing).
            // Starting anyway would run the tunnel with blank credentials.
            if unresolvedSecrets > 0 {
                throw TunnelProviderError.unresolvedSecrets(unresolvedSecrets)
            }

            #if canImport(Libbox)
                try startService(configContent: config, options: startOptions)
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
            stopService()
            commandServer?.close()
            commandServer = nil
        #endif
        completionHandler()
    }

    #if canImport(Libbox)
        private func startService(configContent: String, options: [String: NSObject]?) throws {
            let container = appGroupContainer(options: options)
            let workingPath = container.appendingPathComponent("Working", isDirectory: true)
            let tempPath = container.appendingPathComponent("Temp", isDirectory: true)
            try? FileManager.default.createDirectory(at: workingPath, withIntermediateDirectories: true)
            try? FileManager.default.createDirectory(at: tempPath, withIntermediateDirectories: true)

            let setup = LibboxSetupOptions()
            setup.basePath = container.path
            setup.workingPath = workingPath.path
            setup.tempPath = tempPath.path
            setup.logMaxLines = 3000

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
            commandServer = server

            lastConfigContent = configContent
            try server.startOrReloadService(configContent, options: LibboxOverrideOptions())
        }

        func stopService() {
            do {
                try commandServer?.closeService()
            } catch {
                writeTunnelLog("stopService error: \(error.diagnosticDescription)")
            }
            platformInterface.reset()
        }

        func reloadService() throws {
            guard let commandServer, let lastConfigContent else { return }
            reasserting = true
            defer { reasserting = false }
            try commandServer.startOrReloadService(lastConfigContent, options: LibboxOverrideOptions())
        }
    #endif

    private func loadConfig(options: [String: NSObject]?) throws -> String {
        if let configContent = options?["configContent"] as? String {
            writeTunnelLog("Using inline tunnel settings from start options")
            return configContent
        }

        if let configPath = options?["configPath"] as? String {
            writeTunnelLog("Reading tunnel settings from shared storage")
            return try String(contentsOfFile: configPath, encoding: .utf8)
        }

        let providerConfiguration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration

        if let providerConfiguration,
           let configContent = providerConfiguration["configContent"] as? String
        {
            writeTunnelLog("Using inline tunnel settings from provider configuration")
            return configContent
        }

        if let providerConfiguration,
           let configPath = providerConfiguration["configPath"] as? String
        {
            writeTunnelLog("Reading tunnel settings from provider configuration")
            return try String(contentsOfFile: configPath, encoding: .utf8)
        }

        if let appGroup = options?["appGroup"] as? String ?? providerConfiguration?["appGroup"] as? String,
           let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
        {
            writeTunnelLog("Reading tunnel settings from App Group container")
            return try String(contentsOf: container.appendingPathComponent("hop-sing-box.json"), encoding: .utf8)
        }

        throw TunnelProviderError.missingConfig
    }

    private func secretNonce(options: [String: NSObject]?) -> String {
        let providerConfiguration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        return (options?["secretNonce"] as? String)
            ?? (providerConfiguration?["secretNonce"] as? String)
            ?? ""
    }

    private func visibleStartOptionKeys(_ options: [String: NSObject]?) -> [String] {
        let hiddenKeys: Set = ["configContent", "configPath"]
        let keys = options?.keys.filter { !hiddenKeys.contains($0) }.sorted() ?? []
        return keys.isEmpty ? ["none"] : keys
    }

    private func appGroupContainer(options: [String: NSObject]?) -> URL {
        let providerConfiguration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        if let appGroup = options?["appGroup"] as? String ?? providerConfiguration?["appGroup"] as? String,
           let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
        {
            return container
        }
        // Engine still runs; shared state/logs just won't reach the app.
        return FileManager.default.temporaryDirectory
    }

    private func configureLogURL(options: [String: NSObject]?) {
        let providerConfiguration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration

        if let appGroup = options?["appGroup"] as? String ?? providerConfiguration?["appGroup"] as? String,
           let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
        {
            logURL = container.appendingPathComponent("hop-tunnel.log")
            return
        }

        if let configPath = options?["configPath"] as? String ?? providerConfiguration?["configPath"] as? String {
            logURL = URL(fileURLWithPath: configPath).deletingLastPathComponent().appendingPathComponent("hop-tunnel.log")
        }
    }

    func writeTunnelLog(_ message: String) {
        guard let logURL else {
            return
        }

        do {
            try FileManager.default.createDirectory(at: logURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            rotateTunnelLogIfNeeded(at: logURL)

            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            let line = "[\(formatter.string(from: Date()))] \(message)\n"
            guard let data = line.data(using: .utf8) else {
                return
            }

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

private enum TunnelProviderError: LocalizedError {
    case missingConfig
    case missingSecretNonce
    case unresolvedSecrets(Int)
    case libboxUnavailable

    var errorDescription: String? {
        switch self {
        case .missingConfig:
            "The Hop tunnel extension could not find the tunnel settings."
        case .missingSecretNonce:
            "The Hop tunnel extension received no secret nonce, so credentials cannot be resolved safely. Reconnect from the app."
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
