import Foundation
import NetworkExtension

#if canImport(Libbox)
    @preconcurrency import Libbox
#endif

/// The provider is handed from NetworkExtension's callback thread to a worker
/// queue after start options are snapshotted into value types.
final class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
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

            let rawConfig = try loadConfig(request: request)
            // Generated config carries secret references, not credentials. Resolve
            // them from the shared Keychain here, in memory, just before starting.
            // The nonce (passed via start options, or the persisted provider
            // configuration on an iOS-initiated restart) gates which tokens are
            // resolvable, so import-supplied fields can't forge one.
            let nonce = request.secretNonce
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
                try startService(configContent: config, request: request)
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
        private func startService(configContent: String, request: TunnelStartRequest) throws {
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

    private func loadConfig(request: TunnelStartRequest) throws -> String {
        if let configContent = request.optionConfigContent {
            writeTunnelLog("Using inline tunnel settings from start options")
            return configContent
        }

        if let configPath = request.optionConfigPath {
            writeTunnelLog("Reading tunnel settings from shared storage")
            return try String(contentsOfFile: configPath, encoding: .utf8)
        }

        if let configContent = request.providerConfigContent {
            writeTunnelLog("Using inline tunnel settings from provider configuration")
            return configContent
        }

        if let configPath = request.providerConfigPath {
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

private struct TunnelStartRequest {
    let optionConfigContent: String?
    let optionConfigPath: String?
    let providerConfigContent: String?
    let providerConfigPath: String?
    let appGroup: String?
    let secretNonce: String
    let visibleOptionKeys: [String]

    init(options: [String: NSObject]?, providerConfiguration: [String: Any]?) {
        optionConfigContent = options?["configContent"] as? String
        optionConfigPath = options?["configPath"] as? String
        providerConfigContent = providerConfiguration?["configContent"] as? String
        providerConfigPath = providerConfiguration?["configPath"] as? String
        appGroup = (options?["appGroup"] as? String) ?? (providerConfiguration?["appGroup"] as? String)
        secretNonce = (options?["secretNonce"] as? String) ?? (providerConfiguration?["secretNonce"] as? String) ?? ""

        let hiddenKeys: Set = ["configContent", "configPath"]
        let keys = options?.keys.filter { !hiddenKeys.contains($0) }.sorted() ?? []
        visibleOptionKeys = keys.isEmpty ? ["none"] : keys
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
