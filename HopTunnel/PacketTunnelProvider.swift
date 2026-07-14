import Darwin
import Foundation
import NetworkExtension

#if canImport(LibXray)
    @preconcurrency import LibXray
#endif

private enum TunnelRuntimeFiles {
    static let configFileName = "hop-xray.json"
    static let tunnelLogFileName = "hop-tunnel.log"
}

/// Runs one serialized Xray instance over NetworkExtension's system-owned
/// utun descriptor. All engine calls happen outside `serviceStateLock`: the Go
/// bridge owns callbacks and shutdown work that must never re-enter a held lock.
final class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
    private static let maxConfigBytes = TunnelMemoryPolicy.maximumConfigurationBytes
    private static let maxTunnelLogBytes = 1_048_576
    private static let tunnelLogTrimBytes = 262_144
    private static let maxLogMessageCharacters = 4096

    private lazy var platformInterface = HopPlatformInterface(provider: self)
    private let serviceStateLock = NSLock()
    /// Serializes the full start/stop lifecycle around LibXray's single core.
    private let serviceQueue = DispatchQueue(
        label: "cat.string.hop.tunnel-service",
        qos: .userInitiated,
        autoreleaseFrequency: .workItem,
    )
    private let memoryQueue = DispatchQueue(
        label: "cat.string.hop.tunnel-memory",
        qos: .utility,
        autoreleaseFrequency: .workItem,
    )
    private let tunnelLogLock = NSLock()

    private var xrayStarted = false
    private var memoryWatchdog: DispatchSourceTimer?
    private var softMemoryWarningActive = false
    private var logURL: URL?

    private let tunnelLogDateFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    override func startTunnel(
        options startOptions: [String: NSObject]?,
        completionHandler: @escaping @Sendable (Error?) -> Void,
    ) {
        let request = TunnelStartRequest(
            options: startOptions,
            providerConfiguration: (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
        )

        // Applying NE settings and starting Go are synchronous from Swift's
        // perspective. Never block NetworkExtension's callback thread.
        serviceQueue.async { [weak self] in
            self?.startTunnelOnWorker(request: request, completionHandler: completionHandler)
        }
    }

    private func startTunnelOnWorker(
        request: TunnelStartRequest,
        completionHandler: @escaping @Sendable (Error?) -> Void,
    ) {
        do {
            configureLogURL(request: request)
            writeTunnelLog("PacketTunnelProvider.startTunnel invoked")
            writeTunnelLog("Start option keys: \(request.visibleOptionKeys.joined(separator: ", "))")

            guard !request.secretNonce.isEmpty else {
                throw TunnelProviderError.missingSecretNonce
            }

            #if canImport(LibXray)
                try startService(request: request)
                writeTunnelLog("Xray service started")
                completionHandler(nil)
            #else
                throw TunnelProviderError.xrayUnavailable
            #endif
        } catch {
            writeTunnelLog("Startup failed: \(error.diagnosticDescription)")
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping @Sendable () -> Void) {
        serviceQueue.async { [weak self] in
            self?.stopService(logErrors: true)
            self?.writeTunnelLog("PacketTunnelProvider.stopTunnel reason=\(reason.rawValue)")
            completionHandler()
        }
    }

    #if canImport(LibXray)
        private func startService(request: TunnelStartRequest) throws {
            try autoreleasepool {
                let rawConfig = try loadConfig(request: request)
                let resolved = try resolveConfig(
                    rawConfig: rawConfig,
                    nonce: request.secretNonce,
                    secretsAreResolved: request.configSecretsAreResolved,
                )
                let config = try configWithBoundedEngineLogging(resolved)
                try startXray(config: config, request: request)
            }

            // The bridge has copied the JSON and autoreleasepool released the
            // temporary Data/JSON object graph. Return idle malloc pages before
            // measuring the steady-state footprint.
            Self.relieveNativeMemoryPressure()
            try completeServiceStartup()
        }

        private func startXray(config: String, request: TunnelStartRequest) throws {
            writeTunnelLog("Loaded Xray settings (\(config.utf8.count) bytes)")

            if let footprint = Self.physicalFootprintBytes(),
               footprint >= TunnelMemoryPolicy.hardLimitBytes
            {
                throw TunnelProviderError.memoryBudgetExceeded(footprint)
            }

            let descriptor = try platformInterface.configure(
                dnsServers: request.dnsServers,
                mtu: request.tunnelMTU,
                includeAllNetworks: request.includeAllNetworks,
            )
            writeTunnelLog(
                "Applied NetworkExtension settings mtu=\(HopPlatformInterface.clampedMTU(request.tunnelMTU)) interface=\(descriptor.interfaceName)",
            )

            // A provider process should never retain an earlier instance, but
            // fail safely after an interrupted start instead of overlapping two
            // Go cores under the memory ceiling.
            try XrayBridge.stop()

            let assetPath = try VerifiedXrayGeodata.assetDirectory(in: .main)
            do {
                try XrayBridge.start(
                    configJSON: config,
                    tunFileDescriptor: descriptor.fileDescriptor,
                    assetPath: assetPath,
                )
            } catch {
                try? XrayBridge.stop()
                Self.relieveNativeMemoryPressure()
                platformInterface.reset()
                throw error
            }
        }

        private func completeServiceStartup() throws {
            let footprint = Self.physicalFootprintBytes() ?? 0
            let decision = TunnelMemoryPolicy.decision(
                footprintBytes: footprint,
                softWarningActive: false,
            )
            guard decision.action != .stop else {
                try? XrayBridge.stop()
                Self.relieveNativeMemoryPressure()
                platformInterface.reset()
                throw TunnelProviderError.memoryBudgetExceeded(footprint)
            }

            serviceStateLock.lock()
            xrayStarted = true
            softMemoryWarningActive = decision.softWarningActive
            serviceStateLock.unlock()

            if decision.action == .collectAndWarn {
                try? XrayBridge.collectMemory()
                Self.relieveNativeMemoryPressure()
                let relievedFootprint = Self.physicalFootprintBytes() ?? footprint
                serviceStateLock.lock()
                softMemoryWarningActive = TunnelMemoryPolicy.decision(
                    footprintBytes: relievedFootprint,
                    softWarningActive: softMemoryWarningActive,
                ).softWarningActive
                serviceStateLock.unlock()
                writeTunnelLog("Memory watchdog warning at startup: \(Self.formatBytes(relievedFootprint))")
            }
            startMemoryWatchdog()
        }
    #endif

    private func stopService(logErrors: Bool) {
        serviceStateLock.lock()
        let shouldStop = xrayStarted
        xrayStarted = false
        softMemoryWarningActive = false
        let watchdog = memoryWatchdog
        memoryWatchdog = nil
        serviceStateLock.unlock()

        watchdog?.cancel()
        #if canImport(LibXray)
            var stopError: Error?
            if shouldStop {
                do {
                    try XrayBridge.stop()
                } catch {
                    stopError = error
                }
                Self.relieveNativeMemoryPressure()
            }
        #endif
        platformInterface.reset()
        #if canImport(LibXray)
            if logErrors, let stopError {
                writeTunnelLog("Xray stop error: \(stopError.diagnosticDescription)")
            }
        #endif
    }

    private func startMemoryWatchdog() {
        let timer = DispatchSource.makeTimerSource(queue: memoryQueue)
        // A saturated download can fill several TCP receive windows before a
        // one-second timer fires. Sample cheaply at 4 Hz so the hard stop still
        // has room to run before iOS jetsams the extension.
        timer.schedule(
            deadline: .now() + .milliseconds(TunnelMemoryPolicy.watchdogSampleMilliseconds),
            repeating: .milliseconds(TunnelMemoryPolicy.watchdogSampleMilliseconds),
            leeway: .milliseconds(50),
        )
        timer.setEventHandler { [weak self] in
            self?.sampleMemoryAndEnforceLimits()
        }
        timer.resume()

        serviceStateLock.lock()
        if xrayStarted, memoryWatchdog == nil {
            memoryWatchdog = timer
            serviceStateLock.unlock()
        } else {
            serviceStateLock.unlock()
            timer.cancel()
        }
    }

    private func sampleMemoryAndEnforceLimits() {
        guard let footprint = Self.physicalFootprintBytes() else {
            return
        }

        serviceStateLock.lock()
        guard xrayStarted else {
            serviceStateLock.unlock()
            return
        }
        let decision = TunnelMemoryPolicy.decision(
            footprintBytes: footprint,
            softWarningActive: softMemoryWarningActive,
        )
        softMemoryWarningActive = decision.softWarningActive
        if decision.action == .stop {
            xrayStarted = false
            softMemoryWarningActive = false
            let watchdog = memoryWatchdog
            memoryWatchdog = nil
            serviceStateLock.unlock()

            watchdog?.cancel()
            #if canImport(LibXray)
                try? XrayBridge.stop()
            #endif
            Self.relieveNativeMemoryPressure()
            platformInterface.reset()
            writeTunnelLog(
                "Memory watchdog hard limit reached: \(Self.formatBytes(footprint)); stopped Xray before jetsam",
            )
            cancelTunnelWithError(TunnelProviderError.memoryBudgetExceeded(footprint))
            return
        }
        serviceStateLock.unlock()

        if decision.action == .collectAndWarn {
            #if canImport(LibXray)
                // Ask Go to return idle pages before the process moves any
                // closer to the hard stop.
                try? XrayBridge.collectMemory()
            #endif
            Self.relieveNativeMemoryPressure()
            let relievedFootprint = Self.physicalFootprintBytes() ?? footprint
            serviceStateLock.lock()
            if xrayStarted {
                softMemoryWarningActive = TunnelMemoryPolicy.decision(
                    footprintBytes: relievedFootprint,
                    softWarningActive: softMemoryWarningActive,
                ).softWarningActive
            }
            serviceStateLock.unlock()
            writeTunnelLog("Memory watchdog soft limit reached: \(Self.formatBytes(relievedFootprint))")
        }
    }

    private func resolveConfig(rawConfig: String, nonce: String, secretsAreResolved: Bool) throws -> String {
        guard !secretsAreResolved else {
            return rawConfig
        }
        let (config, unresolvedSecrets) = SecretResolver.resolve(rawConfig, nonce: nonce)
        guard unresolvedSecrets == 0 else {
            throw TunnelProviderError.unresolvedSecrets(unresolvedSecrets)
        }
        return config
    }

    /// The current single-Invoke bridge has no bounded log callback. Disable
    /// direct engine file/console logs and keep lifecycle/errors on Hop's
    /// sanitized, rotating provider log instead.
    private func configWithBoundedEngineLogging(_ config: String) throws -> String {
        guard config.utf8.count <= Self.maxConfigBytes,
              let data = config.data(using: .utf8),
              var root = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw TunnelProviderError.invalidConfig
        }
        let requestedLevel = (root["log"] as? [String: Any])?["loglevel"] as? String ?? "warning"
        root["log"] = [
            "access": "none",
            "dnsLog": false,
            "error": "none",
            "loglevel": requestedLevel,
        ]
        let encoded = try JSONSerialization.data(
            withJSONObject: root,
            options: [.sortedKeys, .withoutEscapingSlashes],
        )
        guard encoded.count <= Self.maxConfigBytes,
              let result = String(data: encoded, encoding: .utf8)
        else {
            throw TunnelProviderError.invalidConfig
        }
        return result
    }

    private func loadConfig(request: TunnelStartRequest) throws -> String {
        if let content = request.optionConfigContent {
            writeTunnelLog("Using inline tunnel settings from start options")
            return try checkedInlineConfig(content)
        }
        if let path = request.optionConfigPath {
            guard isWithinAppGroupContainer(path, request: request) else {
                throw TunnelProviderError.configPathOutsideContainer
            }
            writeTunnelLog("Reading tunnel settings from shared storage")
            return try readAuthenticatedConfig(at: URL(fileURLWithPath: path))
        }
        if let content = request.providerConfigContent {
            writeTunnelLog("Using inline tunnel settings from provider configuration")
            return try checkedInlineConfig(content)
        }
        if let path = request.providerConfigPath {
            guard isWithinAppGroupContainer(path, request: request) else {
                throw TunnelProviderError.configPathOutsideContainer
            }
            writeTunnelLog("Reading tunnel settings from provider configuration")
            return try readAuthenticatedConfig(at: URL(fileURLWithPath: path))
        }
        if let appGroup = request.appGroup,
           let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
        {
            writeTunnelLog("Reading tunnel settings from App Group container")
            return try readAuthenticatedConfig(at: container.appendingPathComponent(TunnelRuntimeFiles.configFileName))
        }
        throw TunnelProviderError.missingConfig
    }

    private func checkedInlineConfig(_ config: String) throws -> String {
        guard config.utf8.count <= Self.maxConfigBytes else {
            throw TunnelProviderError.configTooLarge
        }
        return config
    }

    private func readAuthenticatedConfig(at url: URL) throws -> String {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        if let size = attributes[.size] as? NSNumber, size.intValue > Self.maxConfigBytes {
            throw TunnelProviderError.configTooLarge
        }
        let data = try Data(contentsOf: url)
        guard data.count <= Self.maxConfigBytes else {
            throw TunnelProviderError.configTooLarge
        }
        let secret = SecretStore.runtime.tunnelConfigAuthenticationSecret()
        guard !secret.isEmpty else {
            throw TunnelProviderError.missingConfigAuthenticationSecret
        }
        let signatureURL = TunnelConfigAuthenticator.signatureURL(forConfigURL: url)
        guard let signature = try? String(contentsOf: signatureURL, encoding: .utf8),
              TunnelConfigAuthenticator.isValidSignature(signature, for: data, secret: secret)
        else {
            throw TunnelProviderError.configAuthenticationFailed
        }
        guard let config = String(data: data, encoding: .utf8) else {
            throw TunnelProviderError.invalidConfig
        }
        return config
    }

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
            logURL = container.appendingPathComponent(TunnelRuntimeFiles.tunnelLogFileName)
        } else if let configPath = request.optionConfigPath ?? request.providerConfigPath {
            logURL = URL(fileURLWithPath: configPath)
                .deletingLastPathComponent()
                .appendingPathComponent(TunnelRuntimeFiles.tunnelLogFileName)
        }
    }

    func writeTunnelLog(_ message: String) {
        guard let logURL else { return }
        // Detach a bounded prefix before splitting so a remote-controlled
        // multi-megabyte error cannot create an unbounded substring array.
        let sanitized = String(message.prefix(Self.maxLogMessageCharacters))
            .components(separatedBy: .newlines)
            .joined(separator: " ")

        tunnelLogLock.lock()
        defer { tunnelLogLock.unlock() }
        do {
            try FileManager.default.createDirectory(
                at: logURL.deletingLastPathComponent(),
                withIntermediateDirectories: true,
            )
            rotateTunnelLogIfNeeded(at: logURL)
            let line = "[\(tunnelLogDateFormatter.string(from: Date()))] \(sanitized)\n"
            let data = Data(line.utf8)
            if FileManager.default.fileExists(atPath: logURL.path) {
                let handle = try FileHandle(forWritingTo: logURL)
                defer { try? handle.close() }
                try handle.seekToEnd()
                try handle.write(contentsOf: data)
            } else {
                try data.write(to: logURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            }
        } catch {
            NSLog("Hop tunnel log write failed: %@", error.localizedDescription)
        }
    }

    private func rotateTunnelLogIfNeeded(at logURL: URL) {
        let attributes = try? FileManager.default.attributesOfItem(atPath: logURL.path)
        guard let size = attributes?[.size] as? Int, size > Self.maxTunnelLogBytes else {
            return
        }
        do {
            let handle = try FileHandle(forReadingFrom: logURL)
            let tail: Data
            do {
                defer { try? handle.close() }
                try handle.seek(toOffset: UInt64(size - Self.tunnelLogTrimBytes))
                tail = try handle.readToEnd() ?? Data()
            }
            let trimmed = tail.firstIndex(of: 0x0A).map { tail.suffix(from: tail.index(after: $0)) } ?? tail[...]
            try Data(trimmed).write(
                to: logURL,
                options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication],
            )
        } catch {
            try? Data().write(to: logURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        }
    }

    private static func physicalFootprintBytes() -> UInt64? {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<task_vm_info_data_t>.stride / MemoryLayout<natural_t>.stride,
        )
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        guard result == KERN_SUCCESS else { return nil }
        return info.phys_footprint
    }

    private static func relieveNativeMemoryPressure() {
        _ = malloc_zone_pressure_relief(nil, 0)
    }

    private static func clampedInt64(_ value: UInt64) -> Int64 {
        Int64(min(value, UInt64(Int64.max)))
    }

    fileprivate static func formatBytes(_ bytes: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: clampedInt64(bytes), countStyle: .memory)
    }
}

private struct TunnelStartRequest {
    private static let maxDNSOptionBytes = 512
    private static let maxDNSServerCount = 8
    private static let maxDNSServerBytes = 45

    let optionConfigContent: String?
    let optionConfigPath: String?
    let providerConfigContent: String?
    let providerConfigPath: String?
    let appGroup: String?
    let secretNonce: String
    let configSecretsAreResolved: Bool
    let includeAllNetworks: Bool
    let dnsServers: [String]
    let tunnelMTU: Int
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
        dnsServers = Self.csv((options?["dnsServers"] as? String) ?? (providerConfiguration?["dnsServers"] as? String) ?? "")
        let mtu = Int((options?["tunnelMTU"] as? String) ?? (providerConfiguration?["tunnelMTU"] as? String) ?? "")
        tunnelMTU = HopPlatformInterface.clampedMTU(mtu ?? XrayTunnelNetworkDefaults.mtu)

        let hiddenKeys: Set = ["configContent", "configPath"]
        let keys = options?.keys.filter { !hiddenKeys.contains($0) }.sorted() ?? []
        visibleOptionKeys = keys.isEmpty ? ["none"] : keys
    }

    private static func csv(_ value: String) -> [String] {
        let boundedValue = String(decoding: value.utf8.prefix(maxDNSOptionBytes), as: UTF8.self)
        let candidates = boundedValue.split(
            separator: ",",
            maxSplits: maxDNSServerCount - 1,
            omittingEmptySubsequences: true,
        )
        var servers: [String] = []
        servers.reserveCapacity(maxDNSServerCount)
        for candidate in candidates {
            let server = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !server.isEmpty, server.utf8.count <= maxDNSServerBytes else { continue }
            servers.append(server)
        }
        return servers
    }
}

private enum TunnelProviderError: LocalizedError {
    case missingConfig
    case missingSecretNonce
    case configTooLarge
    case invalidConfig
    case configPathOutsideContainer
    case missingConfigAuthenticationSecret
    case configAuthenticationFailed
    case unresolvedSecrets(Int)
    case memoryBudgetExceeded(UInt64)
    case xrayUnavailable
    case xrayFailure(code: String)

    var errorDescription: String? {
        switch self {
        case .missingConfig:
            "The Hop tunnel extension could not find the tunnel settings."
        case .missingSecretNonce:
            "The Hop tunnel extension received no secret nonce, so credentials cannot be resolved safely. Reconnect from the app."
        case .configTooLarge:
            "The tunnel configuration exceeds the 512 KiB extension limit."
        case .invalidConfig:
            "The tunnel configuration is not a valid Xray JSON object."
        case .configPathOutsideContainer:
            "The Hop tunnel extension refused a config path outside the shared App Group container."
        case .missingConfigAuthenticationSecret:
            "The Hop tunnel extension could not read the tunnel config authentication key from the shared Keychain."
        case .configAuthenticationFailed:
            "The Hop tunnel extension refused tunnel settings whose App Group integrity check failed."
        case let .unresolvedSecrets(count):
            "\(count) credential reference(s) could not be resolved from the shared Keychain."
        case let .memoryBudgetExceeded(bytes):
            "The tunnel stopped at \(PacketTunnelProvider.formatBytes(bytes)) to stay below the iOS Network Extension memory ceiling."
        case .xrayUnavailable:
            "LibXray.xcframework is not linked. Build the pinned framework and regenerate the project."
        case let .xrayFailure(code):
            "Xray rejected the tunnel configuration (\(XrayBridgeResponse.Failure.sanitizedCode(code)))."
        }
    }
}

#if canImport(LibXray)
    /// Minimal adapter for libXray's gomobile package function. The upstream
    /// API is deliberately a single JSON request/response entry point.
    private enum XrayBridge {
        static func start(configJSON: String, tunFileDescriptor: Int32, assetPath: String) throws {
            try invoke(XrayBridgeRequest(
                method: "start",
                configJSON: configJSON,
                assetDirectory: assetPath,
                tunFD: tunFileDescriptor,
            ))
        }

        static func stop() throws {
            try invoke(XrayBridgeRequest(method: "stop"))
        }

        static func collectMemory() throws {
            try invoke(XrayBridgeRequest(method: "collectMemory"))
        }

        private static func invoke(_ request: XrayBridgeRequest) throws {
            let data = try JSONEncoder().encode(request)
            guard let json = String(data: data, encoding: .utf8) else {
                throw TunnelProviderError.xrayUnavailable
            }

            let rawResponse = stringValue(LibXrayInvoke(json))
            guard let responseData = rawResponse.data(using: .utf8) else {
                throw TunnelProviderError.xrayUnavailable
            }
            guard let response = try? JSONDecoder().decode(XrayBridgeResponse.self, from: responseData) else {
                throw TunnelProviderError.xrayUnavailable
            }
            guard response.version == 1 else {
                throw TunnelProviderError.xrayFailure(code: "unsupported_version")
            }
            guard response.ok else {
                throw TunnelProviderError.xrayFailure(code: response.error?.safeCode ?? "unknown")
            }
        }

        /// gomobile nullability has changed across toolchain versions; these
        /// overloads accept either generated Swift signature without force unwraps.
        private static func stringValue(_ value: String) -> String {
            value
        }

        private static func stringValue(_ value: String?) -> String {
            value ?? ""
        }
    }
#endif

private extension Error {
    var diagnosticDescription: String {
        let error = self as NSError
        return "\(localizedDescription) [domain=\(error.domain), code=\(error.code)]"
    }
}
