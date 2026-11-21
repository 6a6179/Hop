import Darwin
import Foundation

enum RuntimeEnvironment {
    static let fallbackAppGroup = "group.cat.string.hop"
    static let configFileName = "hop-xray.json"
    static let stateFileName = "hop-state.json"
    static let tunnelLogFileName = "hop-tunnel.log"

    /// Both identifiers are process-constant (derived from the entitlements and
    /// the bundle) but cost a provisioning-profile regex scan / PlugIns
    /// directory walk to compute — memoize as lazy `static let`s.
    static let appGroupIdentifier: String = resolvedAppGroupIdentifier()

    static let appProvisioningAppGroups: [String] = appProvisioningProfileGroups()
    static let tunnelProvisioningAppGroups: [String] = tunnelProvisioningProfileGroups()

    static var appGroupResolutionDiagnostic: String {
        let appGroups = appProvisioningAppGroups.isEmpty ? "none" : appProvisioningAppGroups.joined(separator: ", ")
        let tunnelGroups = tunnelProvisioningAppGroups.isEmpty ? "none" : tunnelProvisioningAppGroups.joined(separator: ", ")
        let commonGroups = Set(appProvisioningAppGroups).intersection(tunnelProvisioningAppGroups)
        let common = commonGroups.isEmpty ? "none" : prioritizedAppGroups(commonGroups).joined(separator: ", ")
        let transport = usesInlineResolvedTunnelConfiguration ? "inline" : "shared App Group file"
        return "App profile groups: \(appGroups); tunnel profile groups: \(tunnelGroups); common groups: \(common); selected: \(appGroupIdentifier); config transport: \(transport)"
    }

    static var usesInlineResolvedTunnelConfiguration: Bool {
        shouldUseInlineResolvedTunnelConfiguration(
            appGroups: appProvisioningAppGroups,
            tunnelGroups: tunnelProvisioningAppGroups,
            selectedAppGroup: appGroupIdentifier,
        )
    }

    static var sharedContainerURL: URL {
        if let url = appGroupContainerURL {
            return url
        }

        let fallback = privateSupportDirectory
        try? FileManager.default.createDirectory(at: fallback, withIntermediateDirectories: true)
        return fallback
    }

    static var appGroupContainerURL: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupIdentifier)
    }

    static func requireAppGroupAccess() throws {
        if let error = appGroupProfileMismatchError(
            appGroups: appProvisioningAppGroups,
            tunnelGroups: tunnelProvisioningAppGroups,
        ) {
            throw error
        }

        guard appGroupContainerURL != nil else {
            throw RuntimeEnvironmentError.appGroupUnavailable(appGroupIdentifier)
        }
    }

    private static var privateSupportDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Hop", isDirectory: true)
    }

    /// The library belongs to the app. Re-signing can change which shared
    /// containers are accessible without changing the profile Keychain.
    static var stateFileURL: URL {
        privateSupportDirectory.appendingPathComponent("Library", isDirectory: true).appendingPathComponent(stateFileName)
    }

    static var legacyStateFileURLs: [URL] {
        ([privateSupportDirectory] + [appGroupContainerURL].compactMap(\.self)).map { $0.appendingPathComponent(stateFileName) }
    }

    static var tunnelLogFileURL: URL {
        sharedContainerURL.appendingPathComponent(tunnelLogFileName)
    }

    /// Records the exact host/extension identity that iOS is being asked to
    /// launch. This distinguishes stale installs and rewritten bundle IDs from
    /// provider failures without relying on a cached disconnect error.
    static let installedBundleDiagnostic: String = {
        let appIdentity = bundleIdentity(from: Bundle.main.infoDictionary)
        let app = appIdentity?.diagnosticDescription ?? "unknown"
        let tunnel = tunnelExtensionIdentity?.diagnosticDescription ?? "not embedded"
        return "Installed bundles: Hop \(app); HopTunnel \(tunnel)"
    }()

    /// Hop currently embeds one app extension, so resolve its URL once and use
    /// the same bundle for identity and provisioning diagnostics.
    private static let tunnelExtensionURL: URL? = {
        guard let plugInsURL = Bundle.main.builtInPlugInsURL,
              let contents = try? FileManager.default.contentsOfDirectory(
                  at: plugInsURL,
                  includingPropertiesForKeys: nil,
                  options: [.skipsHiddenFiles],
              )
        else {
            return nil
        }
        return contents.first { $0.pathExtension == "appex" }
    }()

    /// Some sideload signers strip app extensions entirely. Without the .appex
    /// the VPN can never start, and a derived provider ID would hide the cause.
    static let tunnelExtensionIsEmbedded = tunnelExtensionURL != nil

    private static let tunnelExtensionIdentity: RuntimeBundleIdentity? = {
        guard let infoURL = tunnelExtensionURL?.appendingPathComponent("Info.plist"),
              let data = try? Data(contentsOf: infoURL),
              let plist = try? PropertyListSerialization.propertyList(
                  from: data,
                  options: [],
                  format: nil,
              ) as? [String: Any]
        else {
            return nil
        }
        return bundleIdentity(from: plist)
    }()

    static let tunnelProviderBundleIdentifier = tunnelExtensionIdentity?.bundleIdentifier
        ?? [Bundle.main.bundleIdentifier, "tunnel"].compactMap(\.self).joined(separator: ".")

    static func bundleIdentity(from infoDictionary: [String: Any]?) -> RuntimeBundleIdentity? {
        guard let infoDictionary,
              let bundleIdentifier = infoDictionary["CFBundleIdentifier"] as? String,
              !bundleIdentifier.isEmpty
        else {
            return nil
        }
        return RuntimeBundleIdentity(
            bundleIdentifier: bundleIdentifier,
            shortVersion: infoDictionary["CFBundleShortVersionString"] as? String ?? "unknown",
            buildVersion: infoDictionary["CFBundleVersion"] as? String ?? "unknown",
        )
    }

    static func selectAppGroup(
        appGroups: [String],
        tunnelGroups: [String],
        canOpen: (String) -> Bool,
    ) -> String {
        let appSet = Set(appGroups)
        let tunnelSet = Set(tunnelGroups)
        let commonSet = appSet.intersection(tunnelSet)
        let candidates: [String] = if !commonSet.isEmpty {
            prioritizedAppGroups(commonSet)
        } else if tunnelSet.isEmpty {
            // Many re-sign/install flows do not leave an embedded provisioning
            // profile inside the .appex, so the app cannot inspect the tunnel's
            // groups at runtime. In that case prefer the checked-in shared App
            // Group used by both entitlements, and only fall back to app-profile
            // groups if that source group is not present in the app signature.
            prioritizedAppGroups(appSet.union([fallbackAppGroup]))
        } else if appSet.isEmpty {
            prioritizedAppGroups(tunnelSet.union([fallbackAppGroup]))
        } else {
            [fallbackAppGroup]
        }
        return candidates.first(where: canOpen) ?? fallbackAppGroup
    }

    static func appGroupProfileMismatchError(
        appGroups: [String],
        tunnelGroups: [String],
    ) -> RuntimeEnvironmentError? {
        let appSet = Set(appGroups)
        let tunnelSet = Set(tunnelGroups)
        guard !appSet.isEmpty, !tunnelSet.isEmpty else {
            return nil
        }

        let commonGroups = appSet.intersection(tunnelSet)
        guard commonGroups.isEmpty else {
            return nil
        }

        return .noSharedAppGroup(appGroups: prioritizedAppGroups(appSet), tunnelGroups: prioritizedAppGroups(tunnelSet))
    }

    static func shouldUseInlineResolvedTunnelConfiguration(
        appGroups: [String],
        tunnelGroups: [String],
        selectedAppGroup: String,
    ) -> Bool {
        let appSet = Set(appGroups)
        let tunnelSet = Set(tunnelGroups)

        guard !tunnelSet.isEmpty else {
            // Re-sign/install flows often omit embedded.mobileprovision from the
            // .appex. If we selected the checked-in shared App Group and the app
            // profile lists it, keep the safer shared-file path; otherwise avoid
            // depending on a container that may be app-only.
            return selectedAppGroup != fallbackAppGroup || !appSet.contains(fallbackAppGroup)
        }

        return !appSet.contains(selectedAppGroup) || !tunnelSet.contains(selectedAppGroup)
    }

    private static func resolvedAppGroupIdentifier() -> String {
        selectAppGroup(
            appGroups: appProvisioningAppGroups,
            tunnelGroups: tunnelProvisioningAppGroups,
            canOpen: canOpenAppGroup,
        )
    }

    private static func appProvisioningProfileGroups() -> [String] {
        guard let url = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision") else {
            return []
        }
        return provisioningProfileGroups(at: url)
    }

    private static func tunnelProvisioningProfileGroups() -> [String] {
        guard let tunnelExtensionURL else { return [] }
        return provisioningProfileGroups(at: tunnelExtensionURL.appendingPathComponent("embedded.mobileprovision"))
    }

    private static func provisioningProfileGroups(at url: URL) -> [String] {
        guard let raw = try? String(contentsOf: url, encoding: .isoLatin1) else { return [] }
        let pattern = #"<string>(group\.[^<]+)</string>"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else {
            return []
        }
        let range = NSRange(raw.startIndex ..< raw.endIndex, in: raw)
        return Array(Set(regex.matches(in: raw, range: range).compactMap { match in
            guard let matchRange = Range(match.range(at: 1), in: raw) else {
                return nil
            }
            return String(raw[matchRange])
        })).sorted()
    }

    private static func canOpenAppGroup(_ group: String) -> Bool {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) != nil
    }

    private static func prioritizedAppGroups(_ groups: Set<String>) -> [String] {
        let sortedGroups = groups.sorted()
        guard groups.contains(fallbackAppGroup) else {
            return sortedGroups
        }
        return [fallbackAppGroup] + sortedGroups.filter { $0 != fallbackAppGroup }
    }
}

struct RuntimeBundleIdentity: Equatable, Sendable {
    let bundleIdentifier: String
    let shortVersion: String
    let buildVersion: String

    var diagnosticDescription: String {
        "\(shortVersion) (\(buildVersion)) [\(bundleIdentifier)]"
    }
}

enum RuntimeEnvironmentError: LocalizedError {
    case appGroupUnavailable(String)
    case noSharedAppGroup(appGroups: [String], tunnelGroups: [String])

    var errorDescription: String? {
        switch self {
        case let .appGroupUnavailable(appGroup):
            "App Group unavailable: \(appGroup)."
        case let .noSharedAppGroup(appGroups, tunnelGroups):
            "No shared App Group. App: \(appGroups.joined(separator: ", ")); tunnel: \(tunnelGroups.joined(separator: ", "))."
        }
    }
}

struct SharedTunnelConfigurationStore {
    private var snapshotDirectory: URL {
        RuntimeEnvironment.sharedContainerURL.appendingPathComponent("TunnelSnapshots", isDirectory: true)
    }

    func snapshotURL(nonce: String) -> URL {
        snapshotDirectory.appendingPathComponent(nonce, isDirectory: true)
            .appendingPathComponent(RuntimeEnvironment.configFileName)
    }

    func pruneSnapshots(keeping nonces: Set<String>) throws {
        guard FileManager.default.fileExists(atPath: snapshotDirectory.path) else { return }
        for directory in try FileManager.default.contentsOfDirectory(at: snapshotDirectory, includingPropertiesForKeys: nil) {
            guard UUID(uuidString: directory.lastPathComponent) != nil,
                  !nonces.contains(directory.lastPathComponent) else { continue }
            try FileManager.default.removeItem(at: directory)
        }
    }

    func writeConfig(_ config: String, nonce: String) throws {
        let url = snapshotURL(nonce: nonce)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)

        let data = Data(config.utf8)
        let secret = SecretStore.runtime.ensureTunnelConfigAuthenticationSecret()
        guard !secret.isEmpty,
              SecretStore.runtime.tunnelConfigAuthenticationSecret() == secret,
              let signature = TunnelConfigAuthenticator.snapshotSignature(for: data, nonce: nonce, secret: secret)
        else {
            throw TunnelConfigStoreError.authenticationSecretUnavailable
        }

        // Generated config carries nonce-bound secret references; protect at rest.
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        try Data(signature.utf8).write(
            to: TunnelConfigAuthenticator.signatureURL(forConfigURL: url),
            options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication],
        )
    }
}

private enum TunnelConfigStoreError: LocalizedError {
    case authenticationSecretUnavailable

    var errorDescription: String? {
        switch self {
        case .authenticationSecretUnavailable:
            "Cannot save tunnel authentication key. Check keychain-access-groups on both targets."
        }
    }
}

struct ExtensionLogCursor: Codable, Equatable, Sendable {
    struct FileIdentity: Codable, Equatable, Sendable {
        let inode: UInt64
        let birthSeconds: Int
        let birthNanoseconds: Int
    }

    let file: FileIdentity?
    let offset: UInt64
    /// Rotation atomically replaces the file while retaining its tail. The last
    /// complete timestamped line locates the overlap in the replacement.
    let lastLine: String?
}

struct ExtensionLogBatch: Sendable {
    let lines: [String]
    let cursor: ExtensionLogCursor?
}

struct SharedTunnelLogStore: Sendable {
    /// Upper bound on how much of the tunnel log the app reads into memory. The
    /// extension rotates the file, but the reader is bounded independently so a
    /// large file can never exhaust app memory or freeze the log UI.
    static let maxReadBytes = 512 * 1024

    var url: URL

    init(url: URL = RuntimeEnvironment.tunnelLogFileURL) {
        self.url = url
    }

    func clear() throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data().write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    func readLines() throws -> [String] {
        try readBatch(after: nil).lines
    }

    func readBatch(after previous: ExtensionLogCursor?) throws -> ExtensionLogBatch {
        let handle: FileHandle
        do {
            handle = try FileHandle(forReadingFrom: url)
        } catch CocoaError.fileReadNoSuchFile {
            return ExtensionLogBatch(lines: [], cursor: previous)
        }
        defer { try? handle.close() }
        var info = stat()
        guard fstat(handle.fileDescriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            throw CocoaError(.fileReadUnknown)
        }
        let file = ExtensionLogCursor.FileIdentity(
            inode: info.st_ino, birthSeconds: info.st_birthtimespec.tv_sec, birthNanoseconds: info.st_birthtimespec.tv_nsec,
        )
        let size = UInt64(info.st_size)
        let resume = previous.flatMap { $0.file == file && $0.offset <= size ? $0.offset : nil }
        let tailStart = size - min(size, UInt64(Self.maxReadBytes))
        let start = max(tailStart, resume ?? 0)
        // Inspect the preceding byte only when clipping a long tail. It may
        // land in the middle of a UTF-8 code point or exactly on a boundary.
        let clipped = start > 0 && start != resume
        let readStart = clipped ? start - 1 : start
        try handle.seek(toOffset: readStart)
        let data = try size > readStart ? handle.read(upToCount: Int(size - readStart)) ?? Data() : Data()
        let completeCount = data.lastIndex(of: 0x0A).map { data.index(after: $0) } ?? 0
        var complete = data.prefix(completeCount)
        if clipped, let newline = complete.firstIndex(of: 0x0A) {
            complete = complete.suffix(from: complete.index(after: newline))
        }
        let lines = complete.split(separator: 0x0A).compactMap { line -> String? in
            let text = String(decoding: line, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            return text.isEmpty ? nil : text
        }
        var newLines = lines[...]
        if resume == nil, let anchor = previous?.lastLine, let index = lines.lastIndex(of: anchor) {
            newLines = lines.suffix(from: lines.index(after: index))
        }
        let cursor = ExtensionLogCursor(
            file: file,
            offset: readStart + UInt64(completeCount),
            lastLine: lines.last ?? (resume != nil ? previous?.lastLine : nil),
        )
        return ExtensionLogBatch(lines: Array(newLines), cursor: cursor)
    }
}
