import Foundation

enum RuntimeEnvironment {
    static let fallbackAppGroup = "group.cat.string.hop"
    static let configFileName = "hop-sing-box.json"
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

        let fallback = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Hop", isDirectory: true)
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

    static var stateFileURL: URL {
        sharedContainerURL.appendingPathComponent(stateFileName)
    }

    static var configFileURL: URL {
        sharedContainerURL.appendingPathComponent(configFileName)
    }

    static var tunnelLogFileURL: URL {
        sharedContainerURL.appendingPathComponent(tunnelLogFileName)
    }

    /// Whether any .appex is embedded under Hop.app/PlugIns. Some sideload
    /// signers strip app extensions entirely; without the .appex the VPN can
    /// never start, and `tunnelProviderBundleIdentifier` silently falls back
    /// to the derived identifier, hiding the problem.
    static let tunnelExtensionIsEmbedded: Bool = {
        guard let plugInsURL = Bundle.main.builtInPlugInsURL,
              let enumerator = FileManager.default.enumerator(at: plugInsURL, includingPropertiesForKeys: nil)
        else {
            return false
        }
        for case let url as URL in enumerator where url.pathExtension == "appex" {
            return true
        }
        return false
    }()

    static let tunnelProviderBundleIdentifier: String = {
        if let plugInsURL = Bundle.main.builtInPlugInsURL,
           let enumerator = FileManager.default.enumerator(at: plugInsURL, includingPropertiesForKeys: nil)
        {
            for case let url as URL in enumerator where url.pathExtension == "appex" {
                let infoURL = url.appendingPathComponent("Info.plist")
                guard let data = try? Data(contentsOf: infoURL),
                      let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
                      let bundleID = plist["CFBundleIdentifier"] as? String
                else {
                    continue
                }
                return bundleID
            }
        }

        return [Bundle.main.bundleIdentifier, "tunnel"].compactMap(\.self).joined(separator: ".")
    }()

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
        guard let plugInsURL = Bundle.main.builtInPlugInsURL,
              let enumerator = FileManager.default.enumerator(at: plugInsURL, includingPropertiesForKeys: nil)
        else { return [] }

        var groups: [String] = []
        for case let url as URL in enumerator where url.pathExtension == "appex" {
            groups.append(contentsOf: provisioningProfileGroups(at: url.appendingPathComponent("embedded.mobileprovision")))
        }
        return Array(Set(groups)).sorted()
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

enum RuntimeEnvironmentError: LocalizedError {
    case appGroupUnavailable(String)
    case noSharedAppGroup(appGroups: [String], tunnelGroups: [String])

    var errorDescription: String? {
        switch self {
        case let .appGroupUnavailable(appGroup):
            "App Group \(appGroup) is unavailable in this build."
        case let .noSharedAppGroup(appGroups, tunnelGroups):
            "Hop.app and HopTunnel.appex do not share an App Group. App groups: \(appGroups.joined(separator: ", ")); tunnel groups: \(tunnelGroups.joined(separator: ", "))."
        }
    }
}

struct SharedTunnelConfigurationStore {
    func writeConfig(_ config: String) throws {
        let url = RuntimeEnvironment.configFileURL
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)

        let data = Data(config.utf8)
        let secret = SecretStore.runtime.ensureTunnelConfigAuthenticationSecret()
        guard !secret.isEmpty,
              SecretStore.runtime.tunnelConfigAuthenticationSecret() == secret,
              let signature = TunnelConfigAuthenticator.signature(for: data, secret: secret)
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
            "The tunnel config authentication key could not be saved to the shared Keychain. Verify the keychain-access-groups entitlement on both app targets."
        }
    }
}

struct SharedTunnelLogStore {
    /// Upper bound on how much of the tunnel log the app reads into memory. The
    /// extension rotates the file, but the reader is bounded independently so a
    /// large file can never exhaust app memory or freeze the log UI.
    static let maxReadBytes = 512 * 1024

    func clear() throws {
        let url = RuntimeEnvironment.tunnelLogFileURL
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data().write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    func readLines() throws -> [String] {
        let url = RuntimeEnvironment.tunnelLogFileURL
        guard FileManager.default.fileExists(atPath: url.path) else {
            return []
        }

        let data = try boundedTail(of: url)
        guard let text = String(data: data, encoding: .utf8) else {
            return []
        }

        return text
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    /// Reads at most `maxReadBytes` from the end of the file, dropping any
    /// partial leading line so callers only ever see whole entries.
    private func boundedTail(of url: URL) throws -> Data {
        let size = try (FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int) ?? 0
        guard size > Self.maxReadBytes else {
            return try Data(contentsOf: url)
        }

        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        try handle.seek(toOffset: UInt64(size - Self.maxReadBytes))
        let tail = try handle.readToEnd() ?? Data()
        if let newline = tail.firstIndex(of: 0x0A) {
            return tail.suffix(from: tail.index(after: newline))
        }
        return tail
    }
}
