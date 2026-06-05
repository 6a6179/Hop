import Foundation

enum RuntimeEnvironment {
    static let fallbackAppGroup = "group.cat.string.hop"
    static let configFileName = "hop-sing-box.json"
    static let stateFileName = "hop-state.json"
    static let tunnelLogFileName = "hop-tunnel.log"

    static var appGroupIdentifier: String {
        entitlementAppGroups().first(where: canOpenAppGroup) ?? fallbackAppGroup
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

    static var stateFileURL: URL {
        sharedContainerURL.appendingPathComponent(stateFileName)
    }

    static var configFileURL: URL {
        sharedContainerURL.appendingPathComponent(configFileName)
    }

    static var tunnelLogFileURL: URL {
        sharedContainerURL.appendingPathComponent(tunnelLogFileName)
    }

    static var tunnelProviderBundleIdentifier: String {
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
    }

    private static func entitlementAppGroups() -> [String] {
        Array(Set(embeddedProvisioningProfileGroups() + [fallbackAppGroup]))
            .sorted()
    }

    private static func embeddedProvisioningProfileGroups() -> [String] {
        guard let url = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"),
              let raw = try? String(contentsOf: url, encoding: .isoLatin1)
        else {
            return []
        }

        let pattern = #"<string>(group\.[^<]+)</string>"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else {
            return []
        }
        let range = NSRange(raw.startIndex ..< raw.endIndex, in: raw)
        return regex.matches(in: raw, range: range).compactMap { match in
            guard let matchRange = Range(match.range(at: 1), in: raw) else {
                return nil
            }
            return String(raw[matchRange])
        }
    }

    private static func canOpenAppGroup(_ group: String) -> Bool {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) != nil
    }
}

struct SharedTunnelConfigurationStore {
    func writeConfig(_ config: String) throws {
        let url = RuntimeEnvironment.configFileURL
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        // Generated config carries nonce-bound secret references; protect at rest.
        try Data(config.utf8).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
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
