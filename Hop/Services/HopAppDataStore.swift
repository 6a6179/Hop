import Foundation

struct XrayMigrationReport: Codable, Equatable {
    var removedProfileNames: [String]
    var removedGroupNames: [String]
    var removedRuleCount: Int
    var blockedTLSProfileNames: [String]

    var isEmpty: Bool {
        removedProfileNames.isEmpty
            && removedGroupNames.isEmpty
            && removedRuleCount == 0
            && blockedTLSProfileNames.isEmpty
    }

    var message: String {
        var lines: [String] = []
        if !removedProfileNames.isEmpty {
            lines.append("Removed unsupported nodes: \(removedProfileNames.joined(separator: ", ")).")
        }
        if !removedGroupNames.isEmpty {
            lines.append("Removed empty groups: \(removedGroupNames.joined(separator: ", ")).")
        }
        if removedRuleCount > 0 {
            lines.append("Removed \(removedRuleCount) rule(s) that referenced removed nodes or groups.")
        }
        if !blockedTLSProfileNames.isEmpty {
            lines.append("These nodes must be edited before connecting because Xray does not accept allowInsecure: \(blockedTLSProfileNames.joined(separator: ", ")).")
        }
        return lines.joined(separator: "\n")
    }
}

struct HopAppData: Codable {
    static let currentSchemaVersion = 2

    var schemaVersion: Int?
    var profiles: [ProxyProfile]
    var groups: [ProxyGroup]
    var subscriptions: [SubscriptionSource]
    var routingMode: RoutingMode
    var selectedTarget: OutboundTarget?
    var settings: AppSettings
    var logs: [String]
    var ruleConfigurations: [RuleConfiguration]?
    var activeRuleConfigurationID: UUID?
    /// Legacy single rule list from before named configurations. Read on load to
    /// migrate; never written by current builds (optionals are omitted on encode).
    var rules: [RoutingRule]?
    var pendingXrayMigrationReport: XrayMigrationReport?

    init(
        profiles: [ProxyProfile],
        groups: [ProxyGroup],
        subscriptions: [SubscriptionSource],
        routingMode: RoutingMode,
        selectedTarget: OutboundTarget?,
        settings: AppSettings,
        logs: [String],
        ruleConfigurations: [RuleConfiguration]? = nil,
        activeRuleConfigurationID: UUID? = nil,
        rules: [RoutingRule]? = nil,
        schemaVersion: Int? = HopAppData.currentSchemaVersion,
        pendingXrayMigrationReport: XrayMigrationReport? = nil,
    ) {
        self.schemaVersion = schemaVersion
        self.profiles = profiles
        self.groups = groups
        self.subscriptions = subscriptions
        self.routingMode = routingMode
        self.selectedTarget = selectedTarget
        self.settings = settings
        self.logs = logs
        self.ruleConfigurations = ruleConfigurations
        self.activeRuleConfigurationID = activeRuleConfigurationID
        self.rules = rules
        self.pendingXrayMigrationReport = pendingXrayMigrationReport
    }
}

struct HopAppDataStore {
    var url: URL
    var secretStore: SecretStore
    var authenticationStore: SecretStore
    /// Shared across value copies of this store; see `SecretWriteCache`.
    private let secretWriteCache = SecretWriteCache()

    init(
        url: URL = RuntimeEnvironment.stateFileURL,
        secretStore: SecretStore = .shared,
        authenticationStore: SecretStore = .runtime,
    ) {
        self.url = url
        self.secretStore = secretStore
        self.authenticationStore = authenticationStore
    }

    func load() -> HopAppData? {
        guard let data = try? Data(contentsOf: url) else {
            return nil
        }

        let hadAuthenticationSecret = !authenticationStore.appStateAuthenticationSecret().isEmpty
        guard !hadAuthenticationSecret || isAuthenticated(data) else {
            NSLog("Hop: app state authentication failed")
            return nil
        }

        guard var decoded = try? JSONDecoder.hop.decode(HopAppData.self, from: data) else {
            return nil
        }

        let didMigrateToXray = migrateToXrayIfNeeded(&decoded)

        // Legacy/plaintext state (written before Keychain migration for
        // profiles, or before subscription URLs were treated as bearer
        // secrets) still carries inline values — detect that so we can migrate
        // it in place.
        let hadInlineProfileSecrets = decoded.profiles.contains { !$0.keychainSecretItems.isEmpty }
        let hadInlineSubscriptionURLs = decoded.subscriptions.contains { !$0.url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        decoded.profiles = decoded.profiles.map { $0.hydratingSecrets(from: secretStore) }
        decoded.subscriptions = decoded.subscriptions.map { $0.hydratingSecrets(from: secretStore) }
        if !hadAuthenticationSecret || hadInlineProfileSecrets || hadInlineSubscriptionURLs || didMigrateToXray {
            save(decoded) // move secrets to the Keychain and rewrite the JSON without them
        }
        return decoded
    }

    /// Performs the destructive engine-compatibility migration exactly once.
    /// Legacy enum cases remain decodable so old state can be inspected before
    /// unsupported nodes and their dangling references are removed.
    private func migrateToXrayIfNeeded(_ data: inout HopAppData) -> Bool {
        guard (data.schemaVersion ?? 0) < HopAppData.currentSchemaVersion else {
            return false
        }

        let unsupportedProfiles = data.profiles.filter { profile in
            switch profile.proto {
            case .tuic, .anyTLS:
                true
            default:
                profile.transport.type == .quic
            }
        }
        let removedProfileIDs = Set(unsupportedProfiles.map(\.id))
        let removedProfileNames = Set(unsupportedProfiles.map { $0.name.lowercased() })
        data.profiles.removeAll { removedProfileIDs.contains($0.id) }

        func targetReferencesRemovedProfile(_ target: OutboundTarget) -> Bool {
            switch target {
            case let .profile(id):
                removedProfileIDs.contains(id)
            case let .named(name):
                removedProfileNames.contains(name.lowercased())
            default:
                false
            }
        }

        for index in data.groups.indices {
            data.groups[index].members.removeAll(where: targetReferencesRemovedProfile)
            if let defaultTarget = data.groups[index].defaultTarget,
               targetReferencesRemovedProfile(defaultTarget)
            {
                data.groups[index].defaultTarget = data.groups[index].members.first
            }
        }

        // Removing one empty group can make a group containing only that group
        // empty as well, so prune to a fixed point.
        var removedGroups: [ProxyGroup] = []
        var removedGroupIDs = Set<ProxyGroup.ID>()
        var removedGroupNames = Set<String>()
        var changed = true
        while changed {
            changed = false
            for index in data.groups.indices {
                data.groups[index].members.removeAll { target in
                    switch target {
                    case let .group(id):
                        removedGroupIDs.contains(id)
                    case let .named(name):
                        removedGroupNames.contains(name.lowercased())
                    default:
                        false
                    }
                }
            }
            let newlyRemoved = data.groups.filter(\.members.isEmpty)
            guard !newlyRemoved.isEmpty else { continue }
            changed = true
            removedGroups.append(contentsOf: newlyRemoved)
            removedGroupIDs.formUnion(newlyRemoved.map(\.id))
            removedGroupNames.formUnion(newlyRemoved.map { $0.name.lowercased() })
            data.groups.removeAll { removedGroupIDs.contains($0.id) }
        }

        func targetIsRemoved(_ target: OutboundTarget) -> Bool {
            if targetReferencesRemovedProfile(target) {
                return true
            }
            switch target {
            case let .group(id):
                return removedGroupIDs.contains(id)
            case let .named(name):
                return removedGroupNames.contains(name.lowercased())
            default:
                return false
            }
        }

        var removedRuleCount = 0
        if var configurations = data.ruleConfigurations {
            for index in configurations.indices {
                let oldCount = configurations[index].rules.count
                configurations[index].rules.removeAll { targetIsRemoved($0.target) }
                removedRuleCount += oldCount - configurations[index].rules.count
            }
            data.ruleConfigurations = configurations
        }
        if var legacyRules = data.rules {
            let oldCount = legacyRules.count
            legacyRules.removeAll { targetIsRemoved($0.target) }
            removedRuleCount += oldCount - legacyRules.count
            data.rules = legacyRules
        }

        if let selectedTarget = data.selectedTarget, targetIsRemoved(selectedTarget) {
            // Deliberately do not fall back to Direct or a different proxy. The
            // user must review and select the post-migration target.
            data.selectedTarget = nil
        }

        let report = XrayMigrationReport(
            removedProfileNames: unsupportedProfiles.map(\.name).sorted(),
            removedGroupNames: removedGroups.map(\.name).sorted(),
            removedRuleCount: removedRuleCount,
            blockedTLSProfileNames: data.profiles
                .filter { $0.security.tls?.allowInsecure == true }
                .map(\.name)
                .sorted(),
        )
        data.pendingXrayMigrationReport = report.isEmpty ? nil : report
        data.schemaVersion = HopAppData.currentSchemaVersion
        return true
    }

    func save(_ data: HopAppData) {
        do {
            // Move secrets into the Keychain and strip them from the JSON so
            // credentials, UUIDs, and private keys are never written in
            // cleartext. `replaceAll` costs one Keychain round-trip per secret
            // plus an enumerate-and-prune pass — with hundreds of imported
            // profiles that dominates every save — so it runs only when the
            // secret set actually changed since the last write. Most saves
            // (log updates, settings, rule edits) change no secret at all.
            // The first save after launch always writes, so a Keychain that
            // drifted while the app was not running heals on next persist.
            let secretItems = data.profiles.flatMap(\.keychainSecretItems) + data.subscriptions.compactMap(\.keychainURLItem)
            if secretWriteCache.changedSinceLastWrite(secretItems) {
                if !secretStore.replaceAll(with: secretItems) {
                    // A write failed inside the Keychain. Drop the cache so the
                    // next save retries the full set instead of skipping forever
                    // on a state that never actually landed.
                    secretWriteCache.invalidate()
                }
            }
            var redacted = data
            redacted.profiles = data.profiles.map { $0.redactingSecrets() }
            redacted.subscriptions = data.subscriptions.map { $0.redactingSecrets() }

            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            let encoded = try JSONEncoder.hop.encode(redacted)
            guard let signature = signature(for: encoded) else {
                NSLog("Hop: unable to authenticate app state; skipping save")
                return
            }
            // Defense-in-depth: protect the (now secret-free) state at rest too.
            try encoded.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            try Data(signature.utf8).write(to: signatureURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } catch {
            assertionFailure("Unable to persist Hop app data: \(error)")
        }
    }

    private var signatureURL: URL {
        TunnelConfigAuthenticator.signatureURL(forConfigURL: url)
    }

    private func signature(for data: Data) -> String? {
        let secret = authenticationStore.ensureAppStateAuthenticationSecret()
        guard !secret.isEmpty, authenticationStore.appStateAuthenticationSecret() == secret else {
            return nil
        }
        return TunnelConfigAuthenticator.signature(for: data, secret: secret)
    }

    private func isAuthenticated(_ data: Data) -> Bool {
        let secret = authenticationStore.appStateAuthenticationSecret()
        guard !secret.isEmpty,
              let signature = try? String(contentsOf: signatureURL, encoding: .utf8)
        else {
            return false
        }
        return TunnelConfigAuthenticator.isValidSignature(signature, for: data, secret: secret)
    }
}

/// Remembers the secret set most recently handed to `SecretStore.replaceAll`
/// so unchanged saves can skip the Keychain entirely. A reference type shared
/// across value copies of `HopAppDataStore`; saves are serialized on
/// `HopStore`'s persist queue, and the lock covers the one load-time migration
/// save that runs before that queue is in play.
private final class SecretWriteCache: @unchecked Sendable {
    private let lock = NSLock()
    private var lastWritten: [String: String]?

    /// Records `items` as the latest intended Keychain state and reports
    /// whether they differ from the previous write (always true for the first).
    func changedSinceLastWrite(_ items: [(key: String, value: String)]) -> Bool {
        let dictionary = Dictionary(items, uniquingKeysWith: { _, last in last })
        lock.lock()
        defer { lock.unlock() }
        if lastWritten == dictionary {
            return false
        }
        lastWritten = dictionary
        return true
    }

    /// Forgets the recorded state after a failed Keychain write, so the next
    /// save runs `replaceAll` again rather than treating the failed state as
    /// already written.
    func invalidate() {
        lock.lock()
        defer { lock.unlock() }
        lastWritten = nil
    }
}

private extension JSONEncoder {
    static var hop: JSONEncoder {
        let encoder = JSONEncoder()
        #if DEBUG
            // Human-readable state files help debugging, but pretty-printing and
            // key-sorting roughly double encode time for a file only the app reads.
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        #endif
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }
}

private extension JSONDecoder {
    static var hop: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}
