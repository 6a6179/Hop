import CryptoKit
import Foundation

struct XrayMigrationReport: Codable, Equatable {
    var removedProfileNames: [String]
    var removedGroupNames: [String]
    var removedRuleCount: Int
    var blockedTLSProfileNames: [String]
    var blockedAdvancedTLSProfileNames: [String]? = nil
    /// Optional for backward compatibility with schema-2 migration reports.
    var disabledLegacySubscriptionGroupNames: [String]? = nil
    var clearedLegacySelectionName: String? = nil
    var requiresLegacyRoutingReview: Bool? = nil

    var isEmpty: Bool {
        removedProfileNames.isEmpty
            && removedGroupNames.isEmpty
            && removedRuleCount == 0
            && blockedTLSProfileNames.isEmpty
            && (blockedAdvancedTLSProfileNames?.isEmpty ?? true)
            && (disabledLegacySubscriptionGroupNames?.isEmpty ?? true)
            && clearedLegacySelectionName == nil
            && requiresLegacyRoutingReview != true
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
            lines.append("Removed \(removedRuleCount) rules with missing nodes or groups.")
        }
        if !blockedTLSProfileNames.isEmpty {
            lines.append("Blocked by allowInsecure: \(blockedTLSProfileNames.joined(separator: ", ")). Enable verification or add certificate pins.")
        }
        if let blockedAdvancedTLSProfileNames, !blockedAdvancedTLSProfileNames.isEmpty {
            lines.append("Advanced TLS trust settings need review before connecting: \(blockedAdvancedTLSProfileNames.joined(separator: ", ")).")
        }
        if let disabledLegacySubscriptionGroupNames, !disabledLegacySubscriptionGroupNames.isEmpty {
            lines.append("Disabled legacy and dependent groups: \(disabledLegacySubscriptionGroupNames.joined(separator: ", ")). Removed targets that could switch sources. Review members before enabling.")
        }
        if let clearedLegacySelectionName {
            lines.append("Cleared \(clearedLegacySelectionName): unknown subscription source. Select a reviewed outbound before connecting.")
        }
        if requiresLegacyRoutingReview == true {
            lines.append("Legacy rules may come from subscriptions. Kept for review; Rule mode disabled.")
        }
        return lines.joined(separator: "\n")
    }
}

struct HopAppData: Codable {
    static let currentSchemaVersion = 3

    var schemaVersion: Int?
    /// Independent of the state schema so a failed shared-log clear cannot
    /// cause destructive state migrations to run again on the next launch.
    var legacyExtensionLogPurgePending: Bool?
    var profiles: [ProxyProfile]
    var groups: [ProxyGroup]
    var subscriptions: [SubscriptionSource]
    var routingMode: RoutingMode
    var selectedTarget: OutboundTarget?
    var settings: AppSettings
    var logs: [String]
    var extensionLogCursor: ExtensionLogCursor?
    var ruleConfigurations: [RuleConfiguration]?
    var activeRuleConfigurationID: UUID?
    /// Legacy single rule list from before named configurations. Read on load to
    /// migrate; never written by current builds (optionals are omitted on encode).
    var rules: [RoutingRule]?
    var pendingXrayMigrationReport: XrayMigrationReport?
    var routingConfigurationMigrationVersion: Int?
    /// Immutable Keychain snapshot referenced by the authenticated state file.
    var secretGeneration: UUID?
    var secretKeys: [String]?

    init(
        profiles: [ProxyProfile],
        groups: [ProxyGroup],
        subscriptions: [SubscriptionSource],
        routingMode: RoutingMode,
        selectedTarget: OutboundTarget?,
        settings: AppSettings,
        logs: [String],
        extensionLogCursor: ExtensionLogCursor? = nil,
        ruleConfigurations: [RuleConfiguration]? = nil,
        activeRuleConfigurationID: UUID? = nil,
        rules: [RoutingRule]? = nil,
        schemaVersion: Int? = HopAppData.currentSchemaVersion,
        legacyExtensionLogPurgePending: Bool? = nil,
        pendingXrayMigrationReport: XrayMigrationReport? = nil,
        routingConfigurationMigrationVersion: Int? = 1,
    ) {
        self.schemaVersion = schemaVersion
        self.legacyExtensionLogPurgePending = legacyExtensionLogPurgePending
        self.profiles = profiles
        self.groups = groups
        self.subscriptions = subscriptions
        self.routingMode = routingMode
        self.selectedTarget = selectedTarget
        self.settings = settings
        self.logs = logs
        self.extensionLogCursor = extensionLogCursor
        self.ruleConfigurations = ruleConfigurations
        self.activeRuleConfigurationID = activeRuleConfigurationID
        self.rules = rules
        self.pendingXrayMigrationReport = pendingXrayMigrationReport
        self.routingConfigurationMigrationVersion = routingConfigurationMigrationVersion
    }
}

struct AppStateEnvelope: Codable {
    var payload: Data
    var signature: String
}

enum LibraryRecoveryError: LocalizedError {
    case conflictingLibraries
    case newerSchema

    var errorDescription: String? {
        switch self {
        case .conflictingLibraries:
            "Hop found conflicting saved libraries from previous installations. Restore a backup containing the library you want to use, then retry. Resetting erases the saved credentials."
        case .newerSchema:
            "This library was saved by a newer version of Hop. Install that version or a later one to open it."
        }
    }
}

struct HopAppDataStore {
    // Includes the base64 envelope. Leave headroom above the retained
    // subscription budget for manual profiles, named rules, logs and metadata.
    static let maximumStateFileBytes = 64 * 1024 * 1024
    private static let maximumLegacyMACBytes = 128
    var url: URL
    var secretStore: SecretStore
    var authenticationStore: SecretStore
    var sharedLogStore: SharedTunnelLogStore
    /// Shared across value copies of this store; see `SecretWriteCache`.
    private let secretWriteCache = SecretWriteCache()
    private let legacyURLs: [URL]
    private let maximumFileBytes: Int

    init(
        url: URL? = nil,
        secretStore: SecretStore = .shared,
        authenticationStore: SecretStore = .runtime,
        sharedLogStore: SharedTunnelLogStore = SharedTunnelLogStore(),
        legacyURLs: [URL]? = nil,
        maximumFileBytes: Int = Self.maximumStateFileBytes,
    ) {
        self.url = url ?? RuntimeEnvironment.stateFileURL
        self.legacyURLs = legacyURLs ?? (url == nil ? RuntimeEnvironment.legacyStateFileURLs : [])
        self.maximumFileBytes = maximumFileBytes
        self.secretStore = secretStore
        self.authenticationStore = authenticationStore
        self.sharedLogStore = sharedLogStore
    }

    func load() -> HopAppData? {
        try? loadExisting()
    }

    /// Only an absent state file represents a new library. All other read,
    /// authentication, and migration failures must preserve the existing library.
    func loadExisting() throws -> HopAppData? {
        guard let data = try readState(at: url) else {
            return try adoptLegacyLibraryIfPresent()
        }
        let stored = try readAuthenticatedState(data)
        var decoded = stored.state
        let storedSecrets = stored.secrets
        let didMigrateToXray = migrateToXrayIfNeeded(&decoded)
        // Must run while the state is still pre-v3: legacy groups had no
        // subscriptionID field and legacy rules had no provenance.
        let didMigrateSubscriptionProvenance = migrateSubscriptionProvenanceIfNeeded(&decoded)
        let didMigrateAdvancedTLS = migrateAdvancedTLSIfNeeded(&decoded)
        let didMigrateLegacyLogState = migrateLegacyLogStateIfNeeded(&decoded)
        let didRemoveVMessCredential = removeLegacyVMessCipherCredentials(&decoded)

        // Legacy/plaintext state (written before Keychain migration for
        // profiles, or before subscription URLs were treated as bearer
        // secrets) still carries inline values — detect that so we can migrate
        // it in place.
        let hadInlineProfileSecrets = decoded.profiles.contains { !$0.keychainSecretItems.isEmpty }
        let hadInlineSubscriptionURLs = decoded.subscriptions.contains { !$0.url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        if !decoded.profiles.isEmpty || !decoded.subscriptions.isEmpty {
            // One Keychain snapshot replaces a separate SecItem lookup for
            // every protocol, REALITY, WireGuard-peer, advanced-JSON, and
            // subscription-URL field. App-state loading already hydrates all
            // of these values into memory; only the round-trip count changes.
            decoded.profiles = decoded.profiles.map { $0.hydratingSecrets(from: storedSecrets) }
            decoded.subscriptions = decoded.subscriptions.map { $0.hydratingSecrets(from: storedSecrets) }
        }
        if stored.legacy || hadInlineProfileSecrets || hadInlineSubscriptionURLs || didMigrateToXray || didMigrateSubscriptionProvenance || didMigrateAdvancedTLS || didMigrateLegacyLogState || didRemoveVMessCredential {
            guard save(decoded) else { throw CocoaError(.fileWriteUnknown) }
        }
        return decoded
    }

    private func readAuthenticatedState(_ data: Data) throws -> (state: HopAppData, secrets: [String: String], legacy: Bool) {
        let envelope = try? JSONDecoder().decode(AppStateEnvelope.self, from: data)
        let payload: Data
        let key = try authenticationStore.readValue(forKey: SecretStore.appStateAuthenticationKey)
        if let envelope {
            guard let key, TunnelConfigAuthenticator.isValidSignature(envelope.signature, for: envelope.payload, secret: key) else {
                throw CocoaError(.fileReadNoPermission)
            }
            payload = envelope.payload
        } else {
            let sidecar = try readLegacySignature()
            if let sidecar {
                // Resume only a verified pending-key bootstrap.
                let secret = try key ?? authenticationStore.readValue(forKey: Self.pendingAuthenticationKey)
                guard let secret, let signature = String(data: sidecar, encoding: .utf8),
                      TunnelConfigAuthenticator.isValidSignature(signature, for: data, secret: secret)
                else { throw CocoaError(.fileReadNoPermission) }
            } else if key != nil {
                throw CocoaError(.fileReadNoPermission)
            }
            payload = data
        }

        let decoded = try JSONDecoder.hop.decode(SupportedState.self, from: payload).data
        guard envelope == nil || (decoded.secretGeneration != nil && decoded.secretKeys != nil) else {
            throw CocoaError(.fileReadCorruptFile)
        }

        // Resolve exactly the committed generation, never the mutable runtime
        // aliases. Missing keys reject the snapshot instead of erasing secrets.
        var storedSecrets: [String: String] = [:]
        if let generation = decoded.secretGeneration, let keys = decoded.secretKeys {
            if !keys.isEmpty {
                let values = try secretStore.allValues()
                for key in keys {
                    guard let value = values[Self.snapshotKey(key, generation: generation)] else {
                        throw CocoaError(.fileReadNoPermission)
                    }
                    storedSecrets[key] = value
                }
            }
        } else if !decoded.profiles.isEmpty || !decoded.subscriptions.isEmpty {
            storedSecrets = try secretStore.allValues()
            guard !decoded.subscriptions.contains(where: {
                $0.url.isEmpty && storedSecrets[HopSecret.subscriptionURLKey(subscriptionID: $0.id)]?.isEmpty != false
            }), !decoded.profiles.contains(where: { $0.hasMissingLegacyAdvancedSecret(in: storedSecrets) })
            else { throw CocoaError(.fileReadNoPermission) }
        }

        return (decoded, storedSecrets, envelope == nil)
    }

    private struct SupportedState: Decodable {
        enum CodingKeys: CodingKey { case schemaVersion }
        let data: HopAppData

        init(from decoder: Decoder) throws {
            let keys = try decoder.container(keyedBy: CodingKeys.self)
            guard try keys.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 0 <= HopAppData.currentSchemaVersion else {
                throw LibraryRecoveryError.newerSchema
            }
            data = try HopAppData(from: decoder)
        }
    }

    private func adoptLegacyLibraryIfPresent() throws -> HopAppData? {
        let candidates = Set(legacyURLs).subtracting([url]).filter { FileManager.default.fileExists(atPath: $0.path) }
        guard !candidates.isEmpty else {
            try prepareEmptyLibrary()
            return nil
        }
        let oldStores = candidates.map {
            HopAppDataStore(url: $0, secretStore: secretStore, authenticationStore: authenticationStore, sharedLogStore: sharedLogStore, maximumFileBytes: maximumFileBytes)
        }
        let previous = try oldStores.count == 1 ? oldStores[0] : recoverableLegacyStore(in: oldStores)
        guard let library = try previous.loadExisting() else { throw CocoaError(.fileReadNoPermission) }
        guard write(library, reason: .adoptLegacyLibrary) else { throw CocoaError(.fileWriteUnknown) }
        try? FileManager.default.removeItem(at: previous.url)
        return try loadExisting()
    }

    /// An earlier writer may already have pruned the generation at one of
    /// the historical paths. Only adopt the sole readable snapshot when
    /// every existing Keychain account is accounted for by that snapshot.
    private func recoverableLegacyStore(in candidates: [Self]) throws -> Self {
        var recoverable: [(store: Self, state: HopAppData, digest: SHA256.Digest)] = []
        for candidate in candidates {
            guard let bytes = try readState(at: candidate.url) else { continue }
            do {
                let result = try candidate.readAuthenticatedState(bytes)
                recoverable.append((candidate, result.state, SHA256.hash(data: bytes)))
            } catch is DecodingError {
                continue
            } catch let error as CocoaError where error.code == .fileReadNoPermission || error.code == .fileReadCorruptFile {
                continue
            }
        }
        guard let choice = recoverable.first, recoverable.allSatisfy({ $0.digest == choice.digest }),
              let generation = choice.state.secretGeneration, let keys = choice.state.secretKeys
        else { throw LibraryRecoveryError.conflictingLibraries }
        let accounts = Set(keys + keys.map { Self.snapshotKey($0, generation: generation) } + [KeychainSecretBackend.accessGroupProbeAccount])
        guard try secretStore.allValues().keys.allSatisfy(accounts.contains) else { throw LibraryRecoveryError.conflictingLibraries }
        return choice.store
    }

    private func removeLegacyVMessCipherCredentials(_ data: inout HopAppData) -> Bool {
        var changed = false
        for index in data.profiles.indices {
            guard case var .vmess(options) = data.profiles[index].options,
                  let delimiter = options.security.firstIndex(of: "="),
                  options.security[..<delimiter].trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "password"
            else { continue }
            options.security = "auto"
            data.profiles[index].options = .vmess(options)
            changed = true
        }
        return changed
    }

    /// Performs the destructive engine-compatibility migration exactly once.
    /// Legacy enum cases remain decodable so old state can be inspected before
    /// unsupported nodes and their dangling references are removed.
    private func migrateToXrayIfNeeded(_ data: inout HopAppData) -> Bool {
        guard (data.schemaVersion ?? 0) < 2 else {
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
        data.schemaVersion = 2
        return true
    }

    /// Before schema 3, imported groups and routing rules had no trustworthy
    /// source marker. Avoid ownership inference from attacker-controlled graph
    /// topology: disable legacy imported groups and remove dynamic references
    /// so later sources cannot retarget them after a user re-enables one.
    private func migrateSubscriptionProvenanceIfNeeded(_ data: inout HopAppData) -> Bool {
        guard (data.schemaVersion ?? 0) < 3 else {
            return false
        }

        var didChange = false
        var disabledGroupNames = Set(data.pendingXrayMigrationReport?.disabledLegacySubscriptionGroupNames ?? [])
        let legacyImportedGroupIDs = Set(data.groups.lazy.filter { $0.importedType != nil }.map(\.id))
        let hasLegacySubscriptionEvidence = !data.subscriptions.isEmpty
            || data.profiles.contains(where: { $0.subscriptionID != nil })
            || !legacyImportedGroupIDs.isEmpty

        /// Disabling an imported child can silently change an enabled ancestor's
        /// fallback route (for example, Imported -> Direct). Propagate the
        /// review boundary through explicit group references without recursion
        /// so even very deep legacy graphs fail closed during migration.
        func normalizedTargetName(_ name: String) -> String {
            name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        }
        let profileCountsByName = Dictionary(
            grouping: data.profiles,
            by: { normalizedTargetName($0.name) },
        ).mapValues(\.count)
        let groupIDsByName = Dictionary(
            grouping: data.groups,
            by: { normalizedTargetName($0.name) },
        ).mapValues { $0.map(\.id) }

        func referencedGroupID(_ target: OutboundTarget) -> ProxyGroup.ID? {
            switch target {
            case let .group(id):
                return id
            case let .named(name):
                let normalized = normalizedTargetName(name)
                guard !["direct", "reject", "proxy"].contains(normalized),
                      profileCountsByName[normalized, default: 0] == 0,
                      let groupIDs = groupIDsByName[normalized],
                      groupIDs.count == 1
                else { return nil }
                return groupIDs[0]
            case .selectedProxy, .direct, .reject, .profile:
                return nil
            }
        }

        func hasUnsafeDynamicTarget(_ group: ProxyGroup) -> Bool {
            guard hasLegacySubscriptionEvidence else { return false }
            var targets = group.members
            if let defaultTarget = group.defaultTarget,
               !targets.contains(defaultTarget)
            {
                targets.append(defaultTarget)
            }
            return targets.contains { target in
                switch target {
                case .selectedProxy:
                    true
                case let .named(name):
                    normalizedTargetName(name) == "proxy"
                case .direct, .reject, .profile, .group:
                    false
                }
            }
        }

        var dependentGroupIndicesByChildID: [UUID: [Int]] = [:]
        for index in data.groups.indices {
            var targets = data.groups[index].members
            if let defaultTarget = data.groups[index].defaultTarget,
               !targets.contains(defaultTarget)
            {
                targets.append(defaultTarget)
            }
            for target in targets {
                guard let childID = referencedGroupID(target) else { continue }
                dependentGroupIndicesByChildID[childID, default: []].append(index)
            }
        }
        let dynamicAncestorGroupIDs = Set(data.groups.lazy.filter(hasUnsafeDynamicTarget).map(\.id))
        var unsafeLegacyGroupIDs = legacyImportedGroupIDs.union(dynamicAncestorGroupIDs)
        var pendingGroupIDs = Array(unsafeLegacyGroupIDs)
        var pendingGroupIndex = 0
        while pendingGroupIndex < pendingGroupIDs.count {
            let childID = pendingGroupIDs[pendingGroupIndex]
            pendingGroupIndex += 1
            for parentIndex in dependentGroupIndicesByChildID[childID] ?? [] {
                let parentID = data.groups[parentIndex].id
                if unsafeLegacyGroupIDs.insert(parentID).inserted {
                    pendingGroupIDs.append(parentID)
                }
            }
        }

        for index in data.groups.indices where data.groups[index].importedType != nil {
            var group = data.groups[index]
            disabledGroupNames.insert(ImportPolicy.sanitizeImportedName(
                group.name,
                fallback: "Imported Group",
            ))
            group.members.removeAll { target in
                switch target {
                case .named, .selectedProxy:
                    true
                case .profile, .group, .direct, .reject:
                    false
                }
            }
            if let defaultTarget = group.defaultTarget,
               !group.members.contains(defaultTarget)
            {
                group.defaultTarget = group.members.first
            }
            group.subscriptionID = nil
            group.isEnabled = false
            group.warning = "Legacy group disabled. Review routing before enabling."
            if group != data.groups[index] {
                data.groups[index] = group
                didChange = true
            }
        }

        for index in data.groups.indices
            where unsafeLegacyGroupIDs.contains(data.groups[index].id)
            && !legacyImportedGroupIDs.contains(data.groups[index].id)
        {
            var group = data.groups[index]
            disabledGroupNames.insert(ImportPolicy.sanitizeImportedName(
                group.name,
                fallback: "Dependent Group",
            ))
            group.isEnabled = false
            group.warning = "Disabled due to legacy group routing. Review dependencies before enabling."
            if group != data.groups[index] {
                data.groups[index] = group
                didChange = true
            }
        }

        var clearedSelectionName = data.pendingXrayMigrationReport?.clearedLegacySelectionName
        let unsafeSelectionName: String? = switch data.selectedTarget {
        case let .group(id) where unsafeLegacyGroupIDs.contains(id):
            data.groups.first(where: { $0.id == id })
                .map { ImportPolicy.sanitizeImportedName($0.name, fallback: "Imported Group") }
                ?? "Missing Imported Group"
        case let .named(name) where hasLegacySubscriptionEvidence:
            switch name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
            case "direct", "reject": nil
            default: ImportPolicy.sanitizeImportedName(name, fallback: "Named Outbound")
            }
        case .selectedProxy where hasLegacySubscriptionEvidence:
            "Active Proxy"
        case .none, .selectedProxy, .direct, .reject, .profile, .group, .named:
            nil
        }
        if let unsafeSelectionName {
            clearedSelectionName = unsafeSelectionName
            data.selectedTarget = nil
            didChange = true
        }

        func rulesAreSemanticallyEqual(_ lhs: [RoutingRule], _ rhs: [RoutingRule]) -> Bool {
            lhs.count == rhs.count && zip(lhs, rhs).allSatisfy {
                $0.kind == $1.kind && $0.value == $1.value && $0.target == $1.target
            }
        }
        let builtInRulesByName = Dictionary(
            uniqueKeysWithValues: RuleConfiguration.builtInConfigurations.map { ($0.name, $0.rules) },
        )
        let hasCustomOrModifiedConfiguration = data.ruleConfigurations?.contains { configuration in
            guard !configuration.rules.isEmpty else { return false }
            guard let builtInRules = builtInRulesByName[configuration.name] else { return true }
            return !rulesAreSemanticallyEqual(configuration.rules, builtInRules)
        } ?? false
        let hasLegacyRules = data.rules?.isEmpty == false
        let requiresRoutingReview = hasLegacySubscriptionEvidence
            && (hasCustomOrModifiedConfiguration || hasLegacyRules)
        if requiresRoutingReview, data.routingMode == .rule {
            data.routingMode = .global
            didChange = true
        }

        var report = data.pendingXrayMigrationReport ?? XrayMigrationReport(
            removedProfileNames: [],
            removedGroupNames: [],
            removedRuleCount: 0,
            blockedTLSProfileNames: [],
        )
        let disabledNames = disabledGroupNames.sorted()
        let desiredDisabledNames: [String]? = disabledNames.isEmpty ? nil : disabledNames
        let desiredRoutingReview: Bool? = (requiresRoutingReview || report.requiresLegacyRoutingReview == true) ? true : nil
        if report.disabledLegacySubscriptionGroupNames != desiredDisabledNames
            || report.clearedLegacySelectionName != clearedSelectionName
            || report.requiresLegacyRoutingReview != desiredRoutingReview
        {
            report.disabledLegacySubscriptionGroupNames = desiredDisabledNames
            report.clearedLegacySelectionName = clearedSelectionName
            report.requiresLegacyRoutingReview = desiredRoutingReview
            data.pendingXrayMigrationReport = report.isEmpty ? nil : report
            didChange = true
        }

        return didChange
    }

    /// Schema 2 allowed security-critical TLS values to live in advanced JSON.
    /// Move only unambiguous, valid values into the reviewed typed model. Any
    /// value that conflicts with an existing typed value, has a folded-key
    /// collision, or cannot be validated remains raw so the config builder
    /// rejects it until the user reviews the profile.
    private func migrateAdvancedTLSIfNeeded(_ data: inout HopAppData) -> Bool {
        guard (data.schemaVersion ?? 0) < 3 else {
            return false
        }

        let migratedFieldNames: Set = [
            "serverName", "fingerprint", "pinnedPeerCertSha256", "verifyPeerCertByName",
            "echConfigList", "curvePreferences", "minVersion", "maxVersion", "cipherSuites",
        ]
        let blockedFieldNames = migratedFieldNames.union(["disableSystemRoot"])

        func keysEqual(_ lhs: String, _ rhs: String) -> Bool {
            lhs.caseInsensitiveCompare(rhs) == .orderedSame
        }

        func uniqueEntry(
            named name: String,
            in object: [String: JSONValue],
        ) -> (key: String, value: JSONValue)? {
            let matches = object.keys.filter { keysEqual($0, name) }
            guard matches.count == 1, let key = matches.first, let value = object[key] else {
                return nil
            }
            return (key, value)
        }

        func isUnbound(_ value: String?) -> Bool {
            value?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != false
        }

        func isPersistedSecretReference(_ value: String) -> Bool {
            value.hasPrefix("##HOP_XRAY_SECRET_REF:") || value.hasPrefix("##HOP_SECRET:")
        }

        var didChange = false
        var blockedProfileNames: Set<String> = []

        for index in data.profiles.indices {
            var profile = data.profiles[index]
            guard profile.security.layer == .tls,
                  var tls = profile.security.tls,
                  var advanced = profile.xrayAdvanced,
                  let streamEntry = uniqueEntry(named: "streamSettings", in: advanced.values),
                  var stream = streamEntry.value.objectValue,
                  let tlsEntry = uniqueEntry(named: "tlsSettings", in: stream),
                  var rawTLS = tlsEntry.value.objectValue
            else { continue }

            var migratedKeys: Set<String> = []

            func commitCandidate(
                key: String,
                candidate: TLSOptions,
            ) {
                guard (try? XrayConfigBuilder().validateTLSOptionsForMigration(candidate)) != nil else {
                    return
                }
                tls = candidate
                migratedKeys.insert(key)
            }

            func migrateString(
                _ name: String,
                when typedValueIsMissing: Bool,
                assign: (inout TLSOptions, String) -> Void,
            ) {
                guard typedValueIsMissing,
                      let entry = uniqueEntry(named: name, in: rawTLS),
                      let value = entry.value.stringValue,
                      !isPersistedSecretReference(value)
                else { return }
                var candidate = tls
                assign(&candidate, value)
                commitCandidate(key: entry.key, candidate: candidate)
            }

            migrateString("serverName", when: isUnbound(tls.serverName)) {
                $0.serverName = $1
            }
            migrateString("fingerprint", when: isUnbound(tls.utlsFingerprint)) {
                $0.utlsFingerprint = $1
            }
            migrateString("pinnedPeerCertSha256", when: isUnbound(tls.pinnedPeerCertSHA256)) {
                $0.pinnedPeerCertSHA256 = $1
            }
            migrateString("verifyPeerCertByName", when: isUnbound(tls.verifyPeerCertByName)) {
                $0.verifyPeerCertByName = $1
            }
            migrateString("echConfigList", when: isUnbound(tls.echConfigList)) {
                $0.echConfigList = $1
            }
            migrateString("cipherSuites", when: isUnbound(tls.cipherSuites)) {
                $0.cipherSuites = $1
            }
            migrateString("minVersion", when: isUnbound(tls.minVersion)) {
                $0.minVersion = $1
            }
            migrateString("maxVersion", when: isUnbound(tls.maxVersion)) {
                $0.maxVersion = $1
            }

            if tls.curvePreferences.isEmpty,
               let entry = uniqueEntry(named: "curvePreferences", in: rawTLS),
               let values = entry.value.arrayValue
            {
                let curves = values.compactMap(\.stringValue)
                if curves.count == values.count {
                    var candidate = tls
                    candidate.curvePreferences = curves
                    commitCandidate(key: entry.key, candidate: candidate)
                }
            }

            for key in migratedKeys {
                rawTLS.removeValue(forKey: key)
            }
            if !migratedKeys.isEmpty {
                profile.security.tls = tls
                if rawTLS.isEmpty {
                    stream.removeValue(forKey: tlsEntry.key)
                } else {
                    stream[tlsEntry.key] = .object(rawTLS)
                }
                if stream.isEmpty {
                    advanced.values.removeValue(forKey: streamEntry.key)
                } else {
                    advanced.values[streamEntry.key] = .object(stream)
                }
                profile.xrayAdvanced = advanced.isEmpty ? nil : advanced
                data.profiles[index] = profile
                didChange = true
            }

            if rawTLS.keys.contains(where: { key in
                blockedFieldNames.contains(where: { keysEqual(key, $0) })
            }) {
                blockedProfileNames.insert(profile.name)
            }
        }

        let existingBlockedNames = data.pendingXrayMigrationReport?.blockedAdvancedTLSProfileNames ?? []
        let sortedBlockedNames = blockedProfileNames.sorted()
        if sortedBlockedNames != existingBlockedNames {
            var report = data.pendingXrayMigrationReport ?? XrayMigrationReport(
                removedProfileNames: [],
                removedGroupNames: [],
                removedRuleCount: 0,
                blockedTLSProfileNames: [],
            )
            report.blockedAdvancedTLSProfileNames = sortedBlockedNames
            data.pendingXrayMigrationReport = report
            didChange = true
        }

        return didChange
    }

    /// Schema 2 could persist raw third-party core diagnostics containing a
    /// profile credential. Their contents cannot be classified reliably after
    /// the profile is edited or removed, so discard the bounded diagnostic
    /// history once instead of carrying a potentially exportable secret forward.
    private func migrateLegacyLogStateIfNeeded(_ data: inout HopAppData) -> Bool {
        guard (data.schemaVersion ?? 0) < HopAppData.currentSchemaVersion else {
            return false
        }

        data.logs.removeAll()
        data.extensionLogCursor = nil
        data.schemaVersion = HopAppData.currentSchemaVersion
        do {
            try sharedLogStore.clear()
            data.legacyExtensionLogPurgePending = nil
        } catch {
            NSLog("Hop: unable to clear legacy tunnel logs during migration")
            data.legacyExtensionLogPurgePending = true
        }
        return true
    }

    @discardableResult
    func save(_ data: HopAppData) -> Bool {
        write(data, reason: .save)
    }

    /// Invoked only after the user explicitly confirms replacement. Commit the
    /// fresh envelope before pruning any credentials from the rejected library.
    func resetUnreadableLibrary(legacyExtensionLogPurgePending: Bool) -> Bool {
        secretWriteCache.invalidate()
        return write(HopAppData(
            profiles: [], groups: [], subscriptions: [], routingMode: .rule,
            selectedTarget: nil, settings: .defaults, logs: [],
            ruleConfigurations: RuleConfiguration.builtInConfigurations,
            activeRuleConfigurationID: RuleConfiguration.defaultConfiguration.id,
            legacyExtensionLogPurgePending: legacyExtensionLogPurgePending ? true : nil,
        ), reason: .reset)
    }

    private enum WriteReason { case save, adoptLegacyLibrary, reset }

    private func write(_ data: HopAppData, reason: WriteReason) -> Bool {
        do {
            let isFirstCommit = !FileManager.default.fileExists(atPath: url.path)
            if reason == .save, isFirstCommit {
                try prepareEmptyLibrary()
            }
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            let secretItems = Dictionary(data.profiles.flatMap(\.keychainSecretItems) + data.subscriptions.compactMap(\.keychainURLItem), uniquingKeysWith: { _, last in last })
            let snapshot = secretWriteCache.prepare(secretItems)
            var redacted = data
            redacted.profiles = data.profiles.map { $0.redactingSecrets() }
            _ = removeLegacyVMessCipherCredentials(&redacted)
            redacted.subscriptions = data.subscriptions.map { $0.redactingSecrets() }
            redacted.secretGeneration = snapshot.generation
            redacted.secretKeys = secretItems.keys.sorted()
            let encoded = try JSONEncoder.hop.encode(redacted)
            guard encoded.count <= maximumFileBytes else { throw CocoaError(.fileWriteOutOfSpace) }
            let secret = try prepareAuthenticationSecret(replacingUnreadableLibrary: reason == .reset)
            guard let signature = TunnelConfigAuthenticator.signature(for: encoded, secret: secret) else {
                throw CocoaError(.fileWriteUnknown)
            }
            let envelope = try JSONEncoder().encode(AppStateEnvelope(payload: encoded, signature: signature))
            guard envelope.count <= maximumFileBytes else { throw CocoaError(.fileWriteOutOfSpace) }
            let generationKeys = Set(secretItems.keys.map { Self.snapshotKey($0, generation: snapshot.generation) })
            if snapshot.needsWrite {
                // Never overwrite the old generation: a failed write or process
                // termination must leave the previous state AND its secrets usable.
                if reason == .save, isFirstCommit, !secretItems.isEmpty {
                    try Data(snapshot.generation.uuidString.utf8).write(to: initialCommitURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
                }
                for (key, value) in secretItems {
                    guard secretStore.setValue(value, forKey: Self.snapshotKey(key, generation: snapshot.generation)) else {
                        throw CocoaError(.fileWriteUnknown)
                    }
                }
            }
            try envelope.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            if isFirstCommit {
                try? FileManager.default.removeItem(at: initialCommitURL)
            }
            // Mirror stable compatibility aliases only after the authenticated
            // state points at its complete immutable snapshot. Tunnel starts
            // use separate nonce-scoped runtime snapshots.
            if snapshot.needsWrite,
               !secretStore.replaceAll(with: secretItems.map { (key: $0.key, value: $0.value) }, preservingKeys: generationKeys)
            {
                throw CocoaError(.fileWriteUnknown)
            }
            try? FileManager.default.removeItem(at: signatureURL)
            return true
        } catch {
            secretWriteCache.invalidate()
            NSLog("Hop: unable to persist app state; retry required (code %ld)", (error as NSError).code)
            return false
        }
    }

    static func snapshotKey(_ key: String, generation: UUID) -> String {
        "app-state.\(generation.uuidString).\(key)"
    }

    private var signatureURL: URL {
        TunnelConfigAuthenticator.signatureURL(forConfigURL: url)
    }

    private var initialCommitURL: URL {
        url.appendingPathExtension("initial-generation")
    }

    /// Interrupted first saves can leave staged accounts without an envelope.
    /// Only clean the generation journaled here, never another installation's.
    private func prepareEmptyLibrary() throws {
        let marker = try TunnelConfigAuthenticator.readRegularFileIfPresent(at: initialCommitURL, limit: 36)
        let generation = marker.flatMap { UUID(uuidString: String(decoding: $0, as: UTF8.self)) }
        try secretStore.prepareEmptyLibrary(retryingGenerationPrefix: generation.map { Self.snapshotKey("", generation: $0) })
    }

    private static let pendingAuthenticationKey = "pending-app-state-authentication-key"

    /// Bootstrap unsigned legacy state without stranding it between creating the
    /// first authentication key and committing its replacement. A pending key
    /// lets the next launch finish an interrupted sidecar/key handoff.
    @discardableResult
    private func prepareAuthenticationSecret(replacingUnreadableLibrary: Bool = false) throws -> String {
        if let existing = try authenticationStore.readValue(forKey: SecretStore.appStateAuthenticationKey), !existing.isEmpty {
            return existing
        }
        if replacingUnreadableLibrary {
            return try storeAuthenticationSecret(SecretStore.randomSecret())
        }
        let previous = try readState(at: url)
        let pending = try authenticationStore.readValue(forKey: Self.pendingAuthenticationKey)
        let secret = pending ?? SecretStore.randomSecret()
        if let previous {
            guard (try? JSONDecoder.hop.decode(HopAppData.self, from: previous)) != nil else {
                throw CocoaError(.fileReadNoPermission)
            }
            if let sidecar = try readLegacySignature() {
                let signature = String(decoding: sidecar, as: UTF8.self)
                guard pending != nil, TunnelConfigAuthenticator.isValidSignature(signature, for: previous, secret: secret) else {
                    throw CocoaError(.fileReadNoPermission)
                }
            } else {
                guard authenticationStore.setValue(secret, forKey: Self.pendingAuthenticationKey),
                      let signature = TunnelConfigAuthenticator.signature(for: previous, secret: secret)
                else {
                    throw CocoaError(.fileWriteUnknown)
                }
                try Data(signature.utf8).write(to: signatureURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            }
        }
        return try storeAuthenticationSecret(secret)
    }

    private func storeAuthenticationSecret(_ secret: String) throws -> String {
        guard authenticationStore.setValue(secret, forKey: SecretStore.appStateAuthenticationKey),
              try authenticationStore.readValue(forKey: SecretStore.appStateAuthenticationKey) == secret
        else {
            throw CocoaError(.fileWriteUnknown)
        }
        authenticationStore.removeValue(forKey: Self.pendingAuthenticationKey)
        return secret
    }

    private func readState(at location: URL) throws -> Data? {
        try TunnelConfigAuthenticator.readRegularFileIfPresent(at: location, limit: maximumFileBytes)
    }

    private func readLegacySignature() throws -> Data? {
        try TunnelConfigAuthenticator.readRegularFileIfPresent(at: signatureURL, limit: Self.maximumLegacyMACBytes)
    }
}

/// Remembers the secret set most recently handed to `SecretStore.replaceAll`
/// so unchanged saves can skip the Keychain entirely. A reference type shared
/// across value copies of `HopAppDataStore`; saves are serialized on
/// `HopStore`'s persist queue, and the lock covers the one load-time migration
/// save that runs before that queue is in play.
private final class SecretWriteCache: @unchecked Sendable {
    private let lock = NSLock()
    private var lastWritten: [String: Data]?
    private var generation = UUID()

    /// Records `items` as the latest intended Keychain state and reports
    /// whether they differ from the previous write (always true for the first).
    func prepare(_ items: [String: String]) -> (generation: UUID, needsWrite: Bool) {
        let bytes = items.mapValues { Data($0.utf8) }
        lock.lock()
        defer { lock.unlock() }
        if lastWritten == bytes {
            return (generation, false)
        }
        lastWritten = bytes
        generation = UUID()
        return (generation, true)
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
