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
            lines.append("Removed \(removedRuleCount) rule(s) that referenced removed nodes or groups.")
        }
        if !blockedTLSProfileNames.isEmpty {
            lines.append("These nodes must be edited before connecting because Xray does not accept allowInsecure: \(blockedTLSProfileNames.joined(separator: ", ")).")
        }
        if let blockedAdvancedTLSProfileNames, !blockedAdvancedTLSProfileNames.isEmpty {
            lines.append("These nodes retain advanced TLS trust-policy fields that could not be migrated safely and must be reviewed before connecting: \(blockedAdvancedTLSProfileNames.joined(separator: ", ")).")
        }
        if let disabledLegacySubscriptionGroupNames, !disabledLegacySubscriptionGroupNames.isEmpty {
            lines.append("Disabled legacy imported groups, groups that depended on them, and removed dynamic targets that could retarget across sources: \(disabledLegacySubscriptionGroupNames.joined(separator: ", ")). Review their remaining members before enabling them.")
        }
        if let clearedLegacySelectionName {
            lines.append("Cleared the legacy selection \(clearedLegacySelectionName) because its subscription ownership could not be proven. Select a reviewed outbound before connecting.")
        }
        if requiresLegacyRoutingReview == true {
            lines.append("Custom legacy routing rules may have come from a subscription. They were preserved for review, and Rule mode was not allowed to remain active.")
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
        legacyExtensionLogPurgePending: Bool? = nil,
        pendingXrayMigrationReport: XrayMigrationReport? = nil,
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
    var sharedLogStore: SharedTunnelLogStore
    /// Shared across value copies of this store; see `SecretWriteCache`.
    private let secretWriteCache = SecretWriteCache()

    init(
        url: URL = RuntimeEnvironment.stateFileURL,
        secretStore: SecretStore = .shared,
        authenticationStore: SecretStore = .runtime,
        sharedLogStore: SharedTunnelLogStore = SharedTunnelLogStore(),
    ) {
        self.url = url
        self.secretStore = secretStore
        self.authenticationStore = authenticationStore
        self.sharedLogStore = sharedLogStore
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
        // Must run while the state is still pre-v3: legacy groups had no
        // subscriptionID field and legacy rules had no provenance.
        let didMigrateSubscriptionProvenance = migrateSubscriptionProvenanceIfNeeded(&decoded)
        let didMigrateAdvancedTLS = migrateAdvancedTLSIfNeeded(&decoded)
        let didMigrateLegacyLogState = migrateLegacyLogStateIfNeeded(&decoded)

        // Legacy/plaintext state (written before Keychain migration for
        // profiles, or before subscription URLs were treated as bearer
        // secrets) still carries inline values — detect that so we can migrate
        // it in place.
        let hadInlineProfileSecrets = decoded.profiles.contains { !$0.keychainSecretItems.isEmpty }
        let hadInlineSubscriptionURLs = decoded.subscriptions.contains { !$0.url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        decoded.profiles = decoded.profiles.map { $0.hydratingSecrets(from: secretStore) }
        decoded.subscriptions = decoded.subscriptions.map { $0.hydratingSecrets(from: secretStore) }
        if !hadAuthenticationSecret || hadInlineProfileSecrets || hadInlineSubscriptionURLs || didMigrateToXray || didMigrateSubscriptionProvenance || didMigrateAdvancedTLS || didMigrateLegacyLogState {
            save(decoded) // move secrets to the Keychain and rewrite the JSON without them
        }
        return decoded
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
            group.warning = "Legacy imported group disabled for routing review."
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
            group.warning = "Group disabled because it depends on a legacy imported group that requires routing review."
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
