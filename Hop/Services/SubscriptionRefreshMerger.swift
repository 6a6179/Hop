import Foundation

/// How a subscription refresh handles settings that authenticate the remote
/// endpoint or set the minimum transport-security posture.
enum SubscriptionRefreshSecurityPolicy: Equatable {
    /// Used by automatic refreshes and unreviewed merge paths. Imported values
    /// are retained in the fetched result, but the stored profile keeps the
    /// existing security-critical values.
    case preserveExisting
    /// Used only after the manual-refresh confirmation has shown the detected
    /// changes to the user.
    case applyReviewedChanges
}

/// A concise, non-secret description of security-critical changes in one
/// matched subscription profile. Profile names are sanitized before display.
struct SubscriptionSecurityChange: Hashable, Identifiable {
    enum Field: String, Hashable {
        case securityLayer = "TLS/REALITY layer"
        case tlsServerName = "TLS server name"
        case tlsClientFingerprint = "TLS client fingerprint"
        case tlsMinimumVersion = "minimum TLS version"
        case tlsMaximumVersion = "maximum TLS version"
        case tlsCipherSuites = "TLS cipher suites"
        case certificatePins = "certificate pins"
        case verificationNames = "certificate verification names"
        case ech = "ECH"
        case postQuantumCurves = "post-quantum TLS curves"
        case finalMaskTransportPolicy = "FinalMask transport policy"
        case vlessEncryption = "VLESS Encryption/Auth"
        case realityPublicKey = "REALITY public key"
        case realityMLDSA = "REALITY ML-DSA-65 verification"
    }

    let profileName: String
    let fields: [Field]

    var id: String {
        profileName + "\u{0}" + fields.map(\.rawValue).joined(separator: "\u{0}")
    }

    var summary: String {
        "\(profileName): \(fields.map(\.rawValue).joined(separator: ", "))"
    }
}

/// Merges a refreshed subscription's profiles and groups into the existing
/// collections, updating matching items in place — keeping their stable IDs so
/// group members, routing rules, and the selected target stay valid — instead
/// of appending duplicates.
///
/// Matching is two-tier: exact identity (everything but the ID) first, then
/// same-subscription name + protocol, so a node whose host or credentials
/// changed is still recognized as the same logical node without letting a
/// provider overwrite unrelated/manual nodes. When several existing items
/// match, the selected one is preferred, then one referenced by a group, and
/// surviving duplicates are collapsed with their references remapped.
///
/// Operates on value copies: every mutation of `HopStore.profiles`/`groups`
/// triggers a full state persist and Keychain rewrite, so the store applies a
/// merge with one assignment per collection rather than one per imported item.
struct SubscriptionRefreshMerger {
    private(set) var profiles: [ProxyProfile]
    private(set) var groups: [ProxyGroup]
    private(set) var selectedTarget: OutboundTarget?
    private(set) var removedProfileIDs: Set<ProxyProfile.ID> = []
    private(set) var removedGroupIDs: Set<ProxyGroup.ID> = []
    private(set) var profileIDReplacements: [ProxyProfile.ID: ProxyProfile.ID] = [:]
    private(set) var groupIDReplacements: [ProxyGroup.ID: ProxyGroup.ID] = [:]
    /// Human-readable notes for security settings an unreviewed merge refused
    /// to change; the store surfaces these in the app log after a refresh.
    private(set) var securityDowngradeWarnings: [String] = []

    mutating func merge(
        _ result: ImportResult,
        securityPolicy: SubscriptionRefreshSecurityPolicy = .preserveExisting,
        replacingSnapshotFor subscriptionID: SubscriptionSource.ID? = nil,
    ) {
        let profilesBeforeRefresh = profiles
        let groupsBeforeRefresh = groups
        let selectedTargetBeforeRefresh = selectedTarget
        removedProfileIDs = []
        removedGroupIDs = []
        profileIDReplacements = [:]
        groupIDReplacements = [:]
        let profileIDMap = mergeProfiles(result.profiles, securityPolicy: securityPolicy)
        let groupIDMap = mergeGroups(result.groups, importedProfileIDMap: profileIDMap)
        if let subscriptionID {
            reconcileSnapshot(
                subscriptionID: subscriptionID,
                retainedProfileIDs: Set(profileIDMap.values),
                retainedGroupIDs: Set(groupIDMap.values),
            )
        }
        invalidateGroupsWithChangedRouting(
            profilesBeforeRefresh: profilesBeforeRefresh,
            groupsBeforeRefresh: groupsBeforeRefresh,
            selectedTargetBeforeRefresh: selectedTargetBeforeRefresh,
        )
    }

    /// Detects manual-review fields using the same match-preference rules as
    /// the merge. New nodes are not "changes"; their separate allow-insecure
    /// gate remains responsible for legacy insecure imports.
    func securityCriticalChanges(in importedProfiles: [ProxyProfile]) -> [SubscriptionSecurityChange] {
        let referencedProfileIDs = referencedProfileIDs()
        let exactIdentities = Set(profiles.map(SubscriptionProfileRefreshIdentity.init))
        var indicesByNameAndProtocol: [NameAndProtocol: [Int]] = [:]
        for index in profiles.indices where profiles[index].subscriptionID != nil {
            indicesByNameAndProtocol[NameAndProtocol(profiles[index]), default: []].append(index)
        }
        var preferredByNameAndProtocol: [NameAndProtocol: Int] = [:]
        for (key, indices) in indicesByNameAndProtocol {
            preferredByNameAndProtocol[key] = preferredProfileIndex(
                from: indices,
                referencedProfileIDs: referencedProfileIDs,
            )
        }
        return importedProfiles.compactMap { importedProfile in
            guard !exactIdentities.contains(SubscriptionProfileRefreshIdentity(importedProfile)),
                  importedProfile.subscriptionID != nil,
                  let profileIndex = preferredByNameAndProtocol[NameAndProtocol(importedProfile)]
            else {
                return nil
            }

            let fields = Self.securityCriticalFields(
                existing: profiles[profileIndex],
                imported: importedProfile,
            )
            guard !fields.isEmpty else { return nil }
            return SubscriptionSecurityChange(
                profileName: ImportPolicy.sanitizeImportedName(importedProfile.name, fallback: "Imported Node"),
                fields: fields,
            )
        }
    }

    /// Names of imported nodes that would *newly* disable TLS certificate
    /// verification if this refresh were applied: allow-insecure nodes with no
    /// exact or same-subscription name+protocol match among the existing
    /// profiles. A matched node is never newly insecure — if the existing
    /// profile is already insecure nothing changes, and if it is secure
    /// the merge security policy blocks the flip (and logs the refusal).
    /// Only genuinely new nodes are inserted verbatim, so refresh flows must
    /// run the blocking insecure-TLS confirmation for these, same as initial
    /// imports (see the AGENTS.md import-gate invariant).
    static func newInsecureProfileNames(existing: [ProxyProfile], imported: [ProxyProfile]) -> [String] {
        let exactIdentities = Set(existing.map(SubscriptionProfileRefreshIdentity.init))
        let ownedNamesAndProtocols = Set(existing.compactMap {
            $0.subscriptionID == nil ? nil : NameAndProtocol($0)
        })
        return imported
            .filter { $0.security.tls?.allowInsecure == true }
            .filter { profile in
                !exactIdentities.contains(SubscriptionProfileRefreshIdentity(profile)) &&
                    (profile.subscriptionID == nil || !ownedNamesAndProtocols.contains(NameAndProtocol(profile)))
            }
            .map { ImportPolicy.sanitizeImportedName($0.name, fallback: "Imported Node") }
    }

    // MARK: - Profiles

    private mutating func mergeProfiles(
        _ importedProfiles: [ProxyProfile],
        securityPolicy: SubscriptionRefreshSecurityPolicy,
    ) -> [ProxyProfile.ID: ProxyProfile.ID] {
        var importedProfileIDMap: [ProxyProfile.ID: ProxyProfile.ID] = [:]
        var indicesByIdentity: [SubscriptionProfileRefreshIdentity: [Int]] = [:]
        var indicesByNameAndProtocol: [NameAndProtocol: [Int]] = [:]
        var insertedProfileIDs: Set<ProxyProfile.ID> = []
        var removedIndices: Set<Int> = []
        // Groups don't change while profiles merge, so the set of
        // group-referenced profile IDs is computed once for all candidates.
        let referencedProfileIDs = referencedProfileIDs()
        for index in profiles.indices {
            indicesByIdentity[SubscriptionProfileRefreshIdentity(profiles[index]), default: []].append(index)
            if profiles[index].subscriptionID != nil {
                indicesByNameAndProtocol[NameAndProtocol(profiles[index]), default: []].append(index)
            }
        }
        var preferredByNameAndProtocol: [NameAndProtocol: Int] = [:]
        for (key, indices) in indicesByNameAndProtocol {
            preferredByNameAndProtocol[key] = preferredProfileIndex(
                from: indices,
                referencedProfileIDs: referencedProfileIDs,
            )
        }

        for importedProfile in importedProfiles {
            let importedIdentity = SubscriptionProfileRefreshIdentity(importedProfile)
            let nameAndProtocol = NameAndProtocol(importedProfile)
            let exactMatches = indicesByIdentity[importedIdentity] ?? []
            let profileIndex = exactMatches.isEmpty
                ? (importedProfile.subscriptionID == nil ? nil : preferredByNameAndProtocol[nameAndProtocol])
                : preferredProfileIndex(from: exactMatches, referencedProfileIDs: referencedProfileIDs)

            if let profileIndex {
                let existingProfile = profiles[profileIndex]
                var updatedProfile = importedProfile
                updatedProfile.id = existingProfile.id
                // Advanced JSON is a local expert override, not subscription
                // data. A matched refresh may update typed provider fields but
                // must never erase or replace the user's local overlay.
                updatedProfile.xrayAdvanced = existingProfile.xrayAdvanced
                // A name-matched update comes from the subscription server.
                // Automatic/unreviewed merges keep every security-critical
                // value; a manual confirmation may opt into the reviewed
                // values. allowInsecure is never allowed to flip on.
                if exactMatches.isEmpty {
                    updatedProfile = applyingSecurityPolicy(
                        existing: existingProfile,
                        imported: updatedProfile,
                        policy: securityPolicy,
                    )
                }

                let existingIdentity = SubscriptionProfileRefreshIdentity(existingProfile)
                let updatedIdentity = SubscriptionProfileRefreshIdentity(updatedProfile)
                if existingIdentity != updatedIdentity {
                    indicesByIdentity[existingIdentity]?.removeAll { $0 == profileIndex }
                    indicesByIdentity[updatedIdentity, default: []].append(profileIndex)
                }
                profiles[profileIndex] = updatedProfile
                importedProfileIDMap[importedProfile.id] = updatedProfile.id
                preferredByNameAndProtocol[nameAndProtocol] = profileIndex

                if !exactMatches.isEmpty {
                    let duplicateIndices = exactMatches.filter { $0 != profileIndex }
                    for duplicateIndex in duplicateIndices {
                        profileIDReplacements[profiles[duplicateIndex].id] = updatedProfile.id
                    }
                    removedIndices.formUnion(duplicateIndices)
                    indicesByIdentity[importedIdentity] = [profileIndex]
                    indicesByNameAndProtocol[nameAndProtocol]?.removeAll { removedIndices.contains($0) }
                }
            } else {
                let index = profiles.endIndex
                profiles.append(importedProfile)
                insertedProfileIDs.insert(importedProfile.id)
                indicesByIdentity[importedIdentity, default: []].append(index)
                if importedProfile.subscriptionID != nil {
                    indicesByNameAndProtocol[nameAndProtocol, default: []].append(index)
                    preferredByNameAndProtocol[nameAndProtocol] = index
                }
                importedProfileIDMap[importedProfile.id] = importedProfile.id
            }
        }

        if !profileIDReplacements.isEmpty {
            for id in Array(profileIDReplacements.keys) {
                profileIDReplacements[id] = resolvedReplacement(
                    for: profileIDReplacements[id] ?? id,
                    in: profileIDReplacements,
                )
            }
            let removedIDs = Set(profileIDReplacements.keys)
            profiles.removeAll { removedIDs.contains($0.id) }
            replaceTargetReferences(profileIDMap: profileIDReplacements)
        }
        for id in Array(importedProfileIDMap.keys) {
            importedProfileIDMap[id] = resolvedReplacement(
                for: importedProfileIDMap[id] ?? id,
                in: profileIDReplacements,
            )
        }
        if !insertedProfileIDs.isEmpty {
            let inserted = profiles.filter { insertedProfileIDs.contains($0.id) }
            profiles = Array(inserted.reversed()) + profiles.filter { !insertedProfileIDs.contains($0.id) }
        }

        return importedProfileIDMap
    }

    private mutating func applyingSecurityPolicy(
        existing: ProxyProfile,
        imported: ProxyProfile,
        policy: SubscriptionRefreshSecurityPolicy,
    ) -> ProxyProfile {
        var updated = imported
        var security = imported.security

        // Xray v26.6.27 rejects allowInsecure. Keep a legacy imported value only
        // on a genuinely new node (behind the existing import gate); a matched
        // secure node can never be flipped, even after another change was
        // reviewed.
        if existing.security.tls?.allowInsecure != true, security.tls?.allowInsecure == true {
            security.tls?.allowInsecure = false
            securityDowngradeWarnings.append(
                "Refresh tried to disable TLS certificate verification for \(imported.name); kept verification enabled.",
            )
        }

        guard policy == .preserveExisting else {
            updated.security = security
            return updated
        }

        if security.layer != existing.security.layer {
            securityDowngradeWarnings.append(
                "Refresh changed \(imported.name) from \(existing.security.layer.displayName) to \(security.layer.displayName); kept the existing security layer until it is reviewed manually.",
            )
            security = existing.security
        } else {
            preserveSecurityCriticalTLS(existing: existing, importedName: imported.name, security: &security)
            preserveSecurityCriticalReality(existing: existing, importedName: imported.name, security: &security)
        }

        if case let .vless(existingOptions) = existing.options,
           case let .vless(currentImportedOptions) = updated.options,
           currentImportedOptions.normalizedEncryption != existingOptions.normalizedEncryption
        {
            var importedOptions = currentImportedOptions
            importedOptions.encryption = existingOptions.encryption
            updated.options = .vless(importedOptions)
            securityDowngradeWarnings.append(
                "Refresh changed or removed VLESS Encryption/Auth for \(imported.name); kept the existing value.",
            )
        }

        if existing.transport.finalMask != imported.transport.finalMask {
            updated.transport.finalMask = existing.transport.finalMask
            securityDowngradeWarnings.append(
                "Refresh changed FinalMask transport policy for \(imported.name); kept the existing value until it is reviewed manually.",
            )
        }

        updated.security = security
        return updated
    }

    private mutating func preserveSecurityCriticalTLS(
        existing: ProxyProfile,
        importedName: String,
        security: inout ProxySecurity,
    ) {
        let existingTLS = existing.security.tls
        guard var importedTLS = security.tls else {
            guard existingTLS != nil else { return }
            security.tls = existingTLS
            securityDowngradeWarnings.append(
                "Refresh removed TLS verification settings for \(importedName); kept the existing values.",
            )
            return
        }

        func preservingString(
            _ existingValue: String?,
            _ importedValue: inout String?,
            label: String,
        ) {
            guard Self.normalizedOptional(existingValue) != Self.normalizedOptional(importedValue) else { return }
            importedValue = existingValue
            securityDowngradeWarnings.append(
                "Refresh changed or removed \(label) for \(importedName); kept the existing value.",
            )
        }

        preservingString(existingTLS?.pinnedPeerCertSHA256, &importedTLS.pinnedPeerCertSHA256, label: "certificate pins")
        preservingString(existingTLS?.verifyPeerCertByName, &importedTLS.verifyPeerCertByName, label: "certificate verification names")
        preservingString(existingTLS?.echConfigList, &importedTLS.echConfigList, label: "ECH")
        preservingString(existingTLS?.serverName, &importedTLS.serverName, label: "TLS server name")
        preservingString(existingTLS?.utlsFingerprint, &importedTLS.utlsFingerprint, label: "TLS client fingerprint")
        preservingString(existingTLS?.maxVersion, &importedTLS.maxVersion, label: "maximum TLS version")
        preservingString(existingTLS?.cipherSuites, &importedTLS.cipherSuites, label: "TLS cipher suites")

        if Self.postQuantumCurves(existingTLS?.curvePreferences ?? []) != Self.postQuantumCurves(importedTLS.curvePreferences) {
            importedTLS.curvePreferences = existingTLS?.curvePreferences ?? []
            securityDowngradeWarnings.append(
                "Refresh changed post-quantum TLS curves for \(importedName); kept the existing curves.",
            )
        }

        if Self.normalizedOptional(importedTLS.minVersion) != Self.normalizedOptional(existingTLS?.minVersion) {
            importedTLS.minVersion = existingTLS?.minVersion
            securityDowngradeWarnings.append(
                "Refresh changed the minimum TLS version for \(importedName); kept the existing minimum.",
            )
        }
        security.tls = importedTLS
    }

    private mutating func preserveSecurityCriticalReality(
        existing: ProxyProfile,
        importedName: String,
        security: inout ProxySecurity,
    ) {
        guard let existingReality = existing.security.reality else { return }
        guard var importedReality = security.reality else {
            security.reality = existingReality
            securityDowngradeWarnings.append(
                "Refresh removed REALITY authentication for \(importedName); kept the existing values.",
            )
            return
        }

        if Self.normalizedOptional(importedReality.publicKey) != Self.normalizedOptional(existingReality.publicKey) {
            importedReality.publicKey = existingReality.publicKey
            securityDowngradeWarnings.append(
                "Refresh changed the REALITY public key for \(importedName); kept the existing key until it is reviewed manually.",
            )
        }
        if Self.normalizedOptional(importedReality.mldsa65Verify) != Self.normalizedOptional(existingReality.mldsa65Verify) {
            importedReality.mldsa65Verify = existingReality.mldsa65Verify
            securityDowngradeWarnings.append(
                "Refresh changed REALITY ML-DSA-65 verification for \(importedName); kept the existing value until it is reviewed manually.",
            )
        }
        if Self.normalizedOptional(importedReality.serverName) != Self.normalizedOptional(existingReality.serverName) {
            importedReality.serverName = existingReality.serverName
            securityDowngradeWarnings.append(
                "Refresh changed the REALITY server name for \(importedName); kept the existing value until it is reviewed manually.",
            )
        }
        if Self.normalizedOptional(importedReality.utlsFingerprint) != Self.normalizedOptional(existingReality.utlsFingerprint) {
            importedReality.utlsFingerprint = existingReality.utlsFingerprint
            securityDowngradeWarnings.append(
                "Refresh changed the REALITY client fingerprint for \(importedName); kept the existing value until it is reviewed manually.",
            )
        }
        security.reality = importedReality
    }

    private static func securityCriticalFields(existing: ProxyProfile, imported: ProxyProfile) -> [SubscriptionSecurityChange.Field] {
        var fields: [SubscriptionSecurityChange.Field] = []
        if existing.security.layer != imported.security.layer {
            fields.append(.securityLayer)
        }

        func appendTLSChange(_ existingValue: String?, _ importedValue: String?, field: SubscriptionSecurityChange.Field) {
            if normalizedOptional(existingValue) != normalizedOptional(importedValue) {
                fields.append(field)
            }
        }

        appendTLSChange(existing.security.tls?.serverName, imported.security.tls?.serverName, field: .tlsServerName)
        appendTLSChange(existing.security.tls?.utlsFingerprint, imported.security.tls?.utlsFingerprint, field: .tlsClientFingerprint)
        appendTLSChange(existing.security.tls?.minVersion, imported.security.tls?.minVersion, field: .tlsMinimumVersion)
        appendTLSChange(existing.security.tls?.maxVersion, imported.security.tls?.maxVersion, field: .tlsMaximumVersion)
        appendTLSChange(existing.security.tls?.cipherSuites, imported.security.tls?.cipherSuites, field: .tlsCipherSuites)
        if normalizedOptional(existing.security.tls?.pinnedPeerCertSHA256) != normalizedOptional(imported.security.tls?.pinnedPeerCertSHA256) {
            fields.append(.certificatePins)
        }
        if normalizedOptional(existing.security.tls?.verifyPeerCertByName) != normalizedOptional(imported.security.tls?.verifyPeerCertByName) {
            fields.append(.verificationNames)
        }
        if normalizedOptional(existing.security.tls?.echConfigList) != normalizedOptional(imported.security.tls?.echConfigList) {
            fields.append(.ech)
        }
        if postQuantumCurves(existing.security.tls?.curvePreferences ?? []) != postQuantumCurves(imported.security.tls?.curvePreferences ?? []) {
            fields.append(.postQuantumCurves)
        }
        if existing.transport.finalMask != imported.transport.finalMask {
            fields.append(.finalMaskTransportPolicy)
        }

        if case let .vless(existingOptions) = existing.options,
           case let .vless(importedOptions) = imported.options,
           existingOptions.normalizedEncryption != importedOptions.normalizedEncryption
        {
            fields.append(.vlessEncryption)
        }
        if normalizedOptional(existing.security.reality?.publicKey) != normalizedOptional(imported.security.reality?.publicKey) {
            fields.append(.realityPublicKey)
        }
        if normalizedOptional(existing.security.reality?.mldsa65Verify) != normalizedOptional(imported.security.reality?.mldsa65Verify) {
            fields.append(.realityMLDSA)
        }
        if normalizedOptional(existing.security.reality?.serverName) != normalizedOptional(imported.security.reality?.serverName),
           !fields.contains(.tlsServerName)
        {
            fields.append(.tlsServerName)
        }
        if normalizedOptional(existing.security.reality?.utlsFingerprint) != normalizedOptional(imported.security.reality?.utlsFingerprint),
           !fields.contains(.tlsClientFingerprint)
        {
            fields.append(.tlsClientFingerprint)
        }
        return fields
    }

    private static func isPostQuantumCurve(_ value: String) -> Bool {
        let value = value.lowercased()
        return value.contains("mlkem") || value.contains("kyber")
    }

    private static func postQuantumCurves(_ values: [String]) -> [String] {
        values
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            .filter { isPostQuantumCurve($0) }
    }

    private static func normalizedOptional(_ value: String?) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private func preferredProfileIndex(from indices: [Int], referencedProfileIDs: Set<ProxyProfile.ID>) -> Int? {
        guard !indices.isEmpty else {
            return nil
        }
        if case let .profile(selectedID) = selectedTarget,
           let selectedIndex = indices.first(where: { profiles[$0].id == selectedID })
        {
            return selectedIndex
        }
        if let referencedIndex = indices.first(where: { referencedProfileIDs.contains(profiles[$0].id) }) {
            return referencedIndex
        }
        return indices.first
    }

    private func referencedProfileIDs() -> Set<ProxyProfile.ID> {
        Set(groups.flatMap { group in
            group.members.compactMap { target in
                if case let .profile(id) = target {
                    return id
                }
                return nil
            }
        })
    }

    // MARK: - Groups

    private mutating func mergeGroups(
        _ importedGroups: [ProxyGroup],
        importedProfileIDMap: [ProxyProfile.ID: ProxyProfile.ID],
    ) -> [ProxyGroup.ID: ProxyGroup.ID] {
        var importedGroupIDMap: [ProxyGroup.ID: ProxyGroup.ID] = [:]
        var indicesByIdentity: [SubscriptionGroupRefreshIdentity: [Int]] = [:]
        var insertedGroupIDs: Set<ProxyGroup.ID> = []
        var groupReferenceCounts: [ProxyGroup.ID: Int] = [:]

        func adjustReferences(in group: ProxyGroup, by delta: Int) {
            for member in group.members {
                guard case let .group(id) = member else { continue }
                let count = (groupReferenceCounts[id] ?? 0) + delta
                groupReferenceCounts[id] = count > 0 ? count : nil
            }
        }

        for index in groups.indices {
            if let identity = SubscriptionGroupRefreshIdentity(groups[index]) {
                indicesByIdentity[identity, default: []].append(index)
            }
            adjustReferences(in: groups[index], by: 1)
        }

        for importedGroup in importedGroups.map({ remappedGroup($0, profileIDMap: importedProfileIDMap, groupIDMap: [:]) }) {
            let identity = SubscriptionGroupRefreshIdentity(importedGroup)
            let matchingIndices = identity.flatMap { indicesByIdentity[$0] } ?? []

            if let groupIndex = preferredGroupIndex(
                from: matchingIndices,
                referenceCounts: groupReferenceCounts,
            ) {
                adjustReferences(in: groups[groupIndex], by: -1)
                let existingGroup = groups[groupIndex]
                var updatedGroup = importedGroup
                updatedGroup.id = existingGroup.id
                updatedGroup.isEnabled = existingGroup.isEnabled
                updatedGroup.warning = existingGroup.warning
                updatedGroup.lastLatencyMilliseconds = existingGroup.lastLatencyMilliseconds
                groups[groupIndex] = updatedGroup
                adjustReferences(in: updatedGroup, by: 1)
                importedGroupIDMap[importedGroup.id] = updatedGroup.id

                let duplicateIndices = matchingIndices.filter { $0 != groupIndex }
                for duplicateIndex in duplicateIndices {
                    adjustReferences(in: groups[duplicateIndex], by: -1)
                    groupIDReplacements[groups[duplicateIndex].id] = updatedGroup.id
                }
                if let identity {
                    indicesByIdentity[identity] = [groupIndex]
                }
            } else {
                let index = groups.endIndex
                groups.append(importedGroup)
                insertedGroupIDs.insert(importedGroup.id)
                adjustReferences(in: importedGroup, by: 1)
                if let identity {
                    indicesByIdentity[identity, default: []].append(index)
                }
                importedGroupIDMap[importedGroup.id] = importedGroup.id
            }
        }

        if !groupIDReplacements.isEmpty {
            for id in Array(groupIDReplacements.keys) {
                groupIDReplacements[id] = resolvedReplacement(
                    for: groupIDReplacements[id] ?? id,
                    in: groupIDReplacements,
                )
            }
            let removedIDs = Set(groupIDReplacements.keys)
            groups.removeAll { removedIDs.contains($0.id) }
        }
        for id in Array(importedGroupIDMap.keys) {
            importedGroupIDMap[id] = resolvedReplacement(
                for: importedGroupIDMap[id] ?? id,
                in: groupIDReplacements,
            )
        }
        if !insertedGroupIDs.isEmpty {
            let inserted = groups.filter { insertedGroupIDs.contains($0.id) }
            groups = Array(inserted.reversed()) + groups.filter { !insertedGroupIDs.contains($0.id) }
        }
        if !importedGroupIDMap.isEmpty || !groupIDReplacements.isEmpty {
            replaceTargetReferences(groupIDMap: importedGroupIDMap.merging(groupIDReplacements) { current, _ in current })
        }
        return importedGroupIDMap
    }

    /// A subscription response is a complete source-owned snapshot. Remove
    /// objects the same source no longer returned, while leaving manual and
    /// other-source state untouched and repairing every ID-based reference.
    private mutating func reconcileSnapshot(
        subscriptionID: SubscriptionSource.ID,
        retainedProfileIDs: Set<ProxyProfile.ID>,
        retainedGroupIDs: Set<ProxyGroup.ID>,
    ) {
        removedProfileIDs = Set(profiles.lazy.filter {
            $0.subscriptionID == subscriptionID && !retainedProfileIDs.contains($0.id)
        }.map(\.id))
        removedGroupIDs = Set(groups.lazy.filter {
            $0.subscriptionID == subscriptionID && !retainedGroupIDs.contains($0.id)
        }.map(\.id))
        profiles.removeAll { removedProfileIDs.contains($0.id) }
        groups.removeAll { removedGroupIDs.contains($0.id) }
        guard !removedProfileIDs.isEmpty || !removedGroupIDs.isEmpty else { return }

        func wasRemoved(_ target: OutboundTarget) -> Bool {
            switch target {
            case let .profile(id):
                removedProfileIDs.contains(id)
            case let .group(id):
                removedGroupIDs.contains(id)
            case .selectedProxy, .direct, .reject, .named:
                false
            }
        }

        groups = groups.map { group in
            var group = group
            group.members.removeAll(where: wasRemoved)
            if let defaultTarget = group.defaultTarget, wasRemoved(defaultTarget) {
                group.defaultTarget = group.members.first
            }
            return group
        }
        if let selectedTarget, wasRemoved(selectedTarget) {
            self.selectedTarget = nil
        } else if case let .group(selectedID) = selectedTarget,
                  groups.first(where: { $0.id == selectedID })?.members.isEmpty == true
        {
            selectedTarget = nil
        }
    }

    /// A refresh can change routing indirectly: reference repair can remove or
    /// remap a member, a named target can begin resolving to a different object,
    /// and disabling a changed child makes an enabled parent use its fallback.
    /// Compare targets in their pre/post namespaces, then propagate through one
    /// reverse-adjacency walk so an attacker-controlled 5,000-group chain stays
    /// O(vertices + edges) on the main actor.
    private mutating func invalidateGroupsWithChangedRouting(
        profilesBeforeRefresh: [ProxyProfile],
        groupsBeforeRefresh: [ProxyGroup],
        selectedTargetBeforeRefresh: OutboundTarget?,
    ) {
        let previousTargets = RoutingTargetIndex(
            profiles: profilesBeforeRefresh,
            groups: groupsBeforeRefresh,
        )
        let currentTargets = RoutingTargetIndex(profiles: profiles, groups: groups)

        var previousGroupByID: [ProxyGroup.ID: ProxyGroup] = [:]
        for group in groupsBeforeRefresh {
            previousGroupByID[group.id] = group
        }

        var currentGroupByID: [ProxyGroup.ID: ProxyGroup] = [:]
        var invalidatedGroupIDs: Set<ProxyGroup.ID> = []
        for group in groups {
            currentGroupByID[group.id] = group
            guard let previousGroup = previousGroupByID[group.id],
                  previousGroup.isEnabled,
                  routingChanged(
                      from: previousGroup,
                      resolvedBy: previousTargets,
                      to: group,
                      resolvedBy: currentTargets,
                  )
            else { continue }
            invalidatedGroupIDs.insert(group.id)
        }

        var parentGroupIDsByChildID: [ProxyGroup.ID: [ProxyGroup.ID]] = [:]
        for group in groups where group.isEnabled {
            var referencedGroupIDs: Set<ProxyGroup.ID> = []
            for target in group.members {
                if let childID = currentTargets.groupID(referencedBy: target) {
                    referencedGroupIDs.insert(childID)
                }
            }
            if let defaultTarget = group.defaultTarget,
               let childID = currentTargets.groupID(referencedBy: defaultTarget)
            {
                referencedGroupIDs.insert(childID)
            }
            for childID in referencedGroupIDs {
                parentGroupIDsByChildID[childID, default: []].append(group.id)
            }
        }

        var pendingGroupIDs = Array(invalidatedGroupIDs)
        var pendingIndex = 0
        while pendingIndex < pendingGroupIDs.count {
            let childID = pendingGroupIDs[pendingIndex]
            pendingIndex += 1
            for parentID in parentGroupIDsByChildID[childID] ?? []
                where currentGroupByID[parentID]?.isEnabled == true
                && invalidatedGroupIDs.insert(parentID).inserted
            {
                pendingGroupIDs.append(parentID)
            }
        }

        if !invalidatedGroupIDs.isEmpty {
            for index in groups.indices where invalidatedGroupIDs.contains(groups[index].id) {
                groups[index].isEnabled = false
                groups[index].warning = "Subscription refresh changed this group or a nested group's routing. Review it before enabling."
                let name = ImportPolicy.sanitizeImportedName(groups[index].name, fallback: "Imported Group")
                securityDowngradeWarnings.append(
                    "Subscription refresh changed routing for group \(name) or a nested group; disabled it until the change is reviewed.",
                )
            }
        }

        let selectedRoutingChanged: Bool = if let selectedTargetBeforeRefresh, let selectedTarget,
                                              Self.isDynamicTarget(selectedTargetBeforeRefresh),
                                              Self.isDynamicTarget(selectedTarget)
        {
            previousTargets.resolve(selectedTargetBeforeRefresh)
                != currentTargets.resolve(selectedTarget)
        } else {
            false
        }
        let selectedResolvedGroupWasInvalidated = selectedTarget
            .flatMap { currentTargets.groupID(referencedBy: $0) }
            .map(invalidatedGroupIDs.contains) == true
        if selectedRoutingChanged || selectedResolvedGroupWasInvalidated {
            selectedTarget = nil
        }
    }

    private func routingChanged(
        from previousGroup: ProxyGroup,
        resolvedBy previousTargets: RoutingTargetIndex,
        to currentGroup: ProxyGroup,
        resolvedBy currentTargets: RoutingTargetIndex,
    ) -> Bool {
        previousGroup.type != currentGroup.type
            || previousGroup.testOptions != currentGroup.testOptions
            || previousGroup.members.map(previousTargets.resolve)
            != currentGroup.members.map(currentTargets.resolve)
            || previousGroup.defaultTarget.map(previousTargets.resolve)
            != currentGroup.defaultTarget.map(currentTargets.resolve)
    }

    private static func isDynamicTarget(_ target: OutboundTarget) -> Bool {
        switch target {
        case .selectedProxy, .named:
            true
        case .direct, .reject, .profile, .group:
            false
        }
    }

    private enum ResolvedRoutingTarget: Hashable {
        case direct
        case reject
        case profile(ProxyProfile.ID)
        case group(ProxyGroup.ID)
        case missingNamed(String)
        case ambiguousNamed(String)
    }

    /// Name resolution mirrors `XrayReachabilityResolver`: built-ins win,
    /// profile/group name collisions are ambiguous, and `selectedProxy` uses
    /// the first profile or (only when there are none) first enabled group.
    private struct RoutingTargetIndex {
        private let profileIDsByName: [String: [ProxyProfile.ID]]
        private let groupIDsByName: [String: [ProxyGroup.ID]]
        private let selectedProxy: ResolvedRoutingTarget

        init(profiles: [ProxyProfile], groups: [ProxyGroup]) {
            profileIDsByName = Dictionary(
                grouping: profiles,
                by: { Self.normalizedName($0.name) },
            ).mapValues { $0.map(\.id) }
            groupIDsByName = Dictionary(
                grouping: groups,
                by: { Self.normalizedName($0.name) },
            ).mapValues { $0.map(\.id) }

            if let profile = profiles.first {
                selectedProxy = .profile(profile.id)
            } else if let group = groups.first(where: \.isEnabled) {
                selectedProxy = .group(group.id)
            } else {
                selectedProxy = .missingNamed("proxy")
            }
        }

        func resolve(_ target: OutboundTarget) -> ResolvedRoutingTarget {
            switch target {
            case .selectedProxy:
                selectedProxy
            case .direct:
                .direct
            case .reject:
                .reject
            case let .profile(id):
                .profile(id)
            case let .group(id):
                .group(id)
            case let .named(name):
                resolveNamed(name)
            }
        }

        func groupID(referencedBy target: OutboundTarget) -> ProxyGroup.ID? {
            guard case let .group(id) = resolve(target) else { return nil }
            return id
        }

        private func resolveNamed(_ name: String) -> ResolvedRoutingTarget {
            let normalized = Self.normalizedName(name)
            switch normalized {
            case "direct":
                return .direct
            case "reject":
                return .reject
            case "proxy":
                return selectedProxy
            default:
                break
            }

            let profileIDs = profileIDsByName[normalized] ?? []
            let groupIDs = groupIDsByName[normalized] ?? []
            guard profileIDs.count + groupIDs.count <= 1 else {
                return .ambiguousNamed(normalized)
            }
            if let profileID = profileIDs.first {
                return .profile(profileID)
            }
            if let groupID = groupIDs.first {
                return .group(groupID)
            }
            return .missingNamed(normalized)
        }

        private static func normalizedName(_ name: String) -> String {
            name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        }
    }

    private func preferredGroupIndex(
        from indices: [Int],
        referenceCounts: [ProxyGroup.ID: Int],
    ) -> Int? {
        guard !indices.isEmpty else {
            return nil
        }
        if case let .group(selectedID) = selectedTarget,
           let selectedIndex = indices.first(where: { groups[$0].id == selectedID })
        {
            return selectedIndex
        }

        if let referencedIndex = indices.first(where: { referenceCounts[groups[$0].id, default: 0] > 0 }) {
            return referencedIndex
        }

        return indices.first
    }

    // MARK: - Reference remapping

    private mutating func replaceTargetReferences(
        profileIDMap: [ProxyProfile.ID: ProxyProfile.ID] = [:],
        groupIDMap: [ProxyGroup.ID: ProxyGroup.ID] = [:],
    ) {
        guard !profileIDMap.isEmpty || !groupIDMap.isEmpty else {
            return
        }

        groups = groups.map {
            remappedGroup($0, profileIDMap: profileIDMap, groupIDMap: groupIDMap)
        }
        selectedTarget = selectedTarget.map {
            remappedTarget($0, profileIDMap: profileIDMap, groupIDMap: groupIDMap)
        }
    }

    private func remappedGroup(
        _ group: ProxyGroup,
        profileIDMap: [ProxyProfile.ID: ProxyProfile.ID],
        groupIDMap: [ProxyGroup.ID: ProxyGroup.ID],
    ) -> ProxyGroup {
        var group = group
        group.members = uniquedTargets(group.members.map { remappedTarget($0, profileIDMap: profileIDMap, groupIDMap: groupIDMap) })
        group.defaultTarget = group.defaultTarget.map { remappedTarget($0, profileIDMap: profileIDMap, groupIDMap: groupIDMap) }
        if let defaultTarget = group.defaultTarget, !group.members.contains(defaultTarget) {
            group.defaultTarget = group.members.first
        }
        return group
    }

    private func remappedTarget(
        _ target: OutboundTarget,
        profileIDMap: [ProxyProfile.ID: ProxyProfile.ID],
        groupIDMap: [ProxyGroup.ID: ProxyGroup.ID],
    ) -> OutboundTarget {
        switch target {
        case let .profile(id):
            profileIDMap[id].map(OutboundTarget.profile) ?? target
        case let .group(id):
            groupIDMap[id].map(OutboundTarget.group) ?? target
        case .selectedProxy, .direct, .reject, .named:
            target
        }
    }

    private func uniquedTargets(_ targets: [OutboundTarget]) -> [OutboundTarget] {
        var seen: Set<OutboundTarget> = []
        return targets.filter { target in
            guard !seen.contains(target) else {
                return false
            }
            seen.insert(target)
            return true
        }
    }

    private func normalizedImportName(_ name: String) -> String {
        name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    private func resolvedReplacement<ID: Hashable>(for id: ID, in replacements: [ID: ID]) -> ID {
        var current = id
        var seen: Set<ID> = []
        while let next = replacements[current], seen.insert(current).inserted {
            current = next
        }
        return current
    }
}

/// The merger's second-tier match key: a refreshed node is "the same node" as
/// an existing one when subscription ownership, name, and protocol agree, even
/// if host or credentials moved. Used by `newInsecureProfileNames` to mirror
/// the merge's matching.
private struct NameAndProtocol: Hashable {
    var subscriptionID: UUID?
    var name: String
    var proto: ProxyProtocol

    init(_ profile: ProxyProfile) {
        subscriptionID = profile.subscriptionID
        name = profile.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        proto = profile.proto
    }
}

/// Everything that identifies a subscription node except its stable ID; two
/// profiles with equal identities are the same imported node.
private struct SubscriptionProfileRefreshIdentity: Hashable {
    var subscriptionID: UUID?
    var name: String
    var host: String
    var port: Int
    var proto: ProxyProtocol
    var options: ProtocolOptions
    var security: ProxySecurity
    var transport: TransportOptions

    init(_ profile: ProxyProfile) {
        subscriptionID = profile.subscriptionID
        name = profile.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        host = profile.endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        port = profile.endpoint.port
        proto = profile.proto
        options = profile.options
        security = profile.security
        transport = profile.transport
    }
}

private struct SubscriptionGroupRefreshIdentity: Hashable {
    var subscriptionID: UUID
    var name: String
    var importedType: String

    init?(_ group: ProxyGroup) {
        guard let subscriptionID = group.subscriptionID,
              let importedType = group.importedType
        else { return nil }
        self.subscriptionID = subscriptionID
        name = group.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        self.importedType = importedType
    }
}
