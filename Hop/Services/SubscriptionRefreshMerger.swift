import Foundation

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
    /// Human-readable notes for security settings the merge refused to weaken;
    /// the store surfaces these in the app log after a refresh.
    private(set) var securityDowngradeWarnings: [String] = []

    mutating func merge(_ result: ImportResult) {
        let profileIDMap = mergeProfiles(result.profiles)
        mergeGroups(result.groups, importedProfileIDMap: profileIDMap)
    }

    /// Names of imported nodes that would *newly* disable TLS certificate
    /// verification if this refresh were applied: allow-insecure nodes with no
    /// exact or same-subscription name+protocol match among the existing
    /// profiles. A matched node is never newly insecure — if the existing
    /// profile is already insecure nothing changes, and if it is secure
    /// `securityPreservingDowngrades` blocks the flip (and logs the refusal).
    /// Only genuinely new nodes are inserted verbatim, so refresh flows must
    /// run the blocking insecure-TLS confirmation for these, same as initial
    /// imports (see the AGENTS.md import-gate invariant).
    static func newInsecureProfileNames(existing: [ProxyProfile], imported: [ProxyProfile]) -> [String] {
        imported
            .filter { $0.security.tls?.allowInsecure == true }
            .filter { profile in
                !existing.contains {
                    SubscriptionProfileRefreshIdentity($0) == SubscriptionProfileRefreshIdentity(profile) ||
                        (profile.subscriptionID != nil && NameAndProtocol($0) == NameAndProtocol(profile))
                }
            }
            .map { ImportPolicy.sanitizeImportedName($0.name, fallback: "Imported Node") }
    }

    // MARK: - Profiles

    private mutating func mergeProfiles(_ importedProfiles: [ProxyProfile]) -> [ProxyProfile.ID: ProxyProfile.ID] {
        var importedProfileIDMap: [ProxyProfile.ID: ProxyProfile.ID] = [:]
        var replacedProfileIDMap: [ProxyProfile.ID: ProxyProfile.ID] = [:]
        // Groups don't change while profiles merge, so the set of
        // group-referenced profile IDs is computed once for all candidates.
        let referencedProfileIDs = referencedProfileIDs()

        for importedProfile in importedProfiles {
            let exactMatches = profileIndices(matchingIdentityOf: importedProfile)
            let matchingIndices = exactMatches.isEmpty ? profileIndices(matchingNameAndProtocolOf: importedProfile) : exactMatches

            if let profileIndex = preferredProfileIndex(from: matchingIndices, referencedProfileIDs: referencedProfileIDs) {
                var updatedProfile = importedProfile
                updatedProfile.id = profiles[profileIndex].id
                // A name-matched update comes from the subscription server and
                // must not silently weaken the stored TLS posture: an attacker
                // controlling the response could otherwise strip certificate
                // verification (or TLS entirely) from a node the user trusts.
                if exactMatches.isEmpty {
                    updatedProfile.security = securityPreservingDowngrades(
                        existing: profiles[profileIndex],
                        imported: updatedProfile,
                    )
                }
                profiles[profileIndex] = updatedProfile
                importedProfileIDMap[importedProfile.id] = updatedProfile.id

                if !exactMatches.isEmpty {
                    for duplicateIndex in matchingIndices where duplicateIndex != profileIndex {
                        replacedProfileIDMap[profiles[duplicateIndex].id] = updatedProfile.id
                    }
                }
            } else {
                profiles.insert(importedProfile, at: 0)
                importedProfileIDMap[importedProfile.id] = importedProfile.id
            }
        }

        if !replacedProfileIDMap.isEmpty {
            let removedIDs = Set(replacedProfileIDMap.keys)
            profiles.removeAll { removedIDs.contains($0.id) }
            replaceTargetReferences(profileIDMap: replacedProfileIDMap)
        }

        return importedProfileIDMap
    }

    /// Returns the security settings to store for a name-matched refresh,
    /// refusing the silent downgrades an attacker-controlled subscription
    /// could push: demoting the security layer (REALITY → TLS → none — REALITY
    /// also carries anti-probing properties plain TLS lacks) and flipping
    /// `allowInsecure` on. Each refusal is recorded as a warning.
    private mutating func securityPreservingDowngrades(existing: ProxyProfile, imported: ProxyProfile) -> ProxySecurity {
        var security = imported.security

        if Self.layerRank(security.layer) < Self.layerRank(existing.security.layer) {
            securityDowngradeWarnings.append(
                "Refresh tried to downgrade \(imported.name) from \(existing.security.layer.displayName) to \(security.layer.displayName); kept the existing security settings.",
            )
            return existing.security
        }

        if existing.security.tls?.allowInsecure == false, security.tls?.allowInsecure == true {
            security.tls?.allowInsecure = false
            securityDowngradeWarnings.append(
                "Refresh tried to disable TLS certificate verification for \(imported.name); kept verification enabled.",
            )
        }

        // A changed REALITY public key re-targets which server the client
        // authenticates. Key rotation is legitimate, so the change applies —
        // but never silently: the log names the node so an unexpected swap
        // pushed by the subscription server is visible to the user.
        if let existingKey = existing.security.reality?.publicKey,
           let importedKey = security.reality?.publicKey,
           !existingKey.isEmpty, existingKey != importedKey
        {
            securityDowngradeWarnings.append(
                "Refresh changed the REALITY public key for \(imported.name). If you did not expect a key rotation from this provider, re-verify the node.",
            )
        }

        return security
    }

    private static func layerRank(_ layer: SecurityLayer) -> Int {
        switch layer {
        case .none: 0
        case .tls: 1
        case .reality: 2
        }
    }

    private func profileIndices(matchingIdentityOf profile: ProxyProfile) -> [Int] {
        let identity = SubscriptionProfileRefreshIdentity(profile)
        return profiles.indices.filter {
            SubscriptionProfileRefreshIdentity(profiles[$0]) == identity
        }
    }

    private func profileIndices(matchingNameAndProtocolOf profile: ProxyProfile) -> [Int] {
        guard profile.subscriptionID != nil else {
            return []
        }
        let normalizedName = normalizedImportName(profile.name)
        return profiles.indices.filter {
            profiles[$0].subscriptionID == profile.subscriptionID &&
                normalizedImportName(profiles[$0].name) == normalizedName &&
                profiles[$0].proto == profile.proto
        }
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

    private mutating func mergeGroups(_ importedGroups: [ProxyGroup], importedProfileIDMap: [ProxyProfile.ID: ProxyProfile.ID]) {
        var importedGroupIDMap: [ProxyGroup.ID: ProxyGroup.ID] = [:]
        var replacedGroupIDMap: [ProxyGroup.ID: ProxyGroup.ID] = [:]

        for importedGroup in importedGroups.map({ remappedGroup($0, profileIDMap: importedProfileIDMap, groupIDMap: [:]) }) {
            let matchingIndices = groupIndices(matchingRefreshIdentityOf: importedGroup)

            if let groupIndex = preferredGroupIndex(from: matchingIndices) {
                var updatedGroup = importedGroup
                updatedGroup.id = groups[groupIndex].id
                groups[groupIndex] = updatedGroup
                importedGroupIDMap[importedGroup.id] = updatedGroup.id

                for duplicateIndex in matchingIndices where duplicateIndex != groupIndex {
                    replacedGroupIDMap[groups[duplicateIndex].id] = updatedGroup.id
                }
            } else {
                groups.insert(importedGroup, at: 0)
                importedGroupIDMap[importedGroup.id] = importedGroup.id
            }
        }

        if !replacedGroupIDMap.isEmpty {
            let removedIDs = Set(replacedGroupIDMap.keys)
            groups.removeAll { removedIDs.contains($0.id) }
        }
        if !importedGroupIDMap.isEmpty || !replacedGroupIDMap.isEmpty {
            replaceTargetReferences(groupIDMap: importedGroupIDMap.merging(replacedGroupIDMap) { current, _ in current })
        }
    }

    private func groupIndices(matchingRefreshIdentityOf group: ProxyGroup) -> [Int] {
        guard let importedType = group.importedType else {
            return []
        }
        let normalizedName = normalizedImportName(group.name)
        return groups.indices.filter {
            normalizedImportName(groups[$0].name) == normalizedName && groups[$0].importedType == importedType
        }
    }

    private func preferredGroupIndex(from indices: [Int]) -> Int? {
        guard !indices.isEmpty else {
            return nil
        }
        if case let .group(selectedID) = selectedTarget,
           let selectedIndex = indices.first(where: { groups[$0].id == selectedID })
        {
            return selectedIndex
        }

        // Recomputed per imported group: merged groups insert as the loop runs,
        // and their members count as references for later candidates.
        let referencedGroupIDs = Set(groups.flatMap { group in
            group.members.compactMap { target in
                if case let .group(id) = target {
                    return id
                }
                return nil
            }
        })
        if let referencedIndex = indices.first(where: { referencedGroupIDs.contains(groups[$0].id) }) {
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
    var name: String
    var host: String
    var port: Int
    var proto: ProxyProtocol
    var options: ProtocolOptions
    var security: ProxySecurity
    var transport: TransportOptions

    init(_ profile: ProxyProfile) {
        name = profile.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        host = profile.endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        port = profile.endpoint.port
        proto = profile.proto
        options = profile.options
        security = profile.security
        transport = profile.transport
    }
}
