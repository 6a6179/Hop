import Foundation

/// Merges a refreshed subscription's profiles and groups into the existing
/// collections, updating matching items in place — keeping their stable IDs so
/// group members, routing rules, and the selected target stay valid — instead
/// of appending duplicates.
///
/// Matching is two-tier: exact identity (everything but the ID) first, then
/// name + protocol, so a node whose host or credentials changed is still
/// recognized as the same logical node. When several existing items match, the
/// selected one is preferred, then one referenced by a group, and surviving
/// duplicates are collapsed with their references remapped.
///
/// Operates on value copies: every mutation of `HopStore.profiles`/`groups`
/// triggers a full state persist and Keychain rewrite, so the store applies a
/// merge with one assignment per collection rather than one per imported item.
struct SubscriptionRefreshMerger {
    private(set) var profiles: [ProxyProfile]
    private(set) var groups: [ProxyGroup]
    private(set) var selectedTarget: OutboundTarget?

    mutating func merge(_ result: ImportResult) {
        let profileIDMap = mergeProfiles(result.profiles)
        mergeGroups(result.groups, importedProfileIDMap: profileIDMap)
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

    private func profileIndices(matchingIdentityOf profile: ProxyProfile) -> [Int] {
        let identity = SubscriptionProfileRefreshIdentity(profile)
        return profiles.indices.filter {
            SubscriptionProfileRefreshIdentity(profiles[$0]) == identity
        }
    }

    private func profileIndices(matchingNameAndProtocolOf profile: ProxyProfile) -> [Int] {
        let normalizedName = normalizedImportName(profile.name)
        return profiles.indices.filter {
            normalizedImportName(profiles[$0].name) == normalizedName && profiles[$0].proto == profile.proto
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
