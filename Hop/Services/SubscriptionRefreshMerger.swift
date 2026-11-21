import CryptoKit
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
        case wireGuardPeerPolicy = "WireGuard peers and routing"
    }

    struct Detail: Hashable {
        let field: Field
        let before: String
        let after: String
    }

    let id: UUID
    let profileName: String
    let details: [Detail]
    var fields: [Field] {
        details.map(\.field)
    }

    // Include the original and proposed snapshots in equality. A second edit
    // to the very same field while the sheet is open requires a fresh review.
    // Digests never go into the displayed text or persistent logs.
    private let originalDigest: Data
    private let proposedDigest: Data

    init(existing: ProxyProfile, imported: ProxyProfile, fields: [Field]) {
        id = existing.id
        profileName = ImportPolicy.sanitizeImportedName(imported.name, fallback: "Imported Node")
        originalDigest = Self.snapshotDigest(existing)
        proposedDigest = Self.snapshotDigest(imported)
        details = fields.map { field in
            let old = Self.description(of: field, in: existing)
            var new = Self.description(of: field, in: imported, replacing: existing)
            if new == "Configured", old == new {
                new = "Replaced"
            }
            return Detail(field: field, before: old, after: new)
        }
    }

    var summary: String {
        "\(profileName): \(fields.map(\.rawValue).joined(separator: ", "))"
    }

    private static func snapshotDigest(_ profile: ProxyProfile) -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.nonConformingFloatEncodingStrategy = .convertToString(positiveInfinity: "Infinity", negativeInfinity: "-Infinity", nan: "NaN")
        guard let data = try? encoder.encode(profile) else {
            // If the model gains an unencodable value, invalidate the review
            // on recheck rather than treating two encoding failures as equal.
            return Data(UUID().uuidString.utf8)
        }
        return Data(SHA256.hash(data: data))
    }

    private static func safeText(_ text: String?) -> String {
        guard let text, !text.isEmpty else { return "Not set" }
        let collapsed = text.split(whereSeparator: \.isWhitespace).joined(separator: " ")
        let scalars = collapsed.unicodeScalars.filter {
            ![.control, .format, .surrogate, .privateUse, .unassigned].contains($0.properties.generalCategory)
        }
        return String(String.UnicodeScalarView(scalars))
    }

    private static func publicFingerprint(_ value: String?, acceptsHex: Bool = false) -> String {
        guard let value, !value.isEmpty else { return "Not set" }
        var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        let bytes: Data
        if acceptsHex, value.utf8.count == 64, value.utf8.allSatisfy({ (48 ... 57).contains($0) || (65 ... 70).contains($0) || (97 ... 102).contains($0) }) {
            let hex = Array(value.utf8)
            bytes = Data(stride(from: 0, to: hex.count, by: 2).compactMap { offset in
                UInt8(String(decoding: hex[offset ... offset + 1], as: UTF8.self), radix: 16)
            })
        } else {
            bytes = Data(base64Encoded: base64) ?? Data(value.utf8)
        }
        return "SHA-256 " + SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    private static func description(of field: Field, in profile: ProxyProfile, replacing previous: ProxyProfile? = nil) -> String {
        let tls = profile.security.tls
        switch field {
        case .securityLayer: return profile.security.layer.displayName
        case .tlsServerName:
            return safeText(profile.security.reality?.serverName ?? SubscriptionRefreshMerger.effectiveTLSServerName(profile))
        case .tlsClientFingerprint: return safeText(profile.security.reality?.utlsFingerprint ?? tls?.utlsFingerprint)
        case .tlsMinimumVersion: return safeText(tls?.minVersion)
        case .tlsMaximumVersion: return safeText(tls?.maxVersion)
        case .tlsCipherSuites: return safeText(tls?.cipherSuites)
        case .certificatePins: return safeText(tls?.pinnedPeerCertSHA256)
        case .verificationNames: return safeText(tls?.verifyPeerCertByName)
        case .postQuantumCurves:
            return tls?.curvePreferences.isEmpty == false ? safeText(tls?.curvePreferences.joined(separator: ", ")) : "Core defaults"
        case .realityPublicKey: return publicFingerprint(profile.security.reality?.publicKey)
        case .realityMLDSA: return publicFingerprint(profile.security.reality?.mldsa65Verify)
        case .ech: return tls?.echConfigList?.isEmpty == false ? "Configured" : "Not set"
        case .finalMaskTransportPolicy: return profile.transport.finalMask == nil ? "Not set" : "Configured"
        case .vlessEncryption:
            guard case let .vless(options) = profile.options, let encryption = options.normalizedEncryption, encryption != "none" else { return "Not set" }
            return "Configured"
        case .wireGuardPeerPolicy:
            guard case let .wireGuard(options) = profile.options else { return "Not set" }
            var previousPeers: [WireGuardPeer] = []
            if case let .wireGuard(old) = previous?.options {
                previousPeers = old.effectivePeers
            }
            return options.effectivePeers.enumerated().map { index, peer in
                let endpoint = peer.endpoint ?? profile.endpoint
                let ranges = peer.allowedIPs ?? ["0.0.0.0/0", "::/0"]
                let psk = if peer.preSharedKey?.isEmpty != false {
                    "Not set"
                } else if let old = previousPeers.first(where: { $0.publicKey == peer.publicKey }), old.preSharedKey?.isEmpty == false, old.preSharedKey != peer.preSharedKey {
                    "Replaced"
                } else {
                    "Configured"
                }
                let host = endpoint.host.contains(":") ? "[\(safeText(endpoint.host))]" : safeText(endpoint.host)
                let routes = ranges.isEmpty ? "None" : safeText(ranges.joined(separator: ", "))
                return "Peer \(index + 1) · \(host):\(endpoint.port)\nPublic key: \(publicFingerprint(peer.publicKey, acceptsHex: true))\nAllowed IPs: \(routes)\nPre-shared key: \(psk)"
            }.joined(separator: "\n\n")
        }
    }
}

/// Merges a refreshed subscription's profiles and groups into the existing
/// collections, updating matching items in place — keeping their stable IDs so
/// group members, routing rules, and the selected target stay valid — instead
/// of appending duplicates.
///
/// Exact records take precedence. Remaining records match within the same
/// subscription, name and protocol, preferring the same endpoint before a
/// changed endpoint. Every old record can supply only one surviving ID. When several existing items
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

    /// Every consumer uses the same inventory plan. Reserving exact records and
    /// then endpoints before name matches keeps a rotated sibling from stealing
    /// a stable ID from an unchanged node later in the response.
    private struct ProfileMatch {
        let imported: ProxyProfile
        var importedIDs: [UUID]
        var existingIndex: Int?
        var exactDuplicates: [Int] = []
        var isExact = false
    }

    private struct NamedEndpoint: Hashable {
        let name: NameAndProtocol
        let host: String
        let port: Int
        init(_ profile: ProxyProfile) {
            name = NameAndProtocol(profile)
            host = profile.endpoint.host.lowercased()
            port = profile.endpoint.port
        }
    }

    private func profileMatches(_ imported: [ProxyProfile]) -> [ProfileMatch] {
        guard !imported.isEmpty else { return [] }
        let owners = Set(imported.map(\.subscriptionID))
        let candidates = profiles.indices.filter { owners.contains(profiles[$0].subscriptionID) }
        var matches: [ProfileMatch] = []
        var importedIndices: [SubscriptionProfileRefreshIdentity: Int] = [:]
        var exactIndices = Dictionary(grouping: candidates) { SubscriptionProfileRefreshIdentity(profiles[$0]) }
        let referenced = referencedProfileIDs()
        var claimed: Set<Int> = []
        for profile in imported {
            let identity = SubscriptionProfileRefreshIdentity(profile)
            if let index = importedIndices[identity] {
                matches[index].importedIDs.append(profile.id)
                continue
            }
            importedIndices[identity] = matches.count
            let exact = exactIndices.removeValue(forKey: identity) ?? []
            let preferred = preferredProfileIndex(from: exact, referencedProfileIDs: referenced)
            claimed.formUnion(exact)
            matches.append(ProfileMatch(imported: profile, importedIDs: [profile.id], existingIndex: preferred,
                                        exactDuplicates: exact.filter { $0 != preferred }, isExact: preferred != nil))
        }

        /// Within each bucket prefer the selected or referenced ID, then the
        /// first library entry. Pop from the end to avoid quadratic removals.
        func priority(_ index: Int) -> Int {
            let id = profiles[index].id
            if selectedTarget == .profile(id) {
                return 0
            }
            return referenced.contains(id) ? 1 : 2
        }
        let available = candidates.filter { !claimed.contains($0) && profiles[$0].subscriptionID != nil }
            .sorted { (priority($0), $0) > (priority($1), $1) }
        var byEndpoint = Dictionary(grouping: available) { NamedEndpoint(profiles[$0]) }
        for index in matches.indices where matches[index].existingIndex == nil && matches[index].imported.subscriptionID != nil {
            if let old = byEndpoint[NamedEndpoint(matches[index].imported)]?.popLast() {
                matches[index].existingIndex = old
                claimed.insert(old)
            }
        }
        var byName = Dictionary(grouping: available.filter { !claimed.contains($0) }) { NameAndProtocol(profiles[$0]) }
        for index in matches.indices where matches[index].existingIndex == nil && matches[index].imported.subscriptionID != nil {
            matches[index].existingIndex = byName[NameAndProtocol(matches[index].imported)]?.popLast()
        }
        return matches
    }

    func securityCriticalChanges(in importedProfiles: [ProxyProfile]) -> [SubscriptionSecurityChange] {
        profileMatches(importedProfiles).compactMap { match in
            guard let index = match.existingIndex, !match.isExact else { return nil }
            let existing = profiles[index]
            let fields = Self.securityCriticalFields(existing: existing, imported: match.imported)
            guard !fields.isEmpty else { return nil }
            return SubscriptionSecurityChange(existing: existing, imported: match.imported, fields: fields)
        }
    }

    static func newInsecureProfileNames(existing: [ProxyProfile], imported: [ProxyProfile]) -> [String] {
        guard imported.contains(where: { $0.security.tls?.allowInsecure == true }) else { return [] }
        return SubscriptionRefreshMerger(profiles: existing, groups: [], selectedTarget: nil)
            .profileMatches(imported)
            .filter { $0.existingIndex == nil && $0.imported.security.tls?.allowInsecure == true }
            .map { ImportPolicy.sanitizeImportedName($0.imported.name, fallback: "Imported Node") }
    }

    // MARK: - Profiles

    private mutating func mergeProfiles(
        _ importedProfiles: [ProxyProfile],
        securityPolicy: SubscriptionRefreshSecurityPolicy,
    ) -> [ProxyProfile.ID: ProxyProfile.ID] {
        var importedProfileIDMap: [UUID: UUID] = [:]
        var inserted: [ProxyProfile] = []
        for match in profileMatches(importedProfiles) {
            var updated = match.imported
            if let index = match.existingIndex {
                let existing = profiles[index]
                updated.id = existing.id
                updated.xrayAdvanced = existing.xrayAdvanced
                if !match.isExact {
                    updated = applyingSecurityPolicy(existing: existing, imported: updated, policy: securityPolicy)
                }
                profiles[index] = updated
                for duplicate in match.exactDuplicates {
                    profileIDReplacements[profiles[duplicate].id] = existing.id
                }
            } else {
                inserted.append(updated)
            }
            for id in match.importedIDs {
                importedProfileIDMap[id] = updated.id
            }
        }
        if !profileIDReplacements.isEmpty {
            let removedIDs = Set(profileIDReplacements.keys)
            profiles.removeAll { removedIDs.contains($0.id) }
            replaceTargetReferences(profileIDMap: profileIDReplacements)
        }
        profiles.insert(contentsOf: inserted.reversed(), at: 0)
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
                "\(imported.name): blocked refresh from disabling TLS certificate verification.",
            )
        }

        guard policy == .preserveExisting else {
            updated.security = security
            return updated
        }

        if security.layer != existing.security.layer {
            securityDowngradeWarnings.append(
                "\(imported.name): \(existing.security.layer.displayName) → \(security.layer.displayName) blocked pending review.",
            )
            security = existing.security
            // Keeping the old TLS layer also keeps its endpoint-derived name.
            if security.layer == .tls, Self.normalizedOptional(security.tls?.serverName) == nil,
               existing.endpoint.host != imported.endpoint.host
            {
                security.tls?.serverName = Self.effectiveTLSServerName(existing)
            }
        } else {
            preserveSecurityCriticalTLS(existing: existing, imported: imported, security: &security)
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
                "\(imported.name): kept VLESS Encryption/Auth; refresh change needs review.",
            )
        }

        if existing.transport.finalMask != imported.transport.finalMask {
            updated.transport.finalMask = existing.transport.finalMask
            securityDowngradeWarnings.append(
                "\(imported.name): kept FinalMask policy; refresh change needs review.",
            )
        }

        if Self.wireGuardPeerPolicyChanged(existing: existing, imported: imported) {
            updated.options = existing.options
            updated.endpoint = existing.endpoint
            securityDowngradeWarnings.append(
                "\(imported.name): kept WireGuard peers and routing; refresh change needs review.",
            )
        }

        updated.security = security
        return updated
    }

    private mutating func preserveSecurityCriticalTLS(
        existing: ProxyProfile,
        imported: ProxyProfile,
        security: inout ProxySecurity,
    ) {
        let existingTLS = existing.security.tls
        guard var importedTLS = security.tls else {
            guard existingTLS != nil else { return }
            security.tls = existingTLS
            securityDowngradeWarnings.append(
                "\(imported.name): TLS verification removal blocked pending review.",
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
                "\(imported.name): kept \(label); refresh change needs review.",
            )
        }

        preservingString(existingTLS?.pinnedPeerCertSHA256, &importedTLS.pinnedPeerCertSHA256, label: "certificate pins")
        preservingString(existingTLS?.verifyPeerCertByName, &importedTLS.verifyPeerCertByName, label: "certificate verification names")
        preservingString(existingTLS?.echConfigList, &importedTLS.echConfigList, label: "ECH")
        if existing.security.layer == .tls {
            if Self.effectiveTLSServerName(existing) != Self.effectiveTLSServerName(imported) {
                importedTLS.serverName = Self.effectiveTLSServerName(existing)
                securityDowngradeWarnings.append("\(imported.name): kept TLS server name; refresh change needs review.")
            }
        } else {
            preservingString(existingTLS?.serverName, &importedTLS.serverName, label: "TLS server name")
        }
        preservingString(existingTLS?.utlsFingerprint, &importedTLS.utlsFingerprint, label: "TLS client fingerprint")
        preservingString(existingTLS?.maxVersion, &importedTLS.maxVersion, label: "maximum TLS version")
        preservingString(existingTLS?.cipherSuites, &importedTLS.cipherSuites, label: "TLS cipher suites")

        if Self.changedPostQuantumPolicy(existingTLS?.curvePreferences ?? [], importedTLS.curvePreferences) {
            importedTLS.curvePreferences = existingTLS?.curvePreferences ?? []
            securityDowngradeWarnings.append(
                "\(imported.name): kept post-quantum TLS curves; refresh change needs review.",
            )
        }

        if Self.normalizedOptional(importedTLS.minVersion) != Self.normalizedOptional(existingTLS?.minVersion) {
            importedTLS.minVersion = existingTLS?.minVersion
            securityDowngradeWarnings.append(
                "\(imported.name): kept minimum TLS version; refresh change needs review.",
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
                "\(importedName): REALITY authentication removal blocked pending review.",
            )
            return
        }

        if Self.normalizedOptional(importedReality.publicKey) != Self.normalizedOptional(existingReality.publicKey) {
            importedReality.publicKey = existingReality.publicKey
            securityDowngradeWarnings.append(
                "\(importedName): kept REALITY public key; refresh change needs review.",
            )
        }
        if Self.normalizedOptional(importedReality.mldsa65Verify) != Self.normalizedOptional(existingReality.mldsa65Verify) {
            importedReality.mldsa65Verify = existingReality.mldsa65Verify
            securityDowngradeWarnings.append(
                "\(importedName): kept REALITY ML-DSA verify key; refresh change needs review.",
            )
        }
        if Self.normalizedOptional(importedReality.serverName) != Self.normalizedOptional(existingReality.serverName) {
            importedReality.serverName = existingReality.serverName
            securityDowngradeWarnings.append(
                "\(importedName): kept REALITY server name; refresh change needs review.",
            )
        }
        if Self.normalizedOptional(importedReality.utlsFingerprint) != Self.normalizedOptional(existingReality.utlsFingerprint) {
            importedReality.utlsFingerprint = existingReality.utlsFingerprint
            securityDowngradeWarnings.append(
                "\(importedName): kept REALITY fingerprint; refresh change needs review.",
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

        appendTLSChange(effectiveTLSServerName(existing), effectiveTLSServerName(imported), field: .tlsServerName)
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
        if changedPostQuantumPolicy(existing.security.tls?.curvePreferences ?? [], imported.security.tls?.curvePreferences ?? []) {
            fields.append(.postQuantumCurves)
        }
        if existing.transport.finalMask != imported.transport.finalMask {
            fields.append(.finalMaskTransportPolicy)
        }
        if wireGuardPeerPolicyChanged(existing: existing, imported: imported) {
            fields.append(.wireGuardPeerPolicy)
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

    private static func wireGuardPeerPolicyChanged(existing: ProxyProfile, imported: ProxyProfile) -> Bool {
        guard case let .wireGuard(old) = existing.options,
              case let .wireGuard(new) = imported.options else { return false }
        // Peer UUIDs identify Keychain accounts, not remote trust. Legacy
        // effectivePeers generates fresh UUIDs on each read, so ignore them.
        return !old.effectivePeers.elementsEqual(new.effectivePeers) { lhs, rhs in
            lhs.publicKey == rhs.publicKey
                && normalizedOptional(lhs.preSharedKey) == normalizedOptional(rhs.preSharedKey)
                && (lhs.endpoint ?? existing.endpoint) == (rhs.endpoint ?? imported.endpoint)
                && (lhs.allowedIPs ?? ["0.0.0.0/0", "::/0"]) == (rhs.allowedIPs ?? ["0.0.0.0/0", "::/0"])
        }
    }

    private static func isPostQuantumCurve(_ value: String) -> Bool {
        let value = value.lowercased()
        return value.contains("mlkem") || value.contains("kyber")
    }

    fileprivate static func effectiveTLSServerName(_ profile: ProxyProfile) -> String? {
        normalizedOptional(profile.security.tls?.serverName) ?? (profile.security.layer == .tls ? profile.endpoint.host : nil)
    }

    private static func changedPostQuantumPolicy(_ old: [String], _ new: [String]) -> Bool {
        // The core defaults offer hybrid curves even though no names are stored.
        if old.isEmpty != new.isEmpty {
            return true
        }
        guard old.contains(where: isPostQuantumCurve) || new.contains(where: isPostQuantumCurve) else { return false }
        return old.map { $0.lowercased() } != new.map { $0.lowercased() }
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
                if updatedGroup.type == .select {
                    // Older saves mixed the provider and local defaults. Keep a differing
                    // previous choice while the routing comparison below prompts for review.
                    updatedGroup.localSelection = existingGroup.localSelection
                        ?? (existingGroup.defaultTarget == updatedGroup.defaultTarget ? .provider : .member(existingGroup.defaultTarget))
                }
                if importedGroup.warning != ImportResult.ambiguousSubscriptionGroupWarning {
                    updatedGroup.isEnabled = existingGroup.isEnabled
                    updatedGroup.warning = existingGroup.warning == ImportResult.ambiguousSubscriptionGroupWarning
                        ? importedGroup.warning : existingGroup.warning
                }
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
            for index in groups.indices {
                if let selected = groups[index].localSelection?.target, !groups[index].members.contains(selected) {
                    groups[index].localSelection = .provider
                }
            }
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
            if let selected = group.localSelection?.target, wasRemoved(selected) {
                group.localSelection = .provider
            }
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
                  !group.isEnabled || routingChanged(
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
                if groups[index].warning != ImportResult.ambiguousSubscriptionGroupWarning {
                    groups[index].warning = ImportResult.changedGroupReviewPrompt
                }
                let name = ImportPolicy.sanitizeImportedName(groups[index].name, fallback: "Imported Group")
                securityDowngradeWarnings.append(
                    "\(name): disabled after a group or nested routing change. Review before enabling.",
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

    enum ResolvedRoutingTarget: Hashable {
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
    struct RoutingTargetIndex {
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
        if let target = group.localSelection?.target {
            let remapped = remappedTarget(target, profileIDMap: profileIDMap, groupIDMap: groupIDMap)
            group.localSelection = .member(remapped)
        }
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
    private static let canonicalID = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    let bytes: Data

    init(_ profile: ProxyProfile) {
        var canonical = profile
        canonical.id = Self.canonicalID
        canonical.xrayAdvanced = nil // Matched records retain local overrides.
        canonical.name = canonical.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        canonical.endpoint.host = canonical.endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if case var .wireGuard(wg) = canonical.options, let peers = wg.peers {
            // Peer IDs address local Keychain items. They do not distinguish
            // two provider records carrying identical peer credentials/routes.
            wg.peers = peers.map { peer in
                var canonicalPeer = peer
                canonicalPeer.id = Self.canonicalID
                return canonicalPeer
            }
            canonical.options = .wireGuard(wg)
        }
        // Swift String equality folds different UTF-8 spellings of passwords
        // and paths. A byte-exact comparison keeps such records independent.
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        bytes = (try? encoder.encode(canonical)) ?? Data(UUID().uuidString.utf8)
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
