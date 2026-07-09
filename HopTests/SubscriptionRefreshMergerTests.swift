@testable import Hop
import XCTest

/// Behavior of the subscription-refresh merge: identity matching, preferred
/// duplicate selection, reference remapping, and the persist batching the
/// extraction exists for.
final class SubscriptionRefreshMergerTests: XCTestCase {
    func testNameAndProtocolMatchUpdatesProfileInPlace() {
        let subscriptionID = UUID()
        let existing = trojanProfile(name: "Tokyo", host: "old.example.com", subscriptionID: subscriptionID)
        var merger = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)

        merger.merge(ImportResult(profiles: [trojanProfile(name: " tokyo ", host: "new.example.com", subscriptionID: subscriptionID)]))

        XCTAssertEqual(merger.profiles.map(\.id), [existing.id], "name match is trimmed + case-insensitive")
        XCTAssertEqual(merger.profiles.first?.endpoint.host, "new.example.com")
    }

    func testNameAndProtocolMatchRequiresSameSubscription() {
        let existing = trojanProfile(name: "Tokyo", host: "manual.example.com")
        var merger = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)

        merger.merge(ImportResult(profiles: [trojanProfile(name: "Tokyo", host: "subscription.example.com", subscriptionID: UUID())]))

        XCTAssertEqual(merger.profiles.count, 2)
        XCTAssertTrue(merger.profiles.contains { $0.id == existing.id && $0.endpoint.host == "manual.example.com" })
    }

    func testNameMatchRequiresSameProtocol() {
        let subscriptionID = UUID()
        let existing = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscriptionID)
        var merger = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)

        let vless = ProxyProfile(
            name: "Tokyo",
            endpoint: Endpoint(host: "jp.example.com", port: 443),
            options: .vless(VLESSOptions(uuid: "u", flow: nil)),
            security: .none,
            subscriptionID: subscriptionID,
        )
        merger.merge(ImportResult(profiles: [vless]))

        XCTAssertEqual(merger.profiles.count, 2, "a different protocol is a different node")
    }

    func testPreferredMatchIsSelectedProfileThenGroupReferenced() {
        let duplicateA = trojanProfile(name: "Tokyo", host: "jp.example.com")
        let duplicateB = trojanProfile(name: "Tokyo", host: "jp.example.com")
        let duplicateC = trojanProfile(name: "Tokyo", host: "jp.example.com")
        let group = ProxyGroup(name: "Auto", type: .urlTest, members: [.profile(duplicateB.id)], importedType: "url-test")

        // Selected duplicate wins even when it is not first or group-referenced.
        var selectedMerger = SubscriptionRefreshMerger(
            profiles: [duplicateA, duplicateB, duplicateC],
            groups: [group],
            selectedTarget: .profile(duplicateC.id),
        )
        selectedMerger.merge(ImportResult(profiles: [trojanProfile(name: "Tokyo", host: "jp.example.com")]))
        XCTAssertEqual(selectedMerger.profiles.map(\.id), [duplicateC.id])
        XCTAssertEqual(selectedMerger.selectedTarget, .profile(duplicateC.id))

        // Without a selected duplicate, the group-referenced one wins and group
        // references survive the dedup.
        var referencedMerger = SubscriptionRefreshMerger(
            profiles: [duplicateA, duplicateB, duplicateC],
            groups: [group],
            selectedTarget: nil,
        )
        referencedMerger.merge(ImportResult(profiles: [trojanProfile(name: "Tokyo", host: "jp.example.com")]))
        XCTAssertEqual(referencedMerger.profiles.map(\.id), [duplicateB.id])
        XCTAssertEqual(referencedMerger.groups.first?.members, [.profile(duplicateB.id)])
    }

    func testSelectedTargetIsRemappedWhenItsProfileIsCollapsed() {
        let kept = trojanProfile(name: "Tokyo", host: "jp.example.com")
        let duplicate = trojanProfile(name: "Tokyo", host: "jp.example.com")
        let group = ProxyGroup(name: "Auto", type: .urlTest, members: [.profile(kept.id)], importedType: "url-test")
        var merger = SubscriptionRefreshMerger(
            profiles: [kept, duplicate],
            groups: [group],
            selectedTarget: .profile(duplicate.id),
        )

        // Neither duplicate is "selected" by identity preference here: the
        // selected one is `duplicate`, so it wins and `kept` collapses into it.
        merger.merge(ImportResult(profiles: [trojanProfile(name: "Tokyo", host: "jp.example.com")]))

        XCTAssertEqual(merger.profiles.map(\.id), [duplicate.id])
        XCTAssertEqual(merger.selectedTarget, .profile(duplicate.id))
        XCTAssertEqual(merger.groups.first?.members, [.profile(duplicate.id)], "group reference follows the collapse")
    }

    // MARK: - Security downgrade protection

    /// A subscription response is attacker-controllable; a refresh that matches
    /// an existing node by name must not silently disable its certificate
    /// verification.
    func testRefreshCannotSilentlyEnableAllowInsecure() throws {
        let subscriptionID = UUID()
        let existing = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscriptionID)
        var weakened = trojanProfile(name: "Tokyo", host: "new.example.com", subscriptionID: subscriptionID)
        weakened.security.tls?.allowInsecure = true
        var merger = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)

        merger.merge(ImportResult(profiles: [weakened]))

        let merged = try XCTUnwrap(merger.profiles.first)
        XCTAssertEqual(merged.id, existing.id)
        XCTAssertEqual(merged.endpoint.host, "new.example.com", "non-security updates still apply")
        XCTAssertEqual(merged.security.tls?.allowInsecure, false, "verification must stay enabled")
        XCTAssertEqual(merger.securityDowngradeWarnings.count, 1)
    }

    func testRefreshCannotSilentlyStripTLSLayer() throws {
        let subscriptionID = UUID()
        let existing = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscriptionID)
        var stripped = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscriptionID)
        stripped.security = .none
        var merger = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)

        merger.merge(ImportResult(profiles: [stripped]))

        let merged = try XCTUnwrap(merger.profiles.first)
        XCTAssertEqual(merged.security, existing.security, "the TLS layer must survive the refresh")
        XCTAssertEqual(merger.securityDowngradeWarnings.count, 1)
    }

    /// REALITY also resists active probing; demoting a node to plain TLS (with
    /// verification still on) is a downgrade a subscription must not push
    /// silently.
    func testRefreshCannotSilentlyDemoteRealityToTLS() throws {
        let subscriptionID = UUID()
        var existing = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscriptionID)
        existing.security = .reality(RealityOptions(publicKey: "PUBLICKEY", shortID: "abcd", serverName: "jp.example.com"))
        let demoted = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscriptionID)
        var merger = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)

        merger.merge(ImportResult(profiles: [demoted]))

        let merged = try XCTUnwrap(merger.profiles.first)
        XCTAssertEqual(merged.security.layer, .reality, "the REALITY layer must survive the refresh")
        XCTAssertEqual(merged.security, existing.security)
        XCTAssertEqual(merger.securityDowngradeWarnings.count, 1)

        // Automatic refreshes preserve the existing layer even when the
        // provider calls the change an upgrade; the user must review which
        // server-authentication mechanism is replacing TLS.
        var upgradeMerger = SubscriptionRefreshMerger(profiles: [demoted], groups: [], selectedTarget: nil)
        upgradeMerger.merge(ImportResult(profiles: [existing]))
        XCTAssertEqual(upgradeMerger.profiles.first?.security.layer, .tls)
        XCTAssertFalse(upgradeMerger.securityDowngradeWarnings.isEmpty)
    }

    func testRefreshStillAppliesLegitimateSecurityUpgrade() throws {
        let subscriptionID = UUID()
        var existing = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscriptionID)
        existing.security.tls?.allowInsecure = true
        let hardened = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscriptionID)
        var merger = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)

        merger.merge(ImportResult(profiles: [hardened]))

        let merged = try XCTUnwrap(merger.profiles.first)
        XCTAssertEqual(merged.security.tls?.allowInsecure, false, "turning verification on is not a downgrade")
        XCTAssertTrue(merger.securityDowngradeWarnings.isEmpty)
    }

    func testDetectsAndPreservesAllPinnedSecurityChangeCategories() throws {
        let subscriptionID = UUID()
        var existing = ProxyProfile(
            name: "Tokyo",
            endpoint: Endpoint(host: "old.example.com", port: 443),
            options: .vless(VLESSOptions(uuid: "user", flow: "xtls-rprx-vision", encryption: "old-auth")),
            security: .reality(RealityOptions(
                publicKey: "OLD-REALITY",
                shortID: "abcd",
                serverName: "old.example.com",
                mldsa65Verify: "OLD-MLDSA",
            )),
            subscriptionID: subscriptionID,
        )
        existing.security.tls?.pinnedPeerCertSHA256 = "OLD-PIN"
        existing.security.tls?.verifyPeerCertByName = "old.example.com"
        existing.security.tls?.echConfigList = "OLD-ECH"
        existing.security.tls?.curvePreferences = ["X25519MLKEM768", "X25519"]
        existing.security.tls?.minVersion = "1.3"

        var imported = existing
        imported.id = UUID()
        imported.endpoint = Endpoint(host: "new.example.com", port: 443)
        imported.options = .vless(VLESSOptions(uuid: "user", flow: "xtls-rprx-vision", encryption: "new-auth"))
        imported.security.reality?.publicKey = "NEW-REALITY"
        imported.security.reality?.mldsa65Verify = "NEW-MLDSA"
        imported.security.tls?.pinnedPeerCertSHA256 = "NEW-PIN"
        imported.security.tls?.verifyPeerCertByName = "new.example.com"
        imported.security.tls?.echConfigList = "NEW-ECH"
        imported.security.tls?.curvePreferences = ["X25519Kyber768Draft00", "X25519"]
        imported.security.tls?.minVersion = "1.2"

        let preview = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)
        let changes = try XCTUnwrap(preview.securityCriticalChanges(in: [imported]).first)
        XCTAssertEqual(changes.profileName, "Tokyo")
        XCTAssertEqual(Set(changes.fields), Set([
            .tlsMinimumVersion,
            .certificatePins,
            .verificationNames,
            .ech,
            .postQuantumCurves,
            .vlessEncryption,
            .realityPublicKey,
            .realityMLDSA,
        ]))

        var automatic = preview
        automatic.merge(ImportResult(profiles: [imported]))
        let preserved = try XCTUnwrap(automatic.profiles.first)
        XCTAssertEqual(preserved.security.tls?.minVersion, "1.3")
        XCTAssertEqual(preserved.security.tls?.pinnedPeerCertSHA256, "OLD-PIN")
        XCTAssertEqual(preserved.security.tls?.verifyPeerCertByName, "old.example.com")
        XCTAssertEqual(preserved.security.tls?.echConfigList, "OLD-ECH")
        XCTAssertEqual(preserved.security.tls?.curvePreferences, ["X25519MLKEM768", "X25519"])
        XCTAssertEqual(preserved.security.reality?.publicKey, "OLD-REALITY")
        XCTAssertEqual(preserved.security.reality?.mldsa65Verify, "OLD-MLDSA")
        guard case let .vless(preservedVLESS) = preserved.options else {
            return XCTFail("Expected VLESS options")
        }
        XCTAssertEqual(preservedVLESS.encryption, "old-auth")

        var reviewed = preview
        reviewed.merge(ImportResult(profiles: [imported]), securityPolicy: .applyReviewedChanges)
        let applied = try XCTUnwrap(reviewed.profiles.first)
        XCTAssertEqual(applied.security.tls?.minVersion, "1.2")
        XCTAssertEqual(applied.security.tls?.pinnedPeerCertSHA256, "NEW-PIN")
        XCTAssertEqual(applied.security.reality?.publicKey, "NEW-REALITY")
        XCTAssertEqual(applied.security.reality?.mldsa65Verify, "NEW-MLDSA")
        guard case let .vless(appliedVLESS) = applied.options else {
            return XCTFail("Expected VLESS options")
        }
        XCTAssertEqual(appliedVLESS.encryption, "new-auth")
    }

    func testSecurityLayerChangeRequiresReviewAndReviewedPolicyAppliesIt() throws {
        let subscriptionID = UUID()
        let existing = trojanProfile(name: "Tokyo", host: "old.example.com", subscriptionID: subscriptionID)
        var imported = trojanProfile(name: "Tokyo", host: "new.example.com", subscriptionID: subscriptionID)
        imported.security = .reality(RealityOptions(
            publicKey: "NEW-REALITY",
            shortID: "abcd",
            serverName: "new.example.com",
        ))
        let preview = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)

        let changes = try XCTUnwrap(preview.securityCriticalChanges(in: [imported]).first)
        XCTAssertTrue(changes.fields.contains(.securityLayer))

        var reviewed = preview
        reviewed.merge(
            ImportResult(profiles: [imported]),
            securityPolicy: .applyReviewedChanges,
        )
        XCTAssertEqual(reviewed.profiles.first?.security.layer, .reality)
        XCTAssertEqual(reviewed.profiles.first?.security.reality?.publicKey, "NEW-REALITY")
    }

    func testReviewedSecurityChangeStillCannotEnableAllowInsecure() throws {
        let subscriptionID = UUID()
        let existing = trojanProfile(name: "Tokyo", host: "old.example.com", subscriptionID: subscriptionID)
        var imported = trojanProfile(name: "Tokyo", host: "new.example.com", subscriptionID: subscriptionID)
        imported.security.tls?.allowInsecure = true
        imported.security.tls?.pinnedPeerCertSHA256 = "NEW-PIN"
        var merger = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)

        merger.merge(
            ImportResult(profiles: [imported]),
            securityPolicy: .applyReviewedChanges,
        )

        let merged = try XCTUnwrap(merger.profiles.first)
        XCTAssertEqual(merged.security.tls?.allowInsecure, false)
        XCTAssertEqual(merged.security.tls?.pinnedPeerCertSHA256, "NEW-PIN")
    }

    func testReviewedLayerChangeCannotIntroduceAllowInsecure() throws {
        let subscriptionID = UUID()
        var existing = trojanProfile(name: "Tokyo", host: "old.example.com", subscriptionID: subscriptionID)
        existing.security = .none
        var imported = trojanProfile(name: "Tokyo", host: "new.example.com", subscriptionID: subscriptionID)
        imported.security.tls?.allowInsecure = true
        var merger = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)

        merger.merge(
            ImportResult(profiles: [imported]),
            securityPolicy: .applyReviewedChanges,
        )

        let merged = try XCTUnwrap(merger.profiles.first)
        XCTAssertEqual(merged.security.layer, .tls)
        XCTAssertEqual(merged.security.tls?.allowInsecure, false)
    }

    @MainActor
    func testManualRefreshBlocksThenAppliesReviewedSecurityChanges() {
        let subscription = SubscriptionSource(name: "Provider", url: "https://example.com/sub")
        var existing = trojanProfile(name: "Tokyo", host: "old.example.com", subscriptionID: subscription.id)
        existing.security.tls?.pinnedPeerCertSHA256 = "OLD-PIN"
        var imported = trojanProfile(name: "Tokyo", host: "new.example.com", subscriptionID: subscription.id)
        imported.security.tls?.pinnedPeerCertSHA256 = "NEW-PIN"
        let store = HopStore(
            profiles: [existing],
            groups: [],
            subscriptions: [subscription],
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )

        let outcome = store.reviewSubscriptionRefresh(ImportResult(profiles: [imported]), for: subscription)
        guard case let .needsSecurityConfirmation(result, changes, reviewedInsecureProfileNames) = outcome else {
            return XCTFail("Expected a blocking security confirmation")
        }
        XCTAssertTrue(reviewedInsecureProfileNames.isEmpty)
        XCTAssertEqual(changes.map(\.fields), [[.certificatePins]])
        XCTAssertEqual(store.profiles.first?.security.tls?.pinnedPeerCertSHA256, "OLD-PIN")

        let confirmed = store.confirmSecuritySubscriptionRefresh(
            result,
            reviewedChanges: changes,
            reviewedInsecureProfileNames: reviewedInsecureProfileNames,
            for: subscription,
        )
        guard case .applied = confirmed else {
            return XCTFail("Expected confirmed refresh to apply")
        }
        XCTAssertEqual(store.profiles.first?.endpoint.host, "new.example.com")
        XCTAssertEqual(store.profiles.first?.security.tls?.pinnedPeerCertSHA256, "NEW-PIN")
    }

    @MainActor
    func testManualRefreshRequiresBothConfirmationsWhenBothRisksArePresent() {
        let subscription = SubscriptionSource(name: "Provider", url: "https://example.com/sub")
        var existing = trojanProfile(name: "Tokyo", host: "old.example.com", subscriptionID: subscription.id)
        existing.security.tls?.pinnedPeerCertSHA256 = "OLD-PIN"
        var changed = trojanProfile(name: "Tokyo", host: "new.example.com", subscriptionID: subscription.id)
        changed.security.tls?.pinnedPeerCertSHA256 = "NEW-PIN"
        let insecure = insecureTrojanProfile(name: "Legacy", subscriptionID: subscription.id)
        let store = HopStore(
            profiles: [existing],
            subscriptions: [subscription],
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )

        let initial = store.reviewSubscriptionRefresh(
            ImportResult(profiles: [changed, insecure]),
            for: subscription,
        )
        guard case let .needsInsecureConfirmation(result, names) = initial else {
            return XCTFail("Expected allow-insecure confirmation first")
        }
        XCTAssertEqual(names, ["Legacy"])

        let afterInsecure = store.confirmInsecureSubscriptionRefresh(
            result,
            reviewedProfileNames: names,
            for: subscription,
        )
        guard case let .needsSecurityConfirmation(reviewResult, changes, reviewedNames) = afterInsecure else {
            return XCTFail("Expected the independent security-change confirmation")
        }
        XCTAssertEqual(reviewedNames, names)
        XCTAssertEqual(changes.map(\.fields), [[.certificatePins]])
        XCTAssertEqual(store.profiles.count, 1, "nothing applies between the two confirmations")

        let applied = store.confirmSecuritySubscriptionRefresh(
            reviewResult,
            reviewedChanges: changes,
            reviewedInsecureProfileNames: reviewedNames,
            for: subscription,
        )
        guard case .applied = applied else {
            return XCTFail("Expected the twice-reviewed refresh to apply")
        }
        XCTAssertEqual(store.profiles.count, 2)
        XCTAssertEqual(store.profiles.first { $0.name == "Tokyo" }?.security.tls?.pinnedPeerCertSHA256, "NEW-PIN")
        XCTAssertEqual(store.profiles.first { $0.name == "Legacy" }?.security.tls?.allowInsecure, true)
    }

    func testImportedGroupWithoutImportedTypeAlwaysInserts() {
        let existing = ProxyGroup(name: "Manual", type: .select, members: [.direct])
        var merger = SubscriptionRefreshMerger(profiles: [], groups: [existing], selectedTarget: nil)

        merger.merge(ImportResult(groups: [ProxyGroup(name: "Manual", type: .select, members: [.direct])]))

        XCTAssertEqual(merger.groups.count, 2, "hand-made groups (no importedType) are never refresh-matched")
    }

    func testRemappedGroupDefaultTargetFallsBackToFirstMember() throws {
        let member = trojanProfile(name: "Tokyo", host: "jp.example.com")
        let stranger = trojanProfile(name: "Osaka", host: "osa.example.com")
        let imported = ProxyGroup(
            name: "Auto",
            type: .urlTest,
            members: [.profile(member.id)],
            defaultTarget: .profile(stranger.id),
            importedType: "url-test",
        )
        var merger = SubscriptionRefreshMerger(profiles: [], groups: [], selectedTarget: nil)

        merger.merge(ImportResult(profiles: [member], groups: [imported]))

        let group = try XCTUnwrap(merger.groups.first)
        XCTAssertEqual(group.defaultTarget, .profile(member.id), "default outside members falls back to first member")
    }

    @MainActor
    func testRefreshPersistsAFixedNumberOfTimesRegardlessOfNodeCount() {
        let backend = InMemorySecretBackend()
        let store = HopStore(
            profiles: [trojanProfile(name: "Existing", host: "e.example.com")],
            groups: [],
            subscriptions: [],
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: SecretStore(backend: backend), authenticationStore: .inMemory()),
        )
        // init may normalize the selected target, which enqueues a save of its
        // own; settle it before taking the baseline.
        store.flushPendingPersists()
        let baseline = backend.allKeysCount

        let imported = (0 ..< 25).map { trojanProfile(name: "Node \($0)", host: "n\($0).example.com") }
        store.applySubscriptionRefresh(ImportResult(profiles: imported))
        store.flushPendingPersists()

        XCTAssertEqual(store.profiles.count, 26)
        // The whole refresh is one batched persist, not one per mutated
        // property or per imported node.
        XCTAssertEqual(backend.allKeysCount - baseline, 1)
    }

    /// A refresh applies without a preview, so routing rules in the response
    /// must be ignored — a malicious subscription could otherwise prepend rules
    /// that re-route chosen domains through an outbound it controls.
    @MainActor
    func testRefreshDoesNotInjectRoutingRulesIntoActiveConfiguration() {
        let store = HopStore(
            profiles: [trojanProfile(name: "Existing", host: "e.example.com")],
            groups: [],
            subscriptions: [],
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )
        let rulesBefore = store.ruleConfigurations.map(\.rules)

        store.applySubscriptionRefresh(ImportResult(
            profiles: [trojanProfile(name: "Existing", host: "n.example.com")],
            rules: [RoutingRule(kind: .domainSuffix, value: "bank.example", target: .direct)],
        ))

        XCTAssertEqual(store.ruleConfigurations.map(\.rules), rulesBefore, "refresh rules must not touch rule configurations")
    }

    @MainActor
    func testInitWithCleanStateDoesNotPersist() {
        let backend = InMemorySecretBackend()
        let url = tempStateURL()
        let store = HopStore(dataStore: HopAppDataStore(url: url, secretStore: SecretStore(backend: backend), authenticationStore: .inMemory()))
        store.flushPendingPersists()

        XCTAssertEqual(backend.allKeysCount, 0, "launching with consistent state must not rewrite it")
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
    }

    private func tempStateURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("hop-merger-tests-\(UUID().uuidString)")
            .appendingPathComponent("hop-state.json")
    }

    // MARK: - newInsecureProfileNames

    func testNewInsecureProfileNamesFlagsBrandNewInsecureProfile() {
        let brandNew = insecureTrojanProfile(name: "Evil")
        let names = SubscriptionRefreshMerger.newInsecureProfileNames(existing: [], imported: [brandNew])
        XCTAssertEqual(names, ["Evil"], "a brand-new allow-insecure profile must be flagged")
    }

    func testNewInsecureProfileNamesSanitizesNamesForConfirmationAlert() {
        let rawName = "Safe\u{202E}" + String(repeating: "x", count: ImportPolicy.maxImportedNameLength + 20)
        let names = SubscriptionRefreshMerger.newInsecureProfileNames(existing: [], imported: [insecureTrojanProfile(name: rawName)])

        XCTAssertEqual(names, [ImportPolicy.sanitizeImportedName(rawName, fallback: "Imported Node")])
        XCTAssertFalse(names[0].unicodeScalars.contains { $0 == "\u{202E}" })
        XCTAssertLessThanOrEqual(names[0].count, ImportPolicy.maxImportedNameLength)
    }

    @MainActor
    func testConfirmedInsecureRefreshSanitizesProfileNamesBeforeSaving() throws {
        let rawName = "Saved\u{202E}" + String(repeating: "x", count: ImportPolicy.maxImportedNameLength + 20)
        let subscription = SubscriptionSource(name: "Sub", url: "https://example.com/sub")
        let store = HopStore(
            subscriptions: [subscription],
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )

        store.confirmInsecureSubscriptionRefresh(
            ImportResult(profiles: [insecureTrojanProfile(name: rawName, subscriptionID: subscription.id)]),
            reviewedProfileNames: [ImportPolicy.sanitizeImportedName(rawName, fallback: "Imported Node")],
            for: subscription,
        )

        let savedName = try XCTUnwrap(store.profiles.first?.name)
        XCTAssertEqual(savedName, ImportPolicy.sanitizeImportedName(rawName, fallback: "Imported Node"))
        XCTAssertFalse(savedName.unicodeScalars.contains { $0 == "\u{202E}" })
        XCTAssertLessThanOrEqual(savedName.count, ImportPolicy.maxImportedNameLength)
    }

    func testNewInsecureProfileNamesDoesNotFlagProfileMatchingExistingInsecureByIdentity() {
        let existing = insecureTrojanProfile(name: "Tokyo")
        // exact refresh identity: same name/host/port/proto/options/security/transport
        let imported = existing
        let names = SubscriptionRefreshMerger.newInsecureProfileNames(existing: [existing], imported: [imported])
        XCTAssertTrue(names.isEmpty, "exact-identity match against an already-insecure existing profile must not be flagged")
    }

    func testNewInsecureProfileNamesDoesNotFlagProfileMatchingExistingInsecureByNameAndProto() {
        let subscriptionID = UUID()
        let existing = insecureTrojanProfile(name: "Tokyo", subscriptionID: subscriptionID)
        var changed = insecureTrojanProfile(name: " tokyo ", subscriptionID: subscriptionID) // same name (trimmed+lowercased), same proto, different host
        changed.endpoint = Endpoint(host: "new.example.com", port: 443)
        let names = SubscriptionRefreshMerger.newInsecureProfileNames(existing: [existing], imported: [changed])
        XCTAssertTrue(names.isEmpty, "name+proto match against an existing already-insecure profile must not be flagged")
    }

    func testNewInsecureProfileNamesDoesNotFlagSecureImportedProfiles() {
        let existing = trojanProfile(name: "Tokyo", host: "jp.example.com")
        let imported = trojanProfile(name: "Berlin", host: "de.example.com")
        let names = SubscriptionRefreshMerger.newInsecureProfileNames(existing: [existing], imported: [imported])
        XCTAssertTrue(names.isEmpty, "a secure imported profile must never be flagged")
    }

    /// An imported allow-insecure profile that name+proto-matches an EXISTING
    /// SECURE profile is not flagged: the merge updates the matched profile and
    /// `securityPreservingDowngrades` blocks the allowInsecure flip (logging a
    /// refusal), so no node ends up newly insecure and prompting the user would
    /// describe an outcome that cannot happen.
    func testNewInsecureProfileNamesDoesNotFlagImportedInsecureWhenExistingMatchIsSecure() throws {
        let subscriptionID = UUID()
        let existing = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscriptionID)
        var imported = insecureTrojanProfile(name: "Tokyo", subscriptionID: subscriptionID) // name matches existing (secure)
        imported.endpoint = Endpoint(host: "new.example.com", port: 443)
        let names = SubscriptionRefreshMerger.newInsecureProfileNames(existing: [existing], imported: [imported])
        XCTAssertTrue(names.isEmpty, "a name+proto match is flip-guarded by the merge, so it is not a NEW insecure node")

        // And the companion guarantee: the merge indeed refuses the flip.
        var merger = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)
        merger.merge(ImportResult(profiles: [imported]))
        let merged = try XCTUnwrap(merger.profiles.first)
        XCTAssertEqual(merged.security.tls?.allowInsecure, false, "securityPreservingDowngrades must block the allowInsecure flip for the matched profile")
        XCTAssertFalse(merger.securityDowngradeWarnings.isEmpty, "the refusal must be recorded as a warning")
    }

    // MARK: - REALITY public-key change warning

    func testAutomaticMergePreservesRealityPublicKeyAndAppendsWarning() throws {
        let subscriptionID = UUID()
        var existing = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscriptionID)
        existing.security = .reality(RealityOptions(publicKey: "OLDKEY", shortID: "abcd"))
        var imported = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscriptionID)
        imported.security = .reality(RealityOptions(publicKey: "NEWKEY", shortID: "abcd"))
        var merger = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)

        merger.merge(ImportResult(profiles: [imported]))

        let merged = try XCTUnwrap(merger.profiles.first)
        XCTAssertEqual(merged.security.reality?.publicKey, "OLDKEY", "an unreviewed refresh must keep the existing REALITY key")
        XCTAssertEqual(merger.securityDowngradeWarnings.count, 1)
        XCTAssertTrue(merger.securityDowngradeWarnings[0].contains("Tokyo"), "warning must name the profile")
        XCTAssertTrue(merger.securityDowngradeWarnings[0].lowercased().contains("reality") || merger.securityDowngradeWarnings[0].lowercased().contains("public key"), "warning must mention the REALITY key change")
    }

    func testRealityPublicKeyUnchangedProducesNoWarning() {
        let subscriptionID = UUID()
        var existing = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscriptionID)
        existing.security = .reality(RealityOptions(publicKey: "SAMEKEY", shortID: "abcd"))
        var imported = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscriptionID)
        imported.security = .reality(RealityOptions(publicKey: "SAMEKEY", shortID: "abcd"))
        var merger = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)

        merger.merge(ImportResult(profiles: [imported]))

        XCTAssertTrue(merger.securityDowngradeWarnings.isEmpty, "no warning when REALITY public key is unchanged")
    }

    // MARK: - Helpers

    private func trojanProfile(name: String, host: String, subscriptionID: UUID? = nil) -> ProxyProfile {
        ProxyProfile(
            name: name,
            endpoint: Endpoint(host: host, port: 443),
            options: .trojan(TrojanOptions(password: "secret")),
            security: .tls(TLSOptions(serverName: host)),
            subscriptionID: subscriptionID,
        )
    }

    private func insecureTrojanProfile(name: String, subscriptionID: UUID? = nil) -> ProxyProfile {
        ProxyProfile(
            name: name,
            endpoint: Endpoint(host: "jp.example.com", port: 443),
            options: .trojan(TrojanOptions(password: "secret")),
            security: .tls(TLSOptions(serverName: "jp.example.com", allowInsecure: true)),
            subscriptionID: subscriptionID,
        )
    }
}
