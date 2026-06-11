@testable import Hop
import XCTest

/// Behavior of the subscription-refresh merge: identity matching, preferred
/// duplicate selection, reference remapping, and the persist batching the
/// extraction exists for.
final class SubscriptionRefreshMergerTests: XCTestCase {
    func testNameAndProtocolMatchUpdatesProfileInPlace() {
        let existing = trojanProfile(name: "Tokyo", host: "old.example.com")
        var merger = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)

        merger.merge(ImportResult(profiles: [trojanProfile(name: " tokyo ", host: "new.example.com")]))

        XCTAssertEqual(merger.profiles.map(\.id), [existing.id], "name match is trimmed + case-insensitive")
        XCTAssertEqual(merger.profiles.first?.endpoint.host, "new.example.com")
    }

    func testNameMatchRequiresSameProtocol() {
        let existing = trojanProfile(name: "Tokyo", host: "jp.example.com")
        var merger = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)

        let vless = ProxyProfile(
            name: "Tokyo",
            endpoint: Endpoint(host: "jp.example.com", port: 443),
            proto: .vless,
            options: .vless(VLESSOptions(uuid: "u", flow: nil)),
            security: .none,
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
        let existing = trojanProfile(name: "Tokyo", host: "jp.example.com")
        var weakened = trojanProfile(name: "Tokyo", host: "new.example.com")
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
        let existing = trojanProfile(name: "Tokyo", host: "jp.example.com")
        var stripped = trojanProfile(name: "Tokyo", host: "jp.example.com")
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
        var existing = trojanProfile(name: "Tokyo", host: "jp.example.com")
        existing.security = .reality(RealityOptions(publicKey: "PUBLICKEY", shortID: "abcd", serverName: "jp.example.com"))
        let demoted = trojanProfile(name: "Tokyo", host: "jp.example.com")
        var merger = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)

        merger.merge(ImportResult(profiles: [demoted]))

        let merged = try XCTUnwrap(merger.profiles.first)
        XCTAssertEqual(merged.security.layer, .reality, "the REALITY layer must survive the refresh")
        XCTAssertEqual(merged.security, existing.security)
        XCTAssertEqual(merger.securityDowngradeWarnings.count, 1)

        // …but moving up to REALITY is an upgrade and applies.
        var upgradeMerger = SubscriptionRefreshMerger(profiles: [demoted], groups: [], selectedTarget: nil)
        upgradeMerger.merge(ImportResult(profiles: [existing]))
        XCTAssertEqual(upgradeMerger.profiles.first?.security.layer, .reality)
        XCTAssertTrue(upgradeMerger.securityDowngradeWarnings.isEmpty)
    }

    func testRefreshStillAppliesLegitimateSecurityUpgrade() throws {
        var existing = trojanProfile(name: "Tokyo", host: "jp.example.com")
        existing.security.tls?.allowInsecure = true
        let hardened = trojanProfile(name: "Tokyo", host: "jp.example.com")
        var merger = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)

        merger.merge(ImportResult(profiles: [hardened]))

        let merged = try XCTUnwrap(merger.profiles.first)
        XCTAssertEqual(merged.security.tls?.allowInsecure, false, "turning verification on is not a downgrade")
        XCTAssertTrue(merger.securityDowngradeWarnings.isEmpty)
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
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: SecretStore(backend: backend)),
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
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory()),
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
        let store = HopStore(dataStore: HopAppDataStore(url: url, secretStore: SecretStore(backend: backend)))
        store.flushPendingPersists()

        XCTAssertEqual(backend.allKeysCount, 0, "launching with consistent state must not rewrite it")
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
    }

    private func tempStateURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("hop-merger-tests-\(UUID().uuidString)")
            .appendingPathComponent("hop-state.json")
    }

    private func trojanProfile(name: String, host: String) -> ProxyProfile {
        ProxyProfile(
            name: name,
            endpoint: Endpoint(host: host, port: 443),
            proto: .trojan,
            options: .trojan(TrojanOptions(password: "secret")),
            security: .tls(TLSOptions(serverName: host)),
        )
    }
}
