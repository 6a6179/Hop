@testable import Hop
import XCTest

final class HopAppDataStoreTests: XCTestCase {
    private func tempStateURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("hop-tests-\(UUID().uuidString)")
            .appendingPathComponent("hop-state.json")
    }

    func testRoundTripsProfilesGroupsSubscriptionsRulesSettingsAndLogs() throws {
        let url = tempStateURL()
        let store = HopAppDataStore(url: url, secretStore: .inMemory())
        let data = HopAppData(
            profiles: SampleData.profiles,
            groups: SampleData.groups,
            subscriptions: [
                SubscriptionSource(
                    name: "Round Trip",
                    url: "https://example.com/sub",
                    lastUpdatedAt: Date(timeIntervalSince1970: 1_800_000_000),
                    lastImportSummary: "3 nodes, 2 groups",
                ),
            ],
            routingMode: .rule,
            selectedTarget: .group(SampleData.proxyGroup.id),
            settings: AppSettings(
                appearance: .dark,
                logLevel: .debug,
                dnsPreset: .quad9,
                dnsStrategy: .ipv6Only,
                proxyDNS: false,
                sniffTraffic: false,
                strictRoute: false,
                logRetention: .oneThousand,
            ),
            logs: ["one", "two"],
            ruleConfigurations: SampleData.ruleConfigurations,
            activeRuleConfigurationID: SampleData.defaultConfiguration.id,
        )

        store.save(data)
        let loaded = try XCTUnwrap(store.load())

        XCTAssertEqual(loaded.profiles, data.profiles)
        XCTAssertEqual(loaded.groups, data.groups)
        XCTAssertEqual(loaded.subscriptions, data.subscriptions)
        XCTAssertEqual(loaded.ruleConfigurations, data.ruleConfigurations)
        XCTAssertEqual(loaded.activeRuleConfigurationID, data.activeRuleConfigurationID)
        XCTAssertEqual(loaded.routingMode, .rule)
        XCTAssertEqual(loaded.selectedTarget, .group(SampleData.proxyGroup.id))
        XCTAssertEqual(loaded.settings, data.settings)
        XCTAssertEqual(loaded.logs, ["one", "two"])
    }

    func testKillSwitchSettingRoundTrips() throws {
        var settings = AppSettings.defaults
        XCTAssertFalse(settings.killSwitch, "kill switch must default off")
        settings.killSwitch = true

        let encoded = try JSONEncoder().encode(settings)
        let decoded = try JSONDecoder().decode(AppSettings.self, from: encoded)
        XCTAssertTrue(decoded.killSwitch)
    }

    func testSettingsDecodeWithoutKillSwitchDefaultsOff() throws {
        // State written by a build predating the kill switch has no such key;
        // the field-by-field decode must fall back to the default, not fail.
        let legacyJSON = #"{"appearance":"dark","logLevel":"info"}"#
        let decoded = try JSONDecoder().decode(AppSettings.self, from: Data(legacyJSON.utf8))
        XCTAssertFalse(decoded.killSwitch)
        XCTAssertEqual(decoded.appearance, .dark)
    }

    @MainActor
    func testStoreUpdatesSubscriptionMetadata() {
        let subscription = SubscriptionSource(name: "Airport", url: "https://example.com/sub")
        let store = HopStore(
            subscriptions: [subscription],
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory()),
        )

        var updated = subscription
        updated.lastUpdatedAt = Date(timeIntervalSince1970: 1_800_000_001)
        updated.lastImportSummary = "4 nodes"

        store.updateSubscription(updated)

        XCTAssertEqual(store.subscriptions.first, updated)
    }

    @MainActor
    func testSubscriptionRefreshUpdatesMatchingProfileInsteadOfDuplicating() throws {
        let existing = trojanProfile(
            id: UUID(),
            name: "Tokyo",
            host: "old.example.com",
            password: "old-password",
        )
        let refreshed = trojanProfile(
            id: UUID(),
            name: "Tokyo",
            host: "new.example.com",
            password: "new-password",
        )
        let store = HopStore(
            profiles: [existing],
            groups: [],
            subscriptions: [],
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory()),
        )

        store.applySubscriptionRefresh(ImportResult(profiles: [refreshed]))

        XCTAssertEqual(store.profiles.count, 1)
        let profile = try XCTUnwrap(store.profiles.first)
        XCTAssertEqual(profile.id, existing.id)
        XCTAssertEqual(profile.endpoint.host, "new.example.com")
        XCTAssertEqual(profile.options, refreshed.options)
    }

    @MainActor
    func testSubscriptionRefreshDeduplicatesProfilesAndPreservesGroupReferences() throws {
        let keptProfile = trojanProfile(id: UUID(), name: "Tokyo", host: "jp.example.com", password: "secret")
        let duplicateProfile = trojanProfile(id: UUID(), name: "Tokyo", host: "jp.example.com", password: "secret")
        let existingGroup = ProxyGroup(
            name: "Auto",
            type: .urlTest,
            members: [.profile(keptProfile.id)],
            defaultTarget: .profile(keptProfile.id),
            importedType: "url-test",
        )
        let importedProfile = trojanProfile(id: UUID(), name: "Tokyo", host: "jp.example.com", password: "secret")
        let importedGroup = ProxyGroup(
            name: "Auto",
            type: .urlTest,
            members: [.profile(importedProfile.id)],
            defaultTarget: .profile(importedProfile.id),
            importedType: "url-test",
        )
        let store = HopStore(
            profiles: [duplicateProfile, keptProfile],
            groups: [existingGroup],
            subscriptions: [],
            selectedTarget: .group(existingGroup.id),
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory()),
        )

        store.applySubscriptionRefresh(ImportResult(profiles: [importedProfile], groups: [importedGroup]))

        XCTAssertEqual(store.profiles.map(\.id), [keptProfile.id])
        XCTAssertEqual(store.groups.count, 1)
        let group = try XCTUnwrap(store.groups.first)
        XCTAssertEqual(group.id, existingGroup.id)
        XCTAssertEqual(group.members, [.profile(keptProfile.id)])
        XCTAssertEqual(group.defaultTarget, .profile(keptProfile.id))
        XCTAssertEqual(store.selectedTarget, .group(existingGroup.id))
    }

    private func trojanProfile(id: UUID, name: String, host: String, password: String) -> ProxyProfile {
        ProxyProfile(
            id: id,
            name: name,
            endpoint: Endpoint(host: host, port: 443),
            proto: .trojan,
            options: .trojan(TrojanOptions(password: password)),
            security: .tls(TLSOptions(serverName: host)),
        )
    }
}
