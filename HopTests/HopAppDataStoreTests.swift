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
}
