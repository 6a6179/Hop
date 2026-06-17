@testable import Hop
import XCTest

final class RuleConfigurationTests: XCTestCase {
    private let builder = SingBoxConfigBuilder()

    private func tempStateURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("hop-config-tests-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("hop-state.json")
    }

    // MARK: - Generated configuration contents

    func testDefaultConfigurationBypassesAppleSystemServices() throws {
        let rule = try XCTUnwrap(
            RuleConfiguration.defaultConfiguration.rules.first {
                $0.kind == .domainSuffix && $0.target == .direct && $0.value.contains("push.apple.com")
            },
        )

        let suffixes = Set(rule.value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) })
        XCTAssertTrue(suffixes.contains("push.apple.com"))
        XCTAssertTrue(suffixes.contains("apple.com"))
        XCTAssertTrue(suffixes.contains("icloud.com"))
        XCTAssertTrue(suffixes.contains("icloud-content.com"))
        XCTAssertTrue(suffixes.contains("mzstatic.com"))
        XCTAssertTrue(suffixes.contains("apple-dns.net"))
    }

    func testChinaConfigurationBypassesChinaAndBlocksAds() {
        let rules = RuleConfiguration.china().rules
        XCTAssertTrue(rules.contains { $0.kind == .geoSite && $0.value == "cn" && $0.target == .direct })
        XCTAssertTrue(rules.contains { $0.kind == .geoIP && $0.value == "cn" && $0.target == .direct })
        XCTAssertTrue(rules.contains { $0.kind == .geoIP && $0.value == "private" && $0.target == .direct })
        XCTAssertTrue(rules.contains { $0.kind == .geoSite && $0.value == "category-ads-all" && $0.target == .reject })
        XCTAssertTrue(rules.contains { $0.kind == .domainSuffix && $0.value.contains("push.apple.com") && $0.target == .direct })
    }

    func testIranConfigurationUsesValidUpstreamRuleSetNames() {
        let rules = RuleConfiguration.iran().rules
        // `geosite-ir` does not exist upstream; the config must use `category-ir`.
        XCTAssertTrue(rules.contains { $0.kind == .geoSite && $0.value == "category-ir" && $0.target == .direct })
        XCTAssertTrue(rules.contains { $0.kind == .geoIP && $0.value == "ir" && $0.target == .direct })
        XCTAssertFalse(rules.contains { $0.kind == .geoSite && $0.value == "ir" })
    }

    func testChinaConfigurationGeneratesCNRuleSetsRoutedToDirect() throws {
        let json = try builder.build(
            profiles: SampleData.profiles,
            groups: SampleData.groups,
            selectedTarget: .group(SampleData.proxyGroup.id),
            routingMode: .rule,
            rules: RuleConfiguration.china().rules,
        )
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        let route = try XCTUnwrap(root["route"] as? [String: Any])

        let tags = Set((route["rule_set"] as? [[String: Any]] ?? []).compactMap { $0["tag"] as? String })
        XCTAssertTrue(tags.contains("geosite-cn"))
        XCTAssertTrue(tags.contains("geoip-cn"))
        XCTAssertTrue(tags.contains("geosite-category-ads-all"))

        let directRuleSets = (route["rules"] as? [[String: Any]] ?? [])
            .filter { ($0["outbound"] as? String) == "direct" }
            .flatMap { $0["rule_set"] as? [String] ?? [] }
        XCTAssertTrue(directRuleSets.contains("geosite-cn"))
        XCTAssertTrue(directRuleSets.contains("geoip-cn"))

        let directDomainSuffixes = (route["rules"] as? [[String: Any]] ?? [])
            .filter { ($0["outbound"] as? String) == "direct" }
            .flatMap { $0["domain_suffix"] as? [String] ?? [] }
        XCTAssertTrue(directDomainSuffixes.contains("push.apple.com"))
        XCTAssertTrue(directDomainSuffixes.contains("icloud.com"))
    }

    // MARK: - Store: select / add / update / delete

    @MainActor
    func testStoreSeedsConfigurationsAndSelectsActive() throws {
        let store = HopStore(dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory()))

        XCTAssertEqual(store.ruleConfigurations.count, 3)
        XCTAssertEqual(store.activeRuleConfigurationID, RuleConfiguration.defaultConfiguration.id)

        let china = try? XCTUnwrap(store.ruleConfigurations.first { $0.name == "China" })
        try store.selectRuleConfiguration(id: XCTUnwrap(china?.id))
        XCTAssertEqual(store.activeRuleConfigurationID, china?.id)
        XCTAssertEqual(store.routingMode, .rule)
        XCTAssertEqual(store.rules, china?.rules)
    }

    @MainActor
    func testStoreAddUpdateDeleteConfiguration() {
        let store = HopStore(dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory()))

        let custom = RuleConfiguration(name: "My Rules", rules: [RoutingRule(kind: .domainSuffix, value: "example.com", target: .direct)])
        store.addRuleConfiguration(custom)
        XCTAssertEqual(store.activeRuleConfigurationID, custom.id)
        XCTAssertEqual(store.rules, custom.rules)

        var renamed = custom
        renamed.name = "Renamed"
        store.updateRuleConfiguration(renamed)
        XCTAssertEqual(store.ruleConfigurations.first { $0.id == custom.id }?.name, "Renamed")

        store.deleteRuleConfiguration(id: custom.id)
        XCTAssertFalse(store.ruleConfigurations.contains { $0.id == custom.id })
        XCTAssertNotNil(store.activeRuleConfigurationID, "active id should fall back after deleting the active config")
        XCTAssertTrue(store.ruleConfigurations.contains { $0.id == store.activeRuleConfigurationID })
    }

    // MARK: - Legacy migration

    @MainActor
    func testLegacyRulesMigrateIntoCustomConfigurationPlusGeneratedOnes() {
        let url = tempStateURL()
        let secretStore = SecretStore.inMemory()

        // Write a pre-configurations state file (uses the legacy `rules` list).
        let legacy = HopAppData(
            profiles: SampleData.profiles,
            groups: SampleData.groups,
            subscriptions: [],
            routingMode: .rule,
            selectedTarget: nil,
            settings: .defaults,
            logs: [],
            rules: SampleData.rules,
        )
        HopAppDataStore(url: url, secretStore: secretStore).save(legacy)

        let store = HopStore(dataStore: HopAppDataStore(url: url, secretStore: secretStore))
        XCTAssertEqual(store.activeRuleConfiguration?.name, "Custom")
        XCTAssertEqual(store.rules, SampleData.rules)
        XCTAssertTrue(store.ruleConfigurations.contains { $0.name == "China" })
        XCTAssertTrue(store.ruleConfigurations.contains { $0.name == "Iran" })
    }

    @MainActor
    func testLoadedGeneratedConfigurationsGainAppleSystemBypass() throws {
        let url = tempStateURL()
        let secretStore = SecretStore.inMemory()
        let oldDefault = RuleConfiguration(
            name: "Default",
            rules: [
                RoutingRule(kind: .geoSite, value: "category-ads-all", target: .reject),
                RoutingRule(kind: .geoIP, value: "private", target: .direct),
                RoutingRule(kind: .domainSuffix, value: "apple.com", target: .direct),
            ],
        )
        let custom = RuleConfiguration(
            name: "Custom",
            rules: [RoutingRule(kind: .domainSuffix, value: "example.com", target: .direct)],
        )

        let loaded = HopAppData(
            profiles: SampleData.profiles,
            groups: SampleData.groups,
            subscriptions: [],
            routingMode: .rule,
            selectedTarget: nil,
            settings: .defaults,
            logs: [],
            ruleConfigurations: [oldDefault, custom],
            activeRuleConfigurationID: oldDefault.id,
        )
        HopAppDataStore(url: url, secretStore: secretStore).save(loaded)

        let store = HopStore(dataStore: HopAppDataStore(url: url, secretStore: secretStore))
        let migratedDefault = try XCTUnwrap(store.ruleConfigurations.first { $0.id == oldDefault.id })
        let appleRule = try XCTUnwrap(migratedDefault.rules.first { $0.kind == .domainSuffix && $0.target == .direct && $0.value.contains("push.apple.com") })
        XCTAssertTrue(appleRule.value.contains("icloud.com"))
        XCTAssertTrue(appleRule.value.contains("apple.com"))
        XCTAssertEqual(store.ruleConfigurations.first { $0.id == custom.id }?.rules, custom.rules)
    }
}
