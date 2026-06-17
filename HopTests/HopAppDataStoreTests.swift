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

    func testSubscriptionURLIsStoredInKeychainNotStateFile() throws {
        let url = tempStateURL()
        let secretStore = SecretStore.inMemory()
        let store = HopAppDataStore(url: url, secretStore: secretStore)
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        let subscription = SubscriptionSource(name: "Airport", url: "https://sub.example.com/path/token?target=hop")
        let data = HopAppData(
            profiles: [],
            groups: [],
            subscriptions: [subscription],
            routingMode: .rule,
            selectedTarget: nil,
            settings: .defaults,
            logs: [],
            ruleConfigurations: SampleData.ruleConfigurations,
            activeRuleConfigurationID: SampleData.defaultConfiguration.id,
        )

        store.save(data)

        let raw = try String(contentsOf: url, encoding: .utf8)
        XCTAssertFalse(raw.contains("path/token"), "subscription bearer URL leaked into JSON")
        XCTAssertEqual(secretStore.value(forKey: HopSecret.subscriptionURLKey(subscriptionID: subscription.id)), subscription.url)
        XCTAssertEqual(try XCTUnwrap(store.load()).subscriptions, [subscription])
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

    // MARK: - Secret-write skip (SecretWriteCache)

    func testSecondSaveWithIdenticalProfilesDoesNotWriteSecretsAgain() {
        let backend = InMemorySecretBackend()
        let url = tempStateURL()
        let store = HopAppDataStore(url: url, secretStore: SecretStore(backend: backend))

        let profile = trojanProfile(id: UUID(), name: "Tokyo", host: "jp.example.com", password: "secret")
        let data = HopAppData(
            profiles: [profile],
            groups: [],
            subscriptions: [],
            routingMode: .global,
            selectedTarget: nil,
            settings: .defaults,
            logs: [],
        )

        store.save(data)
        let writesAfterFirst = backend.allKeysCount

        // Second save with identical profiles — secret set is unchanged
        store.save(data)
        let writesAfterSecond = backend.allKeysCount

        XCTAssertEqual(writesAfterFirst, writesAfterSecond, "second save with identical profiles must not re-enumerate Keychain")
    }

    func testFailedSecretWriteIsRetriedOnNextSave() {
        let backend = FailOnceSecretBackend()
        let url = tempStateURL()
        let store = HopAppDataStore(url: url, secretStore: SecretStore(backend: backend))

        let profile = trojanProfile(id: UUID(), name: "Tokyo", host: "jp.example.com", password: "secret")
        let data = HopAppData(
            profiles: [profile],
            groups: [],
            subscriptions: [],
            routingMode: .global,
            selectedTarget: nil,
            settings: .defaults,
            logs: [],
        )

        // First save: the backend rejects the write, so nothing lands.
        store.save(data)
        XCTAssertNil(backend.value(forKey: HopSecret.key(profileID: profile.id, fieldRaw: "password")))

        // Second save with the UNCHANGED secret set must retry rather than
        // treat the failed state as already written (SecretWriteCache must
        // have been invalidated by the failure).
        store.save(data)
        XCTAssertEqual(
            backend.value(forKey: HopSecret.key(profileID: profile.id, fieldRaw: "password")),
            "secret",
            "a save after a failed Keychain write must rewrite the secret set",
        )
    }

    func testMutatedPasswordCausesSecretWrite() {
        let backend = InMemorySecretBackend()
        let url = tempStateURL()
        let store = HopAppDataStore(url: url, secretStore: SecretStore(backend: backend))

        let profileID = UUID()
        let original = trojanProfile(id: profileID, name: "Tokyo", host: "jp.example.com", password: "old-password")
        let mutated = trojanProfile(id: profileID, name: "Tokyo", host: "jp.example.com", password: "new-password")

        let originalData = HopAppData(
            profiles: [original],
            groups: [],
            subscriptions: [],
            routingMode: .global,
            selectedTarget: nil,
            settings: .defaults,
            logs: [],
        )
        let mutatedData = HopAppData(
            profiles: [mutated],
            groups: [],
            subscriptions: [],
            routingMode: .global,
            selectedTarget: nil,
            settings: .defaults,
            logs: [],
        )

        store.save(originalData)
        let writesAfterFirst = backend.allKeysCount

        store.save(mutatedData)
        let writesAfterMutation = backend.allKeysCount

        XCTAssertGreaterThan(writesAfterMutation, writesAfterFirst, "mutating a password must trigger a Keychain rewrite")
    }

    func testKeychainEndsWithCorrectPasswordAfterIdenticalSaves() {
        let backend = InMemorySecretBackend()
        let url = tempStateURL()
        let store = HopAppDataStore(url: url, secretStore: SecretStore(backend: backend))
        let secretStore = SecretStore(backend: backend)

        let profileID = UUID()
        let profile = trojanProfile(id: profileID, name: "Tokyo", host: "jp.example.com", password: "final-password")
        let data = HopAppData(
            profiles: [profile],
            groups: [],
            subscriptions: [],
            routingMode: .global,
            selectedTarget: nil,
            settings: .defaults,
            logs: [],
        )

        store.save(data)
        store.save(data)

        let key = HopSecret.key(profileID: profileID, fieldRaw: ProfileSecretField.password.rawValue)
        XCTAssertEqual(secretStore.value(forKey: key), "final-password", "Keychain must hold the correct password after two identical saves")
    }

    // MARK: - WireGuard preSharedKey in secretFieldValues

    func testWireGuardSecretFieldValuesIncludesPreSharedKey() {
        let profile = ProxyProfile(
            name: "WG",
            endpoint: Endpoint(host: "wg.example.net", port: 51820),
            options: .wireGuard(WireGuardOptions(
                privateKey: "PRIVATEKEY",
                peerPublicKey: "PEERPUBLICKEY",
                preSharedKey: "PRESHAREDKEY",
                localAddress: ["10.0.0.2/32"],
            )),
            security: .none,
        )
        XCTAssertNotNil(profile.secretFieldValues[.preSharedKey], "preSharedKey must be in secretFieldValues when set")
        XCTAssertEqual(profile.secretFieldValues[.preSharedKey], "PRESHAREDKEY")
    }

    func testWireGuardSecretFieldValuesOmitsPreSharedKeyWhenNil() {
        let profile = ProxyProfile(
            name: "WG",
            endpoint: Endpoint(host: "wg.example.net", port: 51820),
            options: .wireGuard(WireGuardOptions(
                privateKey: "PRIVATEKEY",
                peerPublicKey: "PEERPUBLICKEY",
                preSharedKey: nil,
                localAddress: ["10.0.0.2/32"],
            )),
            security: .none,
        )
        XCTAssertNil(profile.secretFieldValues[.preSharedKey], "preSharedKey must not appear in secretFieldValues when nil")
    }

    func testTokenizingSecretsHandlesPreSharedKey() {
        let profile = ProxyProfile(
            name: "WG",
            endpoint: Endpoint(host: "wg.example.net", port: 51820),
            options: .wireGuard(WireGuardOptions(
                privateKey: "PRIVATEKEY",
                peerPublicKey: "PEERPUBLICKEY",
                preSharedKey: "PRESHAREDKEY",
                localAddress: ["10.0.0.2/32"],
            )),
            security: .none,
        )
        let tokenized = profile.tokenizingSecrets(nonce: "testnonce")
        guard case let .wireGuard(opts) = tokenized.options else {
            return XCTFail("Expected wireGuard options")
        }
        XCTAssertTrue(opts.preSharedKey?.hasPrefix("##HOP_SECRET:") == true, "preSharedKey must be tokenized")
        XCTAssertNotEqual(opts.privateKey, "PRIVATEKEY", "privateKey must also be tokenized")
    }

    func testRedactingSecretsHandlesPreSharedKey() {
        let profile = ProxyProfile(
            name: "WG",
            endpoint: Endpoint(host: "wg.example.net", port: 51820),
            options: .wireGuard(WireGuardOptions(
                privateKey: "PRIVATEKEY",
                peerPublicKey: "PEERPUBLICKEY",
                preSharedKey: "PRESHAREDKEY",
                localAddress: ["10.0.0.2/32"],
            )),
            security: .none,
        )
        let redacted = profile.redactingSecrets()
        guard case let .wireGuard(opts) = redacted.options else {
            return XCTFail("Expected wireGuard options")
        }
        XCTAssertEqual(opts.preSharedKey, "", "preSharedKey must be blanked by redactingSecrets")
    }

    func testHydratingSecretsRestoresPreSharedKey() {
        let backend = InMemorySecretBackend()
        let secretStore = SecretStore(backend: backend)
        let profileID = UUID()

        let key = HopSecret.key(profileID: profileID, fieldRaw: ProfileSecretField.preSharedKey.rawValue)
        secretStore.setValue("PRESHAREDKEY", forKey: key)

        let profile = ProxyProfile(
            id: profileID,
            name: "WG",
            endpoint: Endpoint(host: "wg.example.net", port: 51820),
            options: .wireGuard(WireGuardOptions(
                privateKey: "",
                peerPublicKey: "PEERPUBLICKEY",
                preSharedKey: "",
                localAddress: ["10.0.0.2/32"],
            )),
            security: .none,
        )
        let hydrated = profile.hydratingSecrets(from: secretStore)
        guard case let .wireGuard(opts) = hydrated.options else {
            return XCTFail("Expected wireGuard options")
        }
        XCTAssertEqual(opts.preSharedKey, "PRESHAREDKEY", "hydratingSecrets must restore preSharedKey from the Keychain")
    }

    private func trojanProfile(id: UUID, name: String, host: String, password: String) -> ProxyProfile {
        ProxyProfile(
            id: id,
            name: name,
            endpoint: Endpoint(host: host, port: 443),
            options: .trojan(TrojanOptions(password: password)),
            security: .tls(TLSOptions(serverName: host)),
        )
    }
}
