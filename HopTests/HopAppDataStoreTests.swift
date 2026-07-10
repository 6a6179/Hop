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
        let store = HopAppDataStore(url: url, secretStore: .inMemory(), authenticationStore: .inMemory())
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
    func testSchemaTwoUpgradeClearsAppAndExtensionLogsBeforeTunnelSync() async throws {
        let url = tempStateURL()
        let extensionLogURL = url.deletingLastPathComponent().appendingPathComponent("hop-tunnel.log")
        let sharedLogStore = SharedTunnelLogStore(url: extensionLogURL)
        let store = HopAppDataStore(
            url: url,
            secretStore: .inMemory(),
            authenticationStore: .inMemory(),
            sharedLogStore: sharedLogStore,
        )
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let marker = "UNIT_TEST_MARKER[not-a-secret]"
        try FileManager.default.createDirectory(at: extensionLogURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("Startup failed: \(marker)\n".utf8).write(to: extensionLogURL)
        let legacy = HopAppData(
            profiles: [],
            groups: [],
            subscriptions: [],
            routingMode: .global,
            selectedTarget: nil,
            settings: .defaults,
            logs: ["Xray configuration validation failed (invalid_config): \(marker)"],
            schemaVersion: 2,
        )

        store.save(legacy)
        let migrated = try XCTUnwrap(store.load())

        XCTAssertEqual(migrated.schemaVersion, HopAppData.currentSchemaVersion)
        XCTAssertNotEqual(migrated.legacyExtensionLogPurgePending, true)
        XCTAssertTrue(migrated.logs.isEmpty)
        XCTAssertFalse(try String(contentsOf: url, encoding: .utf8).contains(marker))
        XCTAssertTrue(try sharedLogStore.readLines().isEmpty)

        let controller = TunnelController(logs: migrated.logs, sharedLogStore: sharedLogStore)
        await controller.syncExtensionLogs()
        XCTAssertFalse(controller.logs.joined().contains(marker))

        let currentEntry = "post-migration extension diagnostic"
        try Data("\(currentEntry)\n".utf8).write(to: extensionLogURL)
        XCTAssertEqual(try XCTUnwrap(store.load()).schemaVersion, HopAppData.currentSchemaVersion)
        XCTAssertEqual(try sharedLogStore.readLines(), [currentEntry], "an already-v3 load must not clear current logs")

        await controller.syncExtensionLogs()
        XCTAssertTrue(controller.logs.contains { $0.contains(currentEntry) })
    }

    func testLegacyLogPurgeFailureCompletesStateMigrationAndLeavesOnlySharedPurgePending() throws {
        let url = tempStateURL()
        let blockedParent = url.deletingLastPathComponent().appendingPathComponent("not-a-directory")
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("block directory creation".utf8).write(to: blockedParent)
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        let store = HopAppDataStore(
            url: url,
            secretStore: .inMemory(),
            authenticationStore: .inMemory(),
            sharedLogStore: SharedTunnelLogStore(url: blockedParent.appendingPathComponent("hop-tunnel.log")),
        )
        let subscription = SubscriptionSource(name: "Provider", url: "https://example.com/sub")
        let profile = trojanProfile(
            id: UUID(),
            name: "Preserved",
            host: "safe.example.com",
            password: "secret",
            subscriptionID: subscription.id,
        )
        let legacyGroup = ProxyGroup(
            subscriptionID: subscription.id,
            name: "Legacy Group",
            type: .select,
            members: [.profile(profile.id), .named("Preserved"), .selectedProxy],
            defaultTarget: .named("Preserved"),
            importedType: "select",
        )
        let legacy = HopAppData(
            profiles: [profile],
            groups: [legacyGroup],
            subscriptions: [subscription],
            routingMode: .global,
            selectedTarget: .group(legacyGroup.id),
            settings: .defaults,
            logs: ["legacy core diagnostic"],
            schemaVersion: 2,
        )

        store.save(legacy)
        let loaded = try XCTUnwrap(store.load())

        XCTAssertEqual(loaded.profiles.map(\.id), [profile.id])
        XCTAssertTrue(loaded.logs.isEmpty)
        XCTAssertEqual(loaded.schemaVersion, HopAppData.currentSchemaVersion)
        XCTAssertEqual(loaded.legacyExtensionLogPurgePending, true)
        let sanitizedGroup = try XCTUnwrap(loaded.groups.first)
        XCTAssertNil(sanitizedGroup.subscriptionID)
        XCTAssertFalse(sanitizedGroup.isEnabled)
        XCTAssertEqual(sanitizedGroup.members, [.profile(profile.id)])
        XCTAssertEqual(sanitizedGroup.defaultTarget, .profile(profile.id))
        XCTAssertNil(loaded.selectedTarget)

        let reloaded = try XCTUnwrap(store.load())
        XCTAssertEqual(reloaded.profiles.map(\.id), [profile.id])
        XCTAssertEqual(reloaded.groups, loaded.groups)
        XCTAssertEqual(reloaded.selectedTarget, loaded.selectedTarget)
        XCTAssertEqual(reloaded.pendingXrayMigrationReport, loaded.pendingXrayMigrationReport)
        XCTAssertEqual(reloaded.legacyExtensionLogPurgePending, true)
    }

    @MainActor
    func testMissingRejectedOrUndecodableStatePurgesLegacyLogWithoutOverwritingRejectedState() throws {
        enum InvalidState: String, CaseIterable {
            case missing
            case tampered
            case undecodable
        }

        for invalidState in InvalidState.allCases {
            let directory = FileManager.default.temporaryDirectory
                .appendingPathComponent("HopInvalidStateLogGate-\(invalidState.rawValue)-\(UUID().uuidString)", isDirectory: true)
            let stateURL = directory.appendingPathComponent("hop-state.json")
            let extensionLogURL = directory.appendingPathComponent("hop-tunnel.log")
            let authenticationStore = SecretStore.inMemory()
            let profileSecretStore = SecretStore.inMemory()
            let sharedLogStore = SharedTunnelLogStore(url: extensionLogURL)
            let dataStore = HopAppDataStore(
                url: stateURL,
                secretStore: profileSecretStore,
                authenticationStore: authenticationStore,
                sharedLogStore: sharedLogStore,
            )
            defer { try? FileManager.default.removeItem(at: directory) }
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

            switch invalidState {
            case .missing:
                break
            case .tampered:
                dataStore.save(HopAppData(
                    profiles: [],
                    groups: [],
                    subscriptions: [],
                    routingMode: .global,
                    selectedTarget: nil,
                    settings: .defaults,
                    logs: [],
                ))
                var state = try Data(contentsOf: stateURL)
                state.append(0x20)
                try state.write(to: stateURL)
            case .undecodable:
                try Data("{not-json".utf8).write(to: stateURL)
            }
            XCTAssertNil(dataStore.load(), "\(invalidState.rawValue) state must not be trusted")
            let rejectedState = try? Data(contentsOf: stateURL)
            let sentinelKey = "rejected-state-\(invalidState.rawValue)"
            if invalidState != .missing {
                profileSecretStore.setValue("preserve-me", forKey: sentinelKey)
            }

            let marker = "UNIT_TEST_LEGACY_EXTENSION_SECRET_\(invalidState.rawValue)"
            try Data("Startup failed: \(marker)\n".utf8).write(to: extensionLogURL)
            let controller = TunnelController(
                logs: [],
                maximumLogEntries: 100,
                sharedLogStore: sharedLogStore,
            )
            let store = HopStore(tunnel: controller, dataStore: dataStore)
            store.flushPendingPersists()

            XCTAssertFalse(store.tunnel.requiresLegacyExtensionLogPurge)
            XCTAssertFalse(store.tunnel.logs.joined().contains(marker))
            XCTAssertTrue(try sharedLogStore.readLines().isEmpty)
            if invalidState == .missing {
                XCTAssertFalse(FileManager.default.fileExists(atPath: stateURL.path))
            } else {
                XCTAssertEqual(try Data(contentsOf: stateURL), rejectedState)
                XCTAssertEqual(profileSecretStore.value(forKey: sentinelKey), "preserve-me")
                XCTAssertNil(dataStore.load())
            }

            let explicitProfile = trojanProfile(
                id: UUID(),
                name: "Explicit \(invalidState.rawValue)",
                host: "explicit.example.com",
                password: "new-secret",
            )
            store.addProfile(explicitProfile)
            store.flushPendingPersists()
            let explicitlyReplaced = try XCTUnwrap(dataStore.load())
            XCTAssertEqual(explicitlyReplaced.schemaVersion, HopAppData.currentSchemaVersion)
            XCTAssertEqual(explicitlyReplaced.profiles.map(\.id), [explicitProfile.id])
        }
    }

    @MainActor
    func testMissingStateInitialPurgeKeepsNewUserDataOnCurrentSchema() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("HopMissingStateCurrentSchema-\(UUID().uuidString)", isDirectory: true)
        let stateURL = directory.appendingPathComponent("hop-state.json")
        let extensionLogURL = directory.appendingPathComponent("hop-tunnel.log")
        let sharedLogStore = SharedTunnelLogStore(url: extensionLogURL)
        let dataStore = HopAppDataStore(
            url: stateURL,
            secretStore: .inMemory(),
            authenticationStore: .inMemory(),
            sharedLogStore: sharedLogStore,
        )
        defer { try? FileManager.default.removeItem(at: directory) }

        let store = HopStore(
            tunnel: TunnelController(logs: ["current app log"], sharedLogStore: sharedLogStore),
            dataStore: dataStore,
        )
        let profile = trojanProfile(id: UUID(), name: "Manual", host: "manual.example.com", password: "secret")
        let group = ProxyGroup(
            name: "Reviewed Import",
            type: .select,
            members: [.profile(profile.id)],
            defaultTarget: .profile(profile.id),
            importedType: "select",
        )

        XCTAssertEqual(store.tunnel.logs.count, 1, "the extension-log purge must not clear current app logs")
        store.addProfile(profile)
        store.addGroup(group)
        store.flushPendingPersists()

        let reloaded = HopStore(
            tunnel: TunnelController(sharedLogStore: sharedLogStore),
            dataStore: dataStore,
        )
        XCTAssertEqual(reloaded.groups.first { $0.id == group.id }, group)
        XCTAssertEqual(reloaded.selectedTarget, .group(group.id))
        XCTAssertEqual(try XCTUnwrap(dataStore.load()).schemaVersion, HopAppData.currentSchemaVersion)
    }

    @MainActor
    func testDeferredLegacyLogPurgeFailureKeepsSchemaPendingUntilRetrySucceeds() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("HopDeferredLogPurge-\(UUID().uuidString)", isDirectory: true)
        let stateURL = directory.appendingPathComponent("hop-state.json")
        let blockedParent = directory.appendingPathComponent("not-a-directory")
        let extensionLogURL = blockedParent.appendingPathComponent("hop-tunnel.log")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data("block directory creation".utf8).write(to: blockedParent)
        defer { try? FileManager.default.removeItem(at: directory) }

        let sharedLogStore = SharedTunnelLogStore(url: extensionLogURL)
        let dataStore = HopAppDataStore(
            url: stateURL,
            secretStore: .inMemory(),
            authenticationStore: .inMemory(),
            sharedLogStore: sharedLogStore,
        )
        dataStore.save(HopAppData(
            profiles: [],
            groups: [],
            subscriptions: [],
            routingMode: .global,
            selectedTarget: nil,
            settings: .defaults,
            logs: ["legacy core diagnostic"],
            schemaVersion: 2,
        ))
        let controller = TunnelController(logs: [], sharedLogStore: sharedLogStore)
        let store = HopStore(tunnel: controller, dataStore: dataStore)

        XCTAssertTrue(store.tunnel.requiresLegacyExtensionLogPurge)
        await store.tunnel.syncExtensionLogs()
        XCTAssertTrue(store.tunnel.requiresLegacyExtensionLogPurge)
        store.persist()
        store.flushPendingPersists()
        let pending = try XCTUnwrap(dataStore.load())
        XCTAssertEqual(pending.schemaVersion, HopAppData.currentSchemaVersion)
        XCTAssertEqual(pending.legacyExtensionLogPurgePending, true)

        try FileManager.default.removeItem(at: blockedParent)
        try FileManager.default.createDirectory(at: blockedParent, withIntermediateDirectories: true)
        let marker = "UNIT_TEST_RETRY_LEGACY_EXTENSION_SECRET"
        try Data("Startup failed: \(marker)\n".utf8).write(to: extensionLogURL)

        await store.tunnel.syncExtensionLogs()
        store.flushPendingPersists()

        XCTAssertFalse(store.tunnel.requiresLegacyExtensionLogPurge)
        XCTAssertFalse(store.tunnel.logs.joined().contains(marker))
        XCTAssertTrue(try sharedLogStore.readLines().isEmpty)
        let completed = try XCTUnwrap(dataStore.load())
        XCTAssertEqual(completed.schemaVersion, HopAppData.currentSchemaVersion)
        XCTAssertNotEqual(completed.legacyExtensionLogPurgePending, true)
    }

    @MainActor
    func testFailedSharedLogPurgeDoesNotRepeatReviewedStateMigrationOnNextLaunch() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("HopLogPurgeMigrationOnce-\(UUID().uuidString)", isDirectory: true)
        let stateURL = directory.appendingPathComponent("hop-state.json")
        let blockedParent = directory.appendingPathComponent("not-a-directory")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data("block directory creation".utf8).write(to: blockedParent)
        defer { try? FileManager.default.removeItem(at: directory) }

        let dataStore = HopAppDataStore(
            url: stateURL,
            secretStore: .inMemory(),
            authenticationStore: .inMemory(),
            sharedLogStore: SharedTunnelLogStore(
                url: blockedParent.appendingPathComponent("hop-tunnel.log"),
            ),
        )
        let subscription = SubscriptionSource(name: "Provider", url: "https://example.com/sub")
        let profile = trojanProfile(
            id: UUID(),
            name: "Provider Node",
            host: "node.example.com",
            password: "secret",
            subscriptionID: subscription.id,
        )
        let legacyGroup = ProxyGroup(
            subscriptionID: subscription.id,
            name: "Provider Group",
            type: .select,
            members: [.profile(profile.id), .selectedProxy],
            defaultTarget: .profile(profile.id),
            importedType: "select",
        )
        let customRules = RuleConfiguration(name: "Provider Rules", rules: [
            RoutingRule(kind: .domainSuffix, value: "example.com", target: .direct),
        ])
        dataStore.save(HopAppData(
            profiles: [profile],
            groups: [legacyGroup],
            subscriptions: [subscription],
            routingMode: .rule,
            selectedTarget: .group(legacyGroup.id),
            settings: .defaults,
            logs: ["legacy core diagnostic"],
            ruleConfigurations: [customRules],
            activeRuleConfigurationID: customRules.id,
            schemaVersion: 2,
        ))

        let firstLaunch = HopStore(dataStore: dataStore)
        var reviewedGroup = try XCTUnwrap(firstLaunch.groups.first { $0.id == legacyGroup.id })
        XCTAssertFalse(reviewedGroup.isEnabled)
        XCTAssertEqual(firstLaunch.routingMode, .global)
        XCTAssertNil(firstLaunch.selectedTarget)
        reviewedGroup.isEnabled = true
        reviewedGroup.warning = nil
        firstLaunch.updateGroup(reviewedGroup)
        firstLaunch.routingMode = .rule
        firstLaunch.selectedTarget = .group(reviewedGroup.id)
        firstLaunch.tunnel.logs = ["current reviewed diagnostic"]
        firstLaunch.persist()
        firstLaunch.flushPendingPersists()

        let secondLaunch = HopStore(dataStore: dataStore)

        XCTAssertEqual(secondLaunch.groups.first { $0.id == reviewedGroup.id }, reviewedGroup)
        XCTAssertEqual(secondLaunch.routingMode, .rule)
        XCTAssertEqual(secondLaunch.selectedTarget, .group(reviewedGroup.id))
        XCTAssertEqual(secondLaunch.tunnel.logs, ["current reviewed diagnostic"])
        XCTAssertTrue(secondLaunch.tunnel.requiresLegacyExtensionLogPurge)
        let stillPending = try XCTUnwrap(dataStore.load())
        XCTAssertEqual(stillPending.schemaVersion, HopAppData.currentSchemaVersion)
        XCTAssertEqual(stillPending.legacyExtensionLogPurgePending, true)
    }

    func testSubscriptionURLIsStoredInKeychainNotStateFile() throws {
        let url = tempStateURL()
        let secretStore = SecretStore.inMemory()
        let store = HopAppDataStore(url: url, secretStore: secretStore, authenticationStore: .inMemory())
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

    func testStateAuthenticationRejectsTamperedStateBeforeHydratingSecrets() throws {
        let url = tempStateURL()
        let secretStore = SecretStore.inMemory()
        let authStore = SecretStore.inMemory()
        let store = HopAppDataStore(url: url, secretStore: secretStore, authenticationStore: authStore)
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        let profile = trojanProfile(id: UUID(), name: "Tokyo", host: "safe.example.com", password: "secret")
        let data = HopAppData(
            profiles: [profile],
            groups: [],
            subscriptions: [],
            routingMode: .global,
            selectedTarget: .profile(profile.id),
            settings: .defaults,
            logs: [],
        )

        store.save(data)
        XCTAssertEqual(try XCTUnwrap(store.load()).profiles.first?.endpoint.host, "safe.example.com")

        let tampered = try String(contentsOf: url, encoding: .utf8)
            .replacingOccurrences(of: "safe.example.com", with: "evil.example.com")
        try tampered.write(to: url, atomically: true, encoding: .utf8)

        XCTAssertNil(store.load(), "state tamper must fail before Keychain-backed secrets are rebound")
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

    func testLegacyStateMigrationRemovesUnsupportedXrayProfilesAndReferences() throws {
        let url = tempStateURL()
        let store = HopAppDataStore(url: url, secretStore: .inMemory(), authenticationStore: .inMemory())
        let supported = trojanProfile(id: UUID(), name: "Supported", host: "ok.example.com", password: "secret")
        let tuic = ProxyProfile(
            name: "Old TUIC",
            endpoint: Endpoint(host: "tuic.example.com", port: 443),
            options: .tuic(TUICOptions(uuid: "uuid", password: "password", congestionControl: nil)),
            security: .tls(TLSOptions(serverName: "tuic.example.com")),
        )
        let group = ProxyGroup(
            name: "Legacy Group",
            type: .select,
            members: [.profile(tuic.id)],
            defaultTarget: .profile(tuic.id),
        )
        let rules = [RoutingRule(kind: .domain, value: "example.com", target: .profile(tuic.id))]
        let config = RuleConfiguration(name: "Legacy Rules", rules: rules)
        let data = HopAppData(
            profiles: [supported, tuic],
            groups: [group],
            subscriptions: [],
            routingMode: .rule,
            selectedTarget: .profile(tuic.id),
            settings: .defaults,
            logs: [],
            ruleConfigurations: [config],
            activeRuleConfigurationID: config.id,
            schemaVersion: 1,
        )

        store.save(data)
        let migrated = try XCTUnwrap(store.load())

        XCTAssertEqual(migrated.schemaVersion, HopAppData.currentSchemaVersion)
        XCTAssertEqual(migrated.profiles.map(\.id), [supported.id])
        XCTAssertTrue(migrated.groups.isEmpty)
        XCTAssertTrue(try XCTUnwrap(migrated.ruleConfigurations).first?.rules.isEmpty == true)
        XCTAssertNil(migrated.selectedTarget, "migration must require an explicit post-migration selection")
        XCTAssertEqual(migrated.pendingXrayMigrationReport?.removedProfileNames, ["Old TUIC"])
        XCTAssertEqual(migrated.pendingXrayMigrationReport?.removedGroupNames, ["Legacy Group"])
        XCTAssertEqual(migrated.pendingXrayMigrationReport?.removedRuleCount, 1)
    }

    func testSchemaTwoMigratesSafeAdvancedTLSFieldsIntoTypedOptions() throws {
        let url = tempStateURL()
        let sharedLogStore = SharedTunnelLogStore(
            url: url.deletingLastPathComponent().appendingPathComponent("hop-tunnel.log"),
        )
        let store = HopAppDataStore(
            url: url,
            secretStore: .inMemory(),
            authenticationStore: .inMemory(),
            sharedLogStore: sharedLogStore,
        )
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        var profile = trojanProfile(id: UUID(), name: "Legacy TLS", host: "legacy.example.com", password: "secret")
        profile.security = .tls(TLSOptions(serverName: nil, utlsFingerprint: nil))
        profile.xrayAdvanced = XrayAdvancedDocument([
            "streamSettings": .object([
                "tlsSettings": .object([
                    "serverName": .string("legacy.example.com"),
                    "fingerprint": .string("chrome"),
                    "pinnedPeerCertSha256": .string(String(repeating: "ab", count: 32)),
                    "verifyPeerCertByName": .string("legacy.example.com"),
                    "echConfigList": .string("AQIDBA=="),
                    "curvePreferences": .array([.string("X25519MLKEM768"), .string("X25519")]),
                    "minVersion": .string("1.2"),
                    "maxVersion": .string("1.3"),
                    "cipherSuites": .string("TLS_AES_128_GCM_SHA256"),
                    "alpn": .array([.string("h2")]),
                ]),
                "sockopt": .object(["tcpFastOpen": .bool(true)]),
            ]),
        ])
        let legacy = HopAppData(
            profiles: [profile],
            groups: [],
            subscriptions: [],
            routingMode: .global,
            selectedTarget: .profile(profile.id),
            settings: .defaults,
            logs: [],
            schemaVersion: 2,
        )

        store.save(legacy)
        let loaded = try XCTUnwrap(store.load())
        let migrated = try XCTUnwrap(loaded.profiles.first)
        let tls = try XCTUnwrap(migrated.security.tls)

        XCTAssertEqual(loaded.schemaVersion, HopAppData.currentSchemaVersion)
        XCTAssertEqual(tls.serverName, "legacy.example.com")
        XCTAssertEqual(tls.utlsFingerprint, "chrome")
        XCTAssertEqual(tls.pinnedPeerCertSHA256, String(repeating: "ab", count: 32))
        XCTAssertEqual(tls.verifyPeerCertByName, "legacy.example.com")
        XCTAssertEqual(tls.echConfigList, "AQIDBA==")
        XCTAssertEqual(tls.curvePreferences, ["X25519MLKEM768", "X25519"])
        XCTAssertEqual(tls.minVersion, "1.2")
        XCTAssertEqual(tls.maxVersion, "1.3")
        XCTAssertEqual(tls.cipherSuites, "TLS_AES_128_GCM_SHA256")
        let stream = try XCTUnwrap(migrated.xrayAdvanced?.values["streamSettings"]?.objectValue)
        let remainingTLS = try XCTUnwrap(stream["tlsSettings"]?.objectValue)
        XCTAssertEqual(remainingTLS, ["alpn": .array([.string("h2")])])
        XCTAssertNotNil(stream["sockopt"])
        XCTAssertTrue(loaded.pendingXrayMigrationReport?.blockedAdvancedTLSProfileNames?.isEmpty ?? true)
        XCTAssertNoThrow(try XrayConfigBuilder().build(profile: migrated, routingMode: .global, rules: []))
    }

    func testAdvancedTLSMigrationLeavesCollisionsInvalidValuesAndDisableSystemRootBlocked() throws {
        let url = tempStateURL()
        let store = HopAppDataStore(
            url: url,
            secretStore: .inMemory(),
            authenticationStore: .inMemory(),
            sharedLogStore: SharedTunnelLogStore(
                url: url.deletingLastPathComponent().appendingPathComponent("hop-tunnel.log"),
            ),
        )
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        var profile = trojanProfile(id: UUID(), name: "Blocked TLS", host: "typed.example.com", password: "secret")
        profile.security = .tls(TLSOptions(serverName: "typed.example.com", utlsFingerprint: nil))
        profile.xrayAdvanced = XrayAdvancedDocument([
            "streamSettings": .object([
                "tlsSettings": .object([
                    "serverName": .string("raw.example.com"),
                    "fingerprint": .string("chrome"),
                    "Fingerprint": .string("firefox"),
                    "echConfigList": .string("https://dns.example/dns-query"),
                    "disableSystemRoot": .bool(true),
                ]),
            ]),
        ])
        let legacy = HopAppData(
            profiles: [profile],
            groups: [],
            subscriptions: [],
            routingMode: .global,
            selectedTarget: .profile(profile.id),
            settings: .defaults,
            logs: [],
            schemaVersion: 2,
        )

        store.save(legacy)
        let loaded = try XCTUnwrap(store.load())
        let blocked = try XCTUnwrap(loaded.profiles.first)
        let rawTLS = try XCTUnwrap(
            blocked.xrayAdvanced?.values["streamSettings"]?.objectValue?["tlsSettings"]?.objectValue,
        )

        XCTAssertEqual(blocked.security.tls?.serverName, "typed.example.com")
        XCTAssertNil(blocked.security.tls?.utlsFingerprint)
        XCTAssertEqual(Set(rawTLS.keys), ["serverName", "fingerprint", "Fingerprint", "echConfigList", "disableSystemRoot"])
        XCTAssertEqual(loaded.pendingXrayMigrationReport?.blockedAdvancedTLSProfileNames, ["Blocked TLS"])
        XCTAssertTrue(loaded.pendingXrayMigrationReport?.message.contains("Blocked TLS") == true)
        XCTAssertThrowsError(try XrayConfigBuilder().build(profile: blocked, routingMode: .global, rules: []))
    }

    func testSchemaThreeDoesNotRewriteAdvancedTLS() throws {
        let url = tempStateURL()
        let store = HopAppDataStore(
            url: url,
            secretStore: .inMemory(),
            authenticationStore: .inMemory(),
            sharedLogStore: SharedTunnelLogStore(
                url: url.deletingLastPathComponent().appendingPathComponent("hop-tunnel.log"),
            ),
        )
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        var profile = trojanProfile(id: UUID(), name: "Current TLS", host: "current.example.com", password: "secret")
        profile.security = .tls(TLSOptions(serverName: nil, utlsFingerprint: nil))
        profile.xrayAdvanced = XrayAdvancedDocument([
            "streamSettings": .object([
                "tlsSettings": .object(["serverName": .string("raw.example.com")]),
            ]),
        ])
        let current = HopAppData(
            profiles: [profile],
            groups: [],
            subscriptions: [],
            routingMode: .global,
            selectedTarget: .profile(profile.id),
            settings: .defaults,
            logs: [],
            schemaVersion: 3,
        )

        store.save(current)
        let loaded = try XCTUnwrap(store.load())
        let untouched = try XCTUnwrap(loaded.profiles.first)

        XCTAssertNil(untouched.security.tls?.serverName)
        XCTAssertEqual(
            untouched.xrayAdvanced?.values["streamSettings"]?.objectValue?["tlsSettings"]?.objectValue?["serverName"],
            .string("raw.example.com"),
        )
        XCTAssertNil(loaded.pendingXrayMigrationReport)
    }

    @MainActor
    func testSchemaTwoDisablesLegacyGroupWithoutClaimingOwnerAndRefreshesIntoOwnedGroup() throws {
        let url = tempStateURL()
        let dataStore = HopAppDataStore(
            url: url,
            secretStore: .inMemory(),
            authenticationStore: .inMemory(),
            sharedLogStore: SharedTunnelLogStore(
                url: url.deletingLastPathComponent().appendingPathComponent("hop-tunnel.log"),
            ),
        )
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let subscription = SubscriptionSource(name: "Provider", url: "https://example.com/sub")
        let revoked = trojanProfile(
            id: UUID(),
            name: "Revoked",
            host: "revoked.example.com",
            password: "old-secret",
            subscriptionID: subscription.id,
        )
        let legacyGroup = ProxyGroup(
            subscriptionID: subscription.id,
            name: "Provider Group",
            type: .select,
            members: [.profile(revoked.id), .direct],
            defaultTarget: .profile(revoked.id),
            importedType: "select",
        )
        let manualGroup = ProxyGroup(name: "Manual", type: .select, members: [.direct])
        let builtIns = RuleConfiguration.builtInConfigurations.map { configuration in
            RuleConfiguration(
                id: UUID(),
                name: configuration.name,
                rules: configuration.rules.map {
                    RoutingRule(id: UUID(), kind: $0.kind, value: $0.value, target: $0.target)
                },
            )
        }
        let legacy = HopAppData(
            profiles: [revoked],
            groups: [legacyGroup, manualGroup],
            subscriptions: [subscription],
            routingMode: .rule,
            selectedTarget: .group(legacyGroup.id),
            settings: .defaults,
            logs: [],
            ruleConfigurations: builtIns,
            activeRuleConfigurationID: builtIns.first?.id,
            schemaVersion: 2,
        )
        dataStore.save(legacy)

        let migrated = try XCTUnwrap(dataStore.load())
        XCTAssertNil(migrated.groups.first { $0.id == legacyGroup.id }?.subscriptionID)
        XCTAssertEqual(migrated.groups.first { $0.id == legacyGroup.id }?.isEnabled, false)
        XCTAssertEqual(migrated.groups.first { $0.id == manualGroup.id }, manualGroup)
        XCTAssertNil(migrated.selectedTarget)
        XCTAssertEqual(migrated.routingMode, .rule, "semantic built-in matches must ignore persisted IDs")
        XCTAssertEqual(migrated.pendingXrayMigrationReport?.disabledLegacySubscriptionGroupNames, ["Provider Group"])

        let store = HopStore(dataStore: dataStore)
        let rotated = trojanProfile(
            id: UUID(),
            name: "Rotated",
            host: "rotated.example.com",
            password: "new-secret",
        )
        let refreshedGroup = ProxyGroup(
            name: "Provider Group",
            type: .select,
            members: [.profile(rotated.id)],
            defaultTarget: .profile(rotated.id),
            importedType: "select",
        )

        XCTAssertTrue(store.applySubscriptionRefresh(
            ImportResult(profiles: [rotated], groups: [refreshedGroup]),
            updating: subscription,
        ))

        let storedRotated = try XCTUnwrap(store.profiles.first { $0.name == "Rotated" })
        let storedGroup = try XCTUnwrap(store.groups.first { $0.subscriptionID == subscription.id })
        let retainedLegacyGroup = try XCTUnwrap(store.groups.first { $0.id == legacyGroup.id })
        XCTAssertFalse(store.profiles.contains { $0.id == revoked.id })
        XCTAssertEqual(storedRotated.subscriptionID, subscription.id)
        XCTAssertEqual(storedGroup.subscriptionID, subscription.id)
        XCTAssertEqual(storedGroup.members, [.profile(storedRotated.id)])
        XCTAssertNotEqual(storedGroup.id, legacyGroup.id)
        XCTAssertNil(retainedLegacyGroup.subscriptionID)
        XCTAssertFalse(retainedLegacyGroup.isEnabled)
        XCTAssertNil(store.selectedTarget)
        XCTAssertEqual(store.groups.first { $0.id == manualGroup.id }, manualGroup)
        store.flushPendingPersists()
    }

    @MainActor
    func testSchemaTwoWithoutSourceDisablesAmbiguousImportedGroupAndPreservesManualState() throws {
        let url = tempStateURL()
        let dataStore = HopAppDataStore(
            url: url,
            secretStore: .inMemory(),
            authenticationStore: .inMemory(),
            sharedLogStore: SharedTunnelLogStore(
                url: url.deletingLastPathComponent().appendingPathComponent("hop-tunnel.log"),
            ),
        )
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let unowned = trojanProfile(id: UUID(), name: "Legacy", host: "legacy.example.com", password: "secret")
        let ambiguous = ProxyGroup(
            name: "Legacy Imported",
            type: .select,
            members: [.profile(unowned.id), .named("Legacy"), .selectedProxy],
            defaultTarget: .named("Legacy"),
            importedType: "select",
        )
        let manual = ProxyGroup(name: "Manual", type: .select, members: [.direct], defaultTarget: .direct)
        let opaqueRules = RuleConfiguration(name: "Provider Rules", rules: [
            RoutingRule(kind: .domainSuffix, value: "example.com", target: .named("Legacy")),
        ])
        let legacy = HopAppData(
            profiles: [unowned],
            groups: [ambiguous, manual],
            subscriptions: [],
            routingMode: .rule,
            selectedTarget: .group(ambiguous.id),
            settings: .defaults,
            logs: [],
            ruleConfigurations: [opaqueRules],
            activeRuleConfigurationID: opaqueRules.id,
            schemaVersion: 2,
        )
        dataStore.save(legacy)

        let migrated = try XCTUnwrap(dataStore.load())

        XCTAssertNil(migrated.groups.first { $0.id == ambiguous.id }?.subscriptionID)
        XCTAssertEqual(migrated.groups.first { $0.id == ambiguous.id }?.isEnabled, false)
        XCTAssertEqual(migrated.groups.first { $0.id == ambiguous.id }?.members, [.profile(unowned.id)])
        XCTAssertEqual(migrated.groups.first { $0.id == ambiguous.id }?.defaultTarget, .profile(unowned.id))
        XCTAssertEqual(migrated.groups.first { $0.id == manual.id }, manual)
        XCTAssertNil(migrated.selectedTarget)
        XCTAssertEqual(migrated.routingMode, .global)
        XCTAssertEqual(migrated.ruleConfigurations, [opaqueRules], "opaque rules are preserved for review")
        XCTAssertEqual(migrated.pendingXrayMigrationReport?.disabledLegacySubscriptionGroupNames, ["Legacy Imported"])
        XCTAssertEqual(migrated.pendingXrayMigrationReport?.clearedLegacySelectionName, "Legacy Imported")
        XCTAssertEqual(migrated.pendingXrayMigrationReport?.requiresLegacyRoutingReview, true)

        // Even if the user explicitly reviews and re-enables the sanitized
        // legacy group, a later same-name subscription cannot retarget it.
        let store = HopStore(dataStore: dataStore)
        var reviewedGroup = try XCTUnwrap(store.groups.first { $0.id == ambiguous.id })
        reviewedGroup.isEnabled = true
        store.updateGroup(reviewedGroup)
        let laterSubscription = SubscriptionSource(name: "Later", url: "https://later.example/sub")
        let laterSameName = trojanProfile(
            id: UUID(),
            name: "Legacy",
            host: "later.example.com",
            password: "later-secret",
        )
        XCTAssertTrue(store.applySubscriptionImport(
            ImportResult(profiles: [laterSameName]),
            adding: laterSubscription,
        ))
        store.selectedTarget = .group(ambiguous.id)
        let config = try XrayConfigBuilder().build(
            profiles: store.profiles,
            groups: store.groups,
            selectedTarget: .group(ambiguous.id),
            routingMode: .global,
            rules: [],
        )
        XCTAssertTrue(config.contains("legacy.example.com"))
        XCTAssertFalse(config.contains("later.example.com"))
        store.flushPendingPersists()
    }

    func testSchemaTwoPreservesManualOnlySelections() throws {
        let profile = trojanProfile(id: UUID(), name: "Unowned", host: "unowned.example.com", password: "secret")
        let manualSelections: [(OutboundTarget, String)] = [
            (.profile(profile.id), "Unowned"),
            (.named("Unowned"), "Unowned"),
            (.selectedProxy, "Active Proxy"),
        ]
        for (selection, expectedName) in manualSelections {
            let url = tempStateURL()
            let dataStore = HopAppDataStore(
                url: url,
                secretStore: .inMemory(),
                authenticationStore: .inMemory(),
                sharedLogStore: SharedTunnelLogStore(
                    url: url.deletingLastPathComponent().appendingPathComponent("hop-tunnel.log"),
                ),
            )
            dataStore.save(HopAppData(
                profiles: [profile],
                groups: [],
                subscriptions: [],
                routingMode: .global,
                selectedTarget: selection,
                settings: .defaults,
                logs: [],
                schemaVersion: 2,
            ))

            let migrated = try XCTUnwrap(dataStore.load())
            XCTAssertEqual(migrated.selectedTarget, selection, "manual-only selection \(expectedName) must survive")
            XCTAssertNil(migrated.pendingXrayMigrationReport?.clearedLegacySelectionName)
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
        }

        for selection in [OutboundTarget.direct, .reject] {
            let url = tempStateURL()
            let dataStore = HopAppDataStore(
                url: url,
                secretStore: .inMemory(),
                authenticationStore: .inMemory(),
                sharedLogStore: SharedTunnelLogStore(
                    url: url.deletingLastPathComponent().appendingPathComponent("hop-tunnel.log"),
                ),
            )
            dataStore.save(HopAppData(
                profiles: [profile],
                groups: [],
                subscriptions: [],
                routingMode: .global,
                selectedTarget: selection,
                settings: .defaults,
                logs: [],
                schemaVersion: 2,
            ))

            XCTAssertEqual(try XCTUnwrap(dataStore.load()).selectedTarget, selection)
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
        }
    }

    func testSchemaTwoClearsDynamicSelectionsWhenSubscriptionEvidenceExists() throws {
        let subscription = SubscriptionSource(name: "Provider", url: "https://example.com/sub")
        let profile = trojanProfile(
            id: UUID(),
            name: "Owned",
            host: "owned.example.com",
            password: "secret",
            subscriptionID: subscription.id,
        )
        let dynamicSelections: [(OutboundTarget, String)] = [
            (.named(profile.name), profile.name),
            (.selectedProxy, "Active Proxy"),
        ]
        for (selection, expectedName) in dynamicSelections {
            let url = tempStateURL()
            let dataStore = HopAppDataStore(
                url: url,
                secretStore: .inMemory(),
                authenticationStore: .inMemory(),
                sharedLogStore: SharedTunnelLogStore(
                    url: url.deletingLastPathComponent().appendingPathComponent("hop-tunnel.log"),
                ),
            )
            defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
            dataStore.save(HopAppData(
                profiles: [profile],
                groups: [],
                subscriptions: [subscription],
                routingMode: .global,
                selectedTarget: selection,
                settings: .defaults,
                logs: [],
                schemaVersion: 2,
            ))

            let migrated = try XCTUnwrap(dataStore.load())
            XCTAssertNil(migrated.selectedTarget)
            XCTAssertEqual(migrated.pendingXrayMigrationReport?.clearedLegacySelectionName, expectedName)
        }
    }

    func testSchemaTwoLegacyGroupMigrationIsIterativeForDeepChains() throws {
        let url = tempStateURL()
        let dataStore = HopAppDataStore(
            url: url,
            secretStore: .inMemory(),
            authenticationStore: .inMemory(),
            sharedLogStore: SharedTunnelLogStore(
                url: url.deletingLastPathComponent().appendingPathComponent("hop-tunnel.log"),
            ),
        )
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        let count = 5000
        let ids = (0 ..< count).map { _ in UUID() }
        let groups = (0 ..< count).map { index in
            let target: OutboundTarget = index == 0 ? .direct : .group(ids[index - 1])
            return ProxyGroup(
                id: ids[index],
                name: "Legacy \(index)",
                type: .select,
                members: [target],
                defaultTarget: target,
                importedType: "select",
            )
        }
        dataStore.save(HopAppData(
            profiles: [],
            groups: groups,
            subscriptions: [],
            routingMode: .global,
            selectedTarget: .group(ids[count - 1]),
            settings: .defaults,
            logs: [],
            schemaVersion: 2,
        ))

        let migrated = try XCTUnwrap(dataStore.load())

        XCTAssertEqual(migrated.groups.count, count)
        XCTAssertTrue(migrated.groups.allSatisfy { !$0.isEnabled })
        XCTAssertNil(migrated.selectedTarget)
    }

    func testSchemaTwoMigrationDisablesAndClearsTransitiveLegacyGroupAncestors() throws {
        let url = tempStateURL()
        let dataStore = HopAppDataStore(
            url: url,
            secretStore: .inMemory(),
            authenticationStore: .inMemory(),
            sharedLogStore: SharedTunnelLogStore(
                url: url.deletingLastPathComponent().appendingPathComponent("hop-tunnel.log"),
            ),
        )
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        let imported = ProxyGroup(
            name: "Legacy Imported",
            type: .select,
            members: [.direct],
            defaultTarget: .direct,
            importedType: "select",
        )
        let parent = ProxyGroup(
            name: "Manual Parent",
            type: .select,
            members: [.named(" Legacy Imported "), .direct],
            defaultTarget: .named(" Legacy Imported "),
        )
        let selectedAncestor = ProxyGroup(
            name: "Selected Ancestor",
            type: .select,
            members: [.group(parent.id), .direct],
            defaultTarget: .group(parent.id),
        )
        let unrelated = ProxyGroup(
            name: "Unrelated Manual",
            type: .select,
            members: [.direct],
            defaultTarget: .direct,
        )
        dataStore.save(HopAppData(
            profiles: [],
            groups: [imported, parent, selectedAncestor, unrelated],
            subscriptions: [],
            routingMode: .global,
            selectedTarget: .group(selectedAncestor.id),
            settings: .defaults,
            logs: [],
            schemaVersion: 2,
        ))

        let migrated = try XCTUnwrap(dataStore.load())

        XCTAssertFalse(try XCTUnwrap(migrated.groups.first { $0.id == imported.id }).isEnabled)
        XCTAssertFalse(try XCTUnwrap(migrated.groups.first { $0.id == parent.id }).isEnabled)
        XCTAssertFalse(try XCTUnwrap(migrated.groups.first { $0.id == selectedAncestor.id }).isEnabled)
        XCTAssertEqual(migrated.groups.first { $0.id == unrelated.id }, unrelated)
        XCTAssertNil(migrated.selectedTarget)
        XCTAssertEqual(
            migrated.pendingXrayMigrationReport?.disabledLegacySubscriptionGroupNames,
            ["Legacy Imported", "Manual Parent", "Selected Ancestor"],
        )
        XCTAssertEqual(
            migrated.pendingXrayMigrationReport?.clearedLegacySelectionName,
            "Selected Ancestor",
        )
    }

    func testSchemaTwoMigrationDisablesDynamicProxyAncestorsWithSubscriptionEvidence() throws {
        let url = tempStateURL()
        let dataStore = HopAppDataStore(
            url: url,
            secretStore: .inMemory(),
            authenticationStore: .inMemory(),
            sharedLogStore: SharedTunnelLogStore(
                url: url.deletingLastPathComponent().appendingPathComponent("hop-tunnel.log"),
            ),
        )
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        let imported = ProxyGroup(
            name: "Legacy Imported",
            type: .select,
            members: [.reject],
            defaultTarget: .reject,
            importedType: "select",
        )
        let dynamicParent = ProxyGroup(
            name: "Dynamic Parent",
            type: .select,
            members: [.selectedProxy, .direct],
            defaultTarget: .selectedProxy,
        )
        dataStore.save(HopAppData(
            profiles: [],
            groups: [imported, dynamicParent],
            subscriptions: [],
            routingMode: .global,
            selectedTarget: .group(dynamicParent.id),
            settings: .defaults,
            logs: [],
            schemaVersion: 2,
        ))

        let migrated = try XCTUnwrap(dataStore.load())

        XCTAssertFalse(try XCTUnwrap(migrated.groups.first { $0.id == imported.id }).isEnabled)
        XCTAssertFalse(try XCTUnwrap(migrated.groups.first { $0.id == dynamicParent.id }).isEnabled)
        XCTAssertNil(migrated.selectedTarget)
        XCTAssertEqual(
            migrated.pendingXrayMigrationReport?.disabledLegacySubscriptionGroupNames,
            ["Dynamic Parent", "Legacy Imported"],
        )
    }

    func testSchemaTwoManualOnlyCustomRulesRemainActive() throws {
        let url = tempStateURL()
        let dataStore = HopAppDataStore(
            url: url,
            secretStore: .inMemory(),
            authenticationStore: .inMemory(),
            sharedLogStore: SharedTunnelLogStore(
                url: url.deletingLastPathComponent().appendingPathComponent("hop-tunnel.log"),
            ),
        )
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let profile = trojanProfile(id: UUID(), name: "Manual", host: "manual.example.com", password: "secret")
        let custom = RuleConfiguration(name: "My Rules", rules: [
            RoutingRule(kind: .domainSuffix, value: "example.com", target: .direct),
        ])
        dataStore.save(HopAppData(
            profiles: [profile],
            groups: [],
            subscriptions: [],
            routingMode: .rule,
            selectedTarget: .profile(profile.id),
            settings: .defaults,
            logs: [],
            ruleConfigurations: [custom],
            activeRuleConfigurationID: custom.id,
            schemaVersion: 2,
        ))

        let migrated = try XCTUnwrap(dataStore.load())

        XCTAssertEqual(migrated.routingMode, .rule)
        XCTAssertEqual(migrated.selectedTarget, .profile(profile.id))
        XCTAssertEqual(migrated.ruleConfigurations, [custom])
        XCTAssertNil(migrated.pendingXrayMigrationReport?.requiresLegacyRoutingReview)
    }

    func testLegacyMigrationReportDecodesWithoutNewProvenanceFields() throws {
        let legacyJSON = #"{"removedProfileNames":[],"removedGroupNames":[],"removedRuleCount":0,"blockedTLSProfileNames":[]}"#

        let report = try JSONDecoder().decode(XrayMigrationReport.self, from: Data(legacyJSON.utf8))

        XCTAssertNil(report.disabledLegacySubscriptionGroupNames)
        XCTAssertNil(report.clearedLegacySelectionName)
        XCTAssertNil(report.requiresLegacyRoutingReview)
    }

    @MainActor
    func testStoreUpdatesSubscriptionMetadata() {
        let subscription = SubscriptionSource(name: "Airport", url: "https://example.com/sub")
        let store = HopStore(
            subscriptions: [subscription],
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )

        var updated = subscription
        updated.lastUpdatedAt = Date(timeIntervalSince1970: 1_800_000_001)
        updated.lastImportSummary = "4 nodes"

        store.updateSubscription(updated)

        XCTAssertEqual(store.subscriptions.first, updated)
    }

    @MainActor
    func testSubscriptionRefreshUpdatesMatchingProfileInsteadOfDuplicating() throws {
        let subscriptionID = UUID()
        let subscription = SubscriptionSource(id: subscriptionID, name: "Provider", url: "https://example.com/sub")
        let existing = trojanProfile(
            id: UUID(),
            name: "Tokyo",
            host: "old.example.com",
            password: "old-password",
            subscriptionID: subscriptionID,
        )
        let refreshed = trojanProfile(
            id: UUID(),
            name: "Tokyo",
            host: "new.example.com",
            password: "new-password",
            subscriptionID: subscriptionID,
        )
        let store = HopStore(
            profiles: [existing],
            groups: [],
            subscriptions: [subscription],
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )

        store.applySubscriptionRefresh(ImportResult(profiles: [refreshed]), updating: subscription)

        XCTAssertEqual(store.profiles.count, 1)
        let profile = try XCTUnwrap(store.profiles.first)
        XCTAssertEqual(profile.id, existing.id)
        XCTAssertEqual(profile.endpoint.host, "new.example.com")
        XCTAssertEqual(profile.options, refreshed.options)
    }

    @MainActor
    func testSubscriptionRefreshDeduplicatesProfilesAndPreservesGroupReferences() throws {
        let subscription = SubscriptionSource(name: "Provider", url: "https://example.com/sub")
        let keptProfile = trojanProfile(id: UUID(), name: "Tokyo", host: "jp.example.com", password: "secret", subscriptionID: subscription.id)
        let duplicateProfile = trojanProfile(id: UUID(), name: "Tokyo", host: "jp.example.com", password: "secret", subscriptionID: subscription.id)
        let existingGroup = ProxyGroup(
            subscriptionID: subscription.id,
            name: "Auto",
            type: .urlTest,
            members: [.profile(keptProfile.id)],
            defaultTarget: .profile(keptProfile.id),
            importedType: "url-test",
        )
        let importedProfile = trojanProfile(id: UUID(), name: "Tokyo", host: "jp.example.com", password: "secret", subscriptionID: subscription.id)
        let importedGroup = ProxyGroup(
            subscriptionID: subscription.id,
            name: "Auto",
            type: .urlTest,
            members: [.profile(importedProfile.id)],
            defaultTarget: .profile(importedProfile.id),
            importedType: "url-test",
        )
        let store = HopStore(
            profiles: [duplicateProfile, keptProfile],
            groups: [existingGroup],
            subscriptions: [subscription],
            selectedTarget: .group(existingGroup.id),
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )

        store.applySubscriptionRefresh(
            ImportResult(profiles: [importedProfile], groups: [importedGroup]),
            updating: subscription,
        )

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
        let store = HopAppDataStore(url: url, secretStore: SecretStore(backend: backend), authenticationStore: .inMemory())

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
        let store = HopAppDataStore(url: url, secretStore: SecretStore(backend: backend), authenticationStore: .inMemory())

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
        let store = HopAppDataStore(url: url, secretStore: SecretStore(backend: backend), authenticationStore: .inMemory())

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
        let store = HopAppDataStore(url: url, secretStore: SecretStore(backend: backend), authenticationStore: .inMemory())
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

    private func trojanProfile(id: UUID, name: String, host: String, password: String, subscriptionID: UUID? = nil) -> ProxyProfile {
        ProxyProfile(
            id: id,
            name: name,
            endpoint: Endpoint(host: host, port: 443),
            options: .trojan(TrojanOptions(password: password)),
            security: .tls(TLSOptions(serverName: host)),
            subscriptionID: subscriptionID,
        )
    }
}
