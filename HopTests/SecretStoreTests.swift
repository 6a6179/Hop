@testable import Hop
import XCTest

final class SecretStoreTests: XCTestCase {
    private func makeStore() -> SecretStore {
        SecretStore.inMemory()
    }

    private func makeTempStateURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("hop-secret-tests-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("hop-state.json")
    }

    // MARK: - SecretStore

    func testSecretStoreSetGetUpdateRemove() {
        let store = makeStore()
        defer { store.removeAll() }

        XCTAssertNil(store.value(forKey: "alpha"))
        store.setValue("first", forKey: "alpha")
        XCTAssertEqual(store.value(forKey: "alpha"), "first")
        store.setValue("second", forKey: "alpha")
        XCTAssertEqual(store.value(forKey: "alpha"), "second")
        store.removeValue(forKey: "alpha")
        XCTAssertNil(store.value(forKey: "alpha"))
    }

    func testSecretStoreReplaceAllClearsStaleItems() {
        let store = makeStore()
        defer { store.removeAll() }

        store.setValue("stale", forKey: "old")
        store.replaceAll(with: [("k1", "v1"), ("k2", "v2")])

        XCTAssertNil(store.value(forKey: "old"))
        XCTAssertEqual(store.value(forKey: "k1"), "v1")
        XCTAssertEqual(store.value(forKey: "k2"), "v2")
    }

    /// `replaceAll` must upsert before pruning — a clear-then-rewrite pass
    /// would leave a window where the tunnel extension resolves no secrets and
    /// fails a concurrent start/reload.
    func testReplaceAllUpsertsWithoutClearingFirst() {
        let backend = InMemorySecretBackend()
        let store = SecretStore(backend: backend)

        store.setValue("v1", forKey: "keep")
        store.setValue("old", forKey: "stale")
        store.replaceAll(with: [("keep", "v2"), ("new", "v3")])

        XCTAssertEqual(backend.removeAllCount, 0, "replaceAll must never clear the whole store")
        XCTAssertEqual(store.value(forKey: "keep"), "v2")
        XCTAssertEqual(store.value(forKey: "new"), "v3")
        XCTAssertNil(store.value(forKey: "stale"), "keys absent from the new set are pruned")
    }

    func testSecretStoreHandlesSpecialCharacters() {
        let store = makeStore()
        defer { store.removeAll() }

        let messy = #"p@ss":\word/with#hash and "quotes""#
        store.setValue(messy, forKey: "weird")
        XCTAssertEqual(store.value(forKey: "weird"), messy)
    }

    /// Runtime authentication keys must live in their own Keychain service so
    /// a profile save's `replaceAll` (which rewrites the *profile* secret set)
    /// never evicts them. This guards the wiring that keeps the stores apart.
    func testRuntimeServiceIsSeparateFromProfileSecrets() {
        XCTAssertNotEqual(SecretStore.runtimeService, SecretStore.defaultService)
    }

    // MARK: - Profile redaction / hydration

    func testProfileRedactionRemovesSecretsAndHydrationRestores() {
        let store = makeStore()
        defer { store.removeAll() }

        let profile = SampleData.vlessReality
        XCTAssertFalse(profile.keychainSecretItems.isEmpty)

        let redacted = profile.redactingSecrets()
        XCTAssertTrue(redacted.secretFieldValues.isEmpty, "redacted profile must expose no secrets")

        for item in profile.keychainSecretItems {
            store.setValue(item.value, forKey: item.key)
        }
        let hydrated = redacted.hydratingSecrets(from: store)
        XCTAssertEqual(hydrated, profile)
    }

    func testRealityMLDSA65VerifyIsRedactedAndHydrated() {
        let store = makeStore()
        defer { store.removeAll() }

        let verifyKey = "MLDSA65VERIFY"
        var profile = SampleData.vlessReality
        if var reality = profile.security.reality {
            reality.mldsa65Verify = verifyKey
            profile.security.reality = reality
        }

        let redacted = profile.redactingSecrets()
        XCTAssertFalse(redacted.secretFieldValues.values.contains(verifyKey))
        XCTAssertFalse(redacted.keychainSecretItems.contains { $0.value == verifyKey })

        for item in profile.keychainSecretItems {
            store.setValue(item.value, forKey: item.key)
        }
        let hydrated = redacted.hydratingSecrets(from: store)
        XCTAssertEqual(hydrated, profile)
    }

    func testVLESSEncryptionIsRedactedAndHydrated() {
        let store = makeStore()
        defer { store.removeAll() }

        let encryption = "mlkem768x25519plus.native.0rtt..AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        let profile = ProxyProfile(
            name: "Encrypted VLESS",
            endpoint: Endpoint(host: "edge.example.net", port: 443),
            options: .vless(VLESSOptions(
                uuid: "11111111-1111-4111-8111-111111111111",
                flow: "xtls-rprx-vision",
                encryption: encryption,
            )),
            security: .reality(RealityOptions(publicKey: "PUBLICKEY", shortID: "abcd")),
        )

        let redacted = profile.redactingSecrets()
        XCTAssertFalse(redacted.secretFieldValues.values.contains(encryption))
        XCTAssertFalse(redacted.keychainSecretItems.contains { $0.value == encryption })

        for item in profile.keychainSecretItems {
            store.setValue(item.value, forKey: item.key)
        }
        let hydrated = redacted.hydratingSecrets(from: store)
        XCTAssertEqual(hydrated, profile)
    }

    func testHydrationLeavesFieldsUntouchedWhenKeychainEmpty() {
        let store = makeStore()
        defer { store.removeAll() }

        let profile = SampleData.trojanTLS
        let hydrated = profile.hydratingSecrets(from: store) // nothing stored
        XCTAssertEqual(hydrated, profile)
    }

    func testWireGuardPeerPreSharedKeysUseDistinctStableAccounts() throws {
        let store = makeStore()
        defer { store.removeAll() }
        let peers = try [
            WireGuardPeer(id: XCTUnwrap(UUID(uuidString: "11111111-1111-4111-8111-111111111111")), publicKey: "one", preSharedKey: "psk-one"),
            WireGuardPeer(id: XCTUnwrap(UUID(uuidString: "22222222-2222-4222-8222-222222222222")), publicKey: "two", preSharedKey: "psk-two"),
        ]
        let profile = ProxyProfile(
            name: "WG",
            endpoint: Endpoint(host: "wg.example.net", port: 51820),
            options: .wireGuard(WireGuardOptions(
                privateKey: "private",
                peerPublicKey: peers[0].publicKey,
                localAddress: ["10.0.0.2/32"],
                peers: peers,
            )),
            security: .none,
        )

        let pskItems = profile.keychainSecretItems.filter { $0.value.hasPrefix("psk-") }
        XCTAssertEqual(pskItems.count, 2)
        XCTAssertEqual(Set(pskItems.map(\.key)).count, 2)
        profile.keychainSecretItems.forEach { store.setValue($0.value, forKey: $0.key) }

        let redacted = profile.redactingSecrets()
        guard case let .wireGuard(redactedOptions) = redacted.options else { return XCTFail("Expected WireGuard") }
        XCTAssertEqual(redactedOptions.peers?.map(\.preSharedKey), ["", ""])
        XCTAssertEqual(redacted.hydratingSecrets(from: store), profile)

        guard case let .wireGuard(tokenizedOptions) = profile.tokenizingSecrets(nonce: "nonce").options else { return XCTFail("Expected WireGuard") }
        let tokens = tokenizedOptions.peers?.compactMap(\.preSharedKey) ?? []
        XCTAssertEqual(Set(tokens).count, 2)
        XCTAssertTrue(tokens.allSatisfy { $0.hasPrefix("##HOP_SECRET:nonce:") })
    }

    // MARK: - Tokenization + resolution

    func testTokenizedConfigCarriesNoSecretsAndResolves() throws {
        let store = makeStore()
        defer { store.removeAll() }

        let profile = SampleData.trojanTLS
        for item in profile.keychainSecretItems {
            store.setValue(item.value, forKey: item.key)
        }

        let nonce = "test-nonce-AAAA"
        let json = try XrayConfigBuilder().build(profile: profile.tokenizingSecrets(nonce: nonce), routingMode: .global, rules: [])
        XCTAssertFalse(json.contains("replace-me"), "tokenized config must not contain the secret")
        XCTAssertTrue(json.contains("##HOP_SECRET:"), "tokenized config must reference the secret")
        XCTAssertEqual(
            SecretResolver.referencedKeys(in: json, nonce: nonce),
            Set(profile.keychainSecretItems.map(\.key)),
        )

        let (resolved, unresolved) = SecretResolver.resolve(json, nonce: nonce, using: store)
        XCTAssertEqual(unresolved, 0)
        XCTAssertTrue(resolved.contains("replace-me"), "resolved config must restore the secret")
        XCTAssertFalse(resolved.contains("##HOP_SECRET:"), "resolved config must not leave tokens")
    }

    func testResolverReportsUnresolvedTokens() {
        let store = makeStore()
        defer { store.removeAll() }

        let nonce = "test-nonce-AAAA"
        let token = HopSecret.token(forKey: "missing.password", nonce: nonce)
        let config = "{\"password\":\"\(token)\"}"
        let (resolved, unresolved) = SecretResolver.resolve(config, nonce: nonce, using: store)
        XCTAssertEqual(unresolved, 1)
        XCTAssertFalse(resolved.contains("##HOP_SECRET:"))
    }

    /// Regression for the cross-profile secret-exfiltration finding: an
    /// untrusted field can contain a `##HOP_SECRET:…##` string, but unless it
    /// bears the current run's nonce the resolver must leave it inert and never
    /// substitute a Keychain secret into it.
    func testResolverIgnoresForeignNonceTokens() {
        let store = makeStore()
        defer { store.removeAll() }

        let victimKey = HopSecret.key(profileID: SampleData.trojanTLS.id, fieldRaw: ProfileSecretField.password.rawValue)
        store.setValue("VICTIM-SECRET", forKey: victimKey)

        let realNonce = "real-nonce-1234"
        // An attacker who controls an imported field cannot know `realNonce`, so
        // the best they can do is emit a token with a guessed/foreign nonce.
        let injected = HopSecret.token(forKey: victimKey, nonce: "forged-nonce")
        let config = "{\"path\":\"\(injected)\",\"server\":\"attacker.example\"}"

        let (resolved, unresolved) = SecretResolver.resolve(config, nonce: realNonce, using: store)
        XCTAssertFalse(resolved.contains("VICTIM-SECRET"), "foreign-nonce token must not be resolved")
        XCTAssertTrue(resolved.contains(injected), "inert token should be left untouched")
        XCTAssertEqual(unresolved, 0, "foreign tokens are inert and must not count as unresolved")
        XCTAssertTrue(SecretResolver.referencedKeys(in: config, nonce: realNonce).isEmpty)
    }

    func testTokenizedConfigReferencesOnlyReachableProfileSecrets() throws {
        let selected = SampleData.trojanTLS
        let unreachable = SampleData.hysteria2
        let nonce = "reachable-nonce"
        let config = try XrayConfigBuilder().build(
            profiles: [selected, unreachable].map { $0.tokenizingSecrets(nonce: nonce) },
            groups: [],
            selectedTarget: .profile(selected.id),
            routingMode: .global,
            rules: [],
        )

        let referencedKeys = SecretResolver.referencedKeys(in: config, nonce: nonce)
        XCTAssertEqual(referencedKeys, Set(selected.keychainSecretItems.map(\.key)))
        XCTAssertTrue(referencedKeys.isDisjoint(with: Set(unreachable.keychainSecretItems.map(\.key))))
        XCTAssertFalse(config.contains("replace-me"))
        XCTAssertFalse(config.contains("obfs-secret"))
    }

    // MARK: - HopAppDataStore at-rest behavior

    func testStateFileContainsNoPlaintextSecrets() throws {
        let url = makeTempStateURL()
        let store = makeStore()
        let dataStore = HopAppDataStore(url: url, secretStore: store, authenticationStore: store)
        defer {
            store.removeAll()
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
        }

        dataStore.save(sampleAppData())

        let raw = try String(contentsOf: url, encoding: .utf8)
        XCTAssertFalse(raw.contains("replace-me"), "trojan/hysteria2 passwords leaked into JSON")
        XCTAssertFalse(raw.contains("obfs-secret"), "obfs password leaked into JSON")
        XCTAssertFalse(raw.contains("11111111-1111-4111-8111-111111111111"), "VLESS UUID leaked into JSON")
        XCTAssertFalse(raw.contains("qwertyuiopasdfghjklzxcvbnm1234567890ABCDE"), "REALITY public key leaked into JSON")

        let loaded = try XCTUnwrap(dataStore.load())
        XCTAssertEqual(loaded.profiles, SampleData.profiles, "secrets must be restored from the Keychain on load")
    }

    func testAdvancedSecretSidecarPersistsReferencesAndHydratesValues() throws {
        let url = makeTempStateURL()
        let store = makeStore()
        let dataStore = HopAppDataStore(url: url, secretStore: store, authenticationStore: store)
        defer {
            store.removeAll()
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
        }

        var profile = SampleData.vlessReality
        profile.xrayAdvanced = XrayAdvancedDocument([
            "settings": .object(["seed": .string("vless-seed-secret")]),
            "streamSettings": .object([
                "wsSettings": .object([
                    "headers": .object(["Authorization": .string("Bearer advanced-secret")]),
                ]),
            ]),
        ])
        profile.transport.finalMask = .object([
            "udp": .array([
                .object([
                    "type": .string("salamander"),
                    "settings": .object(["password": .string("mask-password")]),
                ]),
                .object([
                    "type": .string("realm"),
                    "settings": .object(["url": .string("realm://host/token")]),
                ]),
            ]),
        ])

        let data = HopAppData(
            profiles: [profile],
            groups: [],
            subscriptions: [],
            routingMode: .global,
            selectedTarget: .profile(profile.id),
            settings: .defaults,
            logs: [],
        )
        dataStore.save(data)

        let raw = try String(contentsOf: url, encoding: .utf8)
        for secret in ["vless-seed-secret", "Bearer advanced-secret", "mask-password", "realm://host/token"] {
            XCTAssertFalse(raw.contains(secret))
        }
        XCTAssertTrue(raw.contains("##HOP_XRAY_SECRET_REF:"))
        XCTAssertEqual(try XCTUnwrap(dataStore.load()).profiles, [profile])

        let tokenized = profile.tokenizingSecrets(nonce: "advanced-nonce")
        let tokenizedJSON = try String(data: JSONEncoder().encode(tokenized), encoding: .utf8) ?? ""
        XCTAssertFalse(tokenizedJSON.contains("vless-seed-secret"))
        XCTAssertTrue(tokenizedJSON.contains("##HOP_SECRET:advanced-nonce:"))
    }

    func testLegacyPlaintextStateIsMigratedOnLoad() throws {
        let url = makeTempStateURL()
        let store = makeStore()
        defer {
            store.removeAll()
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
        }

        // Simulate state written by a pre-migration build: secrets inline in JSON.
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let legacy = HopAppData(
            profiles: [SampleData.trojanTLS],
            groups: [],
            subscriptions: [],
            routingMode: .rule,
            selectedTarget: nil,
            settings: .defaults,
            logs: [],
            ruleConfigurations: SampleData.ruleConfigurations,
            activeRuleConfigurationID: SampleData.defaultConfiguration.id,
        )
        try encoder.encode(legacy).write(to: url)
        XCTAssertTrue(try String(contentsOf: url, encoding: .utf8).contains("replace-me"))

        let dataStore = HopAppDataStore(url: url, secretStore: store, authenticationStore: store)
        let loaded = try XCTUnwrap(dataStore.load())

        XCTAssertEqual(loaded.profiles, [SampleData.trojanTLS], "secrets must survive migration")
        XCTAssertFalse(try String(contentsOf: url, encoding: .utf8).contains("replace-me"), "migration must rewrite the file without secrets")
        let key = HopSecret.key(profileID: SampleData.trojanTLS.id, fieldRaw: ProfileSecretField.password.rawValue)
        XCTAssertEqual(store.value(forKey: key), "replace-me", "migration must move the secret into the Keychain")
    }

    private func sampleAppData() -> HopAppData {
        HopAppData(
            profiles: SampleData.profiles,
            groups: SampleData.groups,
            subscriptions: [],
            routingMode: .rule,
            selectedTarget: nil,
            settings: .defaults,
            logs: [],
            ruleConfigurations: SampleData.ruleConfigurations,
            activeRuleConfigurationID: SampleData.defaultConfiguration.id,
        )
    }
}
