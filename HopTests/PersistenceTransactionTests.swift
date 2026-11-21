import Foundation
@testable import Hop
import XCTest

final class PersistenceTransactionTests: XCTestCase {
    private let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("hop-persistence-transactions-\(UUID().uuidString)")

    private var stateURL: URL {
        directory.appendingPathComponent("state.json")
    }

    override func setUpWithError() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try FileManager.default.removeItem(at: directory)
    }

    @MainActor
    func testChangingContainerPreservesLibraryUntilItsStateIsAccessible() throws {
        let backend = PersistenceFaultBackend()
        let authentication = SecretStore.inMemory()
        let oldStore = makeStore(backend, authentication: authentication)
        let original = sampleState()
        XCTAssertTrue(oldStore.save(original))
        let originalFile = try Data(contentsOf: stateURL)
        let originalSecrets = try backend.allValues()
        let privateURL = directory.appendingPathComponent("private/Library/state.json")
        let privateStore = HopAppDataStore(url: privateURL, secretStore: SecretStore(backend: backend), authenticationStore: authentication)
        XCTAssertThrowsError(try privateStore.loadExisting())
        XCTAssertEqual(HopStore(dataStore: privateStore).libraryRecoveryMessage, LibraryCredentialError.missingLibrary.errorDescription)
        XCTAssertFalse(privateStore.save(changedState(original)))
        XCTAssertEqual(try Data(contentsOf: stateURL), originalFile)
        XCTAssertEqual(try backend.allValues(), originalSecrets)

        let upgrading = HopAppDataStore(url: privateURL, secretStore: SecretStore(backend: backend), authenticationStore: authentication,
                                        legacyURLs: [stateURL])
        try assertRestores(upgrading, original)
        XCTAssertFalse(FileManager.default.fileExists(atPath: stateURL.path))
        try assertRestores(privateStore, original)
        let edited = changedState(original)
        XCTAssertTrue(privateStore.save(edited))
        try assertRestores(upgrading, edited)

        XCTAssertTrue(RuntimeEnvironment.stateFileURL.path.hasPrefix(FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].path))
        XCTAssertFalse(RuntimeEnvironment.legacyStateFileURLs.contains(RuntimeEnvironment.stateFileURL))
        XCTAssertEqual(HopAppDataStore().url, RuntimeEnvironment.stateFileURL)
    }

    @MainActor
    func testMigrationProtectsConflictingLibrariesAndCanSkipAnObsoleteGeneration() throws {
        let backend = PersistenceFaultBackend()
        let auth = SecretStore.inMemory()
        let olderFile = directory.appendingPathComponent("older.json")
        let canonical = directory.appendingPathComponent("private/state.json")
        let oldStore = makeStore(backend, authentication: auth)
        let original = sampleState()
        XCTAssertTrue(oldStore.save(original))
        let originalEnvelope = try Data(contentsOf: stateURL)
        // Two readable but distinct libraries from the same generation. Their
        // credentials are identical, but throwing away their other edits is unsafe.
        var otherPayload = try readPayload()
        otherPayload.settings.appearance = .dark
        let payload = try encode(otherPayload)
        let signature = try XCTUnwrap(TunnelConfigAuthenticator.signature(for: payload, secret: auth.appStateAuthenticationSecret()))
        try JSONEncoder().encode(AppStateEnvelope(payload: payload, signature: signature)).write(to: olderFile)
        let upgrading = HopAppDataStore(url: canonical, secretStore: SecretStore(backend: backend), authenticationStore: auth, legacyURLs: [stateURL, olderFile])
        let credentials = try backend.allValues()
        XCTAssertThrowsError(try upgrading.loadExisting())
        XCTAssertEqual(HopStore(dataStore: upgrading).libraryRecoveryMessage, LibraryRecoveryError.conflictingLibraries.errorDescription)
        XCTAssertFalse(FileManager.default.fileExists(atPath: canonical.path))
        XCTAssertEqual(try Data(contentsOf: stateURL), originalEnvelope)
        XCTAssertEqual(try backend.allValues(), credentials)

        // The original writer switched generations and already cleaned the
        // old snapshot. Only the current library can now be authenticated and hydrated.
        let updated = changedState(original)
        XCTAssertTrue(oldStore.save(updated))
        try assertRestores(upgrading, updated)
        XCTAssertTrue(FileManager.default.fileExists(atPath: olderFile.path))
    }

    func testPartialFirstSaveCanRetryAfterRelaunch() throws {
        let backend = PersistenceFaultBackend()
        let auth = SecretStore.inMemory()
        backend.rejectNextWrite(afterMatches: 1) { $0.hasPrefix("app-state.") }
        XCTAssertFalse(makeStore(backend, authentication: auth).save(sampleState()))
        XCTAssertFalse(try backend.allValues().isEmpty)
        let restarted = makeStore(backend, authentication: auth)
        XCTAssertNil(try restarted.loadExisting())
        XCTAssertTrue(try backend.allValues().isEmpty)
        let data = sampleState()
        XCTAssertTrue(restarted.save(data))
        try assertRestores(restarted, data)
    }

    func testMissingLegacySubscriptionAndAdvancedCredentialsMustResolveBeforeMigration() throws {
        let backend = PersistenceFaultBackend()
        let store = makeStore(backend, authentication: .inMemory())
        var original = sampleState()
        original.profiles[0].transport.xhttpExtra = .object(["headers": .object(["Authorization": .string("Bearer fixture")])])
        var legacy = original
        legacy.profiles = original.profiles.map { $0.redactingSecrets() }
        legacy.subscriptions = original.subscriptions.map { $0.redactingSecrets() }
        let bytes = try encode(legacy)
        try bytes.write(to: stateURL)
        let profileItems = original.profiles[0].keychainSecretItems
        for item in profileItems where !item.key.contains(".xray.") {
            XCTAssertTrue(backend.setValue(item.value, forKey: item.key))
        }
        XCTAssertThrowsError(try store.loadExisting())
        XCTAssertEqual(try Data(contentsOf: stateURL), bytes)
        let url = try XCTUnwrap(original.subscriptions[0].keychainURLItem)
        XCTAssertTrue(backend.setValue(url.value, forKey: url.key))
        XCTAssertThrowsError(try store.loadExisting())
        XCTAssertEqual(try Data(contentsOf: stateURL), bytes)
        for item in profileItems where item.key.contains(".xray.") {
            XCTAssertTrue(backend.setValue(item.value, forKey: item.key))
        }
        try assertRestores(store, original)
    }

    func testSecretWriteCacheComparesExactUTF8() throws {
        let store = makeStore(PersistenceFaultBackend(), authentication: .inMemory())
        var data = sampleState()
        for password in ["\u{e9}", "e\u{301}"] {
            data.profiles[0].options = .trojan(.init(password: password))
            XCTAssertTrue(store.save(data))
            guard case let .trojan(options) = try XCTUnwrap(store.load()?.profiles.first).options else { return XCTFail("Expected Trojan") }
            XCTAssertEqual(Data(options.password.utf8), Data(password.utf8))
        }
    }

    func testStateAndSidecarReadsAreBoundedAndRejectNonregularFiles() throws {
        let backend = PersistenceFaultBackend()
        let auth = SecretStore.inMemory()
        let store = makeStore(backend, authentication: auth)
        let limited = HopAppDataStore(url: stateURL, secretStore: SecretStore(backend: backend), authenticationStore: auth, maximumFileBytes: 128)
        let original = sampleState()
        XCTAssertTrue(store.save(original))
        let bytes = try Data(contentsOf: stateURL)
        let secrets = try backend.allValues()
        XCTAssertThrowsError(try limited.loadExisting())
        XCTAssertFalse(limited.save(changedState(original)))
        XCTAssertEqual(try Data(contentsOf: stateURL), bytes)
        XCTAssertEqual(try backend.allValues(), secrets)
        try FileManager.default.removeItem(at: stateURL)
        XCTAssertEqual(mkfifo(stateURL.path, 0o600), 0)
        XCTAssertThrowsError(try store.loadExisting())
        try FileManager.default.removeItem(at: stateURL)
        try FileManager.default.createSymbolicLink(at: stateURL, withDestinationURL: URL(fileURLWithPath: "/dev/null"))
        XCTAssertThrowsError(try store.loadExisting())
        try FileManager.default.removeItem(at: stateURL)
        let legacy = try encode(original)
        try legacy.write(to: stateURL)
        try Data(repeating: 32, count: 256).write(to: TunnelConfigAuthenticator.signatureURL(forConfigURL: stateURL))
        XCTAssertThrowsError(try store.loadExisting())
        XCTAssertEqual(try Data(contentsOf: stateURL), legacy)
    }

    @MainActor
    func testNewerSignedSchemaOpensInRecoveryWithoutChangingItsFileOrCredentials() throws {
        let backend = PersistenceFaultBackend()
        let auth = SecretStore.inMemory()
        let store = makeStore(backend, authentication: auth)
        var data = sampleState()
        data.schemaVersion = HopAppData.currentSchemaVersion + 1
        XCTAssertTrue(store.save(data))
        // A newer library may already use an incompatible structure.
        var document = try XCTUnwrap(JSONSerialization.jsonObject(with: persistedStatePayload(at: stateURL)) as? [String: Any])
        document["profiles"] = ["newerLayout": true]
        let payload = try JSONSerialization.data(withJSONObject: document)
        let signature = try XCTUnwrap(TunnelConfigAuthenticator.signature(for: payload, secret: auth.appStateAuthenticationSecret()))
        try JSONEncoder().encode(AppStateEnvelope(payload: payload, signature: signature)).write(to: stateURL)
        let bytes = try Data(contentsOf: stateURL)
        let secrets = try backend.allValues()
        let app = HopStore(dataStore: store)
        XCTAssertTrue(app.libraryLoadFailed)
        XCTAssertEqual(app.libraryRecoveryMessage, LibraryRecoveryError.newerSchema.errorDescription)
        app.settings.appearance = .dark
        app.flushPendingPersists()
        XCTAssertEqual(try Data(contentsOf: stateURL), bytes)
        XCTAssertEqual(try backend.allValues(), secrets)
    }

    func testMigratesLeakedVMessCipherWithoutChangingKeychainUUID() throws {
        let backend = PersistenceFaultBackend()
        let auth = SecretStore.inMemory()
        let store = makeStore(backend, authentication: auth)
        var data = sampleState()
        let uuid = UUID().uuidString
        let leaked = "from-an-older-profile"
        data.profiles[0].options = .vmess(.init(uuid: uuid, security: " Password =\(leaked)", alterID: 0))
        XCTAssertTrue(store.save(data))
        XCTAssertFalse(try String(decoding: persistedStatePayload(at: stateURL), as: UTF8.self).contains(leaked))
        // Sign a fixture matching the previous writer's envelope.
        var old = try readPayload()
        old.profiles[0].options = .vmess(.init(uuid: "", security: " Password =\(leaked)", alterID: 0))
        let payload = try encode(old)
        let signature = try XCTUnwrap(TunnelConfigAuthenticator.signature(for: payload, secret: auth.appStateAuthenticationSecret()))
        try JSONEncoder().encode(AppStateEnvelope(payload: payload, signature: signature)).write(to: stateURL)
        guard case let .vmess(options) = try XCTUnwrap(store.load()?.profiles.first).options else { return XCTFail("Expected VMess") }
        XCTAssertEqual(options.security, "auto")
        XCTAssertEqual(options.uuid, uuid)
        let encoded = try String(decoding: persistedStatePayload(at: stateURL), as: UTF8.self)
        XCTAssertFalse(encoded.contains(leaked))
        XCTAssertFalse(encoded.contains(uuid))
        XCTAssertEqual(backend.value(forKey: HopSecret.key(profileID: data.profiles[0].id, fieldRaw: "uuid")), uuid)
    }

    func testFailedGenerationStagePreservesOldStateAndChangedCredentials() throws {
        let backend = PersistenceFaultBackend()
        let authentication = SecretStore.inMemory()
        let store = makeStore(backend, authentication: authentication)
        let original = sampleState()
        XCTAssertTrue(store.save(original))
        let committedFile = try Data(contentsOf: stateURL)
        let committedSecrets = try backend.allValues()

        // Accept one immutable entry, then fail another: even partial staging
        // must leave both edited credentials and newly added nodes uncommitted.
        backend.rejectNextWrite(afterMatches: 1) { $0.hasPrefix("app-state.") }
        let changed = changedState(original)
        XCTAssertFalse(store.save(changed))
        XCTAssertEqual(try Data(contentsOf: stateURL), committedFile)
        for (key, value) in committedSecrets {
            XCTAssertEqual(backend.value(forKey: key), value)
        }
        try assertRestores(makeStore(backend, authentication: authentication), original)

        XCTAssertTrue(store.save(changed), "the same snapshot must retry after a failed stage")
        try assertRestores(makeStore(backend, authentication: authentication), changed)
    }

    func testFailedFileCommitDoesNotOverwriteOldGeneration() throws {
        let backend = PersistenceFaultBackend()
        let authentication = SecretStore.inMemory()
        let store = makeStore(backend, authentication: authentication)
        let original = sampleState()
        XCTAssertTrue(store.save(original))
        let committedSecrets = try backend.allValues()
        let backupURL = directory.appendingPathComponent("committed-state.json")

        // A directory at the destination fails the atomic file replacement,
        // after the new generation has been staged. Preserve the old file so
        // the next launch can be simulated without a production writer hook.
        try FileManager.default.moveItem(at: stateURL, to: backupURL)
        try FileManager.default.createDirectory(at: stateURL, withIntermediateDirectories: false)
        let changed = changedState(original)
        XCTAssertFalse(store.save(changed))
        XCTAssertGreaterThan(try backend.allValues().count, committedSecrets.count,
                             "the failure must happen after staging new snapshot entries")
        for (key, value) in committedSecrets {
            XCTAssertEqual(backend.value(forKey: key), value)
        }
        try FileManager.default.removeItem(at: stateURL)
        try FileManager.default.moveItem(at: backupURL, to: stateURL)
        try assertRestores(makeStore(backend, authentication: authentication), original)

        XCTAssertTrue(store.save(changed))
        try assertRestores(makeStore(backend, authentication: authentication), changed)
    }

    func testFailedRuntimeAliasWriteKeepsCommittedSnapshotAndRetries() throws {
        let backend = PersistenceFaultBackend()
        let authentication = SecretStore.inMemory()
        let store = makeStore(backend, authentication: authentication)
        let original = sampleState()
        XCTAssertTrue(store.save(original))
        let originalGeneration = try XCTUnwrap(readPayload().secretGeneration)
        let stableKey = HopSecret.key(profileID: original.profiles[0].id, fieldRaw: "password")
        let originalSnapshotKey = HopAppDataStore.snapshotKey(stableKey, generation: originalGeneration)

        backend.rejectNextWrite { $0 == stableKey }
        let changed = changedState(original)
        XCTAssertFalse(store.save(changed))
        XCTAssertEqual(backend.value(forKey: stableKey), "original-password")
        XCTAssertEqual(backend.value(forKey: originalSnapshotKey), "original-password",
                       "failed alias upserts must not prune the previous generation")
        try assertRestores(makeStore(backend, authentication: authentication), changed)

        XCTAssertTrue(store.save(changed), "a failed postcommit mirror must invalidate the unchanged-set cache")
        XCTAssertEqual(backend.value(forKey: stableKey), "changed-password")
        XCTAssertNil(backend.value(forKey: originalSnapshotKey))
        try assertRestores(makeStore(backend, authentication: authentication), changed)
    }

    @MainActor
    func testUnavailableLegacyCredentialsPreserveStateUntilRetry() throws {
        let backend = PersistenceFaultBackend()
        let dataStore = makeStore(backend, authentication: .inMemory())
        let original = sampleState()
        for item in original.profiles.flatMap(\.keychainSecretItems) + original.subscriptions.compactMap(\.keychainURLItem) {
            XCTAssertTrue(backend.setValue(item.value, forKey: item.key))
        }
        var legacy = original
        legacy.profiles = legacy.profiles.map { $0.redactingSecrets() }
        legacy.subscriptions = legacy.subscriptions.map { $0.redactingSecrets() }
        let savedFile = try encode(legacy)
        try savedFile.write(to: stateURL)
        let savedSecrets = try backend.allValues()
        backend.failNextBulkRead()

        let blocked = HopStore(dataStore: dataStore)
        XCTAssertTrue(blocked.libraryLoadFailed)
        blocked.settings.appearance = .dark
        blocked.persist()
        blocked.flushPendingPersists()
        XCTAssertEqual(try Data(contentsOf: stateURL), savedFile)
        XCTAssertEqual(try backend.allValues(), savedSecrets)

        let retried = HopStore(dataStore: dataStore)
        XCTAssertFalse(retried.libraryLoadFailed)
        XCTAssertEqual(retried.profiles, original.profiles)
        XCTAssertEqual(retried.subscriptions, original.subscriptions)
        retried.flushPendingPersists()
    }

    @MainActor
    func testRetryRestoresCommittedLibraryAfterTemporaryCredentialFailure() throws {
        let backend = PersistenceFaultBackend()
        let dataStore = makeStore(backend, authentication: .inMemory())
        let original = sampleState()
        XCTAssertTrue(dataStore.save(original))
        let committedFile = try Data(contentsOf: stateURL)
        let committedSecrets = try backend.allValues()
        backend.failNextBulkRead()

        let blocked = HopStore(dataStore: dataStore)
        XCTAssertTrue(blocked.libraryLoadFailed)
        blocked.settings.appearance = .dark
        blocked.flushPendingPersists()
        XCTAssertEqual(try Data(contentsOf: stateURL), committedFile)
        XCTAssertEqual(try backend.allValues(), committedSecrets)

        let retried = HopStore(dataStore: dataStore)
        XCTAssertFalse(retried.libraryLoadFailed)
        XCTAssertEqual(retried.profiles, original.profiles)
        XCTAssertEqual(retried.subscriptions, original.subscriptions)
        XCTAssertEqual(retried.settings, original.settings)
        retried.flushPendingPersists()
    }

    func testFailedKeyEnumerationRetriesPruningOnUnchangedSave() throws {
        let backend = PersistenceFaultBackend()
        let store = makeStore(backend, authentication: .inMemory())
        let original = sampleState()
        XCTAssertTrue(store.save(original))
        let oldGeneration = try XCTUnwrap(readPayload().secretGeneration)
        let key = HopAppDataStore.snapshotKey(original.profiles[0].keychainSecretItems[0].key, generation: oldGeneration)
        let changed = changedState(original)
        backend.failNextKeyEnumeration()
        XCTAssertFalse(store.save(changed))
        XCTAssertNotNil(backend.value(forKey: key))
        XCTAssertTrue(store.save(changed))
        XCTAssertNil(backend.value(forKey: key))
        try assertRestores(store, changed)
    }

    func testRuntimeAliasChangesCannotChangeSavedCredentials() throws {
        let backend = PersistenceFaultBackend()
        let authentication = SecretStore.inMemory()
        let original = sampleState()
        XCTAssertTrue(makeStore(backend, authentication: authentication).save(original))
        let stableKey = HopSecret.key(profileID: original.profiles[0].id, fieldRaw: "password")
        let subscriptionKey = HopSecret.subscriptionURLKey(subscriptionID: original.subscriptions[0].id)
        XCTAssertTrue(backend.setValue("uncommitted-password", forKey: stableKey))
        XCTAssertTrue(backend.setValue("https://other.example/sub?token=uncommitted", forKey: subscriptionKey))

        let relaunched = makeStore(backend, authentication: authentication)
        try assertRestores(relaunched, original)
        XCTAssertTrue(try relaunched.save(XCTUnwrap(relaunched.load())))
        XCTAssertEqual(backend.value(forKey: stableKey), "original-password")
        XCTAssertEqual(backend.value(forKey: subscriptionKey), original.subscriptions[0].url)
    }

    func testTunnelSnapshotSurvivesProfileEditsDeletionAndOtherNonceStaging() throws {
        let dataStore = makeStore(PersistenceFaultBackend(), authentication: .inMemory())
        let runtime = SecretStore.inMemory()
        let original = sampleState()
        let changed = changedState(original)
        let nonce = UUID().uuidString
        let nextNonce = UUID().uuidString
        let config = try XrayConfigBuilder().build(
            profile: original.profiles[0].tokenizingSecrets(nonce: nonce), routingMode: .global, rules: [],
        )
        for item in original.profiles[0].keychainSecretItems {
            XCTAssertTrue(runtime.setValue(item.value, forKey: HopSecret.runtimeKeyPrefix(nonce: nonce) + item.key))
        }
        XCTAssertTrue(dataStore.save(original))
        XCTAssertTrue(dataStore.save(changed))
        // A pending connection stages its own namespace without changing the
        // config the OS may still restart while manager preferences are saved.
        for item in changed.profiles[0].keychainSecretItems {
            XCTAssertTrue(runtime.setValue(item.value, forKey: HopSecret.runtimeKeyPrefix(nonce: nextNonce) + item.key))
        }
        var deleted = changed
        deleted.profiles = []
        deleted.selectedTarget = nil
        XCTAssertTrue(dataStore.save(deleted))

        let resolved = SecretResolver.resolve(config, nonce: nonce, using: runtime, keyPrefix: HopSecret.runtimeKeyPrefix(nonce: nonce))
        XCTAssertEqual(resolved.unresolved, 0)
        XCTAssertEqual(resolved.config, try XrayConfigBuilder().build(profile: original.profiles[0], routingMode: .global, rules: []))
        let nextConfig = try XrayConfigBuilder().build(
            profile: changed.profiles[0].tokenizingSecrets(nonce: nextNonce), routingMode: .global, rules: [],
        )
        let next = SecretResolver.resolve(nextConfig, nonce: nextNonce, using: runtime, keyPrefix: HopSecret.runtimeKeyPrefix(nonce: nextNonce))
        XCTAssertEqual(next.unresolved, 0)
        XCTAssertEqual(next.config, try XrayConfigBuilder().build(profile: changed.profiles[0], routingMode: .global, rules: []))
    }

    func testMissingSnapshotSecretRejectsStateEvenWhenRuntimeAliasExists() throws {
        let backend = PersistenceFaultBackend()
        let authentication = SecretStore.inMemory()
        let original = sampleState()
        XCTAssertTrue(makeStore(backend, authentication: authentication).save(original))
        let committedFile = try Data(contentsOf: stateURL)
        let generation = try XCTUnwrap(readPayload().secretGeneration)
        let stableKey = HopSecret.key(profileID: original.profiles[0].id, fieldRaw: "password")
        XCTAssertTrue(backend.removeValue(forKey: HopAppDataStore.snapshotKey(stableKey, generation: generation)))
        XCTAssertEqual(backend.value(forKey: stableKey), "original-password")

        XCTAssertNil(makeStore(backend, authentication: authentication).load())
        XCTAssertEqual(try Data(contentsOf: stateURL), committedFile)
    }

    func testEnvelopeAuthenticationBindsGenerationAndSecretManifest() throws {
        let backend = PersistenceFaultBackend()
        let authentication = SecretStore.inMemory()
        XCTAssertTrue(makeStore(backend, authentication: authentication).save(sampleState()))
        let envelope = try JSONDecoder().decode(AppStateEnvelope.self, from: Data(contentsOf: stateURL))
        let payload = try decodePayload(envelope.payload)
        let alternateGeneration = UUID()
        for key in try XCTUnwrap(payload.secretKeys) {
            // The alternate generation is complete, so missing-secret checks
            // cannot accidentally hide a failure to authenticate its identity.
            XCTAssertTrue(backend.setValue("alternate-secret", forKey: HopAppDataStore.snapshotKey(key, generation: alternateGeneration)))
        }
        let secretsBeforeTampering = try backend.allValues()

        for tamperGeneration in [true, false] {
            var tamperedPayload = payload
            if tamperGeneration {
                tamperedPayload.secretGeneration = alternateGeneration
            } else {
                tamperedPayload.secretKeys = []
            }
            var tamperedEnvelope = envelope
            tamperedEnvelope.payload = try encode(tamperedPayload)
            let tamperedFile = try JSONEncoder().encode(tamperedEnvelope)
            try tamperedFile.write(to: stateURL, options: .atomic)

            XCTAssertNil(makeStore(backend, authentication: authentication).load())
            XCTAssertEqual(try Data(contentsOf: stateURL), tamperedFile)
            XCTAssertEqual(try backend.allValues(), secretsBeforeTampering)
        }
    }

    func testSignedLegacyStateMigratesWithoutLosingCredentials() throws {
        let backend = PersistenceFaultBackend()
        let authentication = SecretStore.inMemory()
        let original = sampleState()
        for item in original.profiles.flatMap(\.keychainSecretItems) + original.subscriptions.compactMap(\.keychainURLItem) {
            XCTAssertTrue(backend.setValue(item.value, forKey: item.key))
        }
        var legacy = original
        legacy.profiles = legacy.profiles.map { $0.redactingSecrets() }
        legacy.subscriptions = legacy.subscriptions.map { $0.redactingSecrets() }
        let legacyFile = try encode(legacy)
        let secret = "legacy-authentication-secret"
        XCTAssertTrue(authentication.setValue(secret, forKey: SecretStore.appStateAuthenticationKey))
        let signature = try XCTUnwrap(TunnelConfigAuthenticator.signature(for: legacyFile, secret: secret))
        try legacyFile.write(to: stateURL)
        let signatureURL = TunnelConfigAuthenticator.signatureURL(forConfigURL: stateURL)
        try Data(signature.utf8).write(to: signatureURL)

        try assertRestores(makeStore(backend, authentication: authentication), original)
        XCTAssertNotNil(try readPayload().secretGeneration)
        XCTAssertFalse(FileManager.default.fileExists(atPath: signatureURL.path))
        try assertRestores(makeStore(backend, authentication: authentication), original)
    }

    func testUnsignedLegacyBootstrapResumesAfterAuthenticationKeyWriteFails() throws {
        let backend = PersistenceFaultBackend()
        let authenticationBackend = PersistenceFaultBackend()
        let authentication = SecretStore(backend: authenticationBackend)
        let original = sampleState()
        let legacyFile = try encode(original)
        try legacyFile.write(to: stateURL)
        authenticationBackend.rejectNextWrite { $0 == SecretStore.appStateAuthenticationKey }

        // The partially migrated library stays read-only until retry.
        XCTAssertThrowsError(try makeStore(backend, authentication: authentication).loadExisting())
        XCTAssertEqual(try Data(contentsOf: stateURL), legacyFile)
        XCTAssertTrue(authentication.appStateAuthenticationSecret().isEmpty)
        let signatureURL = TunnelConfigAuthenticator.signatureURL(forConfigURL: stateURL)
        XCTAssertTrue(FileManager.default.fileExists(atPath: signatureURL.path))

        try assertRestores(makeStore(backend, authentication: authentication), original)
        XCTAssertFalse(authentication.appStateAuthenticationSecret().isEmpty)
        XCTAssertNotNil(try readPayload().secretGeneration)
        XCTAssertFalse(FileManager.default.fileExists(atPath: signatureURL.path))
        try assertRestores(makeStore(backend, authentication: authentication), original)
    }

    func testSignedLegacyStateWithMissingAuthenticationKeyIsNotResigned() throws {
        let backend = PersistenceFaultBackend()
        let authentication = SecretStore.inMemory()
        let legacyFile = try encode(sampleState())
        try legacyFile.write(to: stateURL)
        let signature = try XCTUnwrap(TunnelConfigAuthenticator.signature(for: legacyFile, secret: "unavailable-key"))
        let signatureURL = TunnelConfigAuthenticator.signatureURL(forConfigURL: stateURL)
        try Data(signature.utf8).write(to: signatureURL)

        XCTAssertNil(makeStore(backend, authentication: authentication).load())
        XCTAssertEqual(try Data(contentsOf: stateURL), legacyFile)
        XCTAssertEqual(try String(contentsOf: signatureURL, encoding: .utf8), signature)
        XCTAssertTrue(authentication.appStateAuthenticationSecret().isEmpty)
        XCTAssertTrue(try backend.allValues().isEmpty)
    }

    func testReplaceAllDoesNotPruneAfterFailedUpsertAndPreservesSnapshotKeys() throws {
        let backend = PersistenceFaultBackend()
        let store = SecretStore(backend: backend)
        XCTAssertTrue(store.setValue("old-value", forKey: "old"))
        XCTAssertTrue(store.setValue("saved-value", forKey: "snapshot"))
        backend.rejectNextWrite { $0 == "new" }

        XCTAssertFalse(store.replaceAll(with: [("new", "new-value")], preservingKeys: ["snapshot"]))
        XCTAssertEqual(try backend.allValues(), ["old": "old-value", "snapshot": "saved-value"])
        XCTAssertTrue(store.replaceAll(with: [("new", "new-value")], preservingKeys: ["snapshot"]))
        XCTAssertEqual(try backend.allValues(), ["new": "new-value", "snapshot": "saved-value"])
    }

    @MainActor
    func testDeletingAllRuleConfigurationsRemainsEmptyAfterRelaunch() throws {
        let dataStore = makeStore(PersistenceFaultBackend(), authentication: .inMemory())
        let store = HopStore(dataStore: dataStore)
        for configuration in store.ruleConfigurations {
            store.deleteRuleConfiguration(id: configuration.id)
        }
        store.flushPendingPersists()
        XCTAssertTrue(try XCTUnwrap(dataStore.load()?.ruleConfigurations).isEmpty)

        let relaunched = HopStore(dataStore: dataStore)
        XCTAssertTrue(relaunched.ruleConfigurations.isEmpty)
        XCTAssertNil(relaunched.activeRuleConfigurationID)
        XCTAssertTrue(relaunched.rules.isEmpty)
    }

    @MainActor
    func testSubscriptionRemovalBlocksLocalRulesInsteadOfFallingThroughToDirect() throws {
        let dataStore = makeStore(PersistenceFaultBackend(), authentication: .inMemory())
        let source = SubscriptionSource(name: "Provider", url: "https://source.example/sub")
        let manual = sampleState().profiles[0]
        var removed = manual
        removed.id = UUID()
        removed.name = "Removed"
        removed.endpoint.host = "removed.example"
        removed.subscriptionID = source.id
        var retained = removed
        retained.id = UUID()
        retained.name = "Retained"
        retained.endpoint.host = "retained.example"
        let removedGroup = ProxyGroup(
            subscriptionID: source.id, name: "Removed Group", type: .select,
            members: [.profile(removed.id)],
        )
        let configuration = RuleConfiguration(name: "Local policy", rules: [
            RoutingRule(kind: .domain, value: "sensitive.example", target: .profile(removed.id)),
            RoutingRule(kind: .domain, value: "group.example", target: .group(removedGroup.id)),
            RoutingRule(kind: .final, value: "", target: .direct),
        ])
        let store = HopStore(
            profiles: [removed, retained, manual], groups: [removedGroup], subscriptions: [source],
            ruleConfigurations: [configuration], activeRuleConfigurationID: configuration.id,
            routingMode: .rule, selectedTarget: .profile(manual.id), dataStore: dataStore,
        )

        XCTAssertTrue(store.applySubscriptionRefresh(ImportResult(profiles: [retained]), updating: source))
        var expectedRules = configuration.rules
        expectedRules[0].target = .reject
        expectedRules[1].target = .reject
        XCTAssertEqual(store.rules, expectedRules)
        XCTAssertTrue(store.tunnel.logs.contains { $0.contains("Blocked 2 routing rule(s)") })
        let config = try XrayConfigBuilder().build(
            profiles: store.profiles, groups: store.groups, selectedTarget: .profile(manual.id),
            routingMode: store.routingMode, rules: store.rules,
        )
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(config.utf8)) as? [String: Any])
        let routing = try XCTUnwrap(root["routing"] as? [String: Any])
        let emittedRules = try XCTUnwrap(routing["rules"] as? [[String: Any]])
        for domain in ["sensitive.example", "group.example"] {
            let rule = try XCTUnwrap(emittedRules.first { ($0["domain"] as? [String]) == ["full:\(domain)"] })
            XCTAssertEqual(rule["outboundTag"] as? String, "reject")
        }
        store.flushPendingPersists()
        XCTAssertEqual(HopStore(dataStore: dataStore).rules, expectedRules)
    }

    @MainActor
    func testSubscriptionReplacementCannotRetargetImportedNamedRules() throws {
        let dataStore = makeStore(PersistenceFaultBackend(), authentication: .inMemory())
        let source = SubscriptionSource(name: "Provider", url: "https://source.example/sub")
        var manual = sampleState().profiles[0]
        manual.name = "Manual"
        let original = ProxyProfile(
            name: "A", endpoint: Endpoint(host: "old.example", port: 443),
            options: .vless(VLESSOptions(uuid: UUID().uuidString)), security: .tls(TLSOptions()),
            subscriptionID: source.id,
        )
        let originalGroup = ProxyGroup(subscriptionID: source.id, name: "Group A", type: .select, members: [.profile(original.id)])
        let configuration = RuleConfiguration(name: "Local policy")
        let store = HopStore(
            profiles: [original, manual], groups: [originalGroup], subscriptions: [source],
            ruleConfigurations: [configuration], activeRuleConfigurationID: configuration.id,
            routingMode: .rule, selectedTarget: .profile(manual.id), dataStore: dataStore,
        )
        try store.applyImport(ProxyImportService().importText("""
        [Proxy]
        [Rule]
        DOMAIN,sensitive.example,A
        DOMAIN,group.example,Group A
        DOMAIN,stable.example,Manual
        FINAL,DIRECT
        """))
        XCTAssertEqual(store.rules.map(\.target), [.named("A"), .named("Group A"), .named("Manual"), .direct])
        XCTAssertNoThrow(try XrayConfigBuilder().build(
            profiles: store.profiles, groups: store.groups, selectedTarget: .profile(manual.id),
            routingMode: store.routingMode, rules: store.rules,
        ))
        var expectedRules = store.rules
        expectedRules[0].target = .reject
        expectedRules[1].target = .reject
        let replacement = ProxyProfile(
            name: "A", endpoint: Endpoint(host: "new.example", port: 443),
            options: .trojan(TrojanOptions(password: "new-server-secret")), security: .tls(TLSOptions()),
        )
        let replacementGroupTarget = ProxyProfile(
            name: "Group A", endpoint: Endpoint(host: "new-group-target.example", port: 443),
            options: .trojan(TrojanOptions(password: "new-group-secret")), security: .tls(TLSOptions()),
        )

        XCTAssertTrue(store.applySubscriptionRefresh(ImportResult(profiles: [replacement, replacementGroupTarget]), updating: source))
        XCTAssertFalse(store.profiles.contains { $0.id == original.id })
        XCTAssertFalse(store.groups.contains { $0.id == originalGroup.id })
        XCTAssertEqual(store.rules, expectedRules)
        let config = try XrayConfigBuilder().build(
            profiles: store.profiles, groups: store.groups, selectedTarget: .profile(manual.id),
            routingMode: store.routingMode, rules: store.rules,
        )
        XCTAssertFalse(config.contains("new.example"), "a replaced named target must not become a reachable outbound")
        XCTAssertFalse(config.contains("new-group-target.example"), "a group name must not become a new profile target")
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(config.utf8)) as? [String: Any])
        let routing = try XCTUnwrap(root["routing"] as? [String: Any])
        let emittedRules = try XCTUnwrap(routing["rules"] as? [[String: Any]])
        for domain in ["sensitive.example", "group.example"] {
            let rule = try XCTUnwrap(emittedRules.first { ($0["domain"] as? [String]) == ["full:\(domain)"] })
            XCTAssertEqual(rule["outboundTag"] as? String, "reject")
        }
        store.flushPendingPersists()
        XCTAssertEqual(HopStore(dataStore: dataStore).rules, expectedRules)
    }

    @MainActor
    func testManualRenameKeepsNamedRulesAndDeletionBlocksTheirDestinations() throws {
        let data = sampleState()
        var profile = data.profiles[0]
        var group = ProxyGroup(name: "Regional", type: .select, members: [.named(profile.name)], defaultTarget: .named(profile.name))
        let config = RuleConfiguration(name: "Policy")
        let app = HopStore(profiles: [profile], groups: [group], ruleConfigurations: [config], activeRuleConfigurationID: config.id,
                           dataStore: makeStore(PersistenceFaultBackend(), authentication: .inMemory()))
        try app.applyImport(ProxyImportService().importText("""
        [Proxy]
        [Rule]
        DOMAIN,profile.example,Original
        DOMAIN,group.example,Regional
        FINAL,DIRECT
        """))
        profile.name = group.name
        app.updateProfile(profile)
        XCTAssertEqual(app.rules.map(\.target), [.profile(profile.id), .group(group.id), .direct])
        XCTAssertEqual(app.groups[0].members, [.profile(profile.id)])
        group = app.groups[0]
        group.name = "Renamed group"
        app.updateGroup(group)
        XCTAssertEqual(app.rules.map(\.target), [.profile(profile.id), .group(group.id), .direct])
        try app.applyImport(ProxyImportService().importText("""
        [Proxy]
        [Rule]
        DOMAIN,second.example,Renamed group
        """))
        app.deleteGroup(id: group.id)
        XCTAssertEqual(app.rules.first { $0.value == "second.example" }?.target, .reject)
        XCTAssertNoThrow(try XrayConfigBuilder().build(profiles: app.profiles, groups: app.groups, selectedTarget: .profile(profile.id), routingMode: .rule, rules: app.rules))
        app.flushPendingPersists()
    }

    private func makeStore(_ backend: PersistenceFaultBackend, authentication: SecretStore) -> HopAppDataStore {
        HopAppDataStore(url: stateURL, secretStore: SecretStore(backend: backend), authenticationStore: authentication)
    }

    private func sampleState() -> HopAppData {
        let profile = ProxyProfile(
            name: "Original",
            endpoint: Endpoint(host: "original.example.com", port: 443),
            options: .trojan(TrojanOptions(password: "original-password")),
            security: .tls(TLSOptions()),
        )
        return HopAppData(
            profiles: [profile], groups: [],
            subscriptions: [SubscriptionSource(name: "Source", url: "https://source.example/sub?token=original")],
            routingMode: .global, selectedTarget: .profile(profile.id), settings: .defaults, logs: ["Original state"],
        )
    }

    private func changedState(_ original: HopAppData) -> HopAppData {
        var changed = original
        changed.profiles[0].endpoint.host = "changed.example.com"
        changed.profiles[0].options = .trojan(TrojanOptions(password: "changed-password"))
        let added = ProxyProfile(
            name: "Added", endpoint: Endpoint(host: "added.example.com", port: 443),
            options: .trojan(TrojanOptions(password: "added-password")), security: .tls(TLSOptions()),
        )
        changed.profiles.append(added)
        changed.subscriptions[0].url = "https://source.example/sub?token=changed"
        changed.selectedTarget = .profile(added.id)
        changed.logs = ["Changed state"]
        return changed
    }

    private func assertRestores(_ store: HopAppDataStore, _ expected: HopAppData, file: StaticString = #filePath, line: UInt = #line) throws {
        let loaded = try XCTUnwrap(store.load(), file: file, line: line)
        XCTAssertEqual(loaded.profiles, expected.profiles, file: file, line: line)
        XCTAssertEqual(loaded.subscriptions, expected.subscriptions, file: file, line: line)
        XCTAssertEqual(loaded.selectedTarget, expected.selectedTarget, file: file, line: line)
        XCTAssertEqual(loaded.logs, expected.logs, file: file, line: line)
    }

    private func readPayload() throws -> HopAppData {
        let envelope = try JSONDecoder().decode(AppStateEnvelope.self, from: Data(contentsOf: stateURL))
        return try decodePayload(envelope.payload)
    }

    private func decodePayload(_ data: Data) throws -> HopAppData {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(HopAppData.self, from: data)
    }

    private func encode(_ data: HopAppData) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(data)
    }
}

/// Deterministic one-shot write failures; storage and fault state are locked
/// independently, matching the production backend's Sendable boundary.
private final class PersistenceFaultBackend: SecretBackend, @unchecked Sendable {
    private let storage = InMemorySecretBackend()
    private let lock = NSLock()
    private var failurePredicate: (@Sendable (String) -> Bool)?
    private var matchesUntilFailure = 0
    private var rejectBulkRead = false
    private var rejectKeyEnumeration = false

    func failNextBulkRead() {
        lock.withLock { rejectBulkRead = true }
    }

    func failNextKeyEnumeration() {
        lock.withLock { rejectKeyEnumeration = true }
    }

    func rejectNextWrite(afterMatches: Int = 0, matching: @escaping @Sendable (String) -> Bool) {
        lock.withLock {
            failurePredicate = matching
            matchesUntilFailure = afterMatches
        }
    }

    func setValue(_ value: String, forKey key: String) -> Bool {
        let reject = lock.withLock {
            guard failurePredicate?(key) == true else { return false }
            if matchesUntilFailure > 0 {
                matchesUntilFailure -= 1
                return false
            }
            failurePredicate = nil
            return true
        }
        return !reject && storage.setValue(value, forKey: key)
    }

    func value(forKey key: String) -> String? {
        storage.value(forKey: key)
    }

    func allValues() throws -> [String: String] {
        try lock.withLock {
            if rejectBulkRead {
                rejectBulkRead = false
                throw CocoaError(.fileReadNoPermission)
            }
        }
        return storage.allValues()
    }

    func removeValue(forKey key: String) -> Bool {
        storage.removeValue(forKey: key)
    }

    func removeAll() {
        storage.removeAll()
    }

    func allKeys() throws -> [String] {
        try lock.withLock {
            if rejectKeyEnumeration {
                rejectKeyEnumeration = false
                throw CocoaError(.fileReadNoPermission)
            }
        }
        return storage.allKeys()
    }
}
