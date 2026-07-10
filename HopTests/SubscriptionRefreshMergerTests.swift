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

    func testExactIdentityCannotAdoptAnotherSubscriptionProfile() throws {
        let sourceA = UUID()
        let sourceB = UUID()
        let selectedA = trojanProfile(name: "Tokyo", host: "shared.example.com", subscriptionID: sourceA)
        let importedB = trojanProfile(name: "Tokyo", host: "shared.example.com", subscriptionID: sourceB)
        var merger = SubscriptionRefreshMerger(
            profiles: [selectedA],
            groups: [],
            selectedTarget: .profile(selectedA.id),
        )

        merger.merge(ImportResult(profiles: [importedB]))

        XCTAssertEqual(merger.profiles.count, 2)
        XCTAssertEqual(merger.selectedTarget, .profile(selectedA.id))
        XCTAssertEqual(merger.profiles.first { $0.id == selectedA.id }?.subscriptionID, sourceA)

        var changedB = importedB
        changedB.endpoint = Endpoint(host: "rotated.example.com", port: 443)
        merger.merge(ImportResult(profiles: [changedB]))

        let storedB = try XCTUnwrap(merger.profiles.first { $0.subscriptionID == sourceB })
        XCTAssertEqual(storedB.id, importedB.id)
        XCTAssertEqual(storedB.endpoint.host, "rotated.example.com")
        XCTAssertEqual(merger.profiles.first { $0.id == selectedA.id }?.endpoint.host, "shared.example.com")
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
        weakened.security.tls?.serverName = existing.security.tls?.serverName
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

    func testExactRefreshPreservesLocalAdvancedOverlayEvenFromRemoteReplacement() throws {
        let subscriptionID = UUID()
        var existing = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscriptionID)
        existing.xrayAdvanced = XrayAdvancedDocument([
            "streamSettings": .object([
                "realitySettings": .object([
                    "mldsa65Verify": .string("LOCAL-MLDSA"),
                ]),
            ]),
        ])
        var withoutOverlay = existing
        withoutOverlay.id = UUID()
        withoutOverlay.xrayAdvanced = nil
        var merger = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)

        merger.merge(ImportResult(profiles: [withoutOverlay]))
        XCTAssertEqual(try XCTUnwrap(merger.profiles.first).xrayAdvanced, existing.xrayAdvanced)

        var remoteReplacement = withoutOverlay
        remoteReplacement.id = UUID()
        remoteReplacement.xrayAdvanced = XrayAdvancedDocument([
            "streamSettings": .object([
                "realitySettings": .object([
                    "mldsa65Verify": .string("REMOTE-MLDSA"),
                ]),
            ]),
        ])
        merger.merge(
            ImportResult(profiles: [remoteReplacement]),
            securityPolicy: .applyReviewedChanges,
        )

        XCTAssertEqual(try XCTUnwrap(merger.profiles.first).xrayAdvanced, existing.xrayAdvanced)
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
        existing.security.tls?.serverName = "old.example.com"
        existing.security.tls?.utlsFingerprint = "chrome"
        existing.security.tls?.maxVersion = "1.3"
        existing.security.tls?.cipherSuites = "TLS_AES_256_GCM_SHA384"
        existing.transport.finalMask = .object(["udp": .array([.object(["type": .string("XDNS"), "dns": .string("9.9.9.9:53")])])])

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
        imported.security.tls?.serverName = "new.example.com"
        imported.security.tls?.utlsFingerprint = "firefox"
        imported.security.tls?.maxVersion = "1.2"
        imported.security.tls?.cipherSuites = "TLS_AES_128_GCM_SHA256"
        imported.transport.finalMask = .object(["udp": .array([.object(["type": .string("XDNS"), "dns": .string("1.1.1.1:53")])])])

        let preview = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)
        let changes = try XCTUnwrap(preview.securityCriticalChanges(in: [imported]).first)
        XCTAssertEqual(changes.profileName, "Tokyo")
        XCTAssertEqual(Set(changes.fields), Set([
            .tlsMinimumVersion,
            .tlsServerName,
            .tlsClientFingerprint,
            .tlsMaximumVersion,
            .tlsCipherSuites,
            .certificatePins,
            .verificationNames,
            .ech,
            .postQuantumCurves,
            .finalMaskTransportPolicy,
            .vlessEncryption,
            .realityPublicKey,
            .realityMLDSA,
        ]))

        var automatic = preview
        automatic.merge(ImportResult(profiles: [imported]))
        let preserved = try XCTUnwrap(automatic.profiles.first)
        XCTAssertEqual(preserved.security.tls?.minVersion, "1.3")
        XCTAssertEqual(preserved.security.tls?.serverName, "old.example.com")
        XCTAssertEqual(preserved.security.tls?.utlsFingerprint, "chrome")
        XCTAssertEqual(preserved.security.tls?.maxVersion, "1.3")
        XCTAssertEqual(preserved.security.tls?.cipherSuites, "TLS_AES_256_GCM_SHA384")
        XCTAssertEqual(preserved.security.tls?.pinnedPeerCertSHA256, "OLD-PIN")
        XCTAssertEqual(preserved.security.tls?.verifyPeerCertByName, "old.example.com")
        XCTAssertEqual(preserved.security.tls?.echConfigList, "OLD-ECH")
        XCTAssertEqual(preserved.security.tls?.curvePreferences, ["X25519MLKEM768", "X25519"])
        XCTAssertEqual(preserved.security.reality?.publicKey, "OLD-REALITY")
        XCTAssertEqual(preserved.security.reality?.mldsa65Verify, "OLD-MLDSA")
        XCTAssertEqual(preserved.transport.finalMask, existing.transport.finalMask)
        guard case let .vless(preservedVLESS) = preserved.options else {
            return XCTFail("Expected VLESS options")
        }
        XCTAssertEqual(preservedVLESS.encryption, "old-auth")

        // The merge index must reflect the value actually stored after policy
        // preservation, not the raw imported identity. Otherwise the second
        // identical refresh would take the exact-match path and bypass policy.
        automatic.merge(ImportResult(profiles: [imported]))
        let preservedAgain = try XCTUnwrap(automatic.profiles.first)
        XCTAssertEqual(preservedAgain.security.tls?.pinnedPeerCertSHA256, "OLD-PIN")
        XCTAssertEqual(preservedAgain.security.reality?.publicKey, "OLD-REALITY")
        XCTAssertEqual(preservedAgain.transport.finalMask, existing.transport.finalMask)
        guard case let .vless(preservedAgainVLESS) = preservedAgain.options else {
            return XCTFail("Expected VLESS options")
        }
        XCTAssertEqual(preservedAgainVLESS.encryption, "old-auth")

        var reviewed = preview
        reviewed.merge(ImportResult(profiles: [imported]), securityPolicy: .applyReviewedChanges)
        let applied = try XCTUnwrap(reviewed.profiles.first)
        XCTAssertEqual(applied.security.tls?.minVersion, "1.2")
        XCTAssertEqual(applied.security.tls?.serverName, "new.example.com")
        XCTAssertEqual(applied.security.tls?.utlsFingerprint, "firefox")
        XCTAssertEqual(applied.security.tls?.maxVersion, "1.2")
        XCTAssertEqual(applied.security.tls?.cipherSuites, "TLS_AES_128_GCM_SHA256")
        XCTAssertEqual(applied.security.tls?.pinnedPeerCertSHA256, "NEW-PIN")
        XCTAssertEqual(applied.security.reality?.publicKey, "NEW-REALITY")
        XCTAssertEqual(applied.security.reality?.mldsa65Verify, "NEW-MLDSA")
        XCTAssertEqual(applied.transport.finalMask, imported.transport.finalMask)
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
        imported.security.tls?.serverName = existing.security.tls?.serverName
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
    func testManualRefreshReviewsTLSIdentityNegotiationAndFinalMask() {
        let subscription = SubscriptionSource(name: "Provider", url: "https://example.com/sub")
        var existing = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscription.id)
        existing.security.tls?.utlsFingerprint = "chrome"
        existing.security.tls?.maxVersion = "1.3"
        existing.security.tls?.cipherSuites = "OLD-CIPHER"
        existing.transport.finalMask = .object(["udp": .array([.string("old")])])
        var imported = existing
        imported.id = UUID()
        imported.security.tls?.serverName = "replacement.example.com"
        imported.security.tls?.utlsFingerprint = "firefox"
        imported.security.tls?.maxVersion = "1.2"
        imported.security.tls?.cipherSuites = "NEW-CIPHER"
        imported.transport.finalMask = .object(["udp": .array([.string("new")])])
        let store = HopStore(
            profiles: [existing],
            subscriptions: [subscription],
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )

        let outcome = store.reviewSubscriptionRefresh(ImportResult(profiles: [imported]), for: subscription)

        guard case let .needsSecurityConfirmation(_, changes, _) = outcome else {
            return XCTFail("Expected TLS and FinalMask changes to require review")
        }
        XCTAssertEqual(Set(changes.flatMap(\.fields)), Set([
            .tlsServerName,
            .tlsClientFingerprint,
            .tlsMaximumVersion,
            .tlsCipherSuites,
            .finalMaskTransportPolicy,
        ]))
        XCTAssertEqual(store.profiles, [existing])
    }

    @MainActor
    func testManualRefreshRequiresBothConfirmationsWhenBothRisksArePresent() {
        let subscription = SubscriptionSource(name: "Provider", url: "https://example.com/sub")
        var existing = trojanProfile(name: "Tokyo", host: "old.example.com", subscriptionID: subscription.id)
        existing.security.tls?.pinnedPeerCertSHA256 = "OLD-PIN"
        var changed = trojanProfile(name: "Tokyo", host: "new.example.com", subscriptionID: subscription.id)
        changed.security.tls?.serverName = existing.security.tls?.serverName
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

    func testGroupRefreshMatchingRequiresSameSubscriptionOwner() throws {
        let sourceA = UUID()
        let sourceB = UUID()
        let groupA = ProxyGroup(
            subscriptionID: sourceA,
            name: "Primary",
            type: .select,
            members: [.direct],
            defaultTarget: .direct,
            importedType: "select",
        )
        let groupB = ProxyGroup(
            subscriptionID: sourceB,
            name: " primary ",
            type: .select,
            members: [.reject],
            defaultTarget: .reject,
            importedType: "select",
        )
        var merger = SubscriptionRefreshMerger(
            profiles: [],
            groups: [groupA],
            selectedTarget: .group(groupA.id),
        )

        merger.merge(ImportResult(groups: [groupB]))

        XCTAssertEqual(merger.groups.count, 2)
        XCTAssertEqual(merger.selectedTarget, .group(groupA.id))
        XCTAssertEqual(merger.groups.first { $0.id == groupA.id }?.defaultTarget, .direct)

        var refreshedA = groupA
        refreshedA.id = UUID()
        refreshedA.members = [.direct, .reject]
        refreshedA.defaultTarget = .reject
        merger.merge(ImportResult(groups: [refreshedA]))

        let storedA = try XCTUnwrap(merger.groups.first { $0.subscriptionID == sourceA })
        XCTAssertEqual(storedA.id, groupA.id)
        XCTAssertEqual(storedA.defaultTarget, .reject)
        XCTAssertFalse(storedA.isEnabled)
        XCTAssertTrue(storedA.warning?.contains("Review") == true)
        XCTAssertNil(merger.selectedTarget)
        XCTAssertEqual(merger.groups.first { $0.subscriptionID == sourceB }?.defaultTarget, .reject)
    }

    func testGroupRefreshPreservesLocalDisabledStateWhenRoutingIsUnchanged() throws {
        let source = UUID()
        let profile = trojanProfile(name: "Node", host: "node.example.com", subscriptionID: source)
        let existing = ProxyGroup(
            subscriptionID: source,
            name: "Provider",
            type: .select,
            members: [.profile(profile.id)],
            defaultTarget: .profile(profile.id),
            isEnabled: false,
            importedType: "select",
        )
        var refreshed = existing
        refreshed.id = UUID()
        refreshed.isEnabled = true
        var merger = SubscriptionRefreshMerger(
            profiles: [profile],
            groups: [existing],
            selectedTarget: nil,
        )

        merger.merge(ImportResult(groups: [refreshed]))

        let stored = try XCTUnwrap(merger.groups.first)
        XCTAssertEqual(stored.id, existing.id)
        XCTAssertFalse(stored.isEnabled)
        XCTAssertNil(stored.warning)
    }

    func testChangedChildRoutingInvalidatesSelectedAncestorsTransitively() throws {
        let source = UUID()
        let otherSource = UUID()
        let child = ProxyGroup(
            subscriptionID: source,
            name: "Child",
            type: .select,
            members: [.direct],
            defaultTarget: .direct,
            importedType: "select",
        )
        let parent = ProxyGroup(
            subscriptionID: source,
            name: "Parent",
            type: .select,
            members: [.group(child.id), .direct],
            defaultTarget: .group(child.id),
            importedType: "select",
        )
        let selectedAncestor = ProxyGroup(
            subscriptionID: source,
            name: "Selected Ancestor",
            type: .select,
            members: [.group(parent.id)],
            defaultTarget: .group(parent.id),
            importedType: "select",
        )
        let disabledLocally = ProxyGroup(
            name: "Disabled Locally",
            type: .select,
            members: [.group(child.id)],
            isEnabled: false,
            warning: "Local warning",
        )
        let unrelated = ProxyGroup(
            subscriptionID: otherSource,
            name: "Unrelated",
            type: .select,
            members: [.direct],
            importedType: "select",
        )
        var refreshedChild = child
        refreshedChild.id = UUID()
        refreshedChild.members = [.reject]
        refreshedChild.defaultTarget = .reject
        var refreshedParent = parent
        refreshedParent.id = UUID()
        refreshedParent.members = [.group(refreshedChild.id), .direct]
        refreshedParent.defaultTarget = .group(refreshedChild.id)
        var refreshedAncestor = selectedAncestor
        refreshedAncestor.id = UUID()
        refreshedAncestor.members = [.group(refreshedParent.id)]
        refreshedAncestor.defaultTarget = .group(refreshedParent.id)
        var merger = SubscriptionRefreshMerger(
            profiles: [],
            groups: [selectedAncestor, parent, child, disabledLocally, unrelated],
            selectedTarget: .group(selectedAncestor.id),
        )

        merger.merge(
            ImportResult(groups: [refreshedAncestor, refreshedParent, refreshedChild]),
            replacingSnapshotFor: source,
        )

        for id in [child.id, parent.id, selectedAncestor.id] {
            let group = try XCTUnwrap(merger.groups.first { $0.id == id })
            XCTAssertFalse(group.isEnabled)
            XCTAssertTrue(group.warning?.contains("Review") == true)
        }
        XCTAssertNil(merger.selectedTarget)
        XCTAssertEqual(merger.securityDowngradeWarnings.count, 3)
        XCTAssertEqual(merger.groups.first { $0.id == disabledLocally.id }, disabledLocally)
        XCTAssertTrue(try XCTUnwrap(merger.groups.first { $0.id == unrelated.id }).isEnabled)
    }

    func testChangedChildRoutingInvalidatesUniqueNamedAncestorsTransitively() throws {
        let source = UUID()
        let child = ProxyGroup(
            subscriptionID: source,
            name: "Child",
            type: .select,
            members: [.direct],
            defaultTarget: .direct,
            importedType: "select",
        )
        let namedParent = ProxyGroup(
            name: "Named Parent",
            type: .select,
            members: [.named(" child "), .direct],
            defaultTarget: .named(" child "),
        )
        let selectedAncestor = ProxyGroup(
            name: "Selected Ancestor",
            type: .select,
            members: [.group(namedParent.id)],
            defaultTarget: .group(namedParent.id),
        )
        var refreshedChild = child
        refreshedChild.id = UUID()
        refreshedChild.members = [.reject]
        refreshedChild.defaultTarget = .reject
        var merger = SubscriptionRefreshMerger(
            profiles: [],
            groups: [selectedAncestor, namedParent, child],
            selectedTarget: .group(selectedAncestor.id),
        )

        merger.merge(
            ImportResult(groups: [refreshedChild]),
            replacingSnapshotFor: source,
        )

        for id in [child.id, namedParent.id, selectedAncestor.id] {
            let group = try XCTUnwrap(merger.groups.first { $0.id == id })
            XCTAssertFalse(group.isEnabled)
            XCTAssertTrue(group.warning?.contains("Review") == true)
        }
        XCTAssertNil(merger.selectedTarget)
        XCTAssertEqual(merger.securityDowngradeWarnings.count, 3)
    }

    func testNamedProfileReplacementInvalidatesSelectedManualGroup() throws {
        let source = UUID()
        let existing = trojanProfile(name: "Node", host: "old.example.com", subscriptionID: source)
        let replacement = ProxyProfile(
            name: "Node",
            endpoint: Endpoint(host: "new.example.com", port: 443),
            options: .shadowsocks(ShadowsocksOptions(method: "aes-128-gcm", password: "secret")),
            security: .tls(TLSOptions(serverName: "new.example.com")),
            subscriptionID: source,
        )
        let manualGroup = ProxyGroup(
            name: "Manual",
            type: .select,
            members: [.named("node"), .direct],
            defaultTarget: .named("node"),
        )
        var merger = SubscriptionRefreshMerger(
            profiles: [existing],
            groups: [manualGroup],
            selectedTarget: .group(manualGroup.id),
        )

        merger.merge(
            ImportResult(profiles: [replacement]),
            replacingSnapshotFor: source,
        )

        XCTAssertEqual(merger.removedProfileIDs, [existing.id])
        XCTAssertEqual(merger.profiles.map(\.id), [replacement.id])
        let storedGroup = try XCTUnwrap(merger.groups.first)
        XCTAssertFalse(storedGroup.isEnabled)
        XCTAssertNil(merger.selectedTarget)
    }

    func testSelectedProxyAndNamedProxyChangesInvalidateGroupsAndDynamicSelection() {
        let source = UUID()
        let removed = trojanProfile(name: "Removed", host: "old.example.com", subscriptionID: source)
        let fallback = trojanProfile(name: "Fallback", host: "fallback.example.com")
        let selectedProxyGroup = ProxyGroup(
            name: "Selected Proxy",
            type: .select,
            members: [.selectedProxy, .direct],
            defaultTarget: .selectedProxy,
        )
        let namedProxyGroup = ProxyGroup(
            name: "Named Proxy",
            type: .select,
            members: [.named(" PrOxY "), .direct],
            defaultTarget: .named(" PrOxY "),
        )
        var merger = SubscriptionRefreshMerger(
            profiles: [removed, fallback],
            groups: [selectedProxyGroup, namedProxyGroup],
            selectedTarget: .selectedProxy,
        )

        merger.merge(ImportResult(), replacingSnapshotFor: source)

        XCTAssertEqual(merger.profiles.map(\.id), [fallback.id])
        XCTAssertTrue(merger.groups.allSatisfy { !$0.isEnabled })
        XCTAssertNil(merger.selectedTarget)
        XCTAssertEqual(merger.securityDowngradeWarnings.count, 2)
    }

    func testRoutingInvalidationHandlesMaximumRetainedGroupChainIteratively() {
        let source = UUID()
        let leaf = ProxyGroup(
            subscriptionID: source,
            name: "Leaf",
            type: .select,
            members: [.direct],
            defaultTarget: .direct,
            importedType: "select",
        )
        var groups = [leaf]
        var childID = leaf.id
        for index in 1 ..< ImportPolicy.maxImportedItems {
            let parent = ProxyGroup(
                name: "Parent \(index)",
                type: .select,
                members: [.group(childID)],
                defaultTarget: .group(childID),
            )
            groups.append(parent)
            childID = parent.id
        }
        groups.reverse()
        var refreshedLeaf = leaf
        refreshedLeaf.id = UUID()
        refreshedLeaf.members = [.reject]
        refreshedLeaf.defaultTarget = .reject
        var merger = SubscriptionRefreshMerger(
            profiles: [],
            groups: groups,
            selectedTarget: .group(childID),
        )

        merger.merge(
            ImportResult(groups: [refreshedLeaf]),
            replacingSnapshotFor: source,
        )

        XCTAssertEqual(merger.groups.count, ImportPolicy.maxImportedItems)
        XCTAssertTrue(merger.groups.allSatisfy { !$0.isEnabled })
        XCTAssertNil(merger.selectedTarget)
    }

    func testSnapshotGroupDeletionInvalidatesParentAndSelectedAncestor() throws {
        let source = UUID()
        let otherSource = UUID()
        let removedChild = ProxyGroup(
            subscriptionID: source,
            name: "Removed Child",
            type: .select,
            members: [.reject],
            importedType: "select",
        )
        let parent = ProxyGroup(
            subscriptionID: source,
            name: "Parent",
            type: .select,
            members: [.group(removedChild.id), .direct],
            defaultTarget: .group(removedChild.id),
            importedType: "select",
        )
        let selectedAncestor = ProxyGroup(
            subscriptionID: source,
            name: "Selected Ancestor",
            type: .select,
            members: [.group(parent.id)],
            defaultTarget: .group(parent.id),
            importedType: "select",
        )
        let unrelated = ProxyGroup(
            subscriptionID: otherSource,
            name: "Unrelated",
            type: .select,
            members: [.direct],
            importedType: "select",
        )
        var refreshedParent = parent
        refreshedParent.id = UUID()
        var refreshedAncestor = selectedAncestor
        refreshedAncestor.id = UUID()
        refreshedAncestor.members = [.group(refreshedParent.id)]
        refreshedAncestor.defaultTarget = .group(refreshedParent.id)
        var merger = SubscriptionRefreshMerger(
            profiles: [],
            groups: [selectedAncestor, parent, removedChild, unrelated],
            selectedTarget: .group(selectedAncestor.id),
        )

        merger.merge(
            ImportResult(groups: [refreshedAncestor, refreshedParent]),
            replacingSnapshotFor: source,
        )

        XCTAssertEqual(merger.removedGroupIDs, [removedChild.id])
        XCTAssertFalse(merger.groups.contains { $0.id == removedChild.id })
        let storedParent = try XCTUnwrap(merger.groups.first { $0.id == parent.id })
        XCTAssertEqual(storedParent.members, [.direct])
        XCTAssertEqual(storedParent.defaultTarget, .direct)
        XCTAssertFalse(storedParent.isEnabled)
        XCTAssertTrue(storedParent.warning?.contains("Review") == true)
        let storedAncestor = try XCTUnwrap(merger.groups.first { $0.id == selectedAncestor.id })
        XCTAssertFalse(storedAncestor.isEnabled)
        XCTAssertTrue(storedAncestor.warning?.contains("Review") == true)
        XCTAssertNil(merger.selectedTarget)
        XCTAssertTrue(try XCTUnwrap(merger.groups.first { $0.id == unrelated.id }).isEnabled)
    }

    func testRepeatedDuplicateGroupMergeCanonicalizesReplacementsWithoutCycles() throws {
        let source = UUID()
        let duplicateA = ProxyGroup(
            subscriptionID: source,
            name: "Provider",
            type: .select,
            members: [.direct],
            importedType: "select",
        )
        let duplicateB = ProxyGroup(
            subscriptionID: source,
            name: "Provider",
            type: .select,
            members: [.reject],
            importedType: "select",
        )
        let survivor = ProxyGroup(
            subscriptionID: source,
            name: "Provider",
            type: .select,
            members: [.direct, .reject],
            importedType: "select",
        )
        let manualParent = ProxyGroup(
            name: "Manual",
            type: .select,
            members: [.group(duplicateA.id), .group(duplicateB.id), .group(survivor.id)],
        )
        var firstImport = survivor
        firstImport.id = UUID()
        firstImport.members = [.direct]
        var secondImport = firstImport
        secondImport.id = UUID()
        secondImport.members = [.reject]
        var merger = SubscriptionRefreshMerger(
            profiles: [],
            groups: [duplicateA, manualParent, duplicateB, survivor],
            selectedTarget: .group(survivor.id),
        )

        merger.merge(ImportResult(groups: [firstImport, secondImport]))

        let stored = try XCTUnwrap(merger.groups.first { $0.id == survivor.id })
        XCTAssertEqual(stored.members, [.reject])
        XCTAssertEqual(merger.groups.first { $0.id == manualParent.id }?.members, [.group(survivor.id)])
        XCTAssertEqual(merger.groupIDReplacements[duplicateA.id], survivor.id)
        XCTAssertEqual(merger.groupIDReplacements[duplicateB.id], survivor.id)
        XCTAssertTrue(merger.groupIDReplacements.allSatisfy { oldID, replacementID in
            oldID != replacementID && merger.groupIDReplacements[replacementID] == nil
        })
    }

    func testSnapshotReconciliationRemovesOnlyAbsentSameSourceItemsAndRepairsReferences() {
        let sourceA = UUID()
        let sourceB = UUID()
        let oldA = trojanProfile(name: "Old A", host: "old-a.example.com", subscriptionID: sourceA)
        let keptB = trojanProfile(name: "B", host: "b.example.com", subscriptionID: sourceB)
        let manual = trojanProfile(name: "Manual", host: "manual.example.com")
        let oldGroupA = ProxyGroup(
            subscriptionID: sourceA,
            name: "Old Group",
            type: .select,
            members: [.profile(oldA.id)],
            defaultTarget: .profile(oldA.id),
            importedType: "select",
        )
        let manualGroup = ProxyGroup(
            name: "Manual Group",
            type: .select,
            members: [.profile(oldA.id), .group(oldGroupA.id), .named(" Old A "), .profile(manual.id)],
            defaultTarget: .profile(oldA.id),
        )
        let newA = trojanProfile(name: "New A", host: "new-a.example.com", subscriptionID: sourceA)
        var merger = SubscriptionRefreshMerger(
            profiles: [oldA, keptB, manual],
            groups: [oldGroupA, manualGroup],
            selectedTarget: .group(oldGroupA.id),
        )

        merger.merge(
            ImportResult(profiles: [newA]),
            replacingSnapshotFor: sourceA,
        )

        XCTAssertEqual(Set(merger.profiles.map(\.id)), Set([newA.id, keptB.id, manual.id]))
        XCTAssertEqual(merger.groups.map(\.id), [manualGroup.id])
        XCTAssertEqual(merger.groups.first?.members, [.named(" Old A "), .profile(manual.id)])
        XCTAssertEqual(merger.groups.first?.defaultTarget, .named(" Old A "))
        XCTAssertNil(merger.selectedTarget)
        XCTAssertEqual(merger.removedProfileIDs, [oldA.id])
        XCTAssertEqual(merger.removedGroupIDs, [oldGroupA.id])
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
        let subscription = SubscriptionSource(name: "Provider", url: "https://example.com/sub")
        let store = HopStore(
            profiles: [trojanProfile(name: "Existing", host: "e.example.com")],
            groups: [],
            subscriptions: [subscription],
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: SecretStore(backend: backend), authenticationStore: .inMemory()),
        )
        // init may normalize the selected target, which enqueues a save of its
        // own; settle it before taking the baseline.
        store.flushPendingPersists()
        let baseline = backend.allKeysCount

        let imported = (0 ..< 25).map { trojanProfile(name: "Node \($0)", host: "n\($0).example.com") }
        store.applySubscriptionRefresh(ImportResult(profiles: imported), updating: subscription)
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
        let subscription = SubscriptionSource(name: "Provider", url: "https://example.com/sub")
        let store = HopStore(
            profiles: [trojanProfile(name: "Existing", host: "e.example.com")],
            groups: [],
            subscriptions: [subscription],
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )
        let rulesBefore = store.ruleConfigurations.map(\.rules)

        store.applySubscriptionRefresh(ImportResult(
            profiles: [trojanProfile(name: "Existing", host: "n.example.com")],
            rules: [RoutingRule(kind: .domainSuffix, value: "bank.example", target: .direct)],
        ), updating: subscription)

        XCTAssertEqual(store.ruleConfigurations.map(\.rules), rulesBefore, "refresh rules must not touch rule configurations")
    }

    @MainActor
    func testInitialSubscriptionImportStampsAllOwnershipDropsRulesAndPreservesSelection() throws {
        let manual = trojanProfile(name: "Manual", host: "manual.example.com")
        let subscription = SubscriptionSource(name: "Provider", url: "https://example.com/sub")
        let imported = trojanProfile(name: "Tokyo", host: "jp.example.com")
        let importedGroup = ProxyGroup(
            name: "Provider Group",
            type: .select,
            members: [.profile(imported.id)],
            defaultTarget: .profile(imported.id),
            importedType: "select",
        )
        let store = HopStore(
            profiles: [manual],
            selectedTarget: .profile(manual.id),
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )
        let rulesBefore = store.ruleConfigurations.map(\.rules)

        XCTAssertTrue(store.applySubscriptionImport(
            ImportResult(
                profiles: [imported],
                groups: [importedGroup],
                rules: [RoutingRule(kind: .domainSuffix, value: "bank.example", target: .direct)],
            ),
            adding: subscription,
        ))

        let savedProfile = try XCTUnwrap(store.profiles.first { $0.name == "Tokyo" })
        let savedGroup = try XCTUnwrap(store.groups.first { $0.name == "Provider Group" })
        XCTAssertEqual(savedProfile.subscriptionID, subscription.id)
        XCTAssertEqual(savedGroup.subscriptionID, subscription.id)
        XCTAssertFalse(savedGroup.isEnabled)
        XCTAssertTrue(savedGroup.warning?.contains("Review") == true)
        XCTAssertEqual(store.subscriptions, [subscription])
        XCTAssertEqual(store.ruleConfigurations.map(\.rules), rulesBefore)
        XCTAssertEqual(store.selectedTarget, .profile(manual.id))
    }

    @MainActor
    func testInitialSubscriptionImportNeverAutoSelectsOpaqueProviderGroup() throws {
        let profileSubscription = SubscriptionSource(name: "Profiles", url: "https://profiles.example/sub")
        let importedProfile = trojanProfile(name: "Expected", host: "expected.example.com")
        let directDefaultGroup = ProxyGroup(
            name: "Opaque Direct",
            type: .select,
            members: [.direct, .profile(importedProfile.id)],
            defaultTarget: .direct,
            importedType: "select",
        )
        let profileStore = HopStore(
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )
        let preview = ImportResult(
            profiles: [importedProfile],
            groups: [directDefaultGroup],
        ).requiringSubscriptionGroupReview()

        XCTAssertEqual(preview.warnings.map(\.message), [ImportResult.subscriptionGroupReviewWarning])
        XCTAssertFalse(try XCTUnwrap(preview.groups.first).isEnabled)
        let noisyPreview = ImportResult(
            groups: [directDefaultGroup],
            warnings: (0 ..< 5).map { ImportWarning(message: "Parser warning \($0)") },
        )
        .requiringSubscriptionGroupReview()
        .requiringSubscriptionGroupReview()
        XCTAssertEqual(noisyPreview.warnings.first?.message, ImportResult.subscriptionGroupReviewWarning)
        XCTAssertEqual(noisyPreview.warnings.count, 6, "the critical preview warning is front-loaded and deduplicated")
        XCTAssertTrue(profileStore.applySubscriptionImport(preview, adding: profileSubscription))
        XCTAssertEqual(profileStore.selectedTarget, .profile(importedProfile.id))
        XCTAssertFalse(try XCTUnwrap(profileStore.groups.first).isEnabled)

        let groupOnlySubscription = SubscriptionSource(name: "Groups", url: "https://groups.example/sub")
        let rejectDefaultGroup = ProxyGroup(
            name: "Opaque Reject",
            type: .select,
            members: [.reject],
            defaultTarget: .reject,
            importedType: "select",
        )
        let groupOnlyStore = HopStore(
            selectedTarget: .group(UUID()),
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )

        XCTAssertTrue(groupOnlyStore.applySubscriptionImport(
            ImportResult(groups: [rejectDefaultGroup]),
            adding: groupOnlySubscription,
        ))
        XCTAssertEqual(groupOnlyStore.selectedTarget, .direct)
        XCTAssertEqual(groupOnlyStore.groups.first?.defaultTarget, .reject)
        XCTAssertFalse(try XCTUnwrap(groupOnlyStore.groups.first).isEnabled)
    }

    @MainActor
    func testOwnedNamedGroupTargetsStayBoundAcrossSameNameSourcesAndDeletion() throws {
        let sourceA = SubscriptionSource(name: "A", url: "https://a.example/sub")
        let profileA = trojanProfile(name: "Tokyo", host: "a.example.com")
        let exclusiveProfileA = trojanProfile(name: "A Only", host: "a-only.example.com")
        let innerA = ProxyGroup(
            name: "Inner",
            type: .select,
            members: [.direct],
            importedType: "select",
        )
        let exclusiveGroupA = ProxyGroup(
            name: "A Only Group",
            type: .select,
            members: [.direct],
            importedType: "select",
        )
        let topA = ProxyGroup(
            name: "Top",
            type: .select,
            members: [.named("Tokyo"), .named("Inner"), .selectedProxy, .named("PROXY")],
            defaultTarget: .named("Tokyo"),
            importedType: "select",
        )
        let store = HopStore(
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )

        XCTAssertTrue(store.applySubscriptionImport(
            ImportResult(
                profiles: [profileA, exclusiveProfileA],
                groups: [topA, innerA, exclusiveGroupA],
            ),
            adding: sourceA,
        ))
        let savedProfileA = try XCTUnwrap(store.profiles.first {
            $0.subscriptionID == sourceA.id && $0.name == "Tokyo"
        })
        let savedInnerA = try XCTUnwrap(store.groups.first { $0.subscriptionID == sourceA.id && $0.name == "Inner" })
        let savedTopA = try XCTUnwrap(store.groups.first { $0.subscriptionID == sourceA.id && $0.name == "Top" })
        XCTAssertEqual(savedTopA.members, [.profile(savedProfileA.id), .group(savedInnerA.id)])
        XCTAssertEqual(savedTopA.defaultTarget, .profile(savedProfileA.id))
        XCTAssertEqual(store.selectedTarget, .profile(savedProfileA.id))
        // Simulate the explicit review/enabling now required for imported
        // groups before verifying that later same-name sources cannot retarget it.
        var reviewedInnerA = savedInnerA
        reviewedInnerA.isEnabled = true
        store.updateGroup(reviewedInnerA)
        var reviewedTopA = savedTopA
        reviewedTopA.isEnabled = true
        store.updateGroup(reviewedTopA)
        store.selectedTarget = .group(savedTopA.id)

        let sourceB = SubscriptionSource(name: "B", url: "https://b.example/sub")
        let profileB = trojanProfile(name: "Tokyo", host: "b.example.com")
        let innerB = ProxyGroup(
            name: "Inner",
            type: .select,
            members: [.reject],
            importedType: "select",
        )
        let crossSourceOnlyB = ProxyGroup(
            name: "Cross Source Only",
            type: .select,
            members: [.named("A Only"), .named("A Only Group")],
            defaultTarget: .named("A Only"),
            importedType: "select",
        )
        XCTAssertTrue(store.applySubscriptionImport(
            ImportResult(profiles: [profileB], groups: [innerB, crossSourceOnlyB]),
            adding: sourceB,
        ))

        XCTAssertEqual(store.selectedTarget, .group(savedTopA.id))
        XCTAssertEqual(store.groups.first { $0.id == savedTopA.id }?.members, [
            .profile(savedProfileA.id),
            .group(savedInnerA.id),
        ])
        let savedCrossSourceOnlyB = try XCTUnwrap(store.groups.first {
            $0.subscriptionID == sourceB.id && $0.name == "Cross Source Only"
        })
        XCTAssertTrue(savedCrossSourceOnlyB.members.isEmpty)
        XCTAssertNil(savedCrossSourceOnlyB.defaultTarget)
        XCTAssertFalse(savedCrossSourceOnlyB.isEnabled)

        store.deleteSubscription(id: sourceB.id)

        XCTAssertEqual(store.selectedTarget, .group(savedTopA.id))
        XCTAssertEqual(store.groups.first { $0.id == savedTopA.id }?.members, [
            .profile(savedProfileA.id),
            .group(savedInnerA.id),
        ])
        XCTAssertTrue(store.profiles.contains { $0.id == savedProfileA.id })
    }

    @MainActor
    func testSameURLRefreshRestampsOwnershipAndKeepsSecurityReviewEffective() {
        let subscription = SubscriptionSource(name: "Provider", url: "https://example.com/sub")
        var existing = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscription.id)
        existing.security.tls?.pinnedPeerCertSHA256 = "OLD-PIN"
        let existingGroup = ProxyGroup(
            subscriptionID: subscription.id,
            name: "Provider Group",
            type: .select,
            members: [.profile(existing.id)],
            defaultTarget: .profile(existing.id),
            importedType: "select",
        )
        let store = HopStore(
            profiles: [existing],
            groups: [existingGroup],
            subscriptions: [subscription],
            selectedTarget: .group(existingGroup.id),
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )
        var unmarked = existing
        unmarked.id = UUID()
        unmarked.subscriptionID = nil
        var unmarkedGroup = existingGroup
        unmarkedGroup.id = UUID()
        unmarkedGroup.subscriptionID = nil
        unmarkedGroup.members = [.profile(unmarked.id)]
        unmarkedGroup.defaultTarget = .profile(unmarked.id)

        XCTAssertTrue(store.applySubscriptionRefresh(
            ImportResult(profiles: [unmarked], groups: [unmarkedGroup]),
            updating: subscription,
        ))
        XCTAssertEqual(store.profiles.count, 1)
        XCTAssertEqual(store.profiles.first?.id, existing.id)
        XCTAssertEqual(store.profiles.first?.subscriptionID, subscription.id)
        XCTAssertEqual(store.groups.first?.id, existingGroup.id)
        XCTAssertEqual(store.groups.first?.subscriptionID, subscription.id)

        var changedPin = unmarked
        changedPin.id = UUID()
        changedPin.security.tls?.pinnedPeerCertSHA256 = "NEW-PIN"
        let outcome = store.reviewSubscriptionRefresh(
            ImportResult(profiles: [changedPin], groups: [unmarkedGroup]),
            for: subscription,
        )
        guard case let .needsSecurityConfirmation(_, changes, _) = outcome else {
            return XCTFail("Expected source-bound pin change to require review")
        }
        XCTAssertEqual(changes.map(\.fields), [[.certificatePins]])
        XCTAssertEqual(store.profiles.first?.security.tls?.pinnedPeerCertSHA256, "OLD-PIN")
    }

    @MainActor
    func testRetainedBudgetsRejectRefreshAtomicallyAndReturnFailed() {
        let oldDate = Date(timeIntervalSince1970: 1_700_000_000)
        let subscription = SubscriptionSource(
            name: "Provider",
            url: "https://example.com/sub",
            lastUpdatedAt: oldDate,
            lastImportSummary: "old",
        )
        let existing = trojanProfile(name: "Old", host: "old.example.com", subscriptionID: subscription.id)
        let stores = [
            HopStore(
                profiles: [existing],
                subscriptions: [subscription],
                dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
                maxRetainedSubscriptionItems: 1,
                maxRetainedSubscriptionSecretItems: .max,
                maxRetainedSubscriptionBytes: .max,
            ),
            HopStore(
                profiles: [existing],
                subscriptions: [subscription],
                dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
                maxRetainedSubscriptionItems: .max,
                maxRetainedSubscriptionSecretItems: 1,
                maxRetainedSubscriptionBytes: .max,
            ),
            HopStore(
                profiles: [existing],
                subscriptions: [subscription],
                dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
                maxRetainedSubscriptionItems: .max,
                maxRetainedSubscriptionSecretItems: .max,
                maxRetainedSubscriptionBytes: 1,
            ),
        ]
        let replacement = ImportResult(profiles: [
            trojanProfile(name: "New A", host: "a.example.com"),
            trojanProfile(name: "New B", host: "b.example.com"),
        ])

        for store in stores {
            let outcome = store.reviewSubscriptionRefresh(replacement, for: subscription)
            guard case .failed = outcome else {
                return XCTFail("Expected retained subscription budget rejection")
            }
            XCTAssertEqual(store.profiles, [existing])
            XCTAssertTrue(store.groups.isEmpty)
            XCTAssertEqual(store.subscriptions.first?.lastUpdatedAt, oldDate)
            XCTAssertEqual(store.subscriptions.first?.lastImportSummary, "old")
        }
    }

    @MainActor
    func testStoreRefreshReconcilesOnlyTheUpdatingSourceSnapshot() {
        let sourceA = SubscriptionSource(name: "A", url: "https://a.example/sub")
        let sourceB = SubscriptionSource(name: "B", url: "https://b.example/sub")
        let oldA = trojanProfile(name: "Old A", host: "old-a.example.com", subscriptionID: sourceA.id)
        let keptB = trojanProfile(name: "B", host: "b.example.com", subscriptionID: sourceB.id)
        let manual = trojanProfile(name: "Manual", host: "manual.example.com")
        let replacementA = trojanProfile(name: "New A", host: "new-a.example.com")
        let store = HopStore(
            profiles: [oldA, keptB, manual],
            subscriptions: [sourceA, sourceB],
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )

        XCTAssertTrue(store.applySubscriptionRefresh(
            ImportResult(profiles: [replacementA]),
            updating: sourceA,
        ))

        XCTAssertFalse(store.profiles.contains { $0.id == oldA.id })
        XCTAssertTrue(store.profiles.contains { $0.id == keptB.id })
        XCTAssertTrue(store.profiles.contains { $0.id == manual.id })
        XCTAssertEqual(store.profiles.first { $0.name == "New A" }?.subscriptionID, sourceA.id)
    }

    @MainActor
    func testValidatedEmptySnapshotRemovesFinalOwnedStateReferencesAndCredentials() throws {
        let backend = InMemorySecretBackend()
        let subscription = SubscriptionSource(name: "Provider", url: "https://example.com/sub")
        let owned = trojanProfile(name: "Final", host: "final.example.com", subscriptionID: subscription.id)
        let ownedGroup = ProxyGroup(
            subscriptionID: subscription.id,
            name: "Final Group",
            type: .select,
            members: [.profile(owned.id)],
            defaultTarget: .profile(owned.id),
            importedType: "select",
        )
        let manualGroup = ProxyGroup(
            name: "Manual",
            type: .select,
            members: [.profile(owned.id), .group(ownedGroup.id)],
            defaultTarget: .profile(owned.id),
        )
        let rules = RuleConfiguration(name: "Custom", rules: [
            RoutingRule(kind: .domainSuffix, value: "profile.example", target: .profile(owned.id)),
            RoutingRule(kind: .domainSuffix, value: "group.example", target: .group(ownedGroup.id)),
        ])
        let store = HopStore(
            profiles: [owned],
            groups: [ownedGroup, manualGroup],
            subscriptions: [subscription],
            ruleConfigurations: [rules],
            activeRuleConfigurationID: rules.id,
            selectedTarget: .group(ownedGroup.id),
            dataStore: HopAppDataStore(
                url: tempStateURL(),
                secretStore: SecretStore(backend: backend),
                authenticationStore: .inMemory(),
            ),
        )
        store.updateProfile(owned)
        store.flushPendingPersists()
        let ownedSecretKeys = owned.keychainSecretItems.map(\.key)
        XCTAssertFalse(ownedSecretKeys.isEmpty)
        XCTAssertTrue(ownedSecretKeys.allSatisfy { backend.value(forKey: $0) != nil })

        let emptySnapshot = try ProxyImportService().importText("""
        [Proxy]
        # The provider intentionally has no nodes.
        """)
        XCTAssertEqual(emptySnapshot.validatedEmptySubscriptionSnapshot, true)
        XCTAssertTrue(store.applySubscriptionRefresh(emptySnapshot, updating: subscription))
        store.flushPendingPersists()

        XCTAssertTrue(store.profiles.isEmpty)
        XCTAssertEqual(store.groups.map(\.id), [manualGroup.id])
        XCTAssertTrue(store.groups[0].members.isEmpty)
        XCTAssertNil(store.groups[0].defaultTarget)
        XCTAssertTrue(store.rules.isEmpty)
        XCTAssertNil(store.selectedTarget)
        XCTAssertEqual(store.subscriptions, [subscription])
        XCTAssertTrue(ownedSecretKeys.allSatisfy { backend.value(forKey: $0) == nil })
        XCTAssertNotNil(backend.value(forKey: HopSecret.subscriptionURLKey(subscriptionID: subscription.id)))
    }

    @MainActor
    func testRulesOnlyAndMalformedSnapshotsCannotWipeOwnedState() throws {
        let subscription = SubscriptionSource(name: "Provider", url: "https://example.com/sub")
        let owned = trojanProfile(name: "Kept", host: "kept.example.com", subscriptionID: subscription.id)
        let ownedGroup = ProxyGroup(
            subscriptionID: subscription.id,
            name: "Kept Group",
            type: .select,
            members: [.profile(owned.id)],
            importedType: "select",
        )
        let store = HopStore(
            profiles: [owned],
            groups: [ownedGroup],
            subscriptions: [subscription],
            selectedTarget: .group(ownedGroup.id),
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )

        let rulesOnly = try ProxyImportService().importText("""
        [Proxy]
        [Rule]
        DOMAIN-SUFFIX,example.com,DIRECT
        """)
        XCTAssertNil(rulesOnly.validatedEmptySubscriptionSnapshot)
        XCTAssertFalse(store.applySubscriptionRefresh(rulesOnly, updating: subscription))

        let malformedRule = try ProxyImportService().importText("""
        [Proxy]
        [Rule]
        this is not a rule definition
        """)
        XCTAssertNil(malformedRule.validatedEmptySubscriptionSnapshot)
        XCTAssertFalse(store.applySubscriptionRefresh(malformedRule, updating: subscription))

        let malformed = try ProxyImportService().importText("""
        [Proxy]
        this is not a proxy definition
        """)
        XCTAssertNil(malformed.validatedEmptySubscriptionSnapshot)
        XCTAssertFalse(store.applySubscriptionRefresh(malformed, updating: subscription))

        let truncatedText = (["[Proxy]"]
            + Array(repeating: "# filler", count: ImportPolicy.maxLines - 1)
            + ["Late = trojan, late.example.com, 443, password=secret, tls=true"])
            .joined(separator: "\n")
        let truncated = try ProxyImportService().importText(truncatedText)
        XCTAssertNil(truncated.validatedEmptySubscriptionSnapshot)
        XCTAssertFalse(store.applySubscriptionRefresh(truncated, updating: subscription))

        XCTAssertEqual(store.profiles, [owned])
        XCTAssertEqual(store.groups, [ownedGroup])
        XCTAssertEqual(store.selectedTarget, .group(ownedGroup.id))
        XCTAssertEqual(store.subscriptions, [subscription])
    }

    @MainActor
    func testSameNameProtocolAndGroupTypeReplacementsDoNotReuseStaleIDs() throws {
        let subscription = SubscriptionSource(name: "Provider", url: "https://example.com/sub")
        let oldProfile = trojanProfile(name: "Shared", host: "old.example.com", subscriptionID: subscription.id)
        let oldInner = ProxyGroup(
            subscriptionID: subscription.id,
            name: "Inner",
            type: .select,
            members: [.profile(oldProfile.id)],
            importedType: "select",
        )
        let oldTop = ProxyGroup(
            subscriptionID: subscription.id,
            name: "Top",
            type: .select,
            members: [.group(oldInner.id)],
            importedType: "select",
        )
        let store = HopStore(
            profiles: [oldProfile],
            groups: [oldTop, oldInner],
            subscriptions: [subscription],
            selectedTarget: .group(oldTop.id),
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )
        let replacementProfile = ProxyProfile(
            name: "Shared",
            endpoint: Endpoint(host: "new.example.com", port: 443),
            options: .vless(VLESSOptions(uuid: "00000000-0000-0000-0000-000000000001", flow: nil)),
            security: ProxySecurity(layer: .tls, tls: TLSOptions(serverName: "new.example.com")),
        )
        let replacementInner = ProxyGroup(
            name: "Inner",
            type: .urlTest,
            members: [.named("Shared")],
            importedType: "url-test",
        )
        let replacementTop = ProxyGroup(
            name: "Top",
            type: .select,
            members: [.named("Inner")],
            importedType: "select",
        )

        XCTAssertTrue(store.applySubscriptionRefresh(
            ImportResult(
                profiles: [replacementProfile],
                groups: [replacementTop, replacementInner],
            ),
            updating: subscription,
        ))

        let storedProfile = try XCTUnwrap(store.profiles.first { $0.subscriptionID == subscription.id })
        let storedInner = try XCTUnwrap(store.groups.first { $0.subscriptionID == subscription.id && $0.name == "Inner" })
        let storedTop = try XCTUnwrap(store.groups.first { $0.subscriptionID == subscription.id && $0.name == "Top" })
        XCTAssertEqual(storedProfile.proto, .vless)
        XCTAssertNotEqual(storedProfile.id, oldProfile.id)
        XCTAssertEqual(storedInner.importedType, "url-test")
        XCTAssertNotEqual(storedInner.id, oldInner.id)
        XCTAssertEqual(storedInner.members, [.profile(storedProfile.id)])
        XCTAssertEqual(storedTop.id, oldTop.id)
        XCTAssertEqual(storedTop.members, [.group(storedInner.id)])
        XCTAssertFalse(store.profiles.contains { $0.id == oldProfile.id })
        XCTAssertFalse(store.groups.contains { $0.id == oldInner.id })
    }

    @MainActor
    func testDeleteSubscriptionCascadesOnlyOwnedStateAndRepairsUUIDReferences() {
        let subscription = SubscriptionSource(name: "Provider", url: "https://example.com/sub")
        let survivingSubscription = SubscriptionSource(name: "Survivor", url: "https://survivor.example/sub")
        let owned = trojanProfile(name: "Owned", host: "owned.example.com", subscriptionID: subscription.id)
        let sameNameSurvivor = trojanProfile(
            name: "Owned",
            host: "survivor.example.com",
            subscriptionID: survivingSubscription.id,
        )
        let manual = trojanProfile(name: "Manual", host: "manual.example.com")
        let ownedGroup = ProxyGroup(
            subscriptionID: subscription.id,
            name: "Owned Group",
            type: .select,
            members: [.profile(owned.id)],
            defaultTarget: .profile(owned.id),
            importedType: "select",
        )
        let manualGroup = ProxyGroup(
            name: "Manual Group",
            type: .select,
            members: [.profile(owned.id), .group(ownedGroup.id), .named("Owned"), .profile(manual.id)],
            defaultTarget: .profile(owned.id),
        )
        let rules = RuleConfiguration(name: "Custom", rules: [
            RoutingRule(kind: .domainSuffix, value: "owned.example", target: .profile(owned.id)),
            RoutingRule(kind: .domainSuffix, value: "group.example", target: .group(ownedGroup.id)),
            RoutingRule(kind: .domainSuffix, value: "named.example", target: .named(" owned ")),
            RoutingRule(kind: .domainSuffix, value: "manual.example", target: .profile(manual.id)),
        ])
        let store = HopStore(
            profiles: [owned, sameNameSurvivor, manual],
            groups: [ownedGroup, manualGroup],
            subscriptions: [subscription, survivingSubscription],
            ruleConfigurations: [rules],
            activeRuleConfigurationID: rules.id,
            selectedTarget: .group(ownedGroup.id),
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )

        store.deleteSubscription(id: subscription.id)

        XCTAssertEqual(store.profiles.map(\.id), [sameNameSurvivor.id, manual.id])
        XCTAssertEqual(store.groups.map(\.id), [manualGroup.id])
        XCTAssertEqual(store.groups.first?.members, [.named("Owned"), .profile(manual.id)])
        XCTAssertEqual(store.groups.first?.defaultTarget, .named("Owned"))
        XCTAssertEqual(store.rules.map(\.target), [.named(" owned "), .profile(manual.id)])
        XCTAssertEqual(store.subscriptions, [survivingSubscription])
        XCTAssertNotEqual(store.selectedTarget, .group(ownedGroup.id))
    }

    @MainActor
    func testDuplicateCollapseRemapsUUIDRuleTargetToSurvivor() {
        let subscription = SubscriptionSource(name: "Provider", url: "https://example.com/sub")
        let referenced = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscription.id)
        let duplicate = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscription.id)
        let manualGroup = ProxyGroup(name: "Manual", type: .select, members: [.profile(referenced.id)])
        let rules = RuleConfiguration(name: "Custom", rules: [
            RoutingRule(kind: .domainSuffix, value: "example.com", target: .profile(duplicate.id)),
        ])
        let store = HopStore(
            profiles: [duplicate, referenced],
            groups: [manualGroup],
            subscriptions: [subscription],
            ruleConfigurations: [rules],
            activeRuleConfigurationID: rules.id,
            dataStore: HopAppDataStore(url: tempStateURL(), secretStore: .inMemory(), authenticationStore: .inMemory()),
        )

        XCTAssertTrue(store.applySubscriptionRefresh(
            ImportResult(profiles: [trojanProfile(name: "Tokyo", host: "jp.example.com")]),
            updating: subscription,
        ))

        XCTAssertEqual(store.profiles.map(\.id), [referenced.id])
        XCTAssertEqual(store.rules.first?.target, .profile(referenced.id))
    }

    func testLegacyProxyGroupWithoutSubscriptionOwnerDecodesAsUnowned() throws {
        let group = ProxyGroup(name: "Legacy", type: .select, members: [.direct])
        let data = try JSONEncoder().encode(group)

        let decoded = try JSONDecoder().decode(ProxyGroup.self, from: data)

        XCTAssertNil(decoded.subscriptionID)
    }

    func testGroupEditorDraftPreservesSubscriptionOwner() throws {
        let sourceID = UUID()
        let group = ProxyGroup(
            subscriptionID: sourceID,
            name: "Owned",
            type: .select,
            members: [.direct],
        )

        XCTAssertEqual(try XCTUnwrap(ProxyGroupEditorDraft(group: group).group).subscriptionID, sourceID)
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

    func testAutomaticMergePreservesRealityServerNameAndFingerprint() throws {
        let subscriptionID = UUID()
        var existing = trojanProfile(name: "Tokyo", host: "jp.example.com", subscriptionID: subscriptionID)
        existing.security = .reality(RealityOptions(
            publicKey: "PUBLICKEY",
            serverName: "old.example.com",
            utlsFingerprint: "chrome",
        ))
        var imported = existing
        imported.id = UUID()
        imported.security.reality?.serverName = "new.example.com"
        imported.security.reality?.utlsFingerprint = "firefox"
        imported.security.tls?.serverName = "new.example.com"
        imported.security.tls?.utlsFingerprint = "firefox"
        let preview = SubscriptionRefreshMerger(profiles: [existing], groups: [], selectedTarget: nil)

        let change = try XCTUnwrap(preview.securityCriticalChanges(in: [imported]).first)
        XCTAssertEqual(Set(change.fields), Set([.tlsServerName, .tlsClientFingerprint]))

        var automatic = preview
        automatic.merge(ImportResult(profiles: [imported]))
        XCTAssertEqual(automatic.profiles.first?.security.reality?.serverName, "old.example.com")
        XCTAssertEqual(automatic.profiles.first?.security.reality?.utlsFingerprint, "chrome")
        XCTAssertEqual(automatic.profiles.first?.security.tls?.serverName, "old.example.com")
        XCTAssertEqual(automatic.profiles.first?.security.tls?.utlsFingerprint, "chrome")

        var reviewed = preview
        reviewed.merge(ImportResult(profiles: [imported]), securityPolicy: .applyReviewedChanges)
        XCTAssertEqual(reviewed.profiles.first?.security.reality?.serverName, "new.example.com")
        XCTAssertEqual(reviewed.profiles.first?.security.reality?.utlsFingerprint, "firefox")
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
