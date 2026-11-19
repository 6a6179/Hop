import CryptoKit
@testable import Hop
import XCTest

final class RuntimeEnvironmentTests: XCTestCase {
    func testSnapshotReaderRequiresTheInstalledNonceAndBoundedFiles() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("settings.json")
        let signatureURL = TunnelConfigAuthenticator.signatureURL(forConfigURL: url)
        let nonce = UUID().uuidString
        let secret = "test-key"
        let content = "{}"
        let data = Data(content.utf8)
        try data.write(to: url)
        let signature = try XCTUnwrap(TunnelConfigAuthenticator.snapshotSignature(for: data, nonce: nonce, secret: secret))
        try Data(signature.utf8).write(to: signatureURL)
        XCTAssertEqual(try TunnelConfigAuthenticator.readSnapshot(at: url, nonce: nonce, secret: secret), content)
        XCTAssertThrowsError(try TunnelConfigAuthenticator.readSnapshot(at: url, nonce: UUID().uuidString, secret: secret))

        let legacy = try XCTUnwrap(TunnelConfigAuthenticator.signature(for: data, secret: secret))
        try Data(legacy.utf8).write(to: signatureURL)
        XCTAssertThrowsError(try TunnelConfigAuthenticator.readSnapshot(at: url, nonce: nonce, secret: secret))

        for prefix in ["Hop tunnel snapshot v2\u{0}", "Hop tunnel snapshot v3\u{0}v26.7.28\u{0}"] {
            let signedData = Data("\(prefix)\(nonce)\u{0}".utf8) + data
            let oldMAC = HMAC<SHA256>.authenticationCode(for: signedData, using: SymmetricKey(data: Data(secret.utf8)))
            try Data(oldMAC).base64EncodedData().write(to: signatureURL)
            XCTAssertThrowsError(try TunnelConfigAuthenticator.readSnapshot(at: url, nonce: nonce, secret: secret))
        }
        try Data((signature + "\n").utf8).write(to: signatureURL)
        XCTAssertThrowsError(try TunnelConfigAuthenticator.readSnapshot(at: url, nonce: nonce, secret: secret))

        let oversized = Data(repeating: 0x20, count: TunnelMemoryPolicy.maximumConfigurationBytes + 1)
        try oversized.write(to: url)
        let oversizedMAC = try XCTUnwrap(TunnelConfigAuthenticator.snapshotSignature(for: oversized, nonce: nonce, secret: secret))
        try Data(oversizedMAC.utf8).write(to: signatureURL)
        XCTAssertThrowsError(try TunnelConfigAuthenticator.readSnapshot(at: url, nonce: nonce, secret: secret))
    }

    func testBundleIdentityDiagnosticIncludesBundleAndBuildVersions() throws {
        let identity = try XCTUnwrap(RuntimeEnvironment.bundleIdentity(from: [
            "CFBundleIdentifier": "cat.string.hop.tunnel",
            "CFBundleShortVersionString": "0.1.2",
            "CFBundleVersion": "32.1",
        ]))

        XCTAssertEqual(identity.bundleIdentifier, "cat.string.hop.tunnel")
        XCTAssertEqual(identity.diagnosticDescription, "0.1.2 (32.1) [cat.string.hop.tunnel]")
    }

    func testBundleIdentityRejectsMissingBundleIdentifier() {
        XCTAssertNil(RuntimeEnvironment.bundleIdentity(from: [
            "CFBundleShortVersionString": "0.1.2",
            "CFBundleVersion": "32.1",
        ]))
    }

    func testSelectAppGroupPrefersCommonOpenGroup() {
        let selected = RuntimeEnvironment.selectAppGroup(
            appGroups: ["group.app.only", RuntimeEnvironment.fallbackAppGroup],
            tunnelGroups: ["group.tunnel.only", RuntimeEnvironment.fallbackAppGroup],
            canOpen: { $0 == RuntimeEnvironment.fallbackAppGroup },
        )

        XCTAssertEqual(selected, RuntimeEnvironment.fallbackAppGroup)
    }

    func testSelectAppGroupUsesCommonProvisionedGroupWhenSourceGroupIsNotAvailable() {
        let selected = RuntimeEnvironment.selectAppGroup(
            appGroups: ["group.app.only", "group.shared"],
            tunnelGroups: ["group.tunnel.only", "group.shared"],
            canOpen: { $0 == "group.shared" },
        )

        XCTAssertEqual(selected, "group.shared")
    }

    func testSelectAppGroupDoesNotChooseAppOnlyGroupWhenTunnelProfileListsDifferentGroup() {
        let selected = RuntimeEnvironment.selectAppGroup(
            appGroups: ["group.app.only"],
            tunnelGroups: ["group.tunnel.only"],
            canOpen: { $0 == "group.app.only" },
        )

        XCTAssertEqual(selected, RuntimeEnvironment.fallbackAppGroup)
    }

    func testSelectAppGroupPrefersSourceSharedGroupWhenTunnelProfileIsUnavailable() {
        let selected = RuntimeEnvironment.selectAppGroup(
            appGroups: ["group.app"],
            tunnelGroups: [],
            canOpen: { $0 == RuntimeEnvironment.fallbackAppGroup || $0 == "group.app" },
        )

        XCTAssertEqual(selected, RuntimeEnvironment.fallbackAppGroup)
    }

    func testSelectAppGroupFallsBackToAppGroupsWhenTunnelProfileAndSourceGroupAreUnavailable() {
        let selected = RuntimeEnvironment.selectAppGroup(
            appGroups: ["group.app"],
            tunnelGroups: [],
            canOpen: { $0 == "group.app" },
        )

        XCTAssertEqual(selected, "group.app")
    }

    func testAppGroupProfileMismatchErrorReturnsNilWhenTunnelProfileIsUnavailable() {
        XCTAssertNil(RuntimeEnvironment.appGroupProfileMismatchError(
            appGroups: ["group.app"],
            tunnelGroups: [],
        ))
    }

    func testAppGroupProfileMismatchErrorReportsDisjointProfiles() throws {
        let error = try XCTUnwrap(RuntimeEnvironment.appGroupProfileMismatchError(
            appGroups: ["group.app.only"],
            tunnelGroups: ["group.tunnel.only"],
        ))

        XCTAssertTrue(error.localizedDescription.contains("No shared App Group"))
        XCTAssertTrue(error.localizedDescription.contains("group.app.only"))
        XCTAssertTrue(error.localizedDescription.contains("group.tunnel.only"))
    }

    func testInlineResolvedConfigIsUsedWhenTunnelProfileIsUnavailable() {
        XCTAssertTrue(RuntimeEnvironment.shouldUseInlineResolvedTunnelConfiguration(
            appGroups: ["group.app"],
            tunnelGroups: [],
            selectedAppGroup: "group.app",
        ))
    }

    func testSharedConfigFileIsUsedForSourceGroupWhenTunnelProfileIsUnavailable() {
        XCTAssertFalse(RuntimeEnvironment.shouldUseInlineResolvedTunnelConfiguration(
            appGroups: [RuntimeEnvironment.fallbackAppGroup],
            tunnelGroups: [],
            selectedAppGroup: RuntimeEnvironment.fallbackAppGroup,
        ))
    }

    func testSharedConfigFileIsUsedWhenSelectedGroupIsConfirmedOnBothProfiles() {
        XCTAssertFalse(RuntimeEnvironment.shouldUseInlineResolvedTunnelConfiguration(
            appGroups: ["group.app.only", RuntimeEnvironment.fallbackAppGroup],
            tunnelGroups: ["group.tunnel.only", RuntimeEnvironment.fallbackAppGroup],
            selectedAppGroup: RuntimeEnvironment.fallbackAppGroup,
        ))
    }

    func testInlineResolvedConfigIsUsedWhenSelectedGroupIsAppOnly() {
        XCTAssertTrue(RuntimeEnvironment.shouldUseInlineResolvedTunnelConfiguration(
            appGroups: ["group.app.only"],
            tunnelGroups: ["group.tunnel.only"],
            selectedAppGroup: "group.app.only",
        ))
    }
}
