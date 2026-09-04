@testable import Hop
import NetworkExtension
import XCTest

@MainActor
final class TunnelControllerLogTests: XCTestCase {
    func testRefreshRestoresSavedVPNWithoutRelyingOnItsDisplayName() async {
        let controller = TunnelController()
        let unrelated = StatusTestTunnelManager(status: .disconnected, provider: "other.tunnel")
        unrelated.localizedDescription = "Hop"
        let saved = StatusTestTunnelManager(status: .connected)
        saved.localizedDescription = "Renamed VPN"

        await controller.refreshStatus { [unrelated, saved] }
        XCTAssertEqual(controller.state, .connected)

        saved.testConnection.currentStatus = .disconnected
        await controller.refreshStatus { [saved] }
        XCTAssertEqual(controller.state, .disconnected)

        await controller.refreshStatus { [] }
        XCTAssertEqual(controller.state, .disconnected)
    }

    func testPendingStatusRefreshCannotUndoManualDisconnect() async {
        let controller = TunnelController()
        let saved = StatusTestTunnelManager(status: .connected)

        await controller.refreshStatus {
            await controller.disconnect()
            return [saved]
        }

        XCTAssertEqual(controller.state, .disconnected)
    }

    func testFailedPreflightRestoresSavedStatusObserver() async {
        let logURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: logURL) }
        let controller = TunnelController(sharedLogStore: SharedTunnelLogStore(url: logURL))
        let saved = StatusTestTunnelManager(status: .disconnected)
        await controller.refreshStatus { [saved] }
        await controller.connect(
            target: .profile(UUID()),
            profiles: [],
            groups: [],
            routingMode: .rule,
            rules: [],
            settings: .defaults,
        )
        XCTAssertEqual(controller.state, .failed)

        let changed = expectation(description: "Saved VPN status is still observed after failed validation")
        controller.onLogsChanged = {
            if controller.logs.first?.contains("NetworkExtension status: connected") == true {
                changed.fulfill()
            }
        }
        saved.testConnection.currentStatus = .connected
        NotificationCenter.default.post(name: .NEVPNStatusDidChange, object: saved.testConnection)
        let result = await XCTWaiter.fulfillment(of: [changed], timeout: 2)
        controller.onLogsChanged = nil
        XCTAssertEqual(result, .completed)
        XCTAssertEqual(controller.state, .connected)
    }

    func testNewerStatusRefreshWinsAndDisconnectingSkipsRefresh() async {
        let controller = TunnelController()
        let stale = StatusTestTunnelManager(status: .connected)
        await controller.refreshStatus {
            await controller.refreshStatus { [] }
            return [stale]
        }
        XCTAssertEqual(controller.state, .disconnected)

        controller.state = .disconnecting
        await controller.refreshStatus {
            XCTFail("A foreground refresh must not interfere with a pending disconnect")
            return [stale]
        }
        XCTAssertEqual(controller.state, .disconnecting)
    }

    func testSnapshotManagerReloadIgnoresUnsavedCachedNoncesAndPropagatesFailure() async throws {
        let controller = TunnelController()
        let cached = StatusTestTunnelManager(status: .disconnected)
        await controller.refreshStatus { [cached] }
        // Two failed saves can replace both cached retention slots even while
        // the system still points at the original, working snapshot.
        cached.protocolConfiguration = NETunnelProviderProtocol()
        (cached.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration = [
            "secretNonce": "unsaved-second",
            "previousSecretNonce": "unsaved-first",
        ]
        let readError = NSError(domain: "test.preferences", code: 1)
        do {
            _ = try await controller.loadManager(reload: true) { throw readError }
            XCTFail("A failed authoritative read must abort rather than use cached retention slots")
        } catch {
            XCTAssertEqual(error as NSError, readError)
        }

        let persisted = StatusTestTunnelManager(status: .disconnected)
        (persisted.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration = ["secretNonce": "installed"]
        let reloaded = try await controller.loadManager(reload: true) { [persisted] }
        XCTAssertTrue(reloaded === persisted)
        XCTAssertEqual((reloaded.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["secretNonce"] as? String, "installed")
    }

    func testInlineConfigurationDisablesOnDemandWithoutChangingKillSwitch() {
        let manager = NETunnelProviderManager()
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.includeAllNetworks = true
        manager.protocolConfiguration = tunnelProtocol

        for (requested, inline, enabled) in [(true, false, true), (true, true, false), (false, false, false), (false, true, false)] {
            TunnelController.configureOnDemand(manager, requested: requested, usesInlineResolvedConfig: inline)
            XCTAssertEqual(manager.isOnDemandEnabled, enabled)
            XCTAssertEqual(manager.onDemandRules?.count ?? 0, enabled ? 1 : 0)
            XCTAssertTrue(manager.protocolConfiguration?.includeAllNetworks == true)
        }
    }

    // MARK: - appendLog newline collapse

    func testAppendLogCollapsesNewlinesToSpaces() {
        let controller = TunnelController(logs: [], maximumLogEntries: 100)

        controller.appendLog("a\nb")

        // Should produce exactly ONE log entry
        XCTAssertEqual(controller.logs.count, 1, "appendLog with a newline must produce ONE log entry")
        XCTAssertTrue(controller.logs[0].contains("a b"), "newline in message must be collapsed to a space, got: \(controller.logs[0])")
        XCTAssertFalse(controller.logs[0].contains("\n"), "log entry must not contain a literal newline")
    }

    func testAppendLogPreservesMessageContent() {
        let controller = TunnelController(logs: [], maximumLogEntries: 100)

        controller.appendLog("Hello World")

        XCTAssertEqual(controller.logs.count, 1)
        XCTAssertTrue(controller.logs[0].contains("Hello World"))
    }

    func testCoreValidationFailureDropsRawBridgeMessageAndKeepsSafeCode() throws {
        let marker = "UNIT_TEST_MARKER[not-a-secret]"
        let responseData = Data(
            """
            {"version":1,"ok":false,"error":{"code":"invalid_config","message":"\(marker)"}}
            """.utf8,
        )
        let response = try JSONDecoder().decode(XrayBridgeResponse.self, from: responseData)
        let error = XrayCoreClientError.validationFailed(code: response.error?.safeCode ?? "unknown")
        let controller = TunnelController(logs: [], maximumLogEntries: 100)
        controller.appendTunnelStartFailure(error)

        XCTAssertFalse(error.localizedDescription.contains(marker))
        XCTAssertTrue(error.localizedDescription.contains("invalid_config"))
        XCTAssertTrue(error.localizedDescription.contains("Review node settings"))
        XCTAssertFalse(controller.logs.joined().contains(marker))
        XCTAssertTrue(controller.logs.joined().contains("invalid_config"))

        let unknownCodeError = XrayCoreClientError.validationFailed(code: marker)
        XCTAssertFalse(unknownCodeError.localizedDescription.contains(marker))
        XCTAssertTrue(unknownCodeError.localizedDescription.contains("unknown"))
    }

    func testTunnelStartFailureDropsSecretBearingLocalizedDescription() {
        let secret = "UNIT_TEST_PROFILE_SECRET"
        let error = NSError(
            domain: "NEVPNErrorDomain",
            code: 5,
            userInfo: [
                NSLocalizedDescriptionKey: "Untrusted parser detail: \(secret)\nsecond diagnostic line",
            ],
        )
        let controller = TunnelController(logs: [], maximumLogEntries: 100)

        controller.appendTunnelStartFailure(error)

        XCTAssertEqual(controller.logs.count, 2)
        let entries = controller.logs.joined(separator: "\n")
        XCTAssertFalse(entries.contains(secret))
        XCTAssertFalse(entries.contains("Untrusted parser detail"))
        XCTAssertTrue(entries.contains("domain=NEVPNErrorDomain"))
        XCTAssertTrue(entries.contains("code=5"))
        XCTAssertTrue(entries.contains("NetworkExtension IPC failed"))
        XCTAssertTrue(controller.logs.allSatisfy { !$0.contains("\n") })
    }

    func testCachedDisconnectErrorDropsSecretBearingLocalizedDescription() {
        let secret = "UNIT_TEST_CACHED_PROVIDER_SECRET"
        let error = NSError(
            domain: "NEVPNErrorDomain",
            code: 5,
            userInfo: [
                NSLocalizedDescriptionKey: "Pre-fix provider detail: \(secret)",
            ],
        )
        let controller = TunnelController(logs: [], maximumLogEntries: 100)

        controller.appendLastDisconnectError(error)

        let entries = controller.logs.joined(separator: "\n")
        XCTAssertFalse(entries.contains(secret))
        XCTAssertFalse(entries.contains("Pre-fix provider detail"))
        XCTAssertTrue(entries.contains("Most recent disconnect error"))
        XCTAssertTrue(entries.contains("may predate this start"))
        XCTAssertTrue(entries.contains("domain=NEVPNErrorDomain"))
        XCTAssertTrue(entries.contains("code=5"))
        XCTAssertTrue(entries.contains("NetworkExtension IPC failed"))
    }

    func testPluginDisabledDiagnosticDoesNotAssumeAnEntitlementFailure() {
        let error = NSError(domain: "NEVPNConnectionErrorDomain", code: 14)
        let controller = TunnelController(logs: [], maximumLogEntries: 100)

        controller.appendLastDisconnectError(error)

        let entries = controller.logs.joined(separator: "\n")
        XCTAssertTrue(entries.contains("unavailable or outdated"))
        XCTAssertTrue(entries.contains("Remove the saved Hop VPN"))
        XCTAssertTrue(entries.contains("extension's bundle ID and provisioning profile"))
        XCTAssertFalse(entries.contains("missing the Packet Tunnel entitlement"))
    }

    func testLegacyExtensionLogGatePurgesBeforeImport() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("TunnelControllerLogTests-\(UUID().uuidString)", isDirectory: true)
        let logURL = directory.appendingPathComponent("hop-tunnel.log")
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let marker = "UNIT_TEST_PRE_FIX_EXTENSION_SECRET"
        try Data("Startup failed: \(marker)\n".utf8).write(to: logURL)
        let controller = TunnelController(
            logs: [],
            maximumLogEntries: 100,
            sharedLogStore: SharedTunnelLogStore(url: logURL),
            requiresLegacyExtensionLogPurge: true,
        )

        await controller.syncExtensionLogs()

        XCTAssertFalse(controller.logs.joined().contains(marker))
        XCTAssertFalse(controller.requiresLegacyExtensionLogPurge)
        XCTAssertTrue(try SharedTunnelLogStore(url: logURL).readLines().isEmpty)

        try Data("current extension diagnostic\n".utf8).write(to: logURL)
        await controller.syncExtensionLogs()
        XCTAssertTrue(controller.logs.joined().contains("current extension diagnostic"))
    }

    // MARK: - appendLogs ordering

    func testAppendLogsInsertsBothEntriesWithCorrectOrder() {
        let controller = TunnelController(logs: [], maximumLogEntries: 100)

        controller.appendLogs(["first", "second"])

        // Newest-first: "second" lands at index 0, "first" at index 1
        XCTAssertEqual(controller.logs.count, 2)
        XCTAssertTrue(controller.logs[0].contains("second"), "most recent message must be at index 0, got: \(controller.logs[0])")
        XCTAssertTrue(controller.logs[1].contains("first"), "earlier message must be at index 1, got: \(controller.logs[1])")
    }

    func testAppendLogsEmptyArrayIsNoOp() {
        let controller = TunnelController(logs: [], maximumLogEntries: 100)

        controller.appendLogs([])

        XCTAssertTrue(controller.logs.isEmpty, "appendLogs with empty array must not add any entries")
    }

    // MARK: - maximumLogEntries trimming

    func testMaximumLogEntriesTrimmingEnforced() {
        let controller = TunnelController(logs: [], maximumLogEntries: 3)

        controller.appendLogs(["a", "b", "c", "d", "e"])

        XCTAssertEqual(controller.logs.count, 3, "log must be trimmed to maximumLogEntries")
    }

    func testMaximumLogEntriesTrimmingKeepsNewestEntries() {
        let controller = TunnelController(logs: [], maximumLogEntries: 2)

        controller.appendLogs(["old1", "old2", "old3", "newest"])

        XCTAssertEqual(controller.logs.count, 2)
        XCTAssertTrue(controller.logs[0].contains("newest"), "newest entry must be retained at index 0")
        XCTAssertTrue(controller.logs[1].contains("old3"), "second-newest must be at index 1")
    }

    // MARK: - onLogsChanged callback

    func testAppendLogsFiringOnLogsChangedOnce() {
        let controller = TunnelController(logs: [], maximumLogEntries: 100)
        var callCount = 0
        controller.onLogsChanged = { callCount += 1 }

        controller.appendLogs(["first", "second"])

        XCTAssertEqual(callCount, 1, "onLogsChanged must fire exactly once per appendLogs call, not once per message")
    }

    func testAppendLogFiresOnLogsChangedOnce() {
        let controller = TunnelController(logs: [], maximumLogEntries: 100)
        var callCount = 0
        controller.onLogsChanged = { callCount += 1 }

        controller.appendLog("msg")

        XCTAssertEqual(callCount, 1, "appendLog must fire onLogsChanged exactly once")
    }

    func testEmptyAppendLogsDoesNotFireOnLogsChanged() {
        let controller = TunnelController(logs: [], maximumLogEntries: 100)
        var callCount = 0
        controller.onLogsChanged = { callCount += 1 }

        controller.appendLogs([])

        XCTAssertEqual(callCount, 0, "empty appendLogs must not fire onLogsChanged")
    }

    // MARK: - Batch ordering with existing logs

    func testAppendLogsInsertsBatchBeforeExistingLogs() {
        let controller = TunnelController(logs: [], maximumLogEntries: 100)
        controller.appendLog("existing")

        controller.appendLogs(["batch1", "batch2"])

        // Order: batch2 (newest), batch1, existing (oldest)
        XCTAssertEqual(controller.logs.count, 3)
        XCTAssertTrue(controller.logs[0].contains("batch2"))
        XCTAssertTrue(controller.logs[1].contains("batch1"))
        XCTAssertTrue(controller.logs[2].contains("existing"))
    }
}

private final class StatusTestConnection: NEVPNConnection, @unchecked Sendable {
    var currentStatus: NEVPNStatus = .disconnected

    override var status: NEVPNStatus {
        currentStatus
    }
}

private final class StatusTestTunnelManager: NETunnelProviderManager, @unchecked Sendable {
    let testConnection = StatusTestConnection()

    override var connection: NEVPNConnection {
        testConnection
    }

    init(status: NEVPNStatus, provider: String = RuntimeEnvironment.tunnelProviderBundleIdentifier) {
        super.init()
        testConnection.currentStatus = status
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = provider
        protocolConfiguration = tunnelProtocol
    }
}
