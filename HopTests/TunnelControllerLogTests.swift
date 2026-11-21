@testable import Hop
import NetworkExtension
import XCTest

@MainActor
final class TunnelControllerLogTests: XCTestCase {
    func testNetworkReassertionDoesNotDisarmOnDemand() async {
        let controller = TunnelController()
        let saved = StatusTestTunnelManager(status: .connected)
        saved.isOnDemandEnabled = true
        for status: NEVPNStatus in [.connected, .reasserting, .disconnected] {
            saved.testConnection.currentStatus = status
            await controller.refreshStatus { [saved] }
        }
        await Task.yield()
        XCTAssertEqual(controller.state, .disconnected)
        XCTAssertTrue(saved.savedOnDemandFlags.isEmpty)
        XCTAssertTrue(saved.isOnDemandEnabled)
    }

    func testRetryAfterFailedIdleDisarmSavesBeforeStopping() async {
        let controller = TunnelController()
        let saved = StatusTestTunnelManager(status: .disconnected)
        saved.isOnDemandEnabled = true
        saved.saveError = NSError(domain: "test.save", code: 1)
        await controller.refreshStatus { [saved] }
        await controller.disconnect { [saved] }
        XCTAssertTrue(saved.isOnDemandEnabled)
        saved.saveError = nil
        saved.testConnection.currentStatus = .connected
        await controller.refreshStatus { [saved] }
        await controller.disconnect { [saved] }
        XCTAssertEqual(saved.savedOnDemandFlags, [false, false])
        XCTAssertEqual(saved.testConnection.stopCount, 1)
    }

    func testRejectedInstallCannotDisarmOrOverwriteThePreviouslySavedVPN() async throws {
        let controller = TunnelController()
        let attempted = StatusTestTunnelManager(status: .disconnected)
        attempted.saveError = NSError(domain: "test.preferences", code: 1)
        let previouslyInstalled = StatusTestTunnelManager(status: .disconnected)
        previouslyInstalled.isOnDemandEnabled = true
        (previouslyInstalled.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration = ["secretNonce": UUID().uuidString]
        var reads = 0
        await controller.connect(
            target: .direct, targetName: "Direct", profiles: [], groups: [], routingMode: .direct,
            rules: [], settings: .defaults, loadManagers: {
                reads += 1
                return reads == 1 ? [attempted] : [previouslyInstalled]
            },
        )
        XCTAssertEqual(controller.state, .failed)
        XCTAssertEqual(reads, 2)
        XCTAssertEqual(attempted.savedOnDemandFlags.count, 1)
        let cached = try await controller.loadManager()
        XCTAssertTrue(cached === previouslyInstalled)
        XCTAssertTrue(previouslyInstalled.isOnDemandEnabled)
        XCTAssertTrue(previouslyInstalled.savedOnDemandFlags.isEmpty)
    }

    func testCancelDuringInstallCannotLaunchOrOverwriteLaterPreferences() async {
        let controller = TunnelController()
        let saved = StatusTestTunnelManager(status: .disconnected)
        saved.isOnDemandEnabled = true
        let entered = expectation(description: "connect reads preferences")
        var resumeLoad: CheckedContinuation<Void, Never>?
        let connect = Task {
            await controller.connect(
                target: .direct, targetName: "Direct", profiles: [], groups: [],
                routingMode: .direct, rules: [], settings: .defaults,
                loadManagers: {
                    await withCheckedContinuation { continuation in
                        resumeLoad = continuation
                        entered.fulfill()
                    }
                    return [saved]
                },
            )
        }
        let result = await XCTWaiter.fulfillment(of: [entered], timeout: 5)
        guard result == .completed else {
            XCTFail("Did not reach preferences. \(controller.logs)")
            return
        }
        let cancel = Task { await controller.disconnect { [saved] } }
        let deadline = ContinuousClock.now + .seconds(2)
        while controller.state == .connecting, ContinuousClock.now < deadline {
            await Task.yield()
        }
        XCTAssertEqual(controller.state, .disconnecting)
        XCTAssertTrue(saved.savedOnDemandFlags.isEmpty)
        resumeLoad?.resume()
        await connect.value
        await cancel.value
        XCTAssertEqual(saved.savedOnDemandFlags, [false])
        XCTAssertEqual(saved.testConnection.stopCount, 1)
        XCTAssertNil((saved.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["secretNonce"])
        XCTAssertEqual(controller.state, .disconnected)
    }

    func testEraseDisablesAndStopsOnlyHopManagersAndRetriesCleanup() async throws {
        let controller = TunnelController()
        let first = StatusTestTunnelManager(status: .connected)
        let second = StatusTestTunnelManager(status: .reasserting)
        let other = StatusTestTunnelManager(status: .connected, provider: "other.tunnel")
        for manager in [first, second, other] {
            manager.isEnabled = true
            manager.isOnDemandEnabled = true
        }
        let managers = [first, other, second]
        do {
            try await controller.eraseInstalledTunnel(loadManagers: { managers }, eraseSnapshots: { _ in
                throw CocoaError(.fileWriteNoPermission)
            })
            XCTFail("Cleanup failure must leave Erase retryable")
        } catch {}
        for manager in [first, second] {
            XCTAssertEqual(manager.savedOnDemandFlags, [false])
            XCTAssertEqual(manager.testConnection.stopCount, 1)
            XCTAssertEqual(manager.removalCount, 0)
        }
        try await controller.eraseInstalledTunnel(loadManagers: { managers }, eraseSnapshots: { _ in })
        XCTAssertEqual(first.removalCount, 1)
        XCTAssertEqual(second.removalCount, 1)
        XCTAssertEqual(other.removalCount, 0)
        XCTAssertTrue(other.isOnDemandEnabled)
        XCTAssertEqual(other.testConnection.stopCount, 0)
        XCTAssertEqual(controller.state, .disconnected)
    }

    func testEraseWithoutManagerStillRemovesSnapshotFiles() async throws {
        let container = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: container) }
        let directory = container.appendingPathComponent("TunnelSnapshots/old", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let legacy = container.appendingPathComponent(RuntimeEnvironment.configFileName)
        for url in [legacy, TunnelConfigAuthenticator.signatureURL(forConfigURL: legacy), directory.appendingPathComponent("settings")] {
            try Data("old".utf8).write(to: url)
        }
        try await TunnelController().eraseInstalledTunnel(loadManagers: { [] }, eraseSnapshots: { _ in
            try SharedTunnelConfigurationStore.eraseAllSnapshots(in: container)
        })
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: container.path).isEmpty)
    }

    func testDashboardCanCancelAndUseStandaloneOutbounds() {
        XCTAssertEqual(DashboardConnectionAction(state: .connecting, target: nil, hasSelectableProxies: false), .disconnect)
        XCTAssertEqual(DashboardConnectionAction(state: .disconnected, target: .direct, hasSelectableProxies: false), .connect(.direct))
        let group = OutboundTarget.group(UUID())
        XCTAssertEqual(DashboardConnectionAction(state: .disconnected, target: group, hasSelectableProxies: true), .connect(group))
        XCTAssertEqual(DashboardConnectionAction(state: .disconnected, target: nil, hasSelectableProxies: false), .addProfile)
    }

    func testValidationHintIncludesTheLimitWithoutEchoingUntrustedValues() {
        let controller = TunnelController()
        let value = "SECRET_MARKER"
        let limit = 16
        let issue = XrayValidationIssue(path: "/observatory/\(value)", message: "Group \(value) exceeds the \(limit)-target limit.")
        controller.appendTunnelStartFailure(XrayConfigError.validationFailed([issue]))
        XCTAssertEqual(controller.configurationFailureHint, "URL-test groups. Group “…” exceeds the 16-target limit.")
        XCTAssertFalse(controller.logs.joined().contains(value))
        XCTAssertFalse(controller.logs.joined().contains("16-target"))
    }

    func testFailedOnDemandSaveKeepsDisconnectAvailableAndRetriesSaveBeforeStopping() async {
        let controller = TunnelController()
        let saved = StatusTestTunnelManager(status: .connected)
        saved.isOnDemandEnabled = true
        saved.saveError = NSError(domain: "test.preferences", code: 1)
        await controller.refreshStatus { [saved] }

        let reloaded = StatusTestTunnelManager(status: .connected)
        reloaded.isOnDemandEnabled = true
        await controller.disconnect { [reloaded] }
        XCTAssertEqual(controller.state, .connected)
        XCTAssertEqual(saved.testConnection.stopCount, 0)
        XCTAssertTrue(saved.isOnDemandEnabled)

        await controller.disconnect { [reloaded] }
        XCTAssertEqual(reloaded.savedOnDemandFlags, [false])
        XCTAssertEqual(reloaded.testConnection.stopCount, 1)
        XCTAssertEqual(controller.state, .disconnected)
    }

    func testClearDiscardsAlreadyReadExtensionLogBatch() async throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: url) }
        let controller = TunnelController(sharedLogStore: SharedTunnelLogStore(url: url))
        try Data("old entry\n".utf8).write(to: url)

        await controller.syncExtensionLogs { store, previous in
            let batch = try store.readBatch(after: previous)
            controller.clearLogs()
            return batch
        }
        XCTAssertTrue(controller.logs.isEmpty)
        XCTAssertNil(controller.extensionLogCursor)
        await controller.syncExtensionLogs()
        XCTAssertTrue(controller.logs.isEmpty)
    }

    func testLogCursorSurvivesRelaunchDuplicateLinesAndRotation() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("hop-tunnel.log")
        let dataStore = HopAppDataStore(
            url: directory.appendingPathComponent("hop-state.json"), secretStore: .inMemory(),
            authenticationStore: .inMemory(), sharedLogStore: SharedTunnelLogStore(url: url),
        )
        let store = HopStore(dataStore: dataStore)
        try Data("first\nsecond\n".utf8).write(to: url)
        await store.tunnel.syncExtensionLogs()
        store.persist()
        store.flushPendingPersists()

        let restored = HopStore(dataStore: dataStore)
        XCTAssertEqual(restored.tunnel.extensionLogCursor, store.tunnel.extensionLogCursor)
        await restored.tunnel.syncExtensionLogs()
        XCTAssertEqual(restored.tunnel.logs, store.tunnel.logs)
        let handle = try FileHandle(forWritingTo: url)
        try handle.seekToEnd()
        try handle.write(contentsOf: Data("second\n".utf8))
        try handle.close()
        await restored.tunnel.syncExtensionLogs()
        XCTAssertEqual(restored.tunnel.logs.filter { $0.hasSuffix("Extension second") }.count, 2)

        try Data("second\nthird\n".utf8).write(to: url, options: .atomic)
        await restored.tunnel.syncExtensionLogs()
        XCTAssertEqual(restored.tunnel.logs.filter { $0.hasSuffix("Extension second") }.count, 2)
        XCTAssertEqual(restored.tunnel.logs.filter { $0.hasSuffix("Extension third") }.count, 1)
        restored.clearLogs()
        restored.flushPendingPersists()
        XCTAssertTrue(try XCTUnwrap(dataStore.loadExisting()).logs.isEmpty)
        XCTAssertNil(try XCTUnwrap(dataStore.loadExisting()).extensionLogCursor)
    }

    func testRefreshReadsInstalledTargetAndModeFromPreferences() async throws {
        let controller = TunnelController()
        let saved = StatusTestTunnelManager(status: .connected)
        let tunnelProtocol = try XCTUnwrap(saved.protocolConfiguration as? NETunnelProviderProtocol)
        tunnelProtocol.providerConfiguration = ["targetDisplayName": "Office", "routingMode": RoutingMode.global.rawValue]
        saved.protocolConfiguration = tunnelProtocol
        await controller.refreshStatus { [saved] }
        XCTAssertEqual(controller.installedConnection, InstalledTunnelConnection(targetName: "Office", routingMode: .global))
        XCTAssertEqual(InstalledTunnelConnection(targetName: "Office", routingMode: .direct).targetName, "Direct")

        let legacy = StatusTestTunnelManager(status: .connected)
        await controller.refreshStatus { [legacy] }
        XCTAssertNil(controller.installedConnection)
    }

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
            targetName: "Missing Node",
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

    func testLowerRetentionIsPersistedWithoutAnotherAppend() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).appendingPathComponent("state.json")
        let dataStore = HopAppDataStore(url: url, secretStore: .inMemory(), authenticationStore: .inMemory())
        let store = HopStore(dataStore: dataStore)
        store.settings.logRetention = .oneThousand
        store.tunnel.appendLogs((1 ... 150).map(String.init))
        store.settings.logRetention = .oneHundred
        XCTAssertEqual(store.tunnel.logs.count, 100)
        store.flushPendingPersists()
        XCTAssertEqual(try dataStore.loadExisting()?.logs, store.tunnel.logs)
    }

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
    var stopCount = 0

    override func stopVPNTunnel() {
        stopCount += 1
        currentStatus = .disconnected
    }

    override var status: NEVPNStatus {
        currentStatus
    }
}

private final class StatusTestTunnelManager: NETunnelProviderManager, @unchecked Sendable {
    let testConnection = StatusTestConnection()
    var saveError: Error?
    var savedOnDemandFlags: [Bool] = []
    var removalCount = 0

    override func removeFromPreferences(completionHandler: (@Sendable (Error?) -> Void)? = nil) {
        removalCount += 1
        completionHandler?(nil)
    }

    override func saveToPreferences(completionHandler: (@Sendable (Error?) -> Void)? = nil) {
        savedOnDemandFlags.append(isOnDemandEnabled)
        completionHandler?(saveError)
    }

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
