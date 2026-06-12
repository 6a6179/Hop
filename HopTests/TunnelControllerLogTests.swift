@testable import Hop
import XCTest

@MainActor
final class TunnelControllerLogTests: XCTestCase {
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
