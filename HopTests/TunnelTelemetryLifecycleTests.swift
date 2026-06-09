@testable import Hop
import XCTest

/// Main-actor lifecycle of the telemetry client and the view-driven
/// connections-monitoring flag on the controller.
@MainActor
final class TunnelTelemetryLifecycleTests: XCTestCase {
    func testStopPublishesZeroedValuesSynchronously() {
        let client = TunnelTelemetryClient()
        var counters: [TrafficCounters] = []
        var connections: [[TunnelConnectionSnapshot]] = []
        var states: [Bool] = []
        client.onStatus = { counters.append($0) }
        client.onConnections = { connections.append($0) }
        client.onConnectionStateChanged = { isConnected, error in
            states.append(isConnected)
            XCTAssertNil(error, "a plain stop is not an error")
        }

        client.stop()

        XCTAssertEqual(counters, [.zero])
        XCTAssertEqual(connections, [[]])
        XCTAssertEqual(states, [false])
    }

    func testConnectionsStreamStopIsIdempotentAndKeepsList() {
        let client = TunnelTelemetryClient()
        var connections: [[TunnelConnectionSnapshot]] = []
        client.onConnections = { connections.append($0) }

        // Stopping only the connections stream must not publish a reset — the
        // last list stays visible until a resubscribe replaces it.
        client.stopConnections()
        client.stopConnections()

        XCTAssertTrue(connections.isEmpty)
    }

    func testMonitoringFlagFollowsViewLifecycle() {
        let controller = TunnelController(logs: [])
        XCTAssertFalse(controller.isMonitoringConnections)

        // Tunnel is disconnected, so this only records the intent; the stream
        // starts on connect via startTelemetry.
        controller.beginConnectionsMonitoring()
        XCTAssertTrue(controller.isMonitoringConnections)

        controller.endConnectionsMonitoring()
        XCTAssertFalse(controller.isMonitoringConnections)
    }
}
