@testable import Hop
import XCTest

#if canImport(Libbox)
    import Libbox

    /// The libbox-connection → snapshot extraction and its change-detection
    /// cache. Event batches can't be constructed from Swift, but connections
    /// can, so the per-connection mapping and reuse rule are pinned here.
    final class TunnelTelemetrySnapshotTests: XCTestCase {
        func testSnapshotMapsAllFields() {
            let connection = makeConnection()

            let snapshot = TunnelTelemetryClient.snapshot(from: connection, cache: [:])

            XCTAssertEqual(snapshot.id, "c1")
            XCTAssertEqual(snapshot.network, "tcp")
            XCTAssertEqual(snapshot.source, "172.19.0.1:50000")
            XCTAssertEqual(snapshot.destination, "1.2.3.4:443")
            XCTAssertEqual(snapshot.domain, "example.com")
            XCTAssertEqual(snapshot.protocolName, "tls")
            XCTAssertEqual(snapshot.inbound, "tun-in")
            XCTAssertEqual(snapshot.inboundType, "tun")
            XCTAssertEqual(snapshot.outbound, "proxy-1")
            XCTAssertEqual(snapshot.outboundType, "trojan")
            XCTAssertEqual(snapshot.createdAt, Date(timeIntervalSince1970: 1_800_000_000))
            XCTAssertNil(snapshot.closedAt, "closedAt 0 means still active")
            XCTAssertEqual(snapshot.uplinkBytesPerSecond, 100)
            XCTAssertEqual(snapshot.downlinkBytesPerSecond, 200)
            XCTAssertEqual(snapshot.uplinkTotalBytes, 1000)
            XCTAssertEqual(snapshot.downlinkTotalBytes, 2000)
            XCTAssertEqual(snapshot.rule, "rule-0")
            XCTAssertTrue(snapshot.isActive)
        }

        func testSnapshotReusesCacheUntilNumericFieldsMove() {
            let connection = makeConnection()
            let first = TunnelTelemetryClient.snapshot(from: connection, cache: [:])
            let cache = [first.id: first]

            // Mutating only a string field must NOT bust the cache — that is
            // the point: unchanged traffic skips the expensive string reads.
            connection.domain = "changed.example.com"
            let reused = TunnelTelemetryClient.snapshot(from: connection, cache: cache)
            XCTAssertEqual(reused.domain, "example.com", "unchanged numerics reuse the cached snapshot")

            // Any traffic movement forces a full re-extraction.
            connection.downlinkTotal = 2048
            let refreshed = TunnelTelemetryClient.snapshot(from: connection, cache: cache)
            XCTAssertEqual(refreshed.domain, "changed.example.com")
            XCTAssertEqual(refreshed.downlinkTotalBytes, 2048)
        }

        func testSnapshotRefreshesWhenConnectionCloses() {
            let connection = makeConnection()
            let first = TunnelTelemetryClient.snapshot(from: connection, cache: [:])
            let cache = [first.id: first]

            connection.closedAt = 1_800_000_060_000
            let closed = TunnelTelemetryClient.snapshot(from: connection, cache: cache)

            XCTAssertEqual(closed.closedAt, Date(timeIntervalSince1970: 1_800_000_060))
            XCTAssertFalse(closed.isActive)
        }

        func testStatusMessageMapsToTrafficCounters() {
            let message = LibboxStatusMessage()
            message.uplinkTotal = 1234
            message.downlinkTotal = 5678
            message.uplink = 100
            message.downlink = 200
            message.trafficAvailable = true
            message.connectionsIn = 7
            message.connectionsOut = 3

            let counters = TunnelTelemetryClient.counters(from: message)
            XCTAssertEqual(counters.uplinkBytes, 1234)
            XCTAssertEqual(counters.downlinkBytes, 5678)
            XCTAssertEqual(counters.uplinkBytesPerSecond, 100)
            XCTAssertEqual(counters.downlinkBytesPerSecond, 200)
            XCTAssertEqual(counters.activeConnections, 7, "the inbound count is the user-visible one")

            // Rates are meaningless when the engine flags traffic unavailable,
            // and negative bridge values must clamp to zero.
            message.trafficAvailable = false
            message.connectionsIn = -2
            let unavailable = TunnelTelemetryClient.counters(from: message)
            XCTAssertEqual(unavailable.uplinkBytesPerSecond, 0)
            XCTAssertEqual(unavailable.downlinkBytesPerSecond, 0)
            XCTAssertEqual(unavailable.activeConnections, 0)
        }

        private func makeConnection() -> LibboxConnection {
            let connection = LibboxConnection()
            // gomobile quirk in the vendored binding: the `id_` property's
            // declared setter is a no-op; the Go `ID` field is only writable
            // through the `setID:` selector. Reads via `id_` work (that is all
            // production code does).
            _ = connection.perform(NSSelectorFromString("setID:"), with: "c1" as NSString)
            connection.network = "tcp"
            connection.source = "172.19.0.1:50000"
            connection.destination = "1.2.3.4:443"
            connection.domain = "example.com"
            connection.protocol = "tls"
            connection.inbound = "tun-in"
            connection.inboundType = "tun"
            connection.outbound = "proxy-1"
            connection.outboundType = "trojan"
            connection.createdAt = 1_800_000_000_000
            connection.closedAt = 0
            connection.uplink = 100
            connection.downlink = 200
            connection.uplinkTotal = 1000
            connection.downlinkTotal = 2000
            connection.rule = "rule-0"
            return connection
        }
    }
#endif
