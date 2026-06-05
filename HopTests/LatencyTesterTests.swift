@testable import Hop
import XCTest

final class LatencyTesterTests: XCTestCase {
    // MARK: - Settings persistence / backward compatibility

    func testAppSettingsDecodesLegacyStateWithoutLatencyMethod() throws {
        // State written by a build that predates the latency feature must still
        // decode (missing key → default) rather than wiping persisted data.
        let legacy = """
        {
          "appearance": "dark",
          "logLevel": "debug",
          "dnsPreset": "quad9",
          "dnsStrategy": "ipv6_only",
          "proxyDNS": false,
          "sniffTraffic": false,
          "strictRoute": false,
          "logRetention": 1000
        }
        """

        let settings = try JSONDecoder().decode(AppSettings.self, from: Data(legacy.utf8))
        XCTAssertEqual(settings.appearance, .dark)
        XCTAssertEqual(settings.logRetention, .oneThousand)
        XCTAssertEqual(settings.strictRoute, false)
        XCTAssertEqual(settings.latencyTestMethod, .tcp) // defaulted
    }

    func testAppSettingsRoundTripsLatencyMethod() throws {
        var settings = AppSettings.defaults
        settings.latencyTestMethod = .icmp
        let data = try JSONEncoder().encode(settings)
        let decoded = try JSONDecoder().decode(AppSettings.self, from: data)
        XCTAssertEqual(decoded.latencyTestMethod, .icmp)
    }

    func testLatencyTestMethodHasThreeMethods() {
        XCTAssertEqual(Set(LatencyTestMethod.allCases), [.tcp, .connect, .icmp])
        XCTAssertEqual(LatencyTestMethod(rawValue: "tcp"), .tcp)
        for method in LatencyTestMethod.allCases {
            XCTAssertFalse(method.displayName.isEmpty)
            XCTAssertFalse(method.footnote.isEmpty)
        }
    }

    // MARK: - NodeLatencyResult

    func testNodeLatencyResultMilliseconds() {
        XCTAssertEqual(NodeLatencyResult.success(42).milliseconds, 42)
        XCTAssertNil(NodeLatencyResult.testing.milliseconds)
        XCTAssertNil(NodeLatencyResult.failure("x").milliseconds)
    }

    // MARK: - ICMP packet construction

    func testICMPv4EchoRequestHasValidChecksum() {
        let packet = LatencyTester.icmpEchoRequest(isIPv6: false, identifier: 0xABCD, sequence: 7)
        XCTAssertEqual(packet[0], 8) // echo request type
        XCTAssertEqual(packet[1], 0) // code
        // Identifier / sequence are stored big-endian.
        XCTAssertEqual((UInt16(packet[4]) << 8) | UInt16(packet[5]), 0xABCD)
        XCTAssertEqual((UInt16(packet[6]) << 8) | UInt16(packet[7]), 7)
        // A correct checksum makes the one's-complement sum of the whole packet 0xFFFF.
        XCTAssertEqual(onesComplementSum(packet), 0xFFFF)
    }

    func testICMPv6EchoRequestLeavesChecksumForKernel() {
        let packet = LatencyTester.icmpEchoRequest(isIPv6: true, identifier: 1, sequence: 1)
        XCTAssertEqual(packet[0], 128) // ICMPv6 echo request type
        XCTAssertEqual(packet[2], 0)
        XCTAssertEqual(packet[3], 0) // kernel computes ICMPv6 checksum
    }

    func testInternetChecksumKnownValue() {
        // 0x0000 + 0x0000 -> ~0 == 0xFFFF; a single 0xFFFF word -> 0x0000.
        XCTAssertEqual(LatencyTester.internetChecksum([0x00, 0x00]), 0xFFFF)
        XCTAssertEqual(LatencyTester.internetChecksum([0xFF, 0xFF]), 0x0000)
    }

    // MARK: - ICMP reply matching

    func testMatchesIPv4ReplyWithLeadingIPHeader() {
        let reply = ipv4Reply(identifier: 0x1234, sequence: 9, type: 0)
        XCTAssertTrue(LatencyTester.isMatchingReply(reply, isIPv6: false, identifier: 0x1234, sequence: 9))
    }

    func testRejectsIPv4ReplyWithWrongIdentifierOrType() {
        let wrongID = ipv4Reply(identifier: 0x1234, sequence: 9, type: 0)
        XCTAssertFalse(LatencyTester.isMatchingReply(wrongID, isIPv6: false, identifier: 0x9999, sequence: 9))

        let echoRequestType = ipv4Reply(identifier: 0x1234, sequence: 9, type: 8)
        XCTAssertFalse(LatencyTester.isMatchingReply(echoRequestType, isIPv6: false, identifier: 0x1234, sequence: 9))
    }

    func testMatchesIPv6ReplyWithoutIPHeader() {
        let reply: [UInt8] = [129, 0, 0, 0, 0x12, 0x34, 0x00, 0x09] + Array("reply".utf8)
        XCTAssertTrue(LatencyTester.isMatchingReply(reply, isIPv6: true, identifier: 0x1234, sequence: 9))
    }

    func testMatchesBareIPv4ReplyWithoutIPHeader() {
        // Some stacks deliver the ICMP message with no IP header.
        let reply: [UInt8] = [0, 0, 0, 0, 0x12, 0x34, 0x00, 0x09] + Array("reply".utf8)
        XCTAssertTrue(LatencyTester.isMatchingReply(reply, isIPv6: false, identifier: 0x1234, sequence: 9))
    }

    // MARK: - Helpers

    private func ipv4Reply(identifier: UInt16, sequence: UInt16, type: UInt8) -> [UInt8] {
        var header = [UInt8](repeating: 0, count: 20)
        header[0] = 0x45 // IPv4, 20-byte header (IHL = 5)
        let icmp: [UInt8] = [
            type, 0, 0, 0,
            UInt8(identifier >> 8), UInt8(identifier & 0xFF),
            UInt8(sequence >> 8), UInt8(sequence & 0xFF),
        ]
        return header + icmp + Array("reply".utf8)
    }

    private func onesComplementSum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var index = 0
        while index + 1 < bytes.count {
            sum += (UInt32(bytes[index]) << 8) | UInt32(bytes[index + 1])
            index += 2
        }
        if index < bytes.count {
            sum += UInt32(bytes[index]) << 8
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return UInt16(sum & 0xFFFF)
    }
}
