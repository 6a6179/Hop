@testable import Hop
import XCTest
import zlib

final class SubscriptionHTTPContentTests: XCTestCase {
    private let plain = Data("subscription\n".utf8)

    func testIdentityAndCompressedContent() throws {
        XCTAssertEqual(try SubscriptionHTTPContent.decode(plain, encoding: ""), plain)
        XCTAssertEqual(try SubscriptionHTTPContent.decode(plain, encoding: " identity "), plain)
        let gzip = try XCTUnwrap(Data(base64Encoded: "H4sIAAAAAAAC/ysuTSpOLsosKMnMz+MCAJlDri0NAAAA"))
        for encoding in ["gzip", "X-GZip"] {
            XCTAssertEqual(try SubscriptionHTTPContent.decode(gzip, encoding: encoding), plain)
        }
        XCTAssertEqual(try SubscriptionHTTPContent.decode(gzip + gzip, encoding: "gzip"), plain + plain)
        let deflate = try XCTUnwrap(Data(base64Encoded: "eJwrLk0qTi7KLCjJzM/jAgAmuQUw"))
        XCTAssertEqual(try SubscriptionHTTPContent.decode(deflate, encoding: "deflate"), plain)
    }

    func testRejectsIncompleteDamagedAndTrailingData() throws {
        let gzip = try XCTUnwrap(Data(base64Encoded: "H4sIAAAAAAAC/ysuTSpOLsosKMnMz+MCAJlDri0NAAAA"))
        let deflate = try XCTUnwrap(Data(base64Encoded: "eJwrLk0qTi7KLCjJzM/jAgAmuQUw"))
        for (data, encoding) in [(gzip, "gzip"), (deflate, "deflate")] {
            var damaged = data
            damaged[damaged.count - 1] ^= 1
            for invalid in [Data(), data.dropLast(), damaged, data + Data([0xFF])] {
                assertUnavailable(invalid, encoding: encoding)
            }
        }
        assertUnavailable(deflate + deflate, encoding: "deflate")
        assertUnavailable(gzip, encoding: "deflate")
        assertUnavailable(plain, encoding: "br")
    }

    func testLimitsInputAndExpandedOutputIndependently() throws {
        let limit = ImportPolicy.maxPayloadBytes
        let largest = Data(repeating: 0x61, count: limit)
        XCTAssertEqual(try SubscriptionHTTPContent.decode(largest, encoding: "identity").count, limit)
        XCTAssertEqual(try SubscriptionHTTPContent.decode(compressed(largest), encoding: "deflate").count, limit)
        let oversized = largest + Data([0x61])
        assertTooLarge(oversized, encoding: "identity")
        assertTooLarge(oversized, encoding: "gzip")
        try assertTooLarge(compressed(oversized), encoding: "deflate")
    }

    private func compressed(_ data: Data) throws -> Data {
        var size = compressBound(uLong(data.count))
        var output = Data(count: Int(size))
        let status = output.withUnsafeMutableBytes { destination in
            data.withUnsafeBytes { source in
                compress2(destination.bindMemory(to: Bytef.self).baseAddress, &size,
                          source.bindMemory(to: Bytef.self).baseAddress, uLong(source.count), Z_BEST_SPEED)
            }
        }
        guard status == Z_OK else { throw NSError(domain: "zlib fixture", code: Int(status)) }
        return output.prefix(Int(size))
    }

    private func assertUnavailable(_ data: Data, encoding: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try SubscriptionHTTPContent.decode(data, encoding: encoding), file: file, line: line) { error in
            guard case ProxyLinkParseError.subscriptionUnavailable = error else {
                XCTFail("Unexpected error: \(error)", file: file, line: line)
                return
            }
        }
    }

    private func assertTooLarge(_ data: Data, encoding: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try SubscriptionHTTPContent.decode(data, encoding: encoding), file: file, line: line) { error in
            guard case ProxyLinkParseError.payloadTooLarge = error else {
                XCTFail("Unexpected error: \(error)", file: file, line: line)
                return
            }
        }
    }
}
