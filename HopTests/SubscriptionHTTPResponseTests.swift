@testable import Hop
import XCTest

final class SubscriptionHTTPResponseTests: XCTestCase {
    private func bytes(_ text: String) -> Data {
        Data(text.utf8)
    }

    private func body(_ result: SubscriptionHTTPResponse.Result?, file: StaticString = #filePath, line: UInt = #line) -> Data? {
        guard case let .body(body) = result else {
            XCTFail("Missing response body", file: file, line: line)
            return nil
        }
        return body
    }

    func testInformationalResponsesAndFixedLengthAcrossSingleByteReads() throws {
        let data = bytes("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nSet-Cookie: early=1\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 005, 5\r\nSet-Cookie: first=one\r\nSet-Cookie: second=two\r\n\r\nhello")
        var parser = SubscriptionHTTPResponse()
        for byte in data.dropLast() {
            XCTAssertNil(try parser.receive(Data([byte]), endOfStream: false))
        }
        XCTAssertEqual(try body(parser.receive(data.suffix(1), endOfStream: false)), bytes("hello"))
        XCTAssertEqual(parser.setCookieHeaders, ["first=one", "second=two"])
    }

    func testChunkExtensionsTrailersAndEveryPossibleReadBoundary() throws {
        let data = bytes("HTTP/1.1 200 OK\r\ntRaNsFeR-EnCoDiNg: Chunked\r\n\r\n3 ; name = \"a;b\\\"c\";flag\r\nabc\r\n2;foo=bar\r\nde\r\n0;last\r\nChecksum: done\r\n\r\n")
        for cut in data.indices {
            var parser = SubscriptionHTTPResponse()
            XCTAssertNil(try parser.receive(data[..<cut], endOfStream: false))
            XCTAssertEqual(try body(parser.receive(data[cut...], endOfStream: false)), bytes("abcde"))
        }
    }

    func testCloseDelimitedWaitsForCleanEndOfStream() throws {
        var parser = SubscriptionHTTPResponse()
        XCTAssertNil(try parser.receive(bytes("HTTP/1.0 200 OK\r\n\r\none"), endOfStream: false))
        XCTAssertEqual(try body(parser.receive(bytes(" two"), endOfStream: true)), bytes("one two"))
    }

    func testEmptyBodiesAndRedirectsCanFinishBeforeEOF() throws {
        for response in ["HTTP/1.1 204 No Content\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"] {
            var parser = SubscriptionHTTPResponse()
            XCTAssertEqual(try body(parser.receive(bytes(response), endOfStream: false)), Data())
        }
        for status in [301, 302, 303, 307, 308] {
            var parser = SubscriptionHTTPResponse()
            let response = bytes("HTTP/1.1 \(status) Redirect\r\nLocation: ../next?q=1,2\r\nSet-Cookie: id=1; Secure\r\n\r\nredirect body")
            guard case let .redirect(location) = try parser.receive(response, endOfStream: false) else {
                return XCTFail("Expected redirect for \(status)")
            }
            XCTAssertEqual(location, "../next?q=1,2")
            XCTAssertEqual(parser.setCookieHeaders, ["id=1; Secure"])
        }
    }

    func testPartialInventoriesAndPrematureEOF() {
        for response in [
            "HTTP/1.1 206 Partial Content\r\n\r\n",
            "HTTP/1.1 226 IM Used\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Range: bytes 0-2/9\r\n\r\nabc",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabc",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nChecksum: done\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Range: bytes 0-2/9\r\n\r\n",
            "HTTP/1.1 200 OK\r\n",
        ] {
            assertFailure(bytes(response), .incompleteSubscriptionInventory)
        }
    }

    func testInvalidStatusFramingAndUnsupportedCodings() {
        for response in [
            "HTTP/1.1 404 Not Found\r\n\r\n",
            "HTTP/1.1 101 Switching Protocols\r\n\r\n",
            "HTTP/1.1 302 Found\r\n\r\n",
            "HTTP/1.1 302 Found\r\nLocation: /one\r\nLocation: /two\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 1, 3\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Encoding: br\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip, gzip\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\naX",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;name=\"open\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nabc",
        ] {
            assertFailure(bytes(response), .subscriptionUnavailable)
        }
    }

    func testHeadersTrailersAndBodiesHaveIndependentSizeBounds() throws {
        let cap = ImportPolicy.maxPayloadBytes
        let padding = String(repeating: "a", count: 64 * 1024)
        assertFailure(bytes("HTTP/1.1 200 OK\r\nName: \(padding)"), .payloadTooLarge)
        assertFailure(bytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nName: \(padding)"), .payloadTooLarge)
        assertFailure(bytes("HTTP/1.1 200 OK\r\nContent-Length: \(cap + 1)\r\n\r\n"), .payloadTooLarge)
        assertFailure(bytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\(String(cap + 1, radix: 16))\r\n"), .payloadTooLarge)

        var parser = SubscriptionHTTPResponse()
        XCTAssertNil(try parser.receive(bytes("HTTP/1.1 200 OK\r\n\r\n"), endOfStream: false))
        XCTAssertNil(try parser.receive(Data(repeating: 97, count: cap), endOfStream: false))
        XCTAssertThrowsError(try parser.receive(bytes("b"), endOfStream: true)) {
            XCTAssertEqual($0.localizedDescription, ProxyLinkParseError.payloadTooLarge.localizedDescription)
        }
    }

    func testGzipEncodingIsDecodedAfterChunkFraming() throws {
        // A gzip member containing the UTF-8 text "hello".
        let gzip = try XCTUnwrap(Data(base64Encoded: "H4sIAAAAAAACA8tIzcnJBwCGphA2BQAAAA=="))
        var response = bytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: X-Gzip\r\n\r\n\(String(gzip.count, radix: 16))\r\n")
        response.append(gzip)
        response.append(bytes("\r\n0\r\n\r\n"))
        var parser = SubscriptionHTTPResponse()
        XCTAssertEqual(try body(parser.receive(response, endOfStream: true)), bytes("hello"))
    }

    private func assertFailure(_ data: Data, _ expected: ProxyLinkParseError, file: StaticString = #filePath, line: UInt = #line) {
        var parser = SubscriptionHTTPResponse()
        XCTAssertThrowsError(try parser.receive(data, endOfStream: true), file: file, line: line) {
            XCTAssertEqual($0.localizedDescription, expected.localizedDescription, file: file, line: line)
        }
    }
}
