@testable import Hop
import XCTest

final class ProfileImportPayloadDetectorTests: XCTestCase {
    private let detector = ProfileImportPayloadDetector()

    func testDetectsPlainHTTPSURLAsSubscription() throws {
        let payload = detector.detect(" https://sub.example.com/path/token?target=hop ")

        XCTAssertEqual(payload, try .subscription(XCTUnwrap(URL(string: "https://sub.example.com/path/token?target=hop"))))
    }

    func testLeavesCredentialedHTTPSProxyURLAsImportText() {
        let link = "https://user:pass@proxy.example.com:443#HTTPS"

        XCTAssertEqual(detector.detect(link), .importText(link))
    }

    func testLeavesCredentialedHTTPSProxyURLWithPathAsImportText() {
        let link = "https://user:pass@proxy.example.com:443/proxy#HTTPS"

        XCTAssertEqual(detector.detect(link), .importText(link))
    }

    func testLeavesPortOnlyHTTPSProxyURLAsImportText() {
        let link = "https://proxy.example.com:443#HTTPS"

        XCTAssertEqual(detector.detect(link), .importText(link))
    }

    func testDetectsHTTPSURLWithPortAndPathAsSubscription() throws {
        let payload = detector.detect("https://sub.example.com:443/path/token")

        XCTAssertEqual(payload, try .subscription(XCTUnwrap(URL(string: "https://sub.example.com:443/path/token"))))
    }

    func testLeavesProxySchemesAsImportText() {
        let link = "vless://11111111-1111-4111-8111-111111111111@edge.example.net:443?security=reality#Tokyo"

        XCTAssertEqual(detector.detect(link), .importText(link))
    }

    func testIgnoresEmptyPayload() {
        XCTAssertNil(detector.detect("  \n\t  "))
    }
}
