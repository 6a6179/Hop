@testable import Hop
import SwiftUI
import XCTest

/// Tests for AppShellView.importPayload(from:) — the hop:// URL scheme handler.
@MainActor
final class ExternalImportPayloadTests: XCTestCase {
    // MARK: - Valid hop://import?url=

    func testHopImportURLDecodesSubscriptionURL() throws {
        let url = try XCTUnwrap(URL(string: "hop://import?url=https%3A%2F%2Fexample.com%2Fsub"))
        let payload = AppShellView.importPayload(from: url)
        XCTAssertEqual(payload, "https://example.com/sub")
    }

    func testHopImportTextDecodesPayloadText() throws {
        let encoded = "vless%3A%2F%2Fuuid%40host%3A443%23Name"
        let url = try XCTUnwrap(URL(string: "hop://import?text=\(encoded)"))
        let payload = AppShellView.importPayload(from: url)
        XCTAssertEqual(payload, "vless://uuid@host:443#Name")
    }

    // MARK: - text wins over url when both present

    func testTextParamWinsOverURLParamWhenBothPresent() throws {
        let url = try XCTUnwrap(URL(string: "hop://import?url=https%3A%2F%2Fexample.com%2Fsub&text=vless%3A%2F%2Fsome-text"))
        let payload = AppShellView.importPayload(from: url)
        XCTAssertEqual(payload, "vless://some-text", "text param must win over url param when both are present")
    }

    // MARK: - Invalid inputs

    func testNonHopSchemeReturnsNil() throws {
        let url = try XCTUnwrap(URL(string: "https://example.com/import?url=https://example.com/sub"))
        XCTAssertNil(AppShellView.importPayload(from: url), "non-hop scheme must return nil")
    }

    func testHopImportOtherHostReturnsNil() throws {
        let url = try XCTUnwrap(URL(string: "hop://other?url=https://example.com/sub"))
        XCTAssertNil(AppShellView.importPayload(from: url), "hop://other must return nil (only hop://import is handled)")
    }

    func testHopImportMissingQueryReturnsNil() throws {
        let url = try XCTUnwrap(URL(string: "hop://import"))
        XCTAssertNil(AppShellView.importPayload(from: url), "hop://import with no query must return nil")
    }

    func testHopImportEmptyTextReturnsNil() throws {
        let url = try XCTUnwrap(URL(string: "hop://import?text="))
        // Empty text value — falls through to url, which is also missing, so nil
        XCTAssertNil(AppShellView.importPayload(from: url), "empty text value with no url must return nil")
    }

    func testHopImportEmptyURLReturnsNil() throws {
        let url = try XCTUnwrap(URL(string: "hop://import?url="))
        XCTAssertNil(AppShellView.importPayload(from: url), "empty url value must return nil")
    }

    // MARK: - Proxy share-link schemes (vless://, ss://, …)

    func testProxyLinkSchemesPassTheWholeLinkThrough() throws {
        let links = [
            "vless://uuid@host.example.com:443?security=tls&sni=host.example.com#Tokyo",
            "vmess://eyJhZGQiOiJob3N0IiwicG9ydCI6IjQ0MyJ9",
            "trojan://password@host.example.com:443#Node",
            "ss://YWVzLTI1Ni1nY206cGFzcw@host.example.com:8388#SS",
            "ssr://aG9zdDo0NDM6b3JpZ2luOmFlcy0yNTYtY2ZiOnBsYWluOnBhc3M",
            "hysteria2://pass@host.example.com:443#Hy2",
            "hy2://pass@host.example.com:443#Hy2",
            "tuic://uuid:pass@host.example.com:443#TUIC",
            "socks://user:pass@host.example.com:1080#SOCKS",
            "socks5://user:pass@host.example.com:1080#SOCKS",
        ]
        for link in links {
            let url = try XCTUnwrap(URL(string: link), "fixture must parse: \(link)")
            XCTAssertEqual(
                AppShellView.importPayload(from: url),
                link,
                "a proxy share link must be handed through verbatim as the import payload",
            )
        }
    }

    func testProxyLinkSchemeIsCaseInsensitive() throws {
        let url = try XCTUnwrap(URL(string: "VLESS://uuid@host.example.com:443#Tokyo"))
        XCTAssertEqual(AppShellView.importPayload(from: url), "VLESS://uuid@host.example.com:443#Tokyo")
    }

    func testRegisteredSchemesMatchTheHandledSet() throws {
        // The Info.plist registration and the handler must not drift apart:
        // a scheme registered but unhandled opens the app and silently does
        // nothing; handled but unregistered never reaches the app at all.
        // Tests are hosted in Hop.app, so Bundle.main is the app bundle.
        let urlTypes = try XCTUnwrap(
            Bundle.main.infoDictionary?["CFBundleURLTypes"] as? [[String: Any]],
            "Hop.app must declare CFBundleURLTypes",
        )
        let registered = Set(urlTypes.flatMap { ($0["CFBundleURLSchemes"] as? [String]) ?? [] }.map { $0.lowercased() })
        let expected = AppShellView.proxyLinkSchemes.union(["hop"])
        XCTAssertEqual(registered, expected, "Info.plist CFBundleURLSchemes must match the schemes the handler accepts")
    }

    // MARK: - Case insensitivity of scheme and host

    func testHopImportSchemeAndHostAreCaseInsensitive() {
        // The implementation lowercases scheme and host, so HOP://IMPORT must work
        guard let url = URL(string: "HOP://IMPORT?url=https%3A%2F%2Fexample.com%2Fsub") else {
            // Some URL parsers normalize this; if not parseable, skip
            return
        }
        // If the URL was parsed, the payload should be decoded
        let payload = AppShellView.importPayload(from: url)
        // hop:// handling lowercases both scheme and host, so this should succeed
        XCTAssertEqual(payload, "https://example.com/sub")
    }
}
