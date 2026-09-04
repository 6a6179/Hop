@testable import Hop
import XCTest

/// Exercises the subscription transfer policy offline via a stub `URLProtocol`:
/// chunked accumulation, the mid-stream payload cap, status handling, and
/// redirect re-validation.
final class SubscriptionFetcherTests: XCTestCase {
    private var importService: ProxyImportService = {
        var service = ProxyImportService()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [SubscriptionStubProtocol.self]
        service.subscriptionSessionConfiguration = configuration
        return service
    }()

    override func setUp() {
        super.setUp()
        SubscriptionStubProtocol.reset()
    }

    func testFetchesChunkedBodyAndParsesProfiles() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/sub"))
        let body = "trojan://secret@one.example.net:443?security=tls#One\nhysteria2://secret@two.example.net:443?security=tls#Two"
        // Split mid-line so the test fails if chunks are dropped or reordered.
        let bytes = Array(body.utf8)
        SubscriptionStubProtocol.register(url: url, status: 200, chunks: [
            Data(bytes[..<40]), Data(bytes[40 ..< 41]), Data(bytes[41...]),
        ])

        let result = try await importService.importSubscription(url: url)

        XCTAssertEqual(result.profiles.map(\.name), ["One", "Two"])
    }

    func testNon2xxResponseFailsAsUnavailable() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/missing"))
        SubscriptionStubProtocol.register(url: url, status: 404, chunks: [Data("not found".utf8)])

        await assertImportFails(url: url, with: .subscriptionUnavailable)
    }

    func testDeclaredContentLengthOverCapFailsEarly() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/huge-declared"))
        SubscriptionStubProtocol.register(
            url: url,
            status: 200,
            headers: ["Content-Length": "\(ImportPolicy.maxPayloadBytes + 1)"],
            chunks: [Data("ignored".utf8)],
        )

        await assertImportFails(url: url, with: .payloadTooLarge)
    }

    func testStreamedBodyOverCapIsAbortedMidTransfer() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/huge-streamed"))
        // No Content-Length: only the mid-stream check can catch this one.
        let chunk = Data(repeating: UInt8(ascii: "a"), count: 2 * 1024 * 1024)
        SubscriptionStubProtocol.register(url: url, status: 200, chunks: [chunk, chunk, chunk])

        await assertImportFails(url: url, with: .payloadTooLarge)
    }

    func testFetcherAcceptsChunkedBodyExactlyAtCap() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/exact-cap"))
        let twoMiB = Data(repeating: UInt8(ascii: "a"), count: 2 * 1024 * 1024)
        let oneMiB = Data(repeating: UInt8(ascii: "b"), count: 1024 * 1024)
        SubscriptionStubProtocol.register(
            url: url,
            status: 200,
            headers: ["Content-Length": "\(ImportPolicy.maxPayloadBytes)"],
            chunks: [twoMiB, twoMiB, oneMiB],
        )

        let data = try await SubscriptionFetcher.fetch(
            URLRequest(url: url),
            configuration: importService.subscriptionSessionConfiguration,
        )

        XCTAssertEqual(data.count, ImportPolicy.maxPayloadBytes)
        XCTAssertEqual(data.last, UInt8(ascii: "b"))
    }

    func testCancellationStopsStalledTransfer() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/stalled"))
        let started = expectation(description: "Transfer started")
        let stopped = expectation(description: "Transfer stopped")
        let finished = expectation(description: "Fetch returned cancellation")
        SubscriptionStubProtocol.registerStalled(url: url, started: started, stopped: stopped)
        let configuration = importService.subscriptionSessionConfiguration
        let task = Task {
            do {
                _ = try await SubscriptionFetcher.fetch(URLRequest(url: url, timeoutInterval: 5), configuration: configuration)
                XCTFail("A cancelled fetch must not succeed")
            } catch is CancellationError {
                // Expected: the underlying transfer must stop as well.
            } catch {
                XCTFail("Expected CancellationError, got \(error)")
            }
            finished.fulfill()
        }

        await fulfillment(of: [started], timeout: 2)
        task.cancel()
        await fulfillment(of: [stopped, finished], timeout: 2)
    }

    func testPreCancelledFetchNeverStartsRequest() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/pre-cancelled"))
        SubscriptionStubProtocol.register(url: url, status: 200, chunks: [])
        let configuration = importService.subscriptionSessionConfiguration
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            do {
                _ = try await SubscriptionFetcher.fetch(URLRequest(url: url), configuration: configuration)
                XCTFail("A pre-cancelled fetch must not succeed")
            } catch is CancellationError {
                // Expected before the request is started.
            } catch {
                XCTFail("Expected CancellationError, got \(error)")
            }
        }

        await task.value
        XCTAssertTrue(SubscriptionStubProtocol.requestedURLs.isEmpty)
    }

    func testRedirectToDisallowedHostIsRefusedAndNeverRequested() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/bounce"))
        SubscriptionStubProtocol.register(
            url: url,
            status: 302,
            headers: ["Location": "https://169.254.169.254/latest/meta-data"],
            chunks: [],
        )

        // The refused redirect leaves the 3xx as the final response.
        await assertImportFails(url: url, with: .subscriptionUnavailable)
        XCTAssertFalse(
            SubscriptionStubProtocol.requestedURLs.contains { $0.contains("169.254.169.254") },
            "the metadata host must never be contacted",
        )
    }

    func testRedirectToAllowedHostIsFollowed() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/moved"))
        let target = try XCTUnwrap(URL(string: "https://mirror.stub.invalid/sub"))
        SubscriptionStubProtocol.register(url: url, status: 302, headers: ["Location": target.absoluteString], chunks: [])
        SubscriptionStubProtocol.register(url: target, status: 200, chunks: [
            Data("trojan://secret@one.example.net:443?security=tls#Moved".utf8),
        ])

        let result = try await importService.importSubscription(url: url)

        XCTAssertEqual(result.profiles.map(\.name), ["Moved"])
    }

    private func assertImportFails(url: URL, with expected: ProxyLinkParseError, file: StaticString = #filePath, line: UInt = #line) async {
        do {
            _ = try await importService.importSubscription(url: url)
            XCTFail("Expected \(expected) for \(url)", file: file, line: line)
        } catch let error as ProxyLinkParseError {
            if error.localizedDescription != expected.localizedDescription {
                XCTFail("Expected \(expected), got \(error)", file: file, line: line)
            }
        } catch {
            XCTFail("Expected ProxyLinkParseError.\(expected), got \(error)", file: file, line: line)
        }
    }
}

/// Serves canned (optionally chunked, optionally redirecting) responses for
/// the fetcher tests and records every URL the session actually requests.
private final class SubscriptionStubProtocol: URLProtocol {
    private struct Stub {
        var status: Int
        var headers: [String: String]
        var chunks: [Data]
        var stalled: (started: XCTestExpectation, stopped: XCTestExpectation)?
    }

    private nonisolated(unsafe) static var stubs: [String: Stub] = [:]
    private nonisolated(unsafe) static var requested: [String] = []
    private static let lock = NSLock()

    static func reset() {
        lock.lock()
        defer { lock.unlock() }
        stubs = [:]
        requested = []
    }

    static func register(url: URL, status: Int, headers: [String: String] = [:], chunks: [Data]) {
        lock.lock()
        defer { lock.unlock() }
        stubs[url.absoluteString] = Stub(status: status, headers: headers, chunks: chunks)
    }

    static func registerStalled(url: URL, started: XCTestExpectation, stopped: XCTestExpectation) {
        lock.lock()
        defer { lock.unlock() }
        stubs[url.absoluteString] = Stub(status: 200, headers: [:], chunks: [], stalled: (started, stopped))
    }

    static var requestedURLs: [String] {
        lock.lock()
        defer { lock.unlock() }
        return requested
    }

    override class func canInit(with _: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let url = request.url else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL))
            return
        }

        Self.lock.lock()
        Self.requested.append(url.absoluteString)
        let stub = Self.stubs[url.absoluteString]
        Self.lock.unlock()

        // Unregistered URL (e.g. a redirect that should have been refused):
        // serve a server error so the test fails loudly instead of hanging.
        guard let stub else {
            respond(url: url, status: 500, headers: [:], chunks: [])
            return
        }

        if let stalled = stub.stalled {
            stalled.started.fulfill()
            return
        }

        if (300 ..< 400).contains(stub.status), let location = stub.headers["Location"], let target = URL(string: location) {
            let response = HTTPURLResponse(url: url, statusCode: stub.status, httpVersion: "HTTP/1.1", headerFields: stub.headers)!
            client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: target), redirectResponse: response)
            // If the delegate refuses the redirect, this 3xx is the final response.
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocolDidFinishLoading(self)
            return
        }

        respond(url: url, status: stub.status, headers: stub.headers, chunks: stub.chunks)
    }

    override func stopLoading() {
        guard let url = request.url else { return }
        Self.lock.lock()
        let stopped = Self.stubs[url.absoluteString]?.stalled?.stopped
        Self.lock.unlock()
        stopped?.fulfill()
    }

    private func respond(url: URL, status: Int, headers: [String: String], chunks: [Data]) {
        let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        for chunk in chunks {
            client?.urlProtocol(self, didLoad: chunk)
        }
        client?.urlProtocolDidFinishLoading(self)
    }
}
