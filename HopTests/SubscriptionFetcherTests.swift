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

    func testPartialResponseContainingACompleteLinkCannotBecomeASnapshot() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/partial"))
        let prefix = Data("trojan://secret@one.example.net:443#One".utf8)
        SubscriptionStubProtocol.register(url: url, status: 206, chunks: [prefix])
        await assertImportFails(url: url, with: .incompleteSubscriptionInventory)

        SubscriptionStubProtocol.register(url: url, status: 200, headers: ["Content-Range": "bytes 0-37/100"], chunks: [prefix])
        await assertImportFails(url: url, with: .incompleteSubscriptionInventory)
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

    @MainActor
    func testAutoRefreshRechecksConsentAndQueuedSourceBeforeFetching() async throws {
        let firstURL = try XCTUnwrap(URL(string: "https://stub.invalid/first"))
        let secondURL = try XCTUnwrap(URL(string: "https://stub.invalid/second"))
        for revokeConsent in [true, false] {
            SubscriptionStubProtocol.reset()
            let started = expectation(description: "First fetch started")
            SubscriptionStubProtocol.registerStalled(url: firstURL, started: started)
            let first = SubscriptionSource(name: "First", url: firstURL.absoluteString)
            let second = SubscriptionSource(name: "Second", url: secondURL.absoluteString)
            var settings = AppSettings.defaults
            settings.autoRefreshSubscriptions = true
            let store = HopStore(
                subscriptions: [first, second],
                settings: settings,
                dataStore: HopAppDataStore(
                    url: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString),
                    secretStore: .inMemory(),
                    authenticationStore: .inMemory(),
                ),
                importService: importService,
            )
            let refresh = Task { await store.autoRefreshStaleSubscriptions() }
            guard await XCTWaiter.fulfillment(of: [started], timeout: 5) == .completed else {
                refresh.cancel()
                await refresh.value
                return XCTFail("The first subscription request never started")
            }
            if revokeConsent {
                store.settings.autoRefreshSubscriptions = false
            } else {
                store.deleteSubscription(id: second.id)
            }
            SubscriptionStubProtocol.finishStalled(url: firstURL, body: "trojan://secret@one.example.net:443#One")
            await refresh.value
            XCTAssertEqual(SubscriptionStubProtocol.requestedURLs, [firstURL.absoluteString])
            XCTAssertEqual(store.profiles.count, revokeConsent ? 0 : 1)
            store.flushPendingPersists()
        }
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
        var stalled: (started: XCTestExpectation, stopped: XCTestExpectation?)?
    }

    private nonisolated(unsafe) static var stubs: [String: Stub] = [:]
    private nonisolated(unsafe) static var requested: [String] = []
    private nonisolated(unsafe) static var stalledRequests: [String: SubscriptionStubProtocol] = [:]
    private static let lock = NSLock()

    static func reset() {
        lock.lock()
        defer { lock.unlock() }
        stubs = [:]
        requested = []
        stalledRequests = [:]
    }

    static func register(url: URL, status: Int, headers: [String: String] = [:], chunks: [Data]) {
        lock.lock()
        defer { lock.unlock() }
        stubs[url.absoluteString] = Stub(status: status, headers: headers, chunks: chunks)
    }

    static func registerStalled(url: URL, started: XCTestExpectation, stopped: XCTestExpectation? = nil) {
        lock.lock()
        defer { lock.unlock() }
        stubs[url.absoluteString] = Stub(status: 200, headers: [:], chunks: [], stalled: (started, stopped))
    }

    static func finishStalled(url: URL, body: String) {
        lock.lock()
        let request = stalledRequests.removeValue(forKey: url.absoluteString)
        lock.unlock()
        request?.respond(url: url, status: 200, headers: [:], chunks: [Data(body.utf8)])
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
        if stub?.stalled != nil {
            Self.stalledRequests[url.absoluteString] = self
        }
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
        Self.stalledRequests[url.absoluteString] = nil
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
