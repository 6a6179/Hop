@testable import Hop
import XCTest

/// Exercises the complete transfer and HTTP decoder using in-memory sockets.
final class SubscriptionFetcherTests: XCTestCase {
    private let server = StubSubscriptionServer()

    private var importService: ProxyImportService {
        var service = ProxyImportService()
        service.downloadSubscription = { [server] request in
            try await server.fetch(request)
        }
        return service
    }

    func testFetchesChunkedBodyAndParsesProfiles() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/sub"))
        let body = "trojan://secret@one.example.net:443?security=tls#One\nhysteria2://secret@two.example.net:443?security=tls#Two"
        // Split mid-line so the test fails if chunks are dropped or reordered.
        let bytes = Array(body.utf8)
        server.register(url: url, status: 200, chunks: [
            Data(bytes[..<40]), Data(bytes[40 ..< 41]), Data(bytes[41...]),
        ])

        let result = try await importService.importSubscription(url: url)

        XCTAssertEqual(result.profiles.map(\.name), ["One", "Two"])
    }

    func testPartialResponseContainingACompleteLinkCannotBecomeASnapshot() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/partial"))
        let prefix = Data("trojan://secret@one.example.net:443#One".utf8)
        server.register(url: url, status: 206, chunks: [prefix])
        await assertImportFails(url: url, with: .incompleteSubscriptionInventory)

        server.register(url: url, status: 200, headers: ["Content-Range": "bytes 0-37/100"], chunks: [prefix])
        await assertImportFails(url: url, with: .incompleteSubscriptionInventory)
    }

    func testNon2xxResponseFailsAsUnavailable() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/missing"))
        server.register(url: url, status: 404, chunks: [Data("not found".utf8)])

        await assertImportFails(url: url, with: .subscriptionUnavailable)
    }

    func testDeclaredContentLengthOverCapFailsEarly() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/huge-declared"))
        server.register(
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
        server.register(url: url, status: 200, chunks: [chunk, chunk, chunk])

        await assertImportFails(url: url, with: .payloadTooLarge)
    }

    func testFetcherAcceptsChunkedBodyExactlyAtCap() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/exact-cap"))
        let twoMiB = Data(repeating: UInt8(ascii: "a"), count: 2 * 1024 * 1024)
        let oneMiB = Data(repeating: UInt8(ascii: "b"), count: 1024 * 1024)
        server.register(
            url: url,
            status: 200,
            headers: ["Content-Length": "\(ImportPolicy.maxPayloadBytes)"],
            chunks: [twoMiB, twoMiB, oneMiB],
        )

        let data = try await server.fetch(URLRequest(url: url))

        XCTAssertEqual(data.count, ImportPolicy.maxPayloadBytes)
        XCTAssertEqual(data.last, UInt8(ascii: "b"))
    }

    @MainActor
    func testAutoRefreshRechecksConsentAndQueuedSourceBeforeFetching() async throws {
        let firstURL = try XCTUnwrap(URL(string: "https://stub.invalid/first"))
        let secondURL = try XCTUnwrap(URL(string: "https://stub.invalid/second"))
        for revokeConsent in [true, false] {
            server.reset()
            let started = expectation(description: "First fetch started")
            server.registerStalled(url: firstURL, started: started)
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
            server.finishStalled(url: firstURL, body: "trojan://secret@one.example.net:443#One")
            await refresh.value
            XCTAssertEqual(server.requestedURLs, [firstURL.absoluteString])
            XCTAssertEqual(store.profiles.count, revokeConsent ? 0 : 1)
            store.flushPendingPersists()
        }
    }

    func testCancellationStopsStalledTransfer() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/stalled"))
        let started = expectation(description: "Transfer started")
        let stopped = expectation(description: "Transfer stopped")
        let finished = expectation(description: "Fetch returned cancellation")
        server.registerStalled(url: url, started: started, stopped: stopped)
        let task = Task { [server] in
            do {
                _ = try await server.fetch(URLRequest(url: url, timeoutInterval: 5))
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

    func testAbsoluteDeadlineStopsAStartedTransfer() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/slow"))
        let started = expectation(description: "Transfer started")
        let stopped = expectation(description: "Underlying transfer cancelled")
        server.registerStalled(url: url, started: started, stopped: stopped)
        let task = Task { [server] in
            try await server.fetch(URLRequest(url: url, timeoutInterval: 30), timeout: 0.25)
        }
        await fulfillment(of: [started], timeout: 2)
        do {
            _ = try await task.value
            XCTFail("A stalled transfer must exhaust the total resource deadline")
        } catch let error as URLError {
            XCTAssertEqual(error.code, .timedOut)
        }
        await fulfillment(of: [stopped], timeout: 2)
    }

    func testCompleteBodyDeliveredAfterDeadlineTimesOutBeforeTimerRuns() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/late-body"))
        let delivery = expectation(description: "Socket delivered the complete body after the deadline")
        let timeout: TimeInterval = 0.75
        server.register(url: url, status: 200, headers: ["Content-Length": "2"], chunks: [Data("ok".utf8)]) {
            // The body and the timer share a serial queue. Keep this callback
            // running until the deadline passes so the timer cannot fire first.
            _ = DispatchSemaphore(value: 0).wait(timeout: .now() + timeout + 0.1)
            delivery.fulfill()
        }

        do {
            _ = try await server.fetch(URLRequest(url: url), timeout: timeout)
            XCTFail("A complete body delivered after the deadline must time out")
        } catch let error as URLError {
            XCTAssertEqual(error.code, .timedOut)
        }
        await fulfillment(of: [delivery], timeout: 2)
    }

    func testOriginPreservesHostPortAndEscapedRequestTarget() throws {
        for (raw, authority, target) in [
            ("https://feed.example:444/a%2Fb?q=x%2By", "feed.example:444", "/a%2Fb?q=x%2By"),
            ("https://[2606:4700:4700::1111]:8443/sub", "[2606:4700:4700::1111]:8443", "/sub"),
            ("https://feed.example/sub", "feed.example", "/sub"),
        ] {
            let url = try XCTUnwrap(URL(string: raw))
            let origin = try SubscriptionOrigin(url)
            XCTAssertEqual(origin.authority, authority)
            XCTAssertEqual(origin.requestTarget, target)
            XCTAssertEqual(origin.url, url)
        }
    }

    func testMixedDNSAnswerIsRejectedBeforeAnySocketOpens() async throws {
        let url = try XCTUnwrap(URL(string: "https://feed.example.invalid/path"))
        do {
            _ = try await server.fetch(URLRequest(url: url), resolve: { host in
                XCTAssertEqual(host, "feed.example.invalid")
                return ["1.1.1.1", "::1"]
            })
            XCTFail("A mixed DNS answer must fail before connecting")
        } catch let error as ProxyLinkParseError {
            guard case .disallowedSubscriptionHost = error else { return XCTFail("Unexpected blocking reason: \(error)") }
        }
        XCTAssertTrue(server.dialedAddresses.isEmpty)
    }

    func testConnectionRetryUsesOnlyCheckedAddressesAndRetainsHTTPSOrigin() async throws {
        let url = try XCTUnwrap(URL(string: "https://feed.example.invalid:444/a%2Fb?q=x%2By"))
        server.register(url: url, status: 200, chunks: [Data("success".utf8)])
        server.failConnection(to: "1.1.1.1")
        let data = try await server.fetch(URLRequest(url: url), resolve: { host in
            XCTAssertEqual(host, "feed.example.invalid")
            return ["1.1.1.1", "2606:4700:4700::1111"]
        })

        XCTAssertEqual(data, Data("success".utf8))
        XCTAssertEqual(server.dialedAddresses, ["1.1.1.1", "2606:4700:4700::1111"])
        XCTAssertEqual(server.peerNames, ["feed.example.invalid", "feed.example.invalid"])
        XCTAssertTrue(server.lastRequest.hasPrefix("GET /a%2Fb?q=x%2By HTTP/1.1\r\n"))
        XCTAssertTrue(server.lastRequest.contains("\r\nHost: feed.example.invalid:444\r\n"))
    }

    func testFailedOrNonNumericResolutionCannotOpenSubscriptionSocket() throws {
        let url = try XCTUnwrap(URL(string: "https://feed.example/sub"))
        for answers: [String]? in [nil, [], ["still-a-hostname.example"]] {
            XCTAssertThrowsError(try ImportPolicy.subscriptionAddresses(for: url) { _ in answers })
        }
    }

    func testPreCancelledFetchNeverStartsRequest() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/pre-cancelled"))
        server.register(url: url, status: 200, chunks: [])
        let task = Task { [server] in
            withUnsafeCurrentTask { $0?.cancel() }
            do {
                _ = try await server.fetch(URLRequest(url: url))
                XCTFail("A pre-cancelled fetch must not succeed")
            } catch is CancellationError {
                // Expected before the request is started.
            } catch {
                XCTFail("Expected CancellationError, got \(error)")
            }
        }

        await task.value
        XCTAssertTrue(server.requestedURLs.isEmpty)
    }

    func testRedirectToDisallowedHostIsRefusedAndNeverRequested() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/bounce"))
        server.register(
            url: url,
            status: 302,
            headers: ["Location": "https://169.254.169.254/latest/meta-data"],
            chunks: [],
        )

        await assertImportFails(url: url, with: .subscriptionUnavailable)
        XCTAssertFalse(
            server.requestedURLs.contains { $0.contains("169.254.169.254") },
            "the metadata host must never be contacted",
        )
    }

    func testRedirectToAllowedHostIsFollowed() async throws {
        let url = try XCTUnwrap(URL(string: "https://stub.invalid/moved"))
        let target = try XCTUnwrap(URL(string: "https://mirror.stub.invalid/sub"))
        server.register(url: url, status: 302, headers: ["Location": target.absoluteString], chunks: [])
        server.register(url: target, status: 200, chunks: [
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

/// One registry per test instance, shared between the test and the fetcher's serial queues.
private final class StubSubscriptionServer: @unchecked Sendable {
    struct Response: Sendable {
        var chunks: [Data]
        var started: XCTestExpectation?
        var stopped: XCTestExpectation?
        var beforeLastChunk: (@Sendable () -> Void)?
    }

    private let lock = NSLock()
    private var responses = [URL: Response]()
    private var releaseHandlers = [URL: @Sendable (Data) -> Void]()
    private var attempts = [(String, SubscriptionOrigin)]()
    private var sentRequests = [(URL, Data)]()
    private var failedAddresses = Set<String>()

    var requestedURLs: [String] {
        lock.withLock { sentRequests.map(\.0.absoluteString) }
    }

    var dialedAddresses: [String] {
        lock.withLock { attempts.map(\.0) }
    }

    var peerNames: [String] {
        lock.withLock { attempts.map(\.1.peerName) }
    }

    var lastRequest: String {
        lock.withLock { String(decoding: sentRequests.last?.1 ?? Data(), as: UTF8.self) }
    }

    func reset() {
        lock.withLock {
            responses.removeAll()
            releaseHandlers.removeAll()
            attempts.removeAll()
            sentRequests.removeAll()
            failedAddresses.removeAll()
        }
    }

    func fetch(_ request: URLRequest, timeout: TimeInterval = 5, resolve: @escaping SubscriptionFetcher.Resolver = { _ in ["1.1.1.1"] }) async throws -> Data {
        try await SubscriptionFetcher.fetch(request, timeout: timeout, resolve: resolve) { [self] address, origin in
            lock.withLock {
                attempts.append((address, origin))
                return StubSubscriptionConnection(
                    server: self, url: origin.url, response: responses[origin.url],
                    failOnStart: failedAddresses.contains(address),
                )
            }
        }
    }

    func register(url: URL, status: Int, headers: [String: String] = [:], chunks: [Data], beforeLastChunk: (@Sendable () -> Void)? = nil) {
        var fields = headers
        let useChunkFraming = fields["Content-Length"] == nil
        if useChunkFraming {
            fields["Transfer-Encoding"] = "chunked"
        }
        let lines = ["HTTP/1.1 \(status) Fixture"] + fields.map { "\($0.key): \($0.value)" }
        var wire = [Data((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8)]
        for chunk in chunks where !chunk.isEmpty {
            if useChunkFraming {
                wire.append(Data((String(chunk.count, radix: 16) + "\r\n").utf8))
            }
            wire.append(chunk)
            if useChunkFraming {
                wire.append(Data("\r\n".utf8))
            }
        }
        if useChunkFraming {
            wire.append(Data("0\r\n\r\n".utf8))
        }
        lock.withLock { responses[url] = Response(chunks: wire, beforeLastChunk: beforeLastChunk) }
    }

    func registerStalled(url: URL, started: XCTestExpectation, stopped: XCTestExpectation? = nil) {
        lock.withLock { responses[url] = Response(chunks: [], started: started, stopped: stopped) }
    }

    func failConnection(to address: String) {
        lock.withLock { _ = failedAddresses.insert(address) }
    }

    func recordRequest(_ request: Data, url: URL) {
        lock.withLock { sentRequests.append((url, request)) }
    }

    func stall(url: URL, release: @escaping @Sendable (Data) -> Void) {
        lock.withLock { releaseHandlers[url] = release }
    }

    func finishStalled(url: URL, body: String) {
        let resume = lock.withLock { releaseHandlers.removeValue(forKey: url) }
        resume?(Data("HTTP/1.1 200 OK\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)".utf8))
    }

    func cancel(url: URL) {
        lock.withLock { _ = releaseHandlers.removeValue(forKey: url) }
    }
}

/// The fetcher calls this socket on its serial queue. Each result is queued
/// asynchronously, matching Network.framework's callback contract.
private final class StubSubscriptionConnection: SubscriptionConnection, @unchecked Sendable {
    private let server: StubSubscriptionServer
    private let url: URL
    private let response: StubSubscriptionServer.Response?
    private let failOnStart: Bool
    private var queue: DispatchQueue!
    private var index = 0

    init(server: StubSubscriptionServer, url: URL, response: StubSubscriptionServer.Response?, failOnStart: Bool) {
        self.server = server
        self.url = url
        self.response = response
        self.failOnStart = failOnStart
    }

    func start(on queue: DispatchQueue, completion: @escaping @Sendable (Error?) -> Void) {
        self.queue = queue
        queue.async { [failOnStart, response] in
            completion(failOnStart || response == nil ? URLError(.cannotConnectToHost) : nil)
        }
    }

    func send(_ data: Data, completion: @escaping @Sendable (Error?) -> Void) {
        server.recordRequest(data, url: url)
        queue.async { completion(nil) }
    }

    func receive(_ completion: @escaping @Sendable (Data?, Bool, Error?) -> Void) {
        guard let response else {
            queue.async { completion(nil, true, URLError(.badServerResponse)) }
            return
        }
        if let started = response.started {
            let deliveryQueue = queue!
            server.stall(url: url) { data in deliveryQueue.async { completion(data, true, nil) } }
            started.fulfill()
            return
        }
        let chunk = response.chunks[index]
        index += 1
        let ended = index == response.chunks.count
        queue.async {
            if ended {
                response.beforeLastChunk?()
            }
            completion(chunk, ended, nil)
        }
    }

    func cancel() {
        server.cancel(url: url)
        response?.stopped?.fulfill()
    }
}
