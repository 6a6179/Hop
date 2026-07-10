import Foundation

/// Downloads a subscription body with the import policy enforced at the
/// transport layer:
///
/// - Every redirect target is re-applied to
///   `ImportPolicy.validateSubscriptionURL`, so a subscription server cannot
///   bounce the fetch to a cleartext or private/loopback/metadata destination
///   (SSRF, CWE-918). Refusing a redirect lets the task complete with the 3xx
///   response, which then fails the 2xx check below.
/// - The body is accumulated chunk-by-chunk and the transfer is cancelled the
///   moment it exceeds `ImportPolicy.maxPayloadBytes`, so a malicious server
///   can neither force a large allocation nor stream without bound. (A
///   chunk-level delegate replaces the previous per-byte `AsyncBytes` loop,
///   which paid an async-iterator hop and a `Data.append` per byte.)
/// - Non-2xx responses fail with `subscriptionUnavailable`.
///
/// One instance serves one fetch. State is guarded by a lock: delegate
/// callbacks arrive on the session's serial delegate queue while the
/// continuation is installed from the calling task — that handoff is the only
/// concurrency in this type, which is why `@unchecked Sendable` is sound here.
final class SubscriptionFetcher: NSObject, @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    private var received = Data()
    private var failure: Error?

    static func fetch(_ request: URLRequest, configuration: URLSessionConfiguration = .ephemeral) async throws -> Data {
        let fetcher = SubscriptionFetcher()
        let session = URLSession(configuration: configuration, delegate: fetcher, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        return try await withCheckedThrowingContinuation { continuation in
            fetcher.lock.lock()
            fetcher.continuation = continuation
            fetcher.lock.unlock()
            session.dataTask(with: request).resume()
        }
    }

    /// Records `error` as the fetch outcome (first failure wins) so the
    /// completion callback reports it instead of the generic cancellation the
    /// accompanying `cancel()` produces.
    private func fail(_ error: Error) {
        lock.lock()
        defer { lock.unlock() }
        if failure == nil {
            failure = error
        }
    }
}

extension SubscriptionFetcher: URLSessionDataDelegate {
    func urlSession(
        _: URLSession,
        task _: URLSessionTask,
        willPerformHTTPRedirection _: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void,
    ) {
        guard let url = request.url, (try? ImportPolicy.validateSubscriptionURL(url)) != nil else {
            completionHandler(nil)
            return
        }
        completionHandler(request)
    }

    func urlSession(
        _: URLSession,
        dataTask _: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void,
    ) {
        if let http = response as? HTTPURLResponse, !(200 ..< 300).contains(http.statusCode) {
            fail(ProxyLinkParseError.subscriptionUnavailable)
            completionHandler(.cancel)
            return
        }
        if response.expectedContentLength > Int64(ImportPolicy.maxPayloadBytes) {
            fail(ProxyLinkParseError.payloadTooLarge)
            completionHandler(.cancel)
            return
        }
        if response.expectedContentLength > 0 {
            // The declared length has already passed the hard cap above, so
            // reserving it avoids repeated growth/copies without trusting the
            // server with an unbounded allocation.
            lock.lock()
            received.reserveCapacity(Int(response.expectedContentLength))
            lock.unlock()
        }
        completionHandler(.allow)
    }

    func urlSession(_: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        let remaining = max(0, ImportPolicy.maxPayloadBytes - received.count)
        let exceeded = data.count > remaining
        if !exceeded {
            received.append(data)
        }
        lock.unlock()

        if exceeded {
            fail(ProxyLinkParseError.payloadTooLarge)
            dataTask.cancel()
        }
    }

    func urlSession(_: URLSession, task _: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock()
        let continuation = continuation
        self.continuation = nil
        let outcome: Result<Data, Error> = if let failure {
            .failure(failure)
        } else if let error {
            .failure(error)
        } else {
            .success(received)
        }
        lock.unlock()

        continuation?.resume(with: outcome)
    }
}
