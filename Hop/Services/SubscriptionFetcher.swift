import Foundation

/// Each hop resolves once. Only the resulting checked IPs reach the socket,
/// while Host, TLS SNI, and certificate verification use the original URL.
/// One deadline covers DNS, connection attempts, redirects and the whole body.
final class SubscriptionFetcher: @unchecked Sendable {
    typealias Resolver = @Sendable (String) -> [String]?
    typealias Connector = @Sendable (String, SubscriptionOrigin) throws -> any SubscriptionConnection

    private let queue = DispatchQueue(label: "cat.string.hop.subscription-fetch")
    private let resolve: Resolver
    private let connect: Connector
    private let deadline: DispatchTime
    private let cookies = URLSessionConfiguration.ephemeral.httpCookieStorage

    // All mutable state and all connection callbacks are serialized on queue.
    private var continuation: CheckedContinuation<Data, Error>?
    private var finished = false
    private var connection: (any SubscriptionConnection)?
    private var decoder = SubscriptionHTTPResponse()
    private var redirects = 0
    private var timeout: DispatchSourceTimer?
    private var fallback: DispatchWorkItem?

    private init(resolve: @escaping Resolver, connect: @escaping Connector, deadline: DispatchTime) {
        self.deadline = deadline
        self.resolve = resolve
        self.connect = connect
    }

    static func fetch(
        _ request: URLRequest,
        timeout: TimeInterval = ImportPolicy.subscriptionRequestTimeout,
        resolve: @escaping Resolver = { ImportPolicy.resolvedAddresses($0) },
        connect: @escaping Connector = { try SubscriptionTLSConnection(address: $0, origin: $1) },
    ) async throws -> Data {
        try Task.checkCancellation()
        guard let url = request.url else { throw ProxyLinkParseError.invalidURL }
        let origin = try SubscriptionOrigin(url)
        let duration = max(0, min(ImportPolicy.subscriptionRequestTimeout, timeout, request.timeoutInterval))
        let fetcher = SubscriptionFetcher(resolve: resolve, connect: connect, deadline: .now() + duration)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                fetcher.queue.async {
                    guard !fetcher.finished else { return continuation.resume(throwing: CancellationError()) }
                    fetcher.continuation = continuation
                    let expiry = DispatchSource.makeTimerSource(flags: .strict, queue: fetcher.queue)
                    expiry.setEventHandler { [weak fetcher] in fetcher?.finish(.failure(URLError(.timedOut))) }
                    expiry.schedule(deadline: fetcher.deadline, leeway: .nanoseconds(0))
                    fetcher.timeout = expiry
                    expiry.resume()
                    fetcher.startHop(origin)
                }
            }
        } onCancel: {
            fetcher.queue.async { fetcher.finish(.failure(CancellationError())) }
        }
    }

    private func startHop(_ origin: SubscriptionOrigin) {
        decoder = SubscriptionHTTPResponse()
        let resolve = resolve
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let result = Result { try ImportPolicy.subscriptionAddresses(for: origin.url, resolve: resolve) }
            guard let self else { return }
            queue.async {
                guard !self.finished else { return }
                switch result {
                case let .success(addresses): self.open(origin, addresses: addresses[...])
                case let .failure(error): self.finish(.failure(error))
                }
            }
        }
    }

    private func open(_ origin: SubscriptionOrigin, addresses: ArraySlice<String>) {
        do {
            guard DispatchTime.now() < deadline else { throw URLError(.timedOut) }
            guard let address = addresses.first else { throw URLError(.cannotConnectToHost) }
            let next = try connect(address, origin)
            connection = next
            if addresses.count > 1 {
                // A black-holed first address must leave time for the other family.
                let retry = DispatchWorkItem { [weak self, weak next] in
                    guard let self, let next, connection === next else { return }
                    closeConnection()
                    open(origin, addresses: addresses.dropFirst())
                }
                fallback = retry
                queue.asyncAfter(deadline: .now() + 3, execute: retry)
            }
            next.start(on: queue) { [weak self, weak next] error in
                guard let self, let next, connection === next else { return }
                fallback?.cancel()
                fallback = nil
                if let error {
                    closeConnection()
                    if addresses.count > 1 {
                        open(origin, addresses: addresses.dropFirst())
                    } else {
                        finish(.failure(error))
                    }
                    return
                }
                guard DispatchTime.now() < deadline else { return finish(.failure(URLError(.timedOut))) }
                next.send(requestData(for: origin)) { [weak self, weak next] error in
                    guard let self, let next, connection === next else { return }
                    if let error {
                        finish(.failure(error))
                    } else {
                        receive(from: next, origin: origin)
                    }
                }
            }
        } catch {
            finish(.failure(error))
        }
    }

    private func requestData(for origin: SubscriptionOrigin) -> Data {
        var fields = [
            "GET \(origin.requestTarget) HTTP/1.1", "Host: \(origin.authority)",
            "Accept: */*", "Accept-Encoding: gzip, deflate", "Connection: close",
            "User-Agent: Hop/\(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1")",
        ]
        if let components = URLComponents(url: origin.url, resolvingAgainstBaseURL: true), let user = components.user {
            let credentials = Data("\(user):\(components.password ?? "")".utf8).base64EncodedString()
            fields.append("Authorization: Basic " + credentials)
        }
        if let matches = cookies?.cookies(for: origin.url),
           let cookie = HTTPCookie.requestHeaderFields(with: matches)["Cookie"],
           !cookie.contains(where: \.isNewline)
        {
            fields.append("Cookie: " + cookie)
        }
        return Data((fields.joined(separator: "\r\n") + "\r\n\r\n").utf8)
    }

    private func receive(from socket: any SubscriptionConnection, origin: SubscriptionOrigin) {
        socket.receive { [weak self, weak socket] data, ended, error in
            guard let self, let socket, connection === socket else { return }
            if let error {
                return finish(.failure(error))
            }
            do {
                guard let result = try decoder.receive(data ?? Data(), endOfStream: ended) else {
                    return receive(from: socket, origin: origin)
                }
                switch result {
                case let .body(data):
                    finish(.success(data))
                case let .redirect(location):
                    guard redirects < 20, let url = URL(string: location, relativeTo: origin.url)?.absoluteURL,
                          let next = try? SubscriptionOrigin(url) else { throw ProxyLinkParseError.subscriptionUnavailable }
                    for line in decoder.setCookieHeaders {
                        let incoming = HTTPCookie.cookies(withResponseHeaderFields: ["Set-Cookie": line], for: origin.url)
                        cookies?.setCookies(incoming, for: origin.url, mainDocumentURL: origin.url)
                    }
                    redirects += 1
                    closeConnection()
                    startHop(next)
                }
            } catch {
                finish(.failure(error))
            }
        }
    }

    private func closeConnection() {
        fallback?.cancel()
        fallback = nil
        connection?.cancel()
        connection = nil
    }

    private func finish(_ result: Result<Data, Error>) {
        guard !finished else { return }
        finished = true
        timeout?.cancel()
        timeout = nil
        closeConnection()
        let pending = continuation
        continuation = nil
        // The OS can delay the timer's delivery while the device is busy or
        // suspended. A body processed after the deadline must still be rejected.
        if case .success = result, DispatchTime.now() >= deadline {
            pending?.resume(throwing: URLError(.timedOut))
        } else {
            pending?.resume(with: result)
        }
    }
}
