import Foundation
import Network
import Security

/// Outcome of a single node latency probe.
enum NodeLatencyResult: Equatable {
    case testing
    case success(Int) // milliseconds
    case failure(String)

    var milliseconds: Int? {
        if case let .success(value) = self {
            return value
        }
        return nil
    }
}

/// Measures how long it takes to reach a proxy node's server, using one of
/// three transport-level probes. None of these route through the tunnel; they
/// measure reachability of the node's endpoint from the device.
///
/// - `.tcp`: time to complete a TCP handshake to `host:port`.
/// - `.connect`: time to complete a TCP + TLS handshake (falls back to plain
///   TCP when the node has no TLS layer). Certificate validation is disabled
///   because this is a timing probe — no user data is sent — and proxy nodes
///   frequently use REALITY/uTLS that a stock TLS client cannot validate.
/// - `.icmp`: ICMP echo (ping) round-trip time to `host`.
struct LatencyTester {
    var timeout: TimeInterval = 5

    func measure(
        host: String,
        port: Int,
        serverName: String?,
        usesTLS: Bool,
        method: LatencyTestMethod,
    ) async -> NodeLatencyResult {
        switch method {
        case .tcp:
            return await measureConnection(host: host, port: port, tls: nil)
        case .connect:
            let tls = usesTLS ? Self.makeTLSOptions(serverName: serverName ?? host) : nil
            return await measureConnection(host: host, port: port, tls: tls)
        case .icmp:
            return await measureICMP(host: host)
        }
    }

    // MARK: - TCP / TLS

    private func measureConnection(host: String, port: Int, tls: NWProtocolTLS.Options?) async -> NodeLatencyResult {
        guard port > 0, port <= 65535, let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) else {
            return .failure("Invalid port")
        }

        return await withCheckedContinuation { continuation in
            let probe = ConnectionProbe(continuation: continuation)
            probe.start(host: host, port: nwPort, tls: tls, timeout: timeout)
        }
    }

    private static func makeTLSOptions(serverName: String) -> NWProtocolTLS.Options {
        let options = NWProtocolTLS.Options()
        let sec = options.securityProtocolOptions
        if !serverName.isEmpty {
            sec_protocol_options_set_tls_server_name(sec, serverName)
        }
        // Timing probe only — accept any certificate so REALITY/self-signed
        // nodes still report a handshake time.
        sec_protocol_options_set_verify_block(sec, { _, _, complete in complete(true) }, DispatchQueue.global())
        return options
    }

    // MARK: - ICMP

    private func measureICMP(host: String) async -> NodeLatencyResult {
        let timeout = timeout
        return await withCheckedContinuation { (continuation: CheckedContinuation<NodeLatencyResult, Never>) in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: Self.pingOnce(host: host, timeout: timeout))
            }
        }
    }

    private static func pingOnce(host: String, timeout: TimeInterval) -> NodeLatencyResult {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM

        var info: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &info) == 0, let resolved = info else {
            return .failure("Could not resolve host")
        }
        defer { freeaddrinfo(info) }

        let family = resolved.pointee.ai_family
        let isIPv6 = family == AF_INET6
        let proto = isIPv6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP

        let fd = socket(family, SOCK_DGRAM, proto)
        guard fd >= 0 else {
            return .failure("ICMP unavailable")
        }
        defer { close(fd) }

        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        let identifier = UInt16(truncatingIfNeeded: getpid())
        let sequence: UInt16 = 1
        let packet = icmpEchoRequest(isIPv6: isIPv6, identifier: identifier, sequence: sequence)

        let start = DispatchTime.now()
        let sent = packet.withUnsafeBytes { raw in
            sendto(fd, raw.baseAddress, raw.count, 0, resolved.pointee.ai_addr, resolved.pointee.ai_addrlen)
        }
        guard sent >= 0 else {
            return .failure("ICMP send failed")
        }

        var buffer = [UInt8](repeating: 0, count: 1024)
        let deadline = start.uptimeNanoseconds + UInt64(timeout * 1_000_000_000)
        while DispatchTime.now().uptimeNanoseconds < deadline {
            let received = recv(fd, &buffer, buffer.count, 0)
            if received <= 0 {
                break // timed out (SO_RCVTIMEO) or error
            }
            if isMatchingReply(Array(buffer.prefix(received)), isIPv6: isIPv6, identifier: identifier, sequence: sequence) {
                let elapsed = DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds
                return .success(max(Int(Double(elapsed) / 1_000_000), 0))
            }
        }
        return .failure("No reply")
    }

    // MARK: - ICMP packet helpers (exposed for testing)

    /// Standard 16-bit one's-complement Internet checksum (RFC 1071).
    static func internetChecksum(_ bytes: [UInt8]) -> UInt16 {
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
        return UInt16(~sum & 0xFFFF)
    }

    static func icmpEchoRequest(isIPv6: Bool, identifier: UInt16, sequence: UInt16) -> [UInt8] {
        var packet: [UInt8] = [
            isIPv6 ? 128 : 8, // type: echo request
            0, // code
            0, 0, // checksum (filled below for IPv4; kernel fills for IPv6)
            UInt8(identifier >> 8), UInt8(identifier & 0xFF),
            UInt8(sequence >> 8), UInt8(sequence & 0xFF),
        ]
        packet.append(contentsOf: Array("hop-latency-probe".utf8))

        if !isIPv6 {
            let checksum = internetChecksum(packet)
            packet[2] = UInt8(checksum >> 8)
            packet[3] = UInt8(checksum & 0xFF)
        }
        return packet
    }

    static func isMatchingReply(_ data: [UInt8], isIPv6: Bool, identifier: UInt16, sequence: UInt16) -> Bool {
        var offset = 0
        // An IPv4 datagram socket may hand back the IP header; skip it.
        if !isIPv6, let first = data.first, (first >> 4) == 4 {
            offset = Int(first & 0x0F) * 4
        }
        guard data.count >= offset + 8 else {
            return false
        }

        let expectedType: UInt8 = isIPv6 ? 129 : 0 // echo reply
        guard data[offset] == expectedType else {
            return false
        }

        let replyIdentifier = (UInt16(data[offset + 4]) << 8) | UInt16(data[offset + 5])
        let replySequence = (UInt16(data[offset + 6]) << 8) | UInt16(data[offset + 7])
        return replyIdentifier == identifier && replySequence == sequence
    }
}

/// Drives a single `NWConnection` probe and resolves a continuation exactly
/// once, from either the connection state handler or the timeout — both run on
/// the same serial queue, and a lock guards the one-shot resume.
private final class ConnectionProbe: @unchecked Sendable {
    private let continuation: CheckedContinuation<NodeLatencyResult, Never>
    private let queue = DispatchQueue(label: "cat.string.hop.latency")
    private let lock = NSLock()
    private var finished = false
    private var connection: NWConnection?
    private var start = DispatchTime.now()
    /// Keep the probe alive until it resolves; its handlers capture `self`
    /// weakly, and nothing else retains it once `measureConnection` returns.
    private var selfRetain: ConnectionProbe?

    init(continuation: CheckedContinuation<NodeLatencyResult, Never>) {
        self.continuation = continuation
    }

    func start(host: String, port: NWEndpoint.Port, tls: NWProtocolTLS.Options?, timeout: TimeInterval) {
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(host), port: port)
        let parameters = tls.map { NWParameters(tls: $0, tcp: NWProtocolTCP.Options()) } ?? NWParameters.tcp
        let connection = NWConnection(to: endpoint, using: parameters)
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else {
                return
            }
            switch state {
            case .ready:
                finish(.success(elapsedMilliseconds()))
            case let .failed(error):
                finish(.failure(error.localizedDescription))
            case let .waiting(error):
                finish(.failure(error.localizedDescription))
            default:
                break
            }
        }

        lock.lock()
        self.connection = connection
        selfRetain = self
        start = .now()
        lock.unlock()

        connection.start(queue: queue)
        // Always-firing backstop so the continuation resolves even if the
        // connection never reports a terminal state.
        queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
            self?.finish(.failure("Timed out"))
        }
    }

    private func elapsedMilliseconds() -> Int {
        let elapsed = DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds
        return max(Int(Double(elapsed) / 1_000_000), 0)
    }

    private func finish(_ result: NodeLatencyResult) {
        lock.lock()
        if finished {
            lock.unlock()
            return
        }
        finished = true
        let connection = connection
        self.connection = nil
        lock.unlock()

        connection?.stateUpdateHandler = nil
        connection?.cancel()
        continuation.resume(returning: result)
        selfRetain = nil
    }
}
