import Foundation
import Network
import Security

struct SubscriptionOrigin: Sendable {
    let url: URL
    let peerName: String
    let authority: String
    let port: NWEndpoint.Port
    let requestTarget: String

    init(_ url: URL) throws {
        try ImportPolicy.validateSubscriptionURL(url)
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true),
              let host = components.encodedHost, !host.isEmpty, host.utf8.allSatisfy({ (0x21 ... 0x7E).contains($0) }),
              let rawPort = UInt16(exactly: components.port ?? 443), rawPort != 0,
              let port = NWEndpoint.Port(rawValue: rawPort)
        else { throw ProxyLinkParseError.invalidURL }
        self.url = url
        peerName = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        authority = host + (components.port.map { ":\($0)" } ?? "")
        self.port = port
        requestTarget = (components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath)
            + (components.percentEncodedQuery.map { "?" + $0 } ?? "")
    }
}

/// This injection seam lets transfer tests deliver HTTP bytes without DNS or a socket.
protocol SubscriptionConnection: AnyObject, Sendable {
    func start(on queue: DispatchQueue, completion: @escaping @Sendable (Error?) -> Void)
    func send(_ data: Data, completion: @escaping @Sendable (Error?) -> Void)
    func receive(_ completion: @escaping @Sendable (Data?, Bool, Error?) -> Void)
    func cancel()
}

final class SubscriptionTLSConnection: SubscriptionConnection {
    private let socket: NWConnection

    init(address: String, origin: SubscriptionOrigin) throws {
        guard ImportPolicy.isPublicIPAddressLiteral(address) else { throw ProxyLinkParseError.disallowedSubscriptionHost }
        let host: NWEndpoint.Host
        if let ipv4 = IPv4Address(address) {
            host = .ipv4(ipv4)
        } else if let ipv6 = IPv6Address(address) {
            host = .ipv6(ipv6)
        } else {
            throw ProxyLinkParseError.disallowedSubscriptionHost
        }

        let tls = NWProtocolTLS.Options()
        let security = tls.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(security, .TLSv12)
        sec_protocol_options_append_tls_ciphersuite_group(security, .ats)
        sec_protocol_options_add_tls_application_protocol(security, "http/1.1")
        if !ImportPolicy.isIPAddressLiteral(origin.peerName) {
            sec_protocol_options_set_tls_server_name(security, origin.peerName)
        }
        let peerName = origin.peerName
        sec_protocol_options_set_verify_block(security, { _, trust, complete in
            let trust = sec_trust_copy_ref(trust).takeRetainedValue()
            let policy = SecPolicyCreateSSL(true, peerName as CFString)
            complete(SecTrustSetPolicies(trust, policy) == errSecSuccess && SecTrustEvaluateWithError(trust, nil))
        }, .global(qos: .utility))
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        parameters.preferNoProxies = true
        socket = NWConnection(host: host, port: origin.port, using: parameters)
    }

    func start(on queue: DispatchQueue, completion: @escaping @Sendable (Error?) -> Void) {
        socket.stateUpdateHandler = { [socket] state in
            switch state {
            case .ready:
                socket.stateUpdateHandler = nil
                completion(nil)
            case let .waiting(error), let .failed(error):
                socket.stateUpdateHandler = nil
                completion(error)
            default: break
            }
        }
        socket.start(queue: queue)
    }

    func send(_ data: Data, completion: @escaping @Sendable (Error?) -> Void) {
        socket.send(content: data, completion: .contentProcessed { completion($0) })
    }

    func receive(_ completion: @escaping @Sendable (Data?, Bool, Error?) -> Void) {
        socket.receive(minimumIncompleteLength: 1, maximumLength: 32 * 1024) { data, _, ended, error in completion(data, ended, error) }
    }

    func cancel() {
        socket.stateUpdateHandler = nil
        socket.cancel()
    }
}
