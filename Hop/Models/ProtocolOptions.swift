import Foundation

enum ProtocolOptions: Hashable, Codable {
    case vless(VLESSOptions)
    case trojan(TrojanOptions)
    case hysteria2(Hysteria2Options)
    case tuic(TUICOptions)
    case shadowsocks(ShadowsocksOptions)
    case vmess(VMessOptions)
    case http(HTTPOptions)
    case socks(SOCKSOptions)
    case wireGuard(WireGuardOptions)
    case anyTLS(AnyTLSOptions)

    var proto: ProxyProtocol {
        switch self {
        case .vless:
            .vless
        case .trojan:
            .trojan
        case .hysteria2:
            .hysteria2
        case .tuic:
            .tuic
        case .shadowsocks:
            .shadowsocks
        case .vmess:
            .vmess
        case .http:
            .http
        case .socks:
            .socks
        case .wireGuard:
            .wireGuard
        case .anyTLS:
            .anyTLS
        }
    }
}

struct VLESSOptions: Hashable, Codable {
    var uuid: String
    var flow: String?
    var encryption: String? = nil
}

extension VLESSOptions {
    var normalizedEncryption: String? {
        guard let encryption else { return nil }
        let trimmed = encryption.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.lowercased() != "none" else {
            return nil
        }
        return trimmed
    }

    var encryptionAuthLabel: String {
        guard let normalizedEncryption else {
            return "None"
        }

        if normalizedEncryption.lowercased().hasPrefix("mlkem768x25519plus.") {
            switch lastRawBase64URLBlockByteCount(in: normalizedEncryption) {
            case 1184:
                return "ML-KEM-768 auth"
            case 32:
                return "X25519 auth"
            default:
                return "ML-KEM/X25519 auth"
            }
        }

        return "Custom VLESS Encryption"
    }

    var shouldRewriteEncryptionSecret: Bool {
        guard let encryption else { return false }
        return encryption.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() != "none"
    }

    private func lastRawBase64URLBlockByteCount(in value: String) -> Int? {
        value
            .split(separator: ".")
            .reversed()
            .lazy
            .compactMap { rawBase64URLDecodedByteCount(String($0)) }
            .first
    }

    private func rawBase64URLDecodedByteCount(_ value: String) -> Int? {
        guard !value.isEmpty else { return nil }
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = (4 - base64.count % 4) % 4
        if padding < 4 {
            base64.append(String(repeating: "=", count: padding))
        }
        return Data(base64Encoded: base64)?.count
    }
}

struct TrojanOptions: Hashable, Codable {
    var password: String
}

struct Hysteria2Options: Hashable, Codable {
    var password: String
    var obfs: String?
    var obfsPassword: String?
    var up: String? = nil
    var down: String? = nil
    var ports: String? = nil
    var hopIntervalSeconds: Int? = nil
    var udpIdleTimeoutSeconds: Int? = nil
}

struct TUICOptions: Hashable, Codable {
    var uuid: String
    var password: String
    var congestionControl: String?
}

struct ShadowsocksOptions: Hashable, Codable {
    var method: String
    var password: String
}

struct VMessOptions: Hashable, Codable {
    var uuid: String
    var security: String
    var alterID: Int
}

struct HTTPOptions: Hashable, Codable {
    var username: String?
    var password: String?
}

struct SOCKSOptions: Hashable, Codable {
    var username: String?
    var password: String?
}

/// One Xray WireGuard peer. `id` is persisted so each peer's optional
/// pre-shared key has a stable, distinct Keychain account even when peers are
/// edited or shared between Hop installations.
struct WireGuardPeer: Identifiable, Hashable, Codable {
    var id: UUID
    var publicKey: String
    /// `nil` uses the profile endpoint, preserving the original one-peer model.
    var endpoint: Endpoint?
    var preSharedKey: String?
    var allowedIPs: [String]?
    var keepAliveSeconds: Int?

    init(
        id: UUID = UUID(),
        publicKey: String,
        endpoint: Endpoint? = nil,
        preSharedKey: String? = nil,
        allowedIPs: [String]? = nil,
        keepAliveSeconds: Int? = nil,
    ) {
        self.id = id
        self.publicKey = publicKey
        self.endpoint = endpoint
        self.preSharedKey = preSharedKey
        self.allowedIPs = allowedIPs
        self.keepAliveSeconds = keepAliveSeconds
    }

    var preSharedKeyFieldRaw: String {
        "preSharedKey.peer.\(id.uuidString.lowercased())"
    }
}

struct WireGuardOptions: Hashable, Codable {
    var privateKey: String
    // Legacy first-peer fields stay decodable so existing saved profiles and
    // wireguard:// links continue to work. New multi-peer profiles use `peers`.
    var peerPublicKey: String
    var preSharedKey: String? = nil
    var localAddress: [String]
    var allowedIPs: [String]? = nil
    var reserved: [UInt8]? = nil
    var keepAliveSeconds: Int? = nil
    var mtu: Int? = nil
    var domainStrategy: String? = nil
    /// `nil` means the legacy first-peer fields above. Keeping this optional
    /// makes synthesized Codable backward compatible with pre-migration state.
    var peers: [WireGuardPeer]? = nil
}

extension WireGuardOptions {
    var effectivePeers: [WireGuardPeer] {
        if let peers, !peers.isEmpty {
            return peers
        }
        return [WireGuardPeer(
            publicKey: peerPublicKey,
            preSharedKey: preSharedKey,
            allowedIPs: allowedIPs,
            keepAliveSeconds: keepAliveSeconds,
        )]
    }
}

struct AnyTLSOptions: Hashable, Codable {
    var password: String
}
