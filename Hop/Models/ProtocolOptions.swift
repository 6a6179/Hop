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

struct WireGuardOptions: Hashable, Codable {
    var privateKey: String
    var peerPublicKey: String
    /// Optional peer pre-shared key (the `PresharedKey` of a wg peer). Stored
    /// in the Keychain like the private key; emitted as the endpoint peer's
    /// `pre_shared_key`. Decodes as nil from state saved by older builds.
    var preSharedKey: String? = nil
    var localAddress: [String]
}

struct AnyTLSOptions: Hashable, Codable {
    var password: String
}
