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
    var localAddress: [String]
}

struct AnyTLSOptions: Hashable, Codable {
    var password: String
}
