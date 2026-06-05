enum ProxyProtocol: String, CaseIterable, Codable, Identifiable {
    case vless
    case trojan
    case hysteria2
    case tuic
    case shadowsocks
    case vmess
    case http
    case socks
    case wireGuard
    case anyTLS

    var id: String {
        rawValue
    }

    var displayName: String {
        switch self {
        case .vless:
            "VLESS"
        case .trojan:
            "Trojan"
        case .hysteria2:
            "Hysteria2"
        case .tuic:
            "TUIC"
        case .shadowsocks:
            "Shadowsocks"
        case .vmess:
            "VMess"
        case .http:
            "HTTP"
        case .socks:
            "SOCKS"
        case .wireGuard:
            "WireGuard"
        case .anyTLS:
            "AnyTLS"
        }
    }
}
