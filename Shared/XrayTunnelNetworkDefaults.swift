import Foundation

/// One deterministic point-to-point network shared by the app-side Xray
/// renderer and the packet-tunnel extension. Xray owns `.1`; iOS owns `.2`.
enum XrayTunnelNetworkDefaults {
    static let xrayIPv4Address = "172.19.0.1"
    static let providerIPv4Address = "172.19.0.2"
    static let ipv4Mask = "255.255.255.252"
    static let xrayIPv4CIDR = "\(xrayIPv4Address)/30"

    static let xrayIPv6Address = "fdfe:dcba:9876::1"
    static let providerIPv6Address = "fdfe:dcba:9876::2"
    static let ipv6PrefixLength = 126
    static let xrayIPv6CIDR = "\(xrayIPv6Address)/\(ipv6PrefixLength)"

    static let dnsServers = [xrayIPv4Address, xrayIPv6Address]
    static let mtu = 1500
}
