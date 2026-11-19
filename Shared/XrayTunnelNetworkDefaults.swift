import Darwin
import Foundation
import NetworkExtension

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

    static func makeNetworkSettings(dnsServers requestedServers: [String], mtu requestedMTU: Int) -> NEPacketTunnelNetworkSettings {
        // iOS excludes the tunnel server's IPv4 address from the default tunnel route.
        // Hop can dial multiple peers, so use a loopback placeholder and keep both
        // virtual DNS gateways reachable over the tunnel.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.mtu = NSNumber(value: clampedMTU(requestedMTU))

        let ipv4 = NEIPv4Settings(addresses: [providerIPv4Address], subnetMasks: [ipv4Mask])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4

        let ipv6 = NEIPv6Settings(addresses: [providerIPv6Address], networkPrefixLengths: [NSNumber(value: ipv6PrefixLength)])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6

        let servers = requestedServers.filter(isIPAddress)
        let dns = NEDNSSettings(servers: servers.isEmpty ? dnsServers : servers)
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        return settings
    }

    private static func isIPAddress(_ value: String) -> Bool {
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        return value.withCString {
            inet_pton(AF_INET, $0, &ipv4) == 1 || inet_pton(AF_INET6, $0, &ipv6) == 1
        }
    }

    static func clampedMTU(_ value: Int) -> Int {
        min(max(value, 1280), mtu)
    }
}
