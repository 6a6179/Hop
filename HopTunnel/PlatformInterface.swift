import Darwin
import Foundation
import NetworkExtension

struct TunnelDescriptor: Sendable {
    let fileDescriptor: Int32
    let interfaceName: String
}

/// Applies the deterministic NetworkExtension configuration and locates the
/// system-owned utun descriptor consumed by Xray's native iOS TUN inbound.
/// The descriptor is borrowed: neither this adapter nor Xray may close it.
final class HopPlatformInterface {
    private weak var provider: NEPacketTunnelProvider?

    init(provider: NEPacketTunnelProvider) {
        self.provider = provider
    }

    func configure(dnsServers: [String], mtu: Int, includeAllNetworks: Bool) throws -> TunnelDescriptor {
        guard let provider else {
            throw HopTunnelError("tunnel provider was deallocated")
        }

        let settings = Self.makeNetworkSettings(
            dnsServers: dnsServers,
            mtu: mtu,
        )
        // Full-tunnel/kill-switch policy is configured on the app-owned
        // NETunnelProviderProtocol. NEPacketTunnelNetworkSettings has no
        // includeAllNetworks property; its default routes below provide the
        // matching data-plane configuration.
        _ = includeAllNetworks
        try Self.applyNetworkSettings(settings, to: provider)

        if let descriptor = Self.networkExtensionTunnelDescriptor() {
            return descriptor
        }
        throw HopTunnelError("could not find the NetworkExtension utun file descriptor after scanning descriptors 3...1024")
    }

    func reset() {
        // NetworkExtension tears down the borrowed descriptor and settings.
        // Keeping reset explicit makes the service lifecycle intention clear.
    }

    private static func makeNetworkSettings(
        dnsServers: [String],
        mtu: Int,
    ) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: XrayTunnelNetworkDefaults.xrayIPv4Address)
        settings.mtu = NSNumber(value: clampedMTU(mtu))

        let ipv4 = NEIPv4Settings(
            addresses: [XrayTunnelNetworkDefaults.providerIPv4Address],
            subnetMasks: [XrayTunnelNetworkDefaults.ipv4Mask],
        )
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4

        let ipv6 = NEIPv6Settings(
            addresses: [XrayTunnelNetworkDefaults.providerIPv6Address],
            networkPrefixLengths: [NSNumber(value: XrayTunnelNetworkDefaults.ipv6PrefixLength)],
        )
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6

        let requestedDNS = dnsServers.filter(Self.isIPAddress)
        let dns = NEDNSSettings(servers: requestedDNS.isEmpty ? XrayTunnelNetworkDefaults.dnsServers : requestedDNS)
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
        min(max(value, 1280), XrayTunnelNetworkDefaults.mtu)
    }

    private static func applyNetworkSettings(
        _ settings: NEPacketTunnelNetworkSettings,
        to provider: NEPacketTunnelProvider,
    ) throws {
        let result = NetworkSettingsResult()
        let semaphore = DispatchSemaphore(value: 0)
        provider.setTunnelNetworkSettings(settings) { error in
            result.set(error.map(Result.failure) ?? .success(()))
            semaphore.signal()
        }

        guard semaphore.wait(timeout: .now() + .seconds(10)) == .success else {
            throw HopTunnelError("timed out applying tunnel network settings")
        }
        try result.get()
    }

    /// NetworkExtension does not expose its utun descriptor as public API, and
    /// the old `packetFlow.socket.fileDescriptor` KVC path returns nil on
    /// modern iOS. Xray v26.6.27's own iOS integration guide specifies this
    /// bounded getsockopt lookup after `setTunnelNetworkSettings` completes.
    private static func networkExtensionTunnelDescriptor() -> TunnelDescriptor? {
        var nameBuffer = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        for fd in Int32(3) ... Int32(1024) {
            if let name = utunName(for: fd, buffer: &nameBuffer) {
                return TunnelDescriptor(fileDescriptor: fd, interfaceName: name)
            }
        }
        return nil
    }

    private static func utunName(for fd: Int32, buffer: inout [CChar]) -> String? {
        var length = socklen_t(buffer.count)
        // SYSPROTO_CONTROL = 2 and UTUN_OPT_IFNAME = 2. These constants are
        // used by Xray's own Darwin fd discovery example but are not public
        // NetworkExtension API.
        let result = buffer.withUnsafeMutableBytes { bytes in
            getsockopt(fd, 2, 2, bytes.baseAddress, &length)
        }
        guard result == 0 else { return nil }
        let byteCount = min(Int(length), buffer.count)
        let name = buffer.withUnsafeBufferPointer { pointer in
            let bytes = UnsafeRawBufferPointer(pointer).prefix(byteCount)
            let end = bytes.firstIndex(of: 0) ?? bytes.endIndex
            return String(decoding: bytes[..<end], as: UTF8.self)
        }
        return name.hasPrefix("utun") ? name : nil
    }
}

private final class NetworkSettingsResult: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<Void, Error>?

    func set(_ result: Result<Void, Error>) {
        lock.lock()
        self.result = result
        lock.unlock()
    }

    func get() throws {
        lock.lock()
        defer { lock.unlock() }
        guard let result else {
            throw HopTunnelError("setTunnelNetworkSettings completed without a result")
        }
        try result.get()
    }
}

struct HopTunnelError: LocalizedError {
    let message: String

    init(_ message: String) {
        self.message = message
    }

    var errorDescription: String? {
        message
    }
}
