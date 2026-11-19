import Darwin
import Foundation
import Network
import NetworkExtension

struct TunnelDescriptor: Sendable {
    let fileDescriptor: Int32
    let interfaceName: String
    let selectionSummary: String
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

        let settings = XrayTunnelNetworkDefaults.makeNetworkSettings(
            dnsServers: dnsServers,
            mtu: mtu,
        )
        // Full-tunnel/kill-switch policy is configured on the app-owned
        // NETunnelProviderProtocol. NEPacketTunnelNetworkSettings has no
        // includeAllNetworks property; its default routes below provide the
        // matching data-plane configuration.
        _ = includeAllNetworks
        try Self.applyNetworkSettings(settings, to: provider)

        return try Self.networkExtensionTunnelDescriptor(providerName: provider.virtualInterface?.name)
    }

    func reset() {
        // NetworkExtension tears down the borrowed descriptor and settings.
        // Keeping reset explicit makes the service lifecycle intention clear.
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

    /// NetworkExtension exposes the interface name, while Xray needs its borrowed file descriptor.
    private static func networkExtensionTunnelDescriptor(providerName: String?) throws -> TunnelDescriptor {
        var nameBuffer = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        var descriptors: [String: Int32] = [:]
        for fd in Int32(3) ... Int32(1024) {
            guard let name = utunName(for: fd, buffer: &nameBuffer) else { continue }
            if name == providerName {
                return TunnelDescriptor(fileDescriptor: fd, interfaceName: name, selectionSummary: "provider interface")
            }
            if descriptors[name] == nil {
                descriptors[name] = fd
            }
        }
        let open = descriptors.keys.sorted().prefix(6).joined(separator: ",")
        if let providerName {
            let expected = isUTunName(providerName) ? providerName : "non-utun"
            throw HopTunnelError("No descriptor for provider interface \(expected) in 3...1024 (open utuns=\(descriptors.count) [\(open)])")
        }

        let addresses = utunAddressOwners()
        if addresses.matching.count == 1, let name = addresses.matching.first, let fd = descriptors[name] {
            return TunnelDescriptor(fileDescriptor: fd, interfaceName: name, selectionSummary: "provider address")
        }
        // Some iOS environments hide interface metadata. A single distinct utun is
        // usable only when there is no visible address evidence identifying another one.
        if descriptors.count == 1, let (name, fd) = descriptors.first, addresses.matching.isEmpty, !addresses.visible.contains(name) {
            return TunnelDescriptor(fileDescriptor: fd, interfaceName: name, selectionSummary: "sole utun, addresses unavailable")
        }
        let owners = addresses.matching.sorted().prefix(6).joined(separator: ",")
        throw HopTunnelError("Provider interface unavailable, open utuns=\(descriptors.count) [\(open)], configured address owners=\(addresses.matching.count) [\(owners)]")
    }

    private static func utunAddressOwners() -> (matching: Set<String>, visible: Set<String>) {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let head else { return ([], []) }
        defer { freeifaddrs(head) }

        var matching = Set<String>()
        var visible = Set<String>()
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        var next: UnsafeMutablePointer<ifaddrs>? = head
        while let entry = next?.pointee {
            next = entry.ifa_next
            guard let address = entry.ifa_addr, let rawName = entry.ifa_name else { continue }
            let family = Int32(address.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }
            let name = String(cString: rawName)
            guard isUTunName(name) else { continue }
            visible.insert(name)
            let status = getnameinfo(address, socklen_t(address.pointee.sa_len), &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST)
            guard status == 0 else { continue }
            let ip = buffer.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
            if ip == XrayTunnelNetworkDefaults.providerIPv4Address || ip == XrayTunnelNetworkDefaults.providerIPv6Address {
                matching.insert(name)
            }
        }
        return (matching, visible)
    }

    private static func isUTunName(_ name: String) -> Bool {
        let suffix = name.utf8.dropFirst(4)
        return name.hasPrefix("utun") && !suffix.isEmpty && name.utf8.count < Int(IFNAMSIZ) && suffix.allSatisfy { (48 ... 57).contains($0) }
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
        return isUTunName(name) ? name : nil
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
