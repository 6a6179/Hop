import Foundation
import Network
import NetworkExtension

#if canImport(Libbox)
    import Libbox

    /// Bridges sing-box's `libbox` engine to iOS NetworkExtension APIs.
    ///
    /// libbox drives the tunnel through this object: it hands us the TUN
    /// configuration (`openTun`), asks about the default interface, and reports
    /// status. The method set here matches the sing-box **v1.13.12** libbox API
    /// (see `scripts/build-libbox.sh`); newer/older tags rename some of these,
    /// so the engine version and this file must move together.
    ///
    /// Modeled on sing-box-for-apple's `ExtensionPlatformInterface`, trimmed to
    /// what Hop needs (iOS, full-tunnel, no system-proxy / multi-platform paths).
    final class HopPlatformInterface: NSObject {
        private weak var provider: PacketTunnelProvider?
        private var networkSettings: NEPacketTunnelNetworkSettings?
        private var pathMonitor: NWPathMonitor?

        init(provider: PacketTunnelProvider) {
            self.provider = provider
        }

        /// Tear down monitors when the service stops; called from the provider.
        func reset() {
            networkSettings = nil
            pathMonitor?.cancel()
            pathMonitor = nil
        }
    }

    // MARK: - LibboxPlatformInterfaceProtocol

    extension HopPlatformInterface: LibboxPlatformInterfaceProtocol {
        func openTun(_ options: LibboxTunOptionsProtocol?, ret0_: UnsafeMutablePointer<Int32>?) throws {
            guard let options else { throw HopTunnelError("libbox passed nil tun options") }
            guard let ret0_ else { throw HopTunnelError("libbox passed nil return pointer") }
            guard let provider else { throw HopTunnelError("tunnel provider was deallocated") }

            let settings = try Self.makeNetworkSettings(from: options)
            networkSettings = settings

            try runBlocking {
                try await provider.setTunnelNetworkSettings(settings)
            }

            // The NEPacketTunnelFlow exposes the utun fd via KVC; fall back to
            // libbox's own loop-based lookup if Apple ever hides it.
            if let fd = provider.packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32 {
                ret0_.pointee = fd
                return
            }
            let loopFd = LibboxGetTunnelFileDescriptor()
            if loopFd != -1 {
                ret0_.pointee = loopFd
            } else {
                throw HopTunnelError("could not obtain the tun file descriptor")
            }
        }

        func clearDNSCache() {
            guard let provider, let networkSettings else { return }
            // Re-applying the settings flushes the system resolver cache.
            runBlocking {
                try? await provider.setTunnelNetworkSettings(nil)
                try? await provider.setTunnelNetworkSettings(networkSettings)
            }
        }

        func startDefaultInterfaceMonitor(_ listener: LibboxInterfaceUpdateListenerProtocol?) throws {
            guard let listener else { return }
            let monitor = NWPathMonitor()
            pathMonitor = monitor
            let semaphore = DispatchSemaphore(value: 0)
            monitor.pathUpdateHandler = { path in
                Self.notify(listener, of: path)
                semaphore.signal()
                monitor.pathUpdateHandler = { path in
                    Self.notify(listener, of: path)
                }
            }
            monitor.start(queue: .global())
            semaphore.wait()
        }

        func closeDefaultInterfaceMonitor(_: LibboxInterfaceUpdateListenerProtocol?) throws {
            pathMonitor?.cancel()
            pathMonitor = nil
        }

        func getInterfaces() throws -> LibboxNetworkInterfaceIteratorProtocol {
            guard let path = pathMonitor?.currentPath, path.status != .unsatisfied else {
                return NetworkInterfaceIterator([])
            }
            let interfaces = path.availableInterfaces.map { nwInterface -> LibboxNetworkInterface in
                let interface = LibboxNetworkInterface()
                interface.name = nwInterface.name
                interface.index = Int32(nwInterface.index)
                switch nwInterface.type {
                case .wifi:
                    interface.type = LibboxInterfaceTypeWIFI
                case .cellular:
                    interface.type = LibboxInterfaceTypeCellular
                case .wiredEthernet:
                    interface.type = LibboxInterfaceTypeEthernet
                default:
                    interface.type = LibboxInterfaceTypeOther
                }
                return interface
            }
            return NetworkInterfaceIterator(interfaces)
        }

        func findConnectionOwner(
            _: Int32,
            sourceAddress _: String?,
            sourcePort _: Int32,
            destinationAddress _: String?,
            destinationPort _: Int32,
        ) throws -> LibboxConnectionOwner {
            throw HopTunnelError("connection owner lookup is not supported on iOS")
        }

        func localDNSTransport() -> (any LibboxLocalDNSTransportProtocol)? {
            nil
        }

        func usePlatformAutoDetectControl() -> Bool {
            false
        }

        func autoDetectControl(_: Int32) throws {}
        func useProcFS() -> Bool {
            false
        }

        func underNetworkExtension() -> Bool {
            true
        }

        func includeAllNetworks() -> Bool {
            false
        }

        func readWIFIState() -> LibboxWIFIState? {
            nil
        }

        func systemCertificates() -> (any LibboxStringIteratorProtocol)? {
            nil
        }

        func send(_: LibboxNotification?) throws {}

        // MARK: Settings construction

        private static func makeNetworkSettings(from options: LibboxTunOptionsProtocol) throws -> NEPacketTunnelNetworkSettings {
            let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
            guard options.getAutoRoute() else {
                return settings
            }

            settings.mtu = NSNumber(value: options.getMTU())
            let dnsServer = try options.getDNSServerAddress()
            settings.dnsSettings = NEDNSSettings(servers: [dnsServer.value])

            var ipv4Addresses: [String] = []
            var ipv4Masks: [String] = []
            if let iterator = options.getInet4Address() {
                while iterator.hasNext() {
                    guard let prefix = iterator.next() else { break }
                    ipv4Addresses.append(prefix.address())
                    ipv4Masks.append(prefix.mask())
                }
            }
            if !ipv4Addresses.isEmpty {
                let ipv4 = NEIPv4Settings(addresses: ipv4Addresses, subnetMasks: ipv4Masks)
                ipv4.includedRoutes = includedIPv4Routes(options)
                ipv4.excludedRoutes = excludedIPv4Routes(options)
                settings.ipv4Settings = ipv4
            }

            var ipv6Addresses: [String] = []
            var ipv6Prefixes: [NSNumber] = []
            if let iterator = options.getInet6Address() {
                while iterator.hasNext() {
                    guard let prefix = iterator.next() else { break }
                    ipv6Addresses.append(prefix.address())
                    ipv6Prefixes.append(NSNumber(value: prefix.prefix()))
                }
            }
            if !ipv6Addresses.isEmpty {
                let ipv6 = NEIPv6Settings(addresses: ipv6Addresses, networkPrefixLengths: ipv6Prefixes)
                ipv6.includedRoutes = includedIPv6Routes(options)
                ipv6.excludedRoutes = excludedIPv6Routes(options)
                settings.ipv6Settings = ipv6
            }

            return settings
        }

        private static func includedIPv4Routes(_ options: LibboxTunOptionsProtocol) -> [NEIPv4Route] {
            guard let iterator = options.getInet4RouteAddress(), iterator.hasNext() else {
                return [NEIPv4Route.default()]
            }
            var routes: [NEIPv4Route] = []
            while iterator.hasNext() {
                guard let prefix = iterator.next() else { break }
                routes.append(NEIPv4Route(destinationAddress: prefix.address(), subnetMask: prefix.mask()))
            }
            return routes
        }

        private static func excludedIPv4Routes(_ options: LibboxTunOptionsProtocol) -> [NEIPv4Route] {
            guard let iterator = options.getInet4RouteExcludeAddress() else { return [] }
            var routes: [NEIPv4Route] = []
            while iterator.hasNext() {
                guard let prefix = iterator.next() else { break }
                routes.append(NEIPv4Route(destinationAddress: prefix.address(), subnetMask: prefix.mask()))
            }
            return routes
        }

        private static func includedIPv6Routes(_ options: LibboxTunOptionsProtocol) -> [NEIPv6Route] {
            guard let iterator = options.getInet6RouteAddress(), iterator.hasNext() else {
                return [NEIPv6Route.default()]
            }
            var routes: [NEIPv6Route] = []
            while iterator.hasNext() {
                guard let prefix = iterator.next() else { break }
                routes.append(NEIPv6Route(destinationAddress: prefix.address(), networkPrefixLength: NSNumber(value: prefix.prefix())))
            }
            return routes
        }

        private static func excludedIPv6Routes(_ options: LibboxTunOptionsProtocol) -> [NEIPv6Route] {
            guard let iterator = options.getInet6RouteExcludeAddress() else { return [] }
            var routes: [NEIPv6Route] = []
            while iterator.hasNext() {
                guard let prefix = iterator.next() else { break }
                routes.append(NEIPv6Route(destinationAddress: prefix.address(), networkPrefixLength: NSNumber(value: prefix.prefix())))
            }
            return routes
        }

        private static func notify(_ listener: LibboxInterfaceUpdateListenerProtocol, of path: Network.NWPath) {
            guard path.status != .unsatisfied, let primary = path.availableInterfaces.first else {
                listener.updateDefaultInterface("", interfaceIndex: -1, isExpensive: false, isConstrained: false)
                return
            }
            listener.updateDefaultInterface(
                primary.name,
                interfaceIndex: Int32(primary.index),
                isExpensive: path.isExpensive,
                isConstrained: path.isConstrained,
            )
        }
    }

    // MARK: - LibboxCommandServerHandlerProtocol

    extension HopPlatformInterface: LibboxCommandServerHandlerProtocol {
        func serviceStop() throws {
            provider?.stopService()
        }

        func serviceReload() throws {
            try provider?.reloadService()
        }

        func getSystemProxyStatus() throws -> LibboxSystemProxyStatus {
            // Hop runs a full TUN, not a system HTTP proxy.
            LibboxSystemProxyStatus()
        }

        func setSystemProxyEnabled(_: Bool) throws {}

        func writeDebugMessage(_ message: String?) {
            guard let message else { return }
            provider?.writeTunnelLog(message)
        }
    }

    // MARK: - Supporting types

    /// Adapts a Swift array to libbox's pull-style network-interface iterator.
    private final class NetworkInterfaceIterator: NSObject, LibboxNetworkInterfaceIteratorProtocol {
        private var iterator: IndexingIterator<[LibboxNetworkInterface]>
        private var current: LibboxNetworkInterface?

        init(_ interfaces: [LibboxNetworkInterface]) {
            iterator = interfaces.makeIterator()
        }

        func hasNext() -> Bool {
            current = iterator.next()
            return current != nil
        }

        func next() -> LibboxNetworkInterface? {
            current
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
#endif
