import Foundation

enum AppAppearance: String, CaseIterable, Codable, Identifiable {
    case system
    case light
    case dark

    var id: String {
        rawValue
    }

    var displayName: String {
        switch self {
        case .system:
            "System"
        case .light:
            "Light"
        case .dark:
            "Dark"
        }
    }
}

enum ConfigLogLevel: String, CaseIterable, Codable, Identifiable {
    case debug
    case info
    case warn
    case error

    var id: String {
        rawValue
    }

    var displayName: String {
        switch self {
        case .debug:
            "Debug"
        case .info:
            "Info"
        case .warn:
            "Warning"
        case .error:
            "Error"
        }
    }
}

enum DNSPreset: String, CaseIterable, Codable, Identifiable {
    case cloudflare
    case google
    case quad9
    case system

    var id: String {
        rawValue
    }

    var displayName: String {
        switch self {
        case .cloudflare:
            "Cloudflare"
        case .google:
            "Google"
        case .quad9:
            "Quad9"
        case .system:
            "System"
        }
    }
}

enum DNSStrategy: String, CaseIterable, Codable, Identifiable {
    case preferIPv4 = "prefer_ipv4"
    case preferIPv6 = "prefer_ipv6"
    case ipv4Only = "ipv4_only"
    case ipv6Only = "ipv6_only"

    var id: String {
        rawValue
    }

    var displayName: String {
        switch self {
        case .preferIPv4:
            "Prefer IPv4"
        case .preferIPv6:
            "Prefer IPv6"
        case .ipv4Only:
            "IPv4 Only"
        case .ipv6Only:
            "IPv6 Only"
        }
    }
}

enum LogRetention: Int, CaseIterable, Codable, Identifiable {
    case oneHundred = 100
    case fiveHundred = 500
    case oneThousand = 1000

    var id: Int {
        rawValue
    }

    var displayName: String {
        switch self {
        case .oneHundred:
            "100 entries"
        case .fiveHundred:
            "500 entries"
        case .oneThousand:
            "1,000 entries"
        }
    }
}

enum LatencyTestMethod: String, CaseIterable, Codable, Identifiable {
    case tcp
    case connect
    case icmp

    var id: String {
        rawValue
    }

    var displayName: String {
        switch self {
        case .tcp:
            "TCP"
        case .connect:
            "Connect (TLS)"
        case .icmp:
            "ICMP"
        }
    }

    var footnote: String {
        switch self {
        case .tcp:
            "Times a TCP handshake to the node's host and port. Best for TCP-based nodes."
        case .connect:
            "Times a TCP plus TLS handshake (falls back to TCP for nodes without TLS)."
        case .icmp:
            "Pings the node's host. Works for any protocol but may be blocked by some servers."
        }
    }
}

struct AppSettings: Hashable, Codable {
    var appearance: AppAppearance = .system
    var logLevel: ConfigLogLevel = .info
    var dnsPreset: DNSPreset = .cloudflare
    var dnsStrategy: DNSStrategy = .preferIPv4
    var proxyDNS: Bool = true
    var sniffTraffic: Bool = true
    var strictRoute: Bool = true
    /// Kill switch. When on, iOS forces all traffic through the tunnel and drops
    /// it if the extension dies, instead of failing open to the default network.
    var killSwitch: Bool = false
    /// On-demand VPN: iOS starts the tunnel automatically whenever the device
    /// has network access, and restarts it if it stops. Disabled (with the rule
    /// removed from the system configuration) by a manual disconnect so the
    /// user's explicit stop always wins.
    var connectOnDemand: Bool = false
    /// Refresh subscriptions that haven't updated within
    /// `AppSettings.subscriptionStaleness` when the app returns to the
    /// foreground. Off by default: an automatic fetch reveals the user's
    /// current IP to every subscription server without an explicit action.
    var autoRefreshSubscriptions: Bool = false
    var logRetention: LogRetention = .fiveHundred
    var latencyTestMethod: LatencyTestMethod = .tcp
    var xrayAdvanced: XrayAdvancedDocument? = nil

    /// Age beyond which a subscription counts as stale for foreground
    /// auto-refresh.
    static let subscriptionStaleness: TimeInterval = 24 * 60 * 60

    static let defaults = AppSettings()
}

extension AppSettings {
    /// Decode field-by-field so adding a new setting never invalidates state
    /// persisted by an older build (a missing key falls back to its default
    /// rather than failing the whole decode).
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let defaults = AppSettings.defaults
        appearance = try container.decodeIfPresent(AppAppearance.self, forKey: .appearance) ?? defaults.appearance
        logLevel = try container.decodeIfPresent(ConfigLogLevel.self, forKey: .logLevel) ?? defaults.logLevel
        dnsPreset = try container.decodeIfPresent(DNSPreset.self, forKey: .dnsPreset) ?? defaults.dnsPreset
        dnsStrategy = try container.decodeIfPresent(DNSStrategy.self, forKey: .dnsStrategy) ?? defaults.dnsStrategy
        proxyDNS = try container.decodeIfPresent(Bool.self, forKey: .proxyDNS) ?? defaults.proxyDNS
        sniffTraffic = try container.decodeIfPresent(Bool.self, forKey: .sniffTraffic) ?? defaults.sniffTraffic
        strictRoute = try container.decodeIfPresent(Bool.self, forKey: .strictRoute) ?? defaults.strictRoute
        killSwitch = try container.decodeIfPresent(Bool.self, forKey: .killSwitch) ?? defaults.killSwitch
        connectOnDemand = try container.decodeIfPresent(Bool.self, forKey: .connectOnDemand) ?? defaults.connectOnDemand
        autoRefreshSubscriptions = try container.decodeIfPresent(Bool.self, forKey: .autoRefreshSubscriptions) ?? defaults.autoRefreshSubscriptions
        logRetention = try container.decodeIfPresent(LogRetention.self, forKey: .logRetention) ?? defaults.logRetention
        latencyTestMethod = try container.decodeIfPresent(LatencyTestMethod.self, forKey: .latencyTestMethod) ?? defaults.latencyTestMethod
        xrayAdvanced = try container.decodeIfPresent(XrayAdvancedDocument.self, forKey: .xrayAdvanced)
    }
}
