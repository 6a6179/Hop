import Foundation

enum RoutingMode: String, CaseIterable, Codable, Identifiable {
    case rule
    case global
    case direct

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .rule:
            "Rule"
        case .global:
            "Global"
        case .direct:
            "Direct"
        }
    }
}

enum RoutingRuleKind: String, CaseIterable, Codable, Identifiable {
    case final
    case domain
    case domainSuffix
    case domainKeyword
    case domainRegex
    case ipCIDR
    case ipIsPrivate
    case sourceIPCIDR
    case sourceIPIsPrivate
    case port
    case portRange
    case sourcePort
    case sourcePortRange
    case network
    case protocolSniff
    case geoSite
    case geoIP
    case sourceGeoIP
    case networkType
    case networkIsExpensive
    case networkIsConstrained
    case wifiSSID
    case wifiBSSID

    var id: String {
        rawValue
    }

    var displayName: String {
        switch self {
        case .final:
            "Final"
        case .domain:
            "Full Domain"
        case .domainSuffix:
            "Domain Suffix"
        case .domainKeyword:
            "Domain Keyword"
        case .domainRegex:
            "Domain Regex"
        case .ipCIDR:
            "IP CIDR"
        case .ipIsPrivate:
            "Private IP"
        case .sourceIPCIDR:
            "Source IP CIDR"
        case .sourceIPIsPrivate:
            "Private Source IP"
        case .port:
            "Port"
        case .portRange:
            "Port Range"
        case .sourcePort:
            "Source Port"
        case .sourcePortRange:
            "Source Port Range"
        case .network:
            "Network"
        case .protocolSniff:
            "Protocol"
        case .geoSite:
            "GeoSite"
        case .geoIP:
            "GeoIP"
        case .sourceGeoIP:
            "Source GeoIP"
        case .networkType:
            "Network Type"
        case .networkIsExpensive:
            "Expensive Network"
        case .networkIsConstrained:
            "Low Data Mode"
        case .wifiSSID:
            "Wi-Fi SSID"
        case .wifiBSSID:
            "Wi-Fi BSSID"
        }
    }

    var valuePrompt: String {
        switch self {
        case .final:
            "*"
        case .domain:
            "example.com"
        case .domainSuffix:
            "example.com"
        case .domainKeyword:
            "example"
        case .domainRegex:
            "^stun\\..+"
        case .ipCIDR:
            "10.0.0.0/8"
        case .ipIsPrivate:
            "true"
        case .sourceIPCIDR:
            "192.168.0.0/16"
        case .sourceIPIsPrivate:
            "true"
        case .port:
            "443"
        case .portRange:
            "1000:2000"
        case .sourcePort:
            "12345"
        case .sourcePortRange:
            "1000:2000"
        case .network:
            "tcp, udp"
        case .protocolSniff:
            "tls, http, quic"
        case .geoSite:
            VerifiedXrayGeodata.geoSiteCategories.sorted().joined(separator: ", ")
        case .geoIP:
            "private"
        case .sourceGeoIP:
            "private"
        case .networkType:
            "wifi, cellular"
        case .networkIsExpensive:
            "true"
        case .networkIsConstrained:
            "true"
        case .wifiSSID:
            "My Wi-Fi"
        case .wifiBSSID:
            "00:00:00:00:00:00"
        }
    }

    var defaultValue: String {
        switch self {
        case .final:
            "*"
        case .ipIsPrivate, .sourceIPIsPrivate, .networkIsExpensive, .networkIsConstrained:
            "true"
        default:
            ""
        }
    }

    var isAvailableInXray: Bool {
        switch self {
        case .networkType, .networkIsExpensive, .networkIsConstrained, .wifiSSID, .wifiBSSID: false
        default: true
        }
    }

    var sniffingRequirement: String? {
        switch self {
        case .protocolSniff:
            "Enable traffic sniffing in Settings to use protocol rules."
        case .domain, .domainSuffix, .domainKeyword, .domainRegex, .geoSite:
            "Enable traffic sniffing in Settings so the tunnel can match destination domains."
        default:
            nil
        }
    }

    var isBoolean: Bool {
        switch self {
        case .final:
            false
        case .ipIsPrivate, .sourceIPIsPrivate, .networkIsExpensive, .networkIsConstrained:
            true
        default:
            false
        }
    }

    var footerText: String {
        switch self {
        case .final:
            "Matches all remaining traffic. Keep last."
        case .domain:
            "Exact destination domain."
        case .domainSuffix:
            "Domain and subdomains."
        case .domainKeyword:
            "Keyword anywhere in the domain."
        case .domainRegex:
            "Domain regular expression."
        case .ipCIDR:
            "Destination IP range in CIDR notation."
        case .ipIsPrivate:
            "Non-public destination IPs."
        case .sourceIPCIDR:
            "Source IP range in CIDR notation."
        case .sourceIPIsPrivate:
            "Non-public source IPs."
        case .port:
            "Destination ports, comma-separated."
        case .portRange:
            "Destination ranges: 1000:2000, :3000, or 4000:."
        case .sourcePort:
            "Source ports, comma-separated."
        case .sourcePortRange:
            "Source ranges: 1000:2000, :3000, or 4000:."
        case .network:
            "tcp or udp, comma-separated."
        case .protocolSniff:
            "tls, http, or quic. Requires traffic sniffing."
        case .geoSite:
            "GeoSite category from local geodata."
        case .geoIP:
            "GeoIP category from local geodata."
        case .sourceGeoIP:
            "Source GeoIP category from local geodata."
        case .networkType:
            "Unavailable in Hop."
        case .networkIsExpensive:
            "Unavailable in Hop."
        case .networkIsConstrained:
            "Unavailable in Hop."
        case .wifiSSID:
            "Unavailable in Hop."
        case .wifiBSSID:
            "Unavailable in Hop."
        }
    }
}

struct RoutingRule: Identifiable, Hashable, Codable {
    var id: UUID
    var kind: RoutingRuleKind {
        didSet {
            if kind == .final {
                value = kind.defaultValue
            }
        }
    }

    var value: String {
        didSet {
            if kind == .final {
                value = kind.defaultValue
            }
        }
    }

    var target: OutboundTarget

    var matchDescription: String {
        kind == .final ? "All remaining traffic" : value
    }

    init(id: UUID = UUID(), kind: RoutingRuleKind, value: String, target: OutboundTarget) {
        self.id = id
        self.kind = kind
        self.value = kind == .final ? kind.defaultValue : value
        self.target = target
    }

    init(from decoder: Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            id: fields.decode(UUID.self, forKey: .id),
            kind: fields.decode(RoutingRuleKind.self, forKey: .kind),
            value: fields.decode(String.self, forKey: .value),
            target: fields.decode(OutboundTarget.self, forKey: .target),
        )
    }
}
