import Foundation

/// A named, user-manageable routing configuration: a set of routing rules the
/// user can select, edit, and delete like a node. One configuration is active
/// at a time; its rules drive the tunnel when routing is in Rule mode.
struct RuleConfiguration: Identifiable, Hashable, Codable {
    var id: UUID
    var name: String
    var rules: [RoutingRule]

    init(id: UUID = UUID(), name: String, rules: [RoutingRule] = []) {
        self.id = id
        self.name = name
        self.rules = rules
    }
}

extension RuleConfiguration {
    /// Auto-generated "bypass China" configuration: connect directly to Chinese
    /// sites and IPs (and the LAN), send everything else through the selected
    /// outbound, and block ads.
    static func china(id: UUID = UUID()) -> RuleConfiguration {
        RuleConfiguration(id: id, name: "China", rules: bypassRules(geoSite: "cn", geoIP: "cn"))
    }

    /// Auto-generated "bypass Iran" configuration. Uses `geosite-category-ir`
    /// because `geosite-ir` does not exist in SagerNet's published rule-sets.
    static func iran(id: UUID = UUID()) -> RuleConfiguration {
        RuleConfiguration(id: id, name: "Iran", rules: bypassRules(geoSite: "category-ir", geoIP: "ir"))
    }

    /// Whether this configuration has no rules (it then proxies all matched
    /// traffic via the route's final outbound).
    var isEmpty: Bool {
        rules.isEmpty
    }

    private static func bypassRules(geoSite: String, geoIP: String) -> [RoutingRule] {
        [
            RoutingRule(kind: .geoSite, value: "category-ads-all", target: .reject),
            RoutingRule(kind: .geoIP, value: "private", target: .direct),
            RoutingRule(kind: .geoSite, value: geoSite, target: .direct),
            RoutingRule(kind: .geoIP, value: geoIP, target: .direct),
        ]
    }
}
