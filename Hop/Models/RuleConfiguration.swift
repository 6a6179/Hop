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

    @discardableResult
    mutating func saveRule(_ rule: RoutingRule) -> Bool {
        if rule.kind == .final {
            guard !rules.contains(where: { $0.kind == .final && $0.id != rule.id }) else { return false }
            if let index = rules.firstIndex(where: { $0.id == rule.id && $0.kind == .final }) {
                rules[index] = rule
                return true
            }
            rules.removeAll { $0.id == rule.id }
            rules.append(rule)
        } else {
            if let index = rules.firstIndex(where: { $0.id == rule.id }) {
                rules[index] = rule
            } else {
                let final = rules.firstIndex { $0.kind == .final } ?? rules.endIndex
                rules.insert(rule, at: final)
            }
        }
        return true
    }

    mutating func prependImportedRules(_ imported: [RoutingRule]) {
        // Each list is first-match-wins. Rules following its own catch-all
        // were unreachable and must not become active through a merge.
        let incoming = imported.prefix { $0.kind != .final }
        if let fallback = imported.dropFirst(incoming.count).first {
            if let index = rules.firstIndex(where: { $0.kind == .final }) {
                // Keep any unreachable legacy rows behind the original fallback
                // position so an import never deletes or activates local edits.
                rules[index] = fallback
            } else {
                rules.append(fallback)
            }
        }
        rules.insert(contentsOf: incoming, at: 0)
    }
}

extension RuleConfiguration {
    static let defaultConfiguration = RuleConfiguration(name: "Default", rules: appleSystemBypassRules)
    static let builtInConfigurations = [defaultConfiguration, china(), iran()]

    /// Apple system services are intentionally direct in built-in presets so
    /// APNs, iCloud, captive-portal checks, updates, and Apple CDNs keep working
    /// even when the selected proxy is slow, blocked, or incompatible.
    static let appleSystemDomainSuffixes = [
        "push.apple.com",
        "apple.com",
        "icloud.com",
        "icloud-content.com",
        "me.com",
        "mzstatic.com",
        "aaplimg.com",
        "cdn-apple.com",
        "apple-dns.net",
        "apple-mapkit.com",
        "apple.news",
    ]

    static var appleSystemBypassRules: [RoutingRule] {
        [
            RoutingRule(
                kind: .domainSuffix,
                value: appleSystemDomainSuffixes.joined(separator: ", "),
                target: .direct,
            ),
        ]
    }

    func withAppleSystemBypassRule() -> RuleConfiguration {
        let requiredSuffixes = RuleConfiguration.appleSystemDomainSuffixes
        let requiredSet = Set(requiredSuffixes)

        var copy = self
        if let index = copy.rules.firstIndex(where: { rule in
            guard rule.kind == .domainSuffix, rule.target == .direct else { return false }
            return !Set(Self.domainSuffixes(from: rule.value)).isDisjoint(with: requiredSet)
        }) {
            let existingSuffixes = Self.domainSuffixes(from: copy.rules[index].value)
            guard !Set(existingSuffixes).isSuperset(of: requiredSet) else {
                return self
            }
            let existingExtras = existingSuffixes.filter { !requiredSet.contains($0) }
            copy.rules[index].value = (requiredSuffixes + existingExtras).joined(separator: ", ")
            return copy
        }

        let insertionIndex = copy.rules.firstIndex {
            $0.kind == .geoIP && $0.value == "private" && $0.target == .direct
        }.map { $0 + 1 } ?? min(2, copy.rules.count)
        copy.rules.insert(contentsOf: RuleConfiguration.appleSystemBypassRules, at: insertionIndex)
        return copy
    }

    /// Auto-generated "bypass China" configuration. The builder resolves
    /// destination IPs so the small verified GeoIP asset is sufficient without
    /// loading a multi-megabyte GeoSite database in the tunnel extension.
    static func china(id: UUID = UUID()) -> RuleConfiguration {
        RuleConfiguration(id: id, name: "China", rules: bypassRules(geoSite: nil, geoIP: "cn"))
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

    private static func bypassRules(geoSite: String?, geoIP: String) -> [RoutingRule] {
        [RoutingRule(kind: .geoIP, value: "private", target: .direct)]
            + appleSystemBypassRules
            + (geoSite.map { [RoutingRule(kind: .geoSite, value: $0, target: .direct)] } ?? [])
            + [RoutingRule(kind: .geoIP, value: geoIP, target: .direct)]
    }

    private static func domainSuffixes(from value: String) -> [String] {
        value
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            .filter { !$0.isEmpty }
    }
}
