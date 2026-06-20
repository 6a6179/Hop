import Foundation

enum OutboundTarget: Hashable, Codable, Identifiable {
    case selectedProxy
    case direct
    case reject
    case profile(ProxyProfile.ID)
    case group(ProxyGroup.ID)
    case named(String)

    var id: String {
        switch self {
        case .selectedProxy:
            "selected"
        case .direct:
            "direct"
        case .reject:
            "reject"
        case let .profile(id):
            "profile-\(id.uuidString)"
        case let .group(id):
            "group-\(id.uuidString)"
        case let .named(name):
            "named-\(name)"
        }
    }
}

enum ProxyGroupType: String, CaseIterable, Codable, Identifiable {
    case select
    case urlTest
    case unsupported

    var id: String {
        rawValue
    }

    var displayName: String {
        switch self {
        case .select:
            "Manual Select"
        case .urlTest:
            "URL Test"
        case .unsupported:
            "Unsupported"
        }
    }

    var singBoxType: String? {
        switch self {
        case .select:
            "selector"
        case .urlTest:
            "urltest"
        case .unsupported:
            nil
        }
    }
}

struct ProxyGroupTestOptions: Hashable, Codable {
    static let defaultURL = "https://www.gstatic.com/generate_204"

    var url: String
    var intervalSeconds: Int
    var toleranceMilliseconds: Int

    init(
        url: String = ProxyGroupTestOptions.defaultURL,
        intervalSeconds: Int = 600,
        toleranceMilliseconds: Int = 50,
    ) {
        self.url = url
        self.intervalSeconds = intervalSeconds
        self.toleranceMilliseconds = toleranceMilliseconds
    }
}

struct ProxyGroup: Identifiable, Hashable, Codable {
    var id: UUID
    var name: String
    var type: ProxyGroupType
    var members: [OutboundTarget]
    var defaultTarget: OutboundTarget?
    var testOptions: ProxyGroupTestOptions
    var isEnabled: Bool
    var importedType: String?
    var warning: String?
    var lastLatencyMilliseconds: Int?

    init(
        id: UUID = UUID(),
        name: String,
        type: ProxyGroupType,
        members: [OutboundTarget],
        defaultTarget: OutboundTarget? = nil,
        testOptions: ProxyGroupTestOptions = ProxyGroupTestOptions(),
        isEnabled: Bool = true,
        importedType: String? = nil,
        warning: String? = nil,
        lastLatencyMilliseconds: Int? = nil,
    ) {
        self.id = id
        self.name = name
        self.type = type
        self.members = members
        self.defaultTarget = defaultTarget
        self.testOptions = testOptions
        self.isEnabled = isEnabled
        self.importedType = importedType
        self.warning = warning
        self.lastLatencyMilliseconds = lastLatencyMilliseconds
    }
}

struct SubscriptionSource: Identifiable, Hashable, Codable {
    var id: UUID
    var name: String
    var url: String
    var lastUpdatedAt: Date?
    var lastImportSummary: String?

    init(
        id: UUID = UUID(),
        name: String,
        url: String,
        lastUpdatedAt: Date? = nil,
        lastImportSummary: String? = nil,
    ) {
        self.id = id
        self.name = name
        self.url = url
        self.lastUpdatedAt = lastUpdatedAt
        self.lastImportSummary = lastImportSummary
    }
}

struct ImportWarning: Identifiable, Hashable, Codable {
    var id: UUID
    var message: String

    init(id: UUID = UUID(), message: String) {
        self.id = id
        self.message = message
    }
}

struct ImportResult: Hashable, Codable {
    var profiles: [ProxyProfile]
    var groups: [ProxyGroup]
    var rules: [RoutingRule]
    var warnings: [ImportWarning]

    init(
        profiles: [ProxyProfile] = [],
        groups: [ProxyGroup] = [],
        rules: [RoutingRule] = [],
        warnings: [ImportWarning] = [],
    ) {
        self.profiles = profiles
        self.groups = groups
        self.rules = rules
        self.warnings = warnings
    }

    var isEmpty: Bool {
        profiles.isEmpty && groups.isEmpty && rules.isEmpty
    }

    /// Names of imported nodes that disable TLS certificate verification.
    /// Import UIs require an explicit confirmation before saving these — a
    /// share link or subscription can set `allow-insecure` and a dismissible
    /// warning row alone is too easy to save past.
    var insecureTLSProfileNames: [String] {
        profiles.filter { $0.security.tls?.allowInsecure == true }.map(\.name)
    }

    var summary: String {
        "\(profiles.count) nodes, \(groups.count) groups, \(rules.count) rules, \(warnings.count) warnings"
    }

    func markingProfiles(subscriptionID: SubscriptionSource.ID) -> ImportResult {
        var copy = self
        copy.profiles = profiles.map {
            var profile = $0
            profile.subscriptionID = subscriptionID
            return profile
        }
        return copy
    }

    func droppingRules() -> ImportResult {
        guard !rules.isEmpty else {
            return self
        }
        var copy = self
        copy.rules = []
        copy.warnings.append(ImportWarning(message: "Ignored \(rules.count) routing rule(s) from subscription data. Import rules manually to review and apply them."))
        return copy
    }

    /// Returns the result with every profile and group display name run
    /// through `ImportPolicy.sanitizeImportedName`. Applied at the import
    /// chokepoints so spoofable names (bidi overrides, invisible characters,
    /// unbounded length) never reach the UI or the insecure-TLS confirmation.
    /// Group member references by name are remapped to match.
    func sanitizingNames() -> ImportResult {
        var sanitized = self
        sanitized.profiles = profiles.map { profile in
            var profile = profile
            profile.name = ImportPolicy.sanitizeImportedName(profile.name, fallback: "Imported Node")
            return profile
        }
        sanitized.groups = groups.map { group in
            var group = group
            group.name = ImportPolicy.sanitizeImportedName(group.name, fallback: "Imported Group")
            group.members = group.members.map(Self.sanitizingNamedTarget)
            group.defaultTarget = group.defaultTarget.map(Self.sanitizingNamedTarget)
            return group
        }
        sanitized.rules = rules.map { rule in
            var rule = rule
            rule.target = Self.sanitizingNamedTarget(rule.target)
            return rule
        }
        return sanitized
    }

    /// Named targets resolve by display name at config-build time, so they
    /// must be sanitized identically to the names they reference.
    private static func sanitizingNamedTarget(_ target: OutboundTarget) -> OutboundTarget {
        guard case let .named(name) = target else {
            return target
        }
        return .named(ImportPolicy.sanitizeImportedName(name, fallback: "Imported"))
    }

    /// Bounds the number of imported items so a malicious payload cannot create
    /// an unbounded number of profiles/groups/rules. Profiles are kept first,
    /// then groups, then rules; anything beyond `maxItems` is dropped with a
    /// warning.
    func truncated(to maxItems: Int) -> ImportResult {
        let total = profiles.count + groups.count + rules.count
        guard total > maxItems else {
            return self
        }

        var budget = maxItems
        let keptProfiles = Array(profiles.prefix(budget))
        budget -= keptProfiles.count
        let keptGroups = Array(groups.prefix(max(0, budget)))
        budget -= keptGroups.count
        let keptRules = Array(rules.prefix(max(0, budget)))

        var trimmedWarnings = warnings
        trimmedWarnings.append(ImportWarning(message: "Import truncated to \(maxItems) items; \(total - maxItems) were dropped."))

        return ImportResult(profiles: keptProfiles, groups: keptGroups, rules: keptRules, warnings: trimmedWarnings)
    }
}
