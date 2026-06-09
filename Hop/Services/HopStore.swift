import Foundation
import Observation

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
    var logRetention: LogRetention = .fiveHundred
    var latencyTestMethod: LatencyTestMethod = .tcp

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
        logRetention = try container.decodeIfPresent(LogRetention.self, forKey: .logRetention) ?? defaults.logRetention
        latencyTestMethod = try container.decodeIfPresent(LatencyTestMethod.self, forKey: .latencyTestMethod) ?? defaults.latencyTestMethod
    }
}

@MainActor
@Observable
final class HopStore {
    var profiles: [ProxyProfile] {
        didSet {
            persist()
        }
    }

    var groups: [ProxyGroup] {
        didSet {
            persist()
        }
    }

    var subscriptions: [SubscriptionSource] {
        didSet {
            persist()
        }
    }

    var ruleConfigurations: [RuleConfiguration] {
        didSet {
            persist()
        }
    }

    var activeRuleConfigurationID: RuleConfiguration.ID? {
        didSet {
            persist()
        }
    }

    var routingMode: RoutingMode {
        didSet {
            persist()
        }
    }

    var selectedTarget: OutboundTarget? {
        didSet {
            persist()
        }
    }

    var settings: AppSettings {
        didSet {
            tunnel.maximumLogEntries = settings.logRetention.rawValue
            persist()
        }
    }

    var tunnel: TunnelController

    /// Transient per-node latency probe results, keyed by profile id. Not
    /// persisted — latency is only meaningful for the current session.
    var nodeLatencies: [ProxyProfile.ID: NodeLatencyResult] = [:]

    private let dataStore: HopAppDataStore
    private let latencyTester = LatencyTester()
    @ObservationIgnored private var logPersistTask: Task<Void, Never>?

    init(
        profiles: [ProxyProfile]? = nil,
        groups: [ProxyGroup]? = nil,
        subscriptions: [SubscriptionSource]? = nil,
        ruleConfigurations: [RuleConfiguration]? = nil,
        activeRuleConfigurationID: RuleConfiguration.ID? = nil,
        routingMode: RoutingMode? = nil,
        selectedTarget: OutboundTarget? = nil,
        settings: AppSettings? = nil,
        tunnel: TunnelController? = nil,
        dataStore: HopAppDataStore = HopAppDataStore(),
    ) {
        self.dataStore = dataStore

        let loaded = dataStore.load()
        self.profiles = profiles ?? loaded?.profiles ?? SampleData.profiles
        self.groups = groups ?? loaded?.groups ?? SampleData.groups
        self.subscriptions = subscriptions ?? loaded?.subscriptions ?? SampleData.subscriptions

        // Resolve named rule configurations, migrating legacy single-list state
        // (and always seeding the auto-generated China/Iran configs).
        let resolved = Self.resolveConfigurations(
            explicit: ruleConfigurations,
            explicitActiveID: activeRuleConfigurationID,
            loaded: loaded,
        )
        self.ruleConfigurations = resolved.configurations
        self.activeRuleConfigurationID = resolved.activeID

        self.routingMode = routingMode ?? loaded?.routingMode ?? .rule
        self.selectedTarget = selectedTarget ?? loaded?.selectedTarget ?? .group(SampleData.proxyGroup.id)
        self.settings = settings ?? loaded?.settings ?? .defaults
        self.tunnel = tunnel ?? TunnelController(logs: loaded?.logs ?? SampleData.logs)
        self.tunnel.maximumLogEntries = self.settings.logRetention.rawValue
        self.tunnel.onLogsChanged = { [weak self] in
            self?.scheduleLogPersist()
        }
        normalizeSelectedTarget()

        // Persist once if we upgraded an existing file from legacy rules, so the
        // migrated configuration IDs are stable across launches.
        if resolved.didMigrate {
            persist()
        }
    }

    private static func resolveConfigurations(
        explicit: [RuleConfiguration]?,
        explicitActiveID: RuleConfiguration.ID?,
        loaded: HopAppData?,
    ) -> (configurations: [RuleConfiguration], activeID: RuleConfiguration.ID?, didMigrate: Bool) {
        if let explicit {
            return (explicit, explicitActiveID ?? explicit.first?.id, false)
        }
        if let configs = loaded?.ruleConfigurations, !configs.isEmpty {
            let migrated = migrateGeneratedConfigurations(configs)
            let activeID = loaded?.activeRuleConfigurationID ?? configs.first?.id
            return (migrated.configurations, activeID, migrated.didMigrate)
        }
        if let legacy = loaded?.rules, !legacy.isEmpty {
            // Upgrade pre-configurations state: keep the user's rules as "Custom"
            // and add the auto-generated bypass configs.
            let custom = RuleConfiguration(name: "Custom", rules: legacy)
            return ([custom, .china(), .iran()], custom.id, true)
        }
        return (SampleData.ruleConfigurations, SampleData.defaultConfiguration.id, false)
    }

    private static func migrateGeneratedConfigurations(
        _ configurations: [RuleConfiguration],
    ) -> (configurations: [RuleConfiguration], didMigrate: Bool) {
        var didMigrate = false
        let migrated = configurations.map { configuration in
            guard ["Default", "China", "Iran"].contains(configuration.name) else {
                return configuration
            }
            let updated = configuration.withAppleSystemBypassRule()
            didMigrate = didMigrate || updated != configuration
            return updated
        }
        return (migrated, didMigrate)
    }

    var selectedProfile: ProxyProfile? {
        get {
            if case let .profile(id) = selectedTarget {
                return profiles.first { $0.id == id } ?? profiles.first
            }
            return profiles.first
        }
        set {
            selectedTarget = newValue.map { .profile($0.id) }
        }
    }

    var selectedGroup: ProxyGroup? {
        guard case let .group(id) = selectedTarget else {
            return nil
        }
        return groups.first { $0.id == id }
    }

    var selectedTargetDisplayName: String {
        displayName(for: selectedTarget ?? defaultTarget)
    }

    var defaultTarget: OutboundTarget {
        if let firstGroup = groups.first(where: \.isEnabled) {
            return .group(firstGroup.id)
        }
        if let firstProfile = profiles.first {
            return .profile(firstProfile.id)
        }
        return .direct
    }

    /// The currently selected rule configuration, if any.
    var activeRuleConfiguration: RuleConfiguration? {
        ruleConfigurations.first { $0.id == activeRuleConfigurationID }
    }

    /// Rules of the active configuration; consumed by the tunnel/config builder
    /// when routing is in Rule mode.
    var rules: [RoutingRule] {
        activeRuleConfiguration?.rules ?? []
    }

    func displayName(for target: OutboundTarget) -> String {
        switch target {
        case .selectedProxy:
            "Active"
        case .direct:
            "Direct"
        case .reject:
            "Reject"
        case let .profile(id):
            profiles.first { $0.id == id }?.name ?? "Missing Node"
        case let .group(id):
            groups.first { $0.id == id }?.name ?? "Missing Group"
        case let .named(name):
            name
        }
    }

    func addProfile(_ profile: ProxyProfile) {
        profiles.insert(profile, at: 0)
        selectedTarget = .profile(profile.id)
    }

    func updateProfile(_ profile: ProxyProfile) {
        guard let index = profiles.firstIndex(where: { $0.id == profile.id }) else {
            return
        }
        profiles[index] = profile
    }

    func deleteProfile(id: ProxyProfile.ID) {
        profiles.removeAll { $0.id == id }
        nodeLatencies[id] = nil
        groups = groups.map { group in
            var group = group
            group.members.removeAll { $0 == .profile(id) }
            if group.defaultTarget == .profile(id) {
                group.defaultTarget = group.members.first
            }
            return group
        }
        normalizeSelectedTarget()
    }

    func addGroup(_ group: ProxyGroup) {
        groups.insert(group, at: 0)
        selectedTarget = .group(group.id)
    }

    func updateGroup(_ group: ProxyGroup) {
        guard let index = groups.firstIndex(where: { $0.id == group.id }) else {
            return
        }
        groups[index] = group
        normalizeSelectedTarget()
    }

    func deleteGroup(id: ProxyGroup.ID) {
        groups.removeAll { $0.id == id }
        for index in groups.indices {
            groups[index].members.removeAll { $0 == .group(id) }
            if groups[index].defaultTarget == .group(id) {
                groups[index].defaultTarget = groups[index].members.first
            }
        }
        normalizeSelectedTarget()
    }

    func addSubscription(_ subscription: SubscriptionSource) {
        subscriptions.insert(subscription, at: 0)
    }

    func updateSubscription(_ subscription: SubscriptionSource) {
        guard let index = subscriptions.firstIndex(where: { $0.id == subscription.id }) else {
            return
        }
        subscriptions[index] = subscription
    }

    func deleteSubscription(id: SubscriptionSource.ID) {
        subscriptions.removeAll { $0.id == id }
    }

    func selectRuleConfiguration(id: RuleConfiguration.ID) {
        guard ruleConfigurations.contains(where: { $0.id == id }) else {
            return
        }
        activeRuleConfigurationID = id
        // Selecting a rule configuration implies rule-based routing; Global/Direct
        // remain available from the Dashboard.
        routingMode = .rule
    }

    func addRuleConfiguration(_ configuration: RuleConfiguration) {
        ruleConfigurations.insert(configuration, at: 0)
        activeRuleConfigurationID = configuration.id
        routingMode = .rule
    }

    func updateRuleConfiguration(_ configuration: RuleConfiguration) {
        guard let index = ruleConfigurations.firstIndex(where: { $0.id == configuration.id }) else {
            return
        }
        ruleConfigurations[index] = configuration
    }

    func deleteRuleConfiguration(id: RuleConfiguration.ID) {
        ruleConfigurations.removeAll { $0.id == id }
        if activeRuleConfigurationID == id {
            activeRuleConfigurationID = ruleConfigurations.first?.id
        }
    }

    func applyImport(_ result: ImportResult) {
        guard !result.isEmpty else {
            tunnel.appendLog("Import skipped: no runnable items found")
            return
        }

        profiles.insert(contentsOf: result.profiles, at: 0)
        groups.insert(contentsOf: result.groups, at: 0)
        applyImportedRules(result.rules, deduplicate: false)
        selectedTarget = result.groups.first(where: \.isEnabled).map { .group($0.id) } ?? result.profiles.first.map { .profile($0.id) } ?? selectedTarget
        normalizeSelectedTarget()
        tunnel.appendLog("Imported \(result.summary)")
        for warning in result.warnings.prefix(5) {
            tunnel.appendLog("Import warning: \(warning.message)")
        }
    }

    func applySubscriptionRefresh(_ result: ImportResult) {
        guard !result.isEmpty else {
            tunnel.appendLog("Subscription refresh skipped: no runnable items found")
            return
        }

        var importedProfileIDMap: [ProxyProfile.ID: ProxyProfile.ID] = [:]
        var replacedProfileIDMap: [ProxyProfile.ID: ProxyProfile.ID] = [:]

        for importedProfile in result.profiles {
            let exactMatches = profileIndices(matchingIdentityOf: importedProfile)
            let matchingIndices = exactMatches.isEmpty ? profileIndices(matchingNameAndProtocolOf: importedProfile) : exactMatches

            if let profileIndex = preferredProfileIndex(from: matchingIndices) {
                var updatedProfile = importedProfile
                updatedProfile.id = profiles[profileIndex].id
                profiles[profileIndex] = updatedProfile
                importedProfileIDMap[importedProfile.id] = updatedProfile.id

                if !exactMatches.isEmpty {
                    for duplicateIndex in matchingIndices where duplicateIndex != profileIndex {
                        replacedProfileIDMap[profiles[duplicateIndex].id] = updatedProfile.id
                    }
                }
            } else {
                profiles.insert(importedProfile, at: 0)
                importedProfileIDMap[importedProfile.id] = importedProfile.id
            }
        }

        if !replacedProfileIDMap.isEmpty {
            let removedIDs = Set(replacedProfileIDMap.keys)
            profiles.removeAll { removedIDs.contains($0.id) }
            replaceTargetReferences(profileIDMap: replacedProfileIDMap)
        }

        var importedGroupIDMap: [ProxyGroup.ID: ProxyGroup.ID] = [:]
        var replacedGroupIDMap: [ProxyGroup.ID: ProxyGroup.ID] = [:]

        for importedGroup in result.groups.map({ remappedGroup($0, profileIDMap: importedProfileIDMap, groupIDMap: [:]) }) {
            let matchingIndices = groupIndices(matchingRefreshIdentityOf: importedGroup)

            if let groupIndex = preferredGroupIndex(from: matchingIndices) {
                var updatedGroup = importedGroup
                updatedGroup.id = groups[groupIndex].id
                groups[groupIndex] = updatedGroup
                importedGroupIDMap[importedGroup.id] = updatedGroup.id

                for duplicateIndex in matchingIndices where duplicateIndex != groupIndex {
                    replacedGroupIDMap[groups[duplicateIndex].id] = updatedGroup.id
                }
            } else {
                groups.insert(importedGroup, at: 0)
                importedGroupIDMap[importedGroup.id] = importedGroup.id
            }
        }

        if !replacedGroupIDMap.isEmpty {
            let removedIDs = Set(replacedGroupIDMap.keys)
            groups.removeAll { removedIDs.contains($0.id) }
        }
        if !importedGroupIDMap.isEmpty || !replacedGroupIDMap.isEmpty {
            replaceTargetReferences(groupIDMap: importedGroupIDMap.merging(replacedGroupIDMap) { current, _ in current })
        }

        applyImportedRules(result.rules, deduplicate: true)
        normalizeSelectedTarget()
        tunnel.appendLog("Refreshed subscription: \(result.summary)")
        for warning in result.warnings.prefix(5) {
            tunnel.appendLog("Import warning: \(warning.message)")
        }
    }

    private func applyImportedRules(_ importedRules: [RoutingRule], deduplicate: Bool) {
        guard !importedRules.isEmpty else {
            return
        }

        let rulesToInsert: [RoutingRule]
        if deduplicate, let index = ruleConfigurations.firstIndex(where: { $0.id == activeRuleConfigurationID }) {
            let existingRules = Set(ruleConfigurations[index].rules)
            rulesToInsert = importedRules.filter { !existingRules.contains($0) }
        } else {
            rulesToInsert = importedRules
        }

        guard !rulesToInsert.isEmpty else {
            return
        }

        if let index = ruleConfigurations.firstIndex(where: { $0.id == activeRuleConfigurationID }) {
            ruleConfigurations[index].rules.insert(contentsOf: rulesToInsert, at: 0)
        } else {
            let imported = RuleConfiguration(name: "Imported", rules: rulesToInsert)
            ruleConfigurations.insert(imported, at: 0)
            activeRuleConfigurationID = imported.id
        }
    }

    private func profileIndices(matchingIdentityOf profile: ProxyProfile) -> [Int] {
        let identity = SubscriptionProfileRefreshIdentity(profile)
        return profiles.indices.filter {
            SubscriptionProfileRefreshIdentity(profiles[$0]) == identity
        }
    }

    private func profileIndices(matchingNameAndProtocolOf profile: ProxyProfile) -> [Int] {
        let normalizedName = normalizedImportName(profile.name)
        return profiles.indices.filter {
            normalizedImportName(profiles[$0].name) == normalizedName && profiles[$0].proto == profile.proto
        }
    }

    private func preferredProfileIndex(from indices: [Int]) -> Int? {
        guard !indices.isEmpty else {
            return nil
        }
        if case let .profile(selectedID) = selectedTarget,
           let selectedIndex = indices.first(where: { profiles[$0].id == selectedID })
        {
            return selectedIndex
        }

        let referencedProfileIDs = Set(groups.flatMap { group in
            group.members.compactMap { target in
                if case let .profile(id) = target {
                    return id
                }
                return nil
            }
        })
        if let referencedIndex = indices.first(where: { referencedProfileIDs.contains(profiles[$0].id) }) {
            return referencedIndex
        }

        return indices.first
    }

    private func groupIndices(matchingRefreshIdentityOf group: ProxyGroup) -> [Int] {
        guard let importedType = group.importedType else {
            return []
        }
        let normalizedName = normalizedImportName(group.name)
        return groups.indices.filter {
            normalizedImportName(groups[$0].name) == normalizedName && groups[$0].importedType == importedType
        }
    }

    private func preferredGroupIndex(from indices: [Int]) -> Int? {
        guard !indices.isEmpty else {
            return nil
        }
        if case let .group(selectedID) = selectedTarget,
           let selectedIndex = indices.first(where: { groups[$0].id == selectedID })
        {
            return selectedIndex
        }

        let referencedGroupIDs = Set(groups.flatMap { group in
            group.members.compactMap { target in
                if case let .group(id) = target {
                    return id
                }
                return nil
            }
        })
        if let referencedIndex = indices.first(where: { referencedGroupIDs.contains(groups[$0].id) }) {
            return referencedIndex
        }

        return indices.first
    }

    private func remappedGroup(
        _ group: ProxyGroup,
        profileIDMap: [ProxyProfile.ID: ProxyProfile.ID],
        groupIDMap: [ProxyGroup.ID: ProxyGroup.ID],
    ) -> ProxyGroup {
        var group = group
        group.members = uniquedTargets(group.members.map { remappedTarget($0, profileIDMap: profileIDMap, groupIDMap: groupIDMap) })
        group.defaultTarget = group.defaultTarget.map { remappedTarget($0, profileIDMap: profileIDMap, groupIDMap: groupIDMap) }
        if let defaultTarget = group.defaultTarget, !group.members.contains(defaultTarget) {
            group.defaultTarget = group.members.first
        }
        return group
    }

    private func replaceTargetReferences(
        profileIDMap: [ProxyProfile.ID: ProxyProfile.ID] = [:],
        groupIDMap: [ProxyGroup.ID: ProxyGroup.ID] = [:],
    ) {
        guard !profileIDMap.isEmpty || !groupIDMap.isEmpty else {
            return
        }

        groups = groups.map {
            remappedGroup($0, profileIDMap: profileIDMap, groupIDMap: groupIDMap)
        }
        selectedTarget = selectedTarget.map {
            remappedTarget($0, profileIDMap: profileIDMap, groupIDMap: groupIDMap)
        }
    }

    private func remappedTarget(
        _ target: OutboundTarget,
        profileIDMap: [ProxyProfile.ID: ProxyProfile.ID],
        groupIDMap: [ProxyGroup.ID: ProxyGroup.ID],
    ) -> OutboundTarget {
        switch target {
        case let .profile(id):
            profileIDMap[id].map(OutboundTarget.profile) ?? target
        case let .group(id):
            groupIDMap[id].map(OutboundTarget.group) ?? target
        case .selectedProxy, .direct, .reject, .named:
            target
        }
    }

    private func uniquedTargets(_ targets: [OutboundTarget]) -> [OutboundTarget] {
        var seen: Set<OutboundTarget> = []
        return targets.filter { target in
            guard !seen.contains(target) else {
                return false
            }
            seen.insert(target)
            return true
        }
    }

    private func normalizedImportName(_ name: String) -> String {
        name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    func testLatency(for profile: ProxyProfile) async {
        // Don't let a latency probe (TCP/TLS handshake or ICMP echo) reach a
        // private/loopback/link-local address. An imported subscription could
        // otherwise turn the "test latency" action into a LAN scanner. This
        // mirrors the SSRF policy applied to subscription fetches.
        let host = profile.endpoint.host
        guard !ImportPolicy.isDisallowedRemoteHost(host),
              !ImportPolicy.resolvedAddressesAreDisallowed(host)
        else {
            nodeLatencies[profile.id] = .failure("Endpoint host is not permitted for latency testing")
            return
        }
        nodeLatencies[profile.id] = .testing
        let result = await latencyTester.measure(
            host: host,
            port: profile.endpoint.port,
            serverName: profile.security.tls?.serverName ?? host,
            usesTLS: profile.security.layer != .none,
            method: settings.latencyTestMethod,
        )
        nodeLatencies[profile.id] = result
    }

    func clearLogs() {
        tunnel.clearLogs()
    }

    func restoreSampleData() {
        profiles = SampleData.profiles
        groups = SampleData.groups
        subscriptions = SampleData.subscriptions
        ruleConfigurations = SampleData.ruleConfigurations
        activeRuleConfigurationID = SampleData.defaultConfiguration.id
        routingMode = .rule
        selectedTarget = .group(SampleData.proxyGroup.id)
        tunnel.appendLog("Sample profiles, groups, subscriptions, and rules restored")
    }

    func resetSettings() {
        settings = .defaults
        tunnel.appendLog("Settings reset to defaults")
    }

    /// Coalesces frequent log updates into a single delayed persist, so a burst
    /// of log lines (e.g. syncing extension logs) doesn't trigger a storm of
    /// state-file writes and Keychain rewrites — the main cause of the logs lag.
    private func scheduleLogPersist() {
        logPersistTask?.cancel()
        logPersistTask = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .milliseconds(500))
            guard !Task.isCancelled else {
                return
            }
            self?.persist()
        }
    }

    func persist() {
        dataStore.save(
            HopAppData(
                profiles: profiles,
                groups: groups,
                subscriptions: subscriptions,
                routingMode: routingMode,
                selectedTarget: selectedTarget,
                settings: settings,
                logs: tunnel.logs,
                ruleConfigurations: ruleConfigurations,
                activeRuleConfigurationID: activeRuleConfigurationID,
            ),
        )
    }

    private func normalizeSelectedTarget() {
        guard isValid(target: selectedTarget) else {
            selectedTarget = defaultTarget
            return
        }
        persist()
    }

    private func isValid(target: OutboundTarget?) -> Bool {
        guard let target else {
            return false
        }
        return switch target {
        case .selectedProxy, .direct, .reject:
            true
        case let .profile(id):
            profiles.contains { $0.id == id }
        case let .group(id):
            groups.contains { $0.id == id && $0.isEnabled }
        case let .named(name):
            profiles.contains { $0.name == name } || groups.contains { $0.name == name }
        }
    }

    static let preview = HopStore(
        profiles: SampleData.profiles,
        groups: SampleData.groups,
        subscriptions: SampleData.subscriptions,
        ruleConfigurations: SampleData.ruleConfigurations,
        activeRuleConfigurationID: SampleData.defaultConfiguration.id,
        routingMode: .rule,
        selectedTarget: .group(SampleData.proxyGroup.id),
        settings: .defaults,
        tunnel: TunnelController(),
        dataStore: HopAppDataStore(url: URL(fileURLWithPath: "/tmp/hop-preview.json")),
    )
}

private struct SubscriptionProfileRefreshIdentity: Hashable {
    var name: String
    var host: String
    var port: Int
    var proto: ProxyProtocol
    var options: ProtocolOptions
    var security: ProxySecurity
    var transport: TransportOptions

    init(_ profile: ProxyProfile) {
        name = profile.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        host = profile.endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        port = profile.endpoint.port
        proto = profile.proto
        options = profile.options
        security = profile.security
        transport = profile.transport
    }
}
