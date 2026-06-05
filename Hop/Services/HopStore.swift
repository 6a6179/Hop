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
            let activeID = loaded?.activeRuleConfigurationID ?? configs.first?.id
            return (configs, activeID, false)
        }
        if let legacy = loaded?.rules, !legacy.isEmpty {
            // Upgrade pre-configurations state: keep the user's rules as "Custom"
            // and add the auto-generated bypass configs.
            let custom = RuleConfiguration(name: "Custom", rules: legacy)
            return ([custom, .china(), .iran()], custom.id, true)
        }
        return (SampleData.ruleConfigurations, SampleData.defaultConfiguration.id, false)
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
        if !result.rules.isEmpty {
            if let index = ruleConfigurations.firstIndex(where: { $0.id == activeRuleConfigurationID }) {
                ruleConfigurations[index].rules.insert(contentsOf: result.rules, at: 0)
            } else {
                let imported = RuleConfiguration(name: "Imported", rules: result.rules)
                ruleConfigurations.insert(imported, at: 0)
                activeRuleConfigurationID = imported.id
            }
        }
        selectedTarget = result.groups.first(where: \.isEnabled).map { .group($0.id) } ?? result.profiles.first.map { .profile($0.id) } ?? selectedTarget
        normalizeSelectedTarget()
        tunnel.appendLog("Imported \(result.summary)")
        for warning in result.warnings.prefix(5) {
            tunnel.appendLog("Import warning: \(warning.message)")
        }
    }

    func testLatency(for profile: ProxyProfile) async {
        // Don't let a latency probe (TCP/TLS handshake or ICMP echo) reach a
        // private/loopback/link-local address. An imported subscription could
        // otherwise turn the "test latency" action into a LAN scanner. This
        // mirrors the SSRF policy applied to subscription fetches.
        let host = profile.endpoint.host
        guard !ImportPolicy.isDisallowedRemoteHost(host) else {
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
