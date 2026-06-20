import Foundation
import Observation

/// What a `HopStore.refreshSubscription` produced, for the caller to present.
enum SubscriptionRefreshOutcome {
    case applied(summary: String)
    /// The refresh would introduce nodes that disable TLS certificate
    /// verification and were not already insecure; nothing was applied. The
    /// caller must run the blocking insecure-TLS confirmation, then call
    /// `confirmInsecureSubscriptionRefresh`.
    case needsInsecureConfirmation(result: ImportResult, newInsecureProfileNames: [String])
    case failed(message: String)
}

@MainActor
@Observable
final class HopStore {
    var profiles: [ProxyProfile] {
        didSet {
            persistUnlessBatched()
        }
    }

    var groups: [ProxyGroup] {
        didSet {
            persistUnlessBatched()
        }
    }

    var subscriptions: [SubscriptionSource] {
        didSet {
            persistUnlessBatched()
        }
    }

    var ruleConfigurations: [RuleConfiguration] {
        didSet {
            persistUnlessBatched()
        }
    }

    var activeRuleConfigurationID: RuleConfiguration.ID? {
        didSet {
            persistUnlessBatched()
        }
    }

    var routingMode: RoutingMode {
        didSet {
            persistUnlessBatched()
        }
    }

    var selectedTarget: OutboundTarget? {
        didSet {
            persistUnlessBatched()
        }
    }

    var settings: AppSettings {
        didSet {
            tunnel.maximumLogEntries = settings.logRetention.rawValue
            persistUnlessBatched()
        }
    }

    var tunnel: TunnelController

    /// Transient per-node latency probe results, keyed by profile id. Not
    /// persisted — latency is only meaningful for the current session.
    var nodeLatencies: [ProxyProfile.ID: NodeLatencyResult] = [:]

    /// Subscriptions with a fetch in flight (manual or auto-refresh). Drives
    /// the per-row spinner and prevents overlapping refreshes of one source.
    var refreshingSubscriptionIDs: Set<SubscriptionSource.ID> = []

    /// Import text handed in from outside the app (the `hop://` URL scheme),
    /// waiting for `ProfilesView` to present it in the gated import sheet.
    /// Untrusted by definition — never applied without the preview/confirm
    /// flow. Transient; not persisted.
    var pendingExternalImportText: String?

    private let dataStore: HopAppDataStore
    private let latencyTester = LatencyTester()
    private let importService = ProxyImportService()
    @ObservationIgnored private var logPersistTask: Task<Void, Never>?
    /// Suppresses the per-`didSet` persist while a multi-property mutation runs;
    /// see `withBatchedPersist`.
    @ObservationIgnored private var persistBatchDepth = 0
    /// Serial queue for state saves: each save encodes the full state, rewrites
    /// the Keychain secret set, and writes the file — work that visibly stalls
    /// the main thread when run inline. Serial ordering keeps the newest
    /// snapshot the last one written.
    @ObservationIgnored private let persistQueue = DispatchQueue(label: "cat.string.hop.persist", qos: .utility)

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
        self.profiles = profiles ?? loaded?.profiles ?? []
        self.groups = groups ?? loaded?.groups ?? []
        self.subscriptions = subscriptions ?? loaded?.subscriptions ?? []

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
        self.selectedTarget = selectedTarget ?? loaded?.selectedTarget
        self.settings = settings ?? loaded?.settings ?? .defaults
        self.tunnel = tunnel ?? TunnelController(logs: loaded?.logs ?? [])
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
        return (RuleConfiguration.builtInConfigurations, RuleConfiguration.defaultConfiguration.id, false)
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
        withBatchedPersist {
            profiles.insert(profile, at: 0)
            selectedTarget = .profile(profile.id)
        }
    }

    func updateProfile(_ profile: ProxyProfile) {
        guard let index = profiles.firstIndex(where: { $0.id == profile.id }) else {
            return
        }
        profiles[index] = profile
    }

    func deleteProfile(id: ProxyProfile.ID) {
        withBatchedPersist {
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
    }

    func addGroup(_ group: ProxyGroup) {
        withBatchedPersist {
            groups.insert(group, at: 0)
            selectedTarget = .group(group.id)
        }
    }

    func updateGroup(_ group: ProxyGroup) {
        guard let index = groups.firstIndex(where: { $0.id == group.id }) else {
            return
        }
        withBatchedPersist {
            groups[index] = group
            normalizeSelectedTarget()
        }
    }

    func deleteGroup(id: ProxyGroup.ID) {
        withBatchedPersist {
            groups.removeAll { $0.id == id }
            for index in groups.indices {
                groups[index].members.removeAll { $0 == .group(id) }
                if groups[index].defaultTarget == .group(id) {
                    groups[index].defaultTarget = groups[index].members.first
                }
            }
            normalizeSelectedTarget()
        }
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
        withBatchedPersist {
            activeRuleConfigurationID = id
            // Selecting a rule configuration implies rule-based routing; Global/Direct
            // remain available from the Dashboard.
            routingMode = .rule
        }
    }

    func addRuleConfiguration(_ configuration: RuleConfiguration) {
        withBatchedPersist {
            ruleConfigurations.insert(configuration, at: 0)
            activeRuleConfigurationID = configuration.id
            routingMode = .rule
        }
    }

    func updateRuleConfiguration(_ configuration: RuleConfiguration) {
        guard let index = ruleConfigurations.firstIndex(where: { $0.id == configuration.id }) else {
            return
        }
        ruleConfigurations[index] = configuration
    }

    func deleteRuleConfiguration(id: RuleConfiguration.ID) {
        withBatchedPersist {
            ruleConfigurations.removeAll { $0.id == id }
            if activeRuleConfigurationID == id {
                activeRuleConfigurationID = ruleConfigurations.first?.id
            }
        }
    }

    func applyImport(_ result: ImportResult) {
        guard !result.isEmpty else {
            tunnel.appendLog("Import skipped: no runnable items found")
            return
        }

        withBatchedPersist {
            profiles.insert(contentsOf: result.profiles, at: 0)
            groups.insert(contentsOf: result.groups, at: 0)
            applyImportedRules(result.rules)
            selectedTarget = result.groups.first(where: \.isEnabled).map { .group($0.id) } ?? result.profiles.first.map { .profile($0.id) } ?? selectedTarget
            normalizeSelectedTarget()
        }
        tunnel.appendLog("Imported \(result.summary)")
        for warning in result.warnings.prefix(5) {
            tunnel.appendLog("Import warning: \(warning.message)")
        }
    }

    func applySubscriptionRefresh(_ result: ImportResult, updating subscription: SubscriptionSource? = nil) {
        guard !result.isEmpty else {
            tunnel.appendLog("Subscription refresh skipped: no runnable items found")
            return
        }

        // Merge on value copies and assign each collection once: every
        // `profiles`/`groups` mutation persists the whole state (file write +
        // Keychain rewrite), so per-item updates would write once per node.
        // The subscription record updates inside the same batch — a refresh is
        // one logical mutation and persists once.
        var merger = SubscriptionRefreshMerger(profiles: profiles, groups: groups, selectedTarget: selectedTarget)
        merger.merge(result)
        withBatchedPersist {
            profiles = merger.profiles
            groups = merger.groups
            selectedTarget = merger.selectedTarget
            normalizeSelectedTarget()
            if let subscription, let index = subscriptions.firstIndex(where: { $0.id == subscription.id }) {
                subscriptions[index] = subscription
            }
        }

        // Unlike a user-initiated import (which shows a preview), a refresh
        // applies without review — so routing rules from the response are NOT
        // installed. A subscription server could otherwise silently prepend
        // rules that re-route chosen domains through an outbound it controls.
        if !result.rules.isEmpty {
            tunnel.appendLog("Ignored \(result.rules.count) routing rule(s) from subscription refresh. Import the subscription manually to review and apply rule changes.")
        }
        for warning in merger.securityDowngradeWarnings.prefix(5) {
            tunnel.appendLog("Refresh warning: \(warning)")
        }
        tunnel.appendLog("Refreshed subscription: \(result.summary)")
        for warning in result.warnings.prefix(5) {
            tunnel.appendLog("Import warning: \(warning.message)")
        }
    }

    /// Fetches a subscription and merges the result, returning what happened so
    /// the caller can present it. Refreshes that would introduce *new*
    /// allow-insecure nodes are not applied here — they come back as
    /// `.needsInsecureConfirmation`, and the caller must run the blocking
    /// insecure-TLS confirmation before applying via
    /// `confirmInsecureSubscriptionRefresh`. Matched nodes are already
    /// protected by the merger's downgrade guards.
    func refreshSubscription(_ subscription: SubscriptionSource) async -> SubscriptionRefreshOutcome {
        guard !refreshingSubscriptionIDs.contains(subscription.id) else {
            return .failed(message: "A refresh for this subscription is already running.")
        }
        guard let url = URL(string: subscription.url) else {
            return .failed(message: "The subscription URL is invalid.")
        }

        refreshingSubscriptionIDs.insert(subscription.id)
        defer { refreshingSubscriptionIDs.remove(subscription.id) }

        let result: ImportResult
        do {
            result = try await importService.importSubscription(url: url).markingProfiles(subscriptionID: subscription.id)
        } catch {
            return .failed(message: error.localizedDescription)
        }

        let newInsecureNames = SubscriptionRefreshMerger.newInsecureProfileNames(existing: profiles, imported: result.profiles)
        guard newInsecureNames.isEmpty else {
            return .needsInsecureConfirmation(result: result, newInsecureProfileNames: newInsecureNames)
        }

        applyRefreshResult(result, for: subscription)
        return .applied(summary: result.summary)
    }

    /// Applies a refresh the user explicitly confirmed despite it introducing
    /// new allow-insecure nodes. Only call after the blocking
    /// `insecureTLSImportConfirmation` has run.
    func confirmInsecureSubscriptionRefresh(_ result: ImportResult, for subscription: SubscriptionSource) {
        applyRefreshResult(result, for: subscription)
    }

    /// Refreshes every subscription that hasn't updated within
    /// `AppSettings.subscriptionStaleness`. Used on foregrounding when the
    /// auto-refresh setting is on. Refreshes that would add new allow-insecure
    /// nodes are skipped — there is no user present to run the blocking
    /// confirmation, and applying without it would bypass the import gate.
    func autoRefreshStaleSubscriptions() async {
        guard settings.autoRefreshSubscriptions else {
            return
        }

        let staleBefore = Date.now.addingTimeInterval(-AppSettings.subscriptionStaleness)
        let stale = subscriptions.filter { ($0.lastUpdatedAt ?? .distantPast) < staleBefore }
        guard !stale.isEmpty else {
            return
        }

        tunnel.appendLog("Auto-refreshing \(stale.count) stale subscription(s)")
        for subscription in stale {
            switch await refreshSubscription(subscription) {
            case let .applied(summary):
                tunnel.appendLog("Auto-refreshed \(subscription.name): \(summary)")
            case let .needsInsecureConfirmation(_, names):
                tunnel.appendLog("Auto-refresh of \(subscription.name) skipped: it adds \(names.count) node(s) that disable TLS certificate verification. Refresh manually to review.")
            case let .failed(message):
                tunnel.appendLog("Auto-refresh of \(subscription.name) failed: \(message)")
            }
        }
    }

    private func applyRefreshResult(_ result: ImportResult, for subscription: SubscriptionSource) {
        var refreshed = subscription
        refreshed.lastUpdatedAt = .now
        refreshed.lastImportSummary = result.summary
        applySubscriptionRefresh(result, updating: refreshed)
    }

    private func applyImportedRules(_ importedRules: [RoutingRule]) {
        guard !importedRules.isEmpty else {
            return
        }

        if let index = ruleConfigurations.firstIndex(where: { $0.id == activeRuleConfigurationID }) {
            ruleConfigurations[index].rules.insert(contentsOf: importedRules, at: 0)
        } else {
            let imported = RuleConfiguration(name: "Imported", rules: importedRules)
            ruleConfigurations.insert(imported, at: 0)
            activeRuleConfigurationID = imported.id
        }
    }

    func testLatency(for profile: ProxyProfile) async {
        // Don't let a latency probe (TCP/TLS handshake or ICMP echo) reach a
        // private/loopback/link-local address. An imported subscription could
        // otherwise turn the "test latency" action into a LAN scanner. This
        // mirrors the SSRF policy applied to subscription fetches.
        let host = profile.endpoint.host
        guard let probeHost = ImportPolicy.resolvedPublicAddressForProbe(host)
        else {
            nodeLatencies[profile.id] = .failure("Endpoint host is not permitted for latency testing")
            return
        }
        nodeLatencies[profile.id] = .testing
        let result = await latencyTester.measure(
            host: probeHost,
            port: profile.endpoint.port,
            serverName: profile.security.tls?.serverName ?? host,
            usesTLS: profile.security.layer != .none,
            method: settings.latencyTestMethod,
        )
        nodeLatencies[profile.id] = result
    }

    /// Probes the given nodes (all profiles by default) with bounded
    /// concurrency. Each probe runs the same private-host policy as
    /// `testLatency`, so an imported list can't fan a bulk test out into a
    /// LAN scan.
    func testAllLatencies(_ profilesToTest: [ProxyProfile]? = nil, maxConcurrent: Int = 6) async {
        let snapshot = profilesToTest ?? profiles
        await withTaskGroup(of: Void.self) { group in
            var index = 0
            while index < snapshot.count, index < maxConcurrent {
                let profile = snapshot[index]
                group.addTask { await self.testLatency(for: profile) }
                index += 1
            }
            while await group.next() != nil {
                if index < snapshot.count {
                    let profile = snapshot[index]
                    group.addTask { await self.testLatency(for: profile) }
                    index += 1
                }
            }
        }
    }

    func clearLogs() {
        tunnel.clearLogs()
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
        let snapshot = HopAppData(
            profiles: profiles,
            groups: groups,
            subscriptions: subscriptions,
            routingMode: routingMode,
            selectedTarget: selectedTarget,
            settings: settings,
            logs: tunnel.logs,
            ruleConfigurations: ruleConfigurations,
            activeRuleConfigurationID: activeRuleConfigurationID,
        )
        let dataStore = dataStore
        persistQueue.async {
            dataStore.save(snapshot)
        }
    }

    /// Runs `body` with intermediate `didSet` persists suppressed, then saves
    /// once. Without this, a mutation that assigns several stored properties
    /// (import, delete, restore) rewrites the state file and Keychain once per
    /// assignment.
    private func withBatchedPersist(_ body: () -> Void) {
        persistBatchDepth += 1
        body()
        persistBatchDepth -= 1
        persist()
    }

    private func persistUnlessBatched() {
        if persistBatchDepth == 0 {
            persist()
        }
    }

    /// Blocks until every enqueued save has been written. For tests that assert
    /// on the persisted state right after a mutation.
    func flushPendingPersists() {
        persistQueue.sync {}
    }

    /// Repoints `selectedTarget` at a valid default when it references a
    /// removed/disabled item. A still-valid target is left untouched — the
    /// mutation that invalidated it has already persisted via `didSet`, so
    /// persisting again here (notably from `init` on every launch) would only
    /// rewrite the state file and Keychain with identical content.
    private func normalizeSelectedTarget() {
        guard selectedTarget != nil else {
            return
        }
        if !isValid(target: selectedTarget) {
            selectedTarget = defaultTarget
        }
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

    static let preview: HopStore = {
        #if DEBUG
            return HopStore(
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
        #else
            return HopStore(dataStore: HopAppDataStore(url: URL(fileURLWithPath: "/tmp/hop-preview.json")))
        #endif
    }()
}
