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
    /// A matched node changed security values that authenticate the server or
    /// define the TLS/PQ floor. Nothing was applied; the caller must show the
    /// concise review and then call `confirmSecuritySubscriptionRefresh`.
    case needsSecurityConfirmation(
        result: ImportResult,
        changes: [SubscriptionSecurityChange],
        reviewedInsecureProfileNames: [String],
    )
    case failed(message: String)
}

enum SubscriptionRefreshMode: Equatable {
    case manual
    case automatic
}

private struct RetainedSubscriptionState: Encodable {
    let profiles: [ProxyProfile]
    let groups: [ProxyGroup]
    let subscriptions: [SubscriptionSource]
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

    /// One-time report produced while removing profiles the Xray engine cannot
    /// run. It remains persisted until the user acknowledges it.
    var pendingXrayMigrationReport: XrayMigrationReport? {
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
    @ObservationIgnored private let maxRetainedSubscriptionItems: Int
    @ObservationIgnored private let maxRetainedSubscriptionSecretItems: Int
    @ObservationIgnored private let maxRetainedSubscriptionBytes: Int
    /// A rejected or missing state is not overwritten just because its shared
    /// log was purged. Explicit state mutations make a new snapshot persistable.
    @ObservationIgnored private var hasPersistableState: Bool
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
        pendingXrayMigrationReport: XrayMigrationReport? = nil,
        settings: AppSettings? = nil,
        tunnel: TunnelController? = nil,
        dataStore: HopAppDataStore = HopAppDataStore(),
        maxRetainedSubscriptionItems: Int = ImportPolicy.maxImportedItems,
        maxRetainedSubscriptionSecretItems: Int = ImportPolicy.maxRetainedSubscriptionSecretItems,
        maxRetainedSubscriptionBytes: Int = ImportPolicy.maxRetainedSubscriptionBytes,
    ) {
        self.dataStore = dataStore
        self.maxRetainedSubscriptionItems = maxRetainedSubscriptionItems
        self.maxRetainedSubscriptionSecretItems = maxRetainedSubscriptionSecretItems
        self.maxRetainedSubscriptionBytes = maxRetainedSubscriptionBytes

        let loaded = dataStore.load()
        hasPersistableState = loaded != nil
        // A missing or rejected state cannot prove that its shared log is safe,
        // while valid state records the retry independently of schema migration.
        let requiresLegacyExtensionLogPurge = loaded == nil
            || loaded?.legacyExtensionLogPurgePending == true
        let resolvedProfiles = profiles ?? loaded?.profiles ?? []
        let unresolvedGroups = groups ?? loaded?.groups ?? []
        let resolvedGroups = ImportResult.bindingOwnedNamedReferences(
            profiles: resolvedProfiles,
            groups: unresolvedGroups,
        )
        let didBindLoadedGroupReferences = groups == nil && loaded != nil && resolvedGroups != unresolvedGroups
        self.profiles = resolvedProfiles
        self.groups = resolvedGroups
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
        self.pendingXrayMigrationReport = pendingXrayMigrationReport ?? loaded?.pendingXrayMigrationReport
        self.settings = settings ?? loaded?.settings ?? .defaults
        self.tunnel = tunnel ?? TunnelController(
            logs: loaded?.logs ?? [],
            sharedLogStore: dataStore.sharedLogStore,
            requiresLegacyExtensionLogPurge: requiresLegacyExtensionLogPurge,
        )
        // Tests and previews may inject a controller; never let injection
        // bypass a pending authenticated-state migration.
        self.tunnel.requiresLegacyExtensionLogPurge = self.tunnel.requiresLegacyExtensionLogPurge
            || requiresLegacyExtensionLogPurge
        self.tunnel.maximumLogEntries = self.settings.logRetention.rawValue
        self.tunnel.onLogsChanged = { [weak self] in
            self?.scheduleLogPersist()
        }
        self.tunnel.onLegacyExtensionLogPurgeCompleted = { [weak self] in
            guard let self else {
                return
            }
            persistLoadedState()
        }
        // Resolve the gate before a brand-new user can save current data under
        // the legacy schema. A failed clear remains pending and retryable.
        try? self.tunnel.purgeLegacyExtensionLogIfNeeded()
        normalizeSelectedTarget()

        // Persist once if we upgraded an existing file from legacy rules, so the
        // migrated configuration IDs are stable across launches.
        if resolved.didMigrate || didBindLoadedGroupReferences {
            persistLoadedState()
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
            var updated = configuration.withAppleSystemBypassRule()
            updated.rules.removeAll { rule in
                rule.kind == .geoSite
                    && !rule.value.split(separator: ",").allSatisfy {
                        VerifiedXrayGeodata.geoSiteCategories.contains(String($0).trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
                    }
            }
            didMigrate = didMigrate || updated != configuration
            return updated
        }
        return (migrated, didMigrate)
    }

    var selectedProfile: ProxyProfile? {
        get {
            if case let .profile(id) = selectedTarget {
                return profiles.first { $0.id == id }
            }
            return nil
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
        selectedTarget.map { displayName(for: $0) } ?? "Select Outbound"
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

    func updateSubscription(_ subscription: SubscriptionSource) {
        guard let index = subscriptions.firstIndex(where: { $0.id == subscription.id }) else {
            return
        }
        subscriptions[index] = subscription
    }

    func deleteSubscription(id: SubscriptionSource.ID) {
        let removedProfileIDs = Set(profiles.lazy.filter { $0.subscriptionID == id }.map(\.id))
        let removedGroupIDs = Set(groups.lazy.filter { $0.subscriptionID == id }.map(\.id))
        withBatchedPersist {
            profiles.removeAll { removedProfileIDs.contains($0.id) }
            groups.removeAll { removedGroupIDs.contains($0.id) }
            repairReferences(removingProfiles: removedProfileIDs, groups: removedGroupIDs)
            subscriptions.removeAll { $0.id == id }
            normalizeSelectedTarget()
        }
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

    /// Persists a newly fetched subscription and its source-owned content as
    /// one mutation. Subscription rules never enter active routing policy.
    @discardableResult
    func applySubscriptionImport(
        _ untrustedResult: ImportResult,
        adding subscription: SubscriptionSource,
    ) -> Bool {
        let result = preparedSubscriptionResult(untrustedResult, subscriptionID: subscription.id)
        guard !result.isEmpty else {
            tunnel.appendLog("Subscription import skipped: no runnable items found")
            return false
        }
        let projectedSubscriptions = [subscription] + subscriptions
        guard subscriptionInputFitsBudget(
            result,
            replacing: subscription.id,
            subscriptions: projectedSubscriptions,
        ) else {
            tunnel.appendLog("Subscription import rejected: retained subscription data exceeds the app safety limit")
            return false
        }

        // Provider groups may contain opaque DIRECT/REJECT defaults or nested
        // policies. Save them for review, but never activate one as a side
        // effect of importing a subscription.
        let existingSelection = isValid(target: selectedTarget) ? selectedTarget : nil
        let importedSelection = existingSelection ?? result.profiles.first.map { .profile($0.id) }
        var merger = SubscriptionRefreshMerger(
            profiles: profiles,
            groups: groups,
            selectedTarget: importedSelection,
        )
        merger.merge(result, replacingSnapshotFor: subscription.id)
        guard subscriptionStateFitsBudget(
            profiles: merger.profiles,
            groups: merger.groups,
            subscriptions: projectedSubscriptions,
        ) else {
            tunnel.appendLog("Subscription import rejected: retained subscription data exceeds the app safety limit")
            return false
        }

        withBatchedPersist {
            profiles = merger.profiles
            groups = merger.groups
            selectedTarget = merger.selectedTarget
            subscriptions = projectedSubscriptions
            repairReferences(
                removingProfiles: merger.removedProfileIDs,
                groups: merger.removedGroupIDs,
                remappingProfiles: merger.profileIDReplacements,
                remappingGroups: merger.groupIDReplacements,
            )
            normalizeSelectedTarget()
        }
        tunnel.appendLog("Imported subscription: \(result.summary)")
        for warning in result.warnings.prefix(5) {
            tunnel.appendLog("Import warning: \(warning.message)")
        }
        return true
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

    @discardableResult
    func applySubscriptionRefresh(
        _ untrustedResult: ImportResult,
        updating subscription: SubscriptionSource,
        securityPolicy: SubscriptionRefreshSecurityPolicy = .preserveExisting,
    ) -> Bool {
        let result = preparedSubscriptionResult(untrustedResult, subscriptionID: subscription.id)
        guard !result.isEmpty || result.validatedEmptySubscriptionSnapshot == true else {
            tunnel.appendLog("Subscription refresh skipped: no runnable items found")
            return false
        }
        guard let subscriptionIndex = subscriptions.firstIndex(where: { $0.id == subscription.id }) else {
            tunnel.appendLog("Subscription refresh skipped: source no longer exists")
            return false
        }
        var projectedSubscriptions = subscriptions
        projectedSubscriptions[subscriptionIndex] = subscription
        guard subscriptionInputFitsBudget(
            result,
            replacing: subscription.id,
            subscriptions: projectedSubscriptions,
        ) else {
            tunnel.appendLog("Subscription refresh rejected: retained subscription data exceeds the app safety limit")
            return false
        }

        // Merge on value copies and assign each collection once: every
        // `profiles`/`groups` mutation persists the whole state (file write +
        // Keychain rewrite), so per-item updates would write once per node.
        // The subscription record updates inside the same batch — a refresh is
        // one logical mutation and persists once.
        var merger = SubscriptionRefreshMerger(profiles: profiles, groups: groups, selectedTarget: selectedTarget)
        merger.merge(
            result,
            securityPolicy: securityPolicy,
            replacingSnapshotFor: subscription.id,
        )
        guard subscriptionStateFitsBudget(
            profiles: merger.profiles,
            groups: merger.groups,
            subscriptions: projectedSubscriptions,
        ) else {
            tunnel.appendLog("Subscription refresh rejected: retained subscription data exceeds the app safety limit")
            return false
        }

        withBatchedPersist {
            profiles = merger.profiles
            groups = merger.groups
            selectedTarget = merger.selectedTarget
            subscriptions = projectedSubscriptions
            repairReferences(
                removingProfiles: merger.removedProfileIDs,
                groups: merger.removedGroupIDs,
                remappingProfiles: merger.profileIDReplacements,
                remappingGroups: merger.groupIDReplacements,
            )
            normalizeSelectedTarget()
        }

        for warning in merger.securityDowngradeWarnings.prefix(5) {
            tunnel.appendLog("Refresh warning: \(warning)")
        }
        tunnel.appendLog("Refreshed subscription: \(result.summary)")
        for warning in result.warnings.prefix(5) {
            tunnel.appendLog("Import warning: \(warning.message)")
        }
        return true
    }

    /// Fetches a subscription and merges the result, returning what happened so
    /// the caller can present it. Refreshes that would introduce *new*
    /// allow-insecure nodes are not applied here — they come back as
    /// `.needsInsecureConfirmation`, and the caller must run the blocking
    /// insecure-TLS confirmation before applying via
    /// `confirmInsecureSubscriptionRefresh`. Manual refreshes also return a
    /// blocking security review for matched-node TLS/REALITY/PQ/auth changes;
    /// automatic refreshes keep the stored values and apply only noncritical
    /// updates.
    func refreshSubscription(
        _ subscription: SubscriptionSource,
        mode: SubscriptionRefreshMode = .manual,
    ) async -> SubscriptionRefreshOutcome {
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
            result = try await preparedSubscriptionResult(
                importService.importSubscription(url: url),
                subscriptionID: subscription.id,
            )
        } catch {
            return .failed(message: error.localizedDescription)
        }

        if mode == .manual {
            return reviewSubscriptionRefresh(result, for: subscription)
        }

        let newInsecureNames = SubscriptionRefreshMerger.newInsecureProfileNames(existing: profiles, imported: result.profiles)
        guard newInsecureNames.isEmpty else {
            return .needsInsecureConfirmation(result: result, newInsecureProfileNames: newInsecureNames)
        }
        return applyRefreshResult(result, for: subscription, securityPolicy: .preserveExisting)
    }

    /// Applies a refresh the user explicitly confirmed despite it introducing
    /// new allow-insecure nodes. If the same result also changes pinned
    /// security values, it remains blocked and returns the second confirmation
    /// outcome instead of applying both decisions behind the first alert.
    @discardableResult
    func confirmInsecureSubscriptionRefresh(
        _ result: ImportResult,
        reviewedProfileNames: [String],
        for subscription: SubscriptionSource,
    ) -> SubscriptionRefreshOutcome {
        reviewSubscriptionRefresh(
            result,
            for: subscription,
            reviewedInsecureProfileNames: reviewedProfileNames,
        )
    }

    /// Applies only the security-change categories shown by the manual review.
    /// The current state is checked again so an intervening profile edit cannot
    /// introduce a new, unreviewed category before this confirmation lands.
    @discardableResult
    func confirmSecuritySubscriptionRefresh(
        _ result: ImportResult,
        reviewedChanges: [SubscriptionSecurityChange],
        reviewedInsecureProfileNames: [String],
        for subscription: SubscriptionSource,
    ) -> SubscriptionRefreshOutcome {
        let result = preparedSubscriptionResult(result, subscriptionID: subscription.id)
        let newInsecureNames = SubscriptionRefreshMerger.newInsecureProfileNames(existing: profiles, imported: result.profiles)
        guard Self.reviewedNames(reviewedInsecureProfileNames, cover: newInsecureNames) else {
            return .needsInsecureConfirmation(result: result, newInsecureProfileNames: newInsecureNames)
        }

        let changes = subscriptionSecurityChanges(in: result)
        guard changes == reviewedChanges else {
            if changes.isEmpty {
                return applyRefreshResult(result, for: subscription, securityPolicy: .preserveExisting)
            }
            return .needsSecurityConfirmation(
                result: result,
                changes: changes,
                reviewedInsecureProfileNames: reviewedInsecureProfileNames,
            )
        }

        return applyRefreshResult(result, for: subscription, securityPolicy: .applyReviewedChanges)
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
            switch await refreshSubscription(subscription, mode: .automatic) {
            case let .applied(summary):
                tunnel.appendLog("Auto-refreshed \(subscription.name): \(summary)")
            case let .needsInsecureConfirmation(_, names):
                tunnel.appendLog("Auto-refresh of \(subscription.name) skipped: it adds \(names.count) node(s) that disable TLS certificate verification. Refresh manually to review.")
            case .needsSecurityConfirmation:
                // Automatic mode preserves these values and therefore never
                // returns a manual-review outcome. Keep this fail-closed if a
                // future code path violates that contract.
                tunnel.appendLog("Auto-refresh of \(subscription.name) skipped: security changes require manual review.")
            case let .failed(message):
                tunnel.appendLog("Auto-refresh of \(subscription.name) failed: \(message)")
            }
        }
    }

    /// Processes an already fetched manual result. Kept internal so focused
    /// tests can verify the blocking outcome without making a network request.
    func reviewSubscriptionRefresh(
        _ untrustedResult: ImportResult,
        for subscription: SubscriptionSource,
        reviewedInsecureProfileNames: [String] = [],
    ) -> SubscriptionRefreshOutcome {
        let result = preparedSubscriptionResult(untrustedResult, subscriptionID: subscription.id)
        let newInsecureNames = SubscriptionRefreshMerger.newInsecureProfileNames(existing: profiles, imported: result.profiles)
        guard Self.reviewedNames(reviewedInsecureProfileNames, cover: newInsecureNames) else {
            return .needsInsecureConfirmation(result: result, newInsecureProfileNames: newInsecureNames)
        }

        let changes = subscriptionSecurityChanges(in: result)
        guard changes.isEmpty else {
            return .needsSecurityConfirmation(
                result: result,
                changes: changes,
                reviewedInsecureProfileNames: reviewedInsecureProfileNames,
            )
        }

        return applyRefreshResult(result, for: subscription, securityPolicy: .preserveExisting)
    }

    private func subscriptionSecurityChanges(in result: ImportResult) -> [SubscriptionSecurityChange] {
        SubscriptionRefreshMerger(
            profiles: profiles,
            groups: groups,
            selectedTarget: selectedTarget,
        ).securityCriticalChanges(in: result.profiles)
    }

    private static func reviewedNames(_ reviewed: [String], cover current: [String]) -> Bool {
        var remaining = Dictionary(reviewed.map { ($0, 1) }, uniquingKeysWith: { $0 + $1 })
        for name in current {
            guard let count = remaining[name], count > 0 else { return false }
            remaining[name] = count - 1
        }
        return true
    }

    private func applyRefreshResult(
        _ result: ImportResult,
        for subscription: SubscriptionSource,
        securityPolicy: SubscriptionRefreshSecurityPolicy,
    ) -> SubscriptionRefreshOutcome {
        var refreshed = subscription
        refreshed.lastUpdatedAt = .now
        refreshed.lastImportSummary = result.summary
        guard applySubscriptionRefresh(result, updating: refreshed, securityPolicy: securityPolicy) else {
            return .failed(message: "The refresh exceeds the retained subscription safety limit.")
        }
        return .applied(summary: result.summary)
    }

    private func preparedSubscriptionResult(
        _ result: ImportResult,
        subscriptionID: SubscriptionSource.ID,
    ) -> ImportResult {
        result
            .markingSubscriptionOwnership(subscriptionID: subscriptionID)
            .droppingRules()
            .sanitizingNames()
            .requiringSubscriptionGroupReview()
    }

    private func subscriptionStateFitsBudget(
        profiles: [ProxyProfile],
        groups: [ProxyGroup],
        subscriptions: [SubscriptionSource],
    ) -> Bool {
        let ownedProfiles = profiles.filter { $0.subscriptionID != nil }
        let ownedGroups = groups.filter { $0.subscriptionID != nil }
        guard ownedProfiles.count <= maxRetainedSubscriptionItems,
              ownedGroups.count <= maxRetainedSubscriptionItems - ownedProfiles.count
        else {
            return false
        }

        var secretItemCount = subscriptions.count
        guard secretItemCount <= maxRetainedSubscriptionSecretItems else { return false }
        for profile in ownedProfiles {
            let profileSecretCount = profile.keychainSecretItems.count
            guard profileSecretCount <= maxRetainedSubscriptionSecretItems - secretItemCount else {
                return false
            }
            secretItemCount += profileSecretCount
        }

        let retained = RetainedSubscriptionState(
            profiles: ownedProfiles,
            groups: ownedGroups,
            subscriptions: subscriptions,
        )
        guard let encoded = try? JSONEncoder().encode(retained) else {
            return false
        }
        return encoded.count <= maxRetainedSubscriptionBytes
    }

    /// Cheap pre-merge projection: the refreshing source's prior snapshot will
    /// be replaced, so combine only other retained sources with the incoming
    /// snapshot. This rejects cumulative excess before identity matching.
    private func subscriptionInputFitsBudget(
        _ result: ImportResult,
        replacing subscriptionID: SubscriptionSource.ID,
        subscriptions: [SubscriptionSource],
    ) -> Bool {
        let projectedProfiles = profiles.filter {
            $0.subscriptionID != nil && $0.subscriptionID != subscriptionID
        } + result.profiles
        let projectedGroups = groups.filter {
            $0.subscriptionID != nil && $0.subscriptionID != subscriptionID
        } + result.groups
        return subscriptionStateFitsBudget(
            profiles: projectedProfiles,
            groups: projectedGroups,
            subscriptions: subscriptions,
        )
    }

    private func repairReferences(
        removingProfiles profileIDs: Set<ProxyProfile.ID>,
        groups groupIDs: Set<ProxyGroup.ID>,
        remappingProfiles profileIDMap: [ProxyProfile.ID: ProxyProfile.ID] = [:],
        remappingGroups groupIDMap: [ProxyGroup.ID: ProxyGroup.ID] = [:],
    ) {
        guard !profileIDs.isEmpty || !groupIDs.isEmpty || !profileIDMap.isEmpty || !groupIDMap.isEmpty else { return }

        func repaired(_ target: OutboundTarget) -> OutboundTarget? {
            switch target {
            case let .profile(id):
                if profileIDs.contains(id) {
                    return nil
                }
                return profileIDMap[id].map(OutboundTarget.profile) ?? target
            case let .group(id):
                if groupIDs.contains(id) {
                    return nil
                }
                return groupIDMap[id].map(OutboundTarget.group) ?? target
            case .selectedProxy, .direct, .reject, .named:
                return target
            }
        }

        groups = groups.map { group in
            var group = group
            let hadDefaultTarget = group.defaultTarget != nil
            group.members = group.members.compactMap(repaired)
            group.defaultTarget = group.defaultTarget.flatMap(repaired)
            if hadDefaultTarget,
               group.defaultTarget.map({ !group.members.contains($0) }) ?? true
            {
                group.defaultTarget = group.members.first
            }
            return group
        }
        for index in ruleConfigurations.indices {
            ruleConfigurations[index].rules = ruleConfigurations[index].rules.compactMap { rule in
                guard let target = repaired(rule.target) else { return nil }
                var rule = rule
                rule.target = target
                return rule
            }
        }
        if let selectedTarget {
            self.selectedTarget = repaired(selectedTarget)
        }
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

    func acknowledgeXrayMigration() {
        pendingXrayMigrationReport = nil
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
            self?.persistLoadedState()
        }
    }

    func persist() {
        hasPersistableState = true
        enqueuePersist()
    }

    private func persistLoadedState() {
        guard hasPersistableState else {
            return
        }
        enqueuePersist()
    }

    private func enqueuePersist() {
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
            schemaVersion: HopAppData.currentSchemaVersion,
            legacyExtensionLogPurgePending: tunnel.requiresLegacyExtensionLogPurge ? true : nil,
            pendingXrayMigrationReport: pendingXrayMigrationReport,
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
