import SwiftUI
import UniformTypeIdentifiers

struct ProfilesView: View {
    @Environment(HopStore.self) private var store
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @State private var selectedSection: ProfilesSection = .nodes
    @State private var activeSheet: ProfilesSheet?
    @State private var importNotice: ProfileImportNotice?
    @State private var searchText = ""
    /// A refresh held back because it would add new allow-insecure nodes;
    /// applied only after the user confirms.
    @State private var pendingInsecureRefresh: PendingInsecureRefresh?
    @State private var showInsecureRefreshConfirmation = false
    /// A manual refresh held back because a matched node changed pinned TLS,
    /// REALITY, PQ, or VLESS authentication settings.
    @State private var pendingSecurityRefresh: PendingSecurityRefresh?
    @State private var applySecurityRefreshOnDismiss = false
    @State private var shareQRItem: ShareQRItem?

    private let importService = ProxyImportService()

    var body: some View {
        List {
            Section {
                Picker("Profile Section", selection: $selectedSection) {
                    ForEach(ProfilesSection.allCases, id: \.self) { section in
                        Text(section.title).tag(section)
                    }
                }
                .pickerStyle(.segmented)
            }

            switch selectedSection {
            case .nodes:
                nodesSection
                if !store.groups.isEmpty {
                    groupsSection
                }
            case .subscriptions:
                subscriptionsSection
            }
        }
        .navigationTitle("Profiles")
        .navigationBarTitleDisplayMode(.inline)
        .sensoryFeedback(.selection, trigger: store.selectedTarget)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Section("Import") {
                        Button("Scan QR Code", systemImage: "qrcode.viewfinder") {
                            activeSheet = .scanner
                        }
                        Button("Paste or Import", systemImage: "doc.on.clipboard") {
                            activeSheet = .importText(prefill: "")
                        }
                    }

                    Section("Create") {
                        Button("New Node", systemImage: "server.rack") {
                            activeSheet = .profile(Self.newProfile(), isNew: true)
                        }
                        Button("New Group", systemImage: "rectangle.stack.badge.plus") {
                            activeSheet = .group(Self.newGroup(profiles: store.profiles), isNew: true)
                        }
                    }
                } label: {
                    Label("Add", systemImage: "plus.circle")
                }
            }
        }
        .sheet(item: $activeSheet, onDismiss: {
            guard applySecurityRefreshOnDismiss else { return }
            applySecurityRefreshOnDismiss = false
            // Recheck the approved snapshot after dismissal so SwiftUI can
            // present the outcome, including a fresh review when needed.
            applyPendingSecurityRefresh()
        }) { sheet in
            switch sheet {
            case let .profile(profile, isNew):
                ProfileEditorView(profile: profile, isNew: isNew) { updated in
                    let current = store.profiles.first { $0.id == profile.id }
                    guard Self.canSaveEditor(original: profile, isNew: isNew, current: current) else { return false }
                    if isNew {
                        store.addProfile(updated)
                    } else {
                        store.updateProfile(updated)
                    }
                    selectedSection = .nodes
                    return true
                }
            case let .group(group, isNew):
                ProxyGroupEditorView(group: group, isNew: isNew) { updated in
                    let current = store.groups.first { $0.id == group.id }
                    guard Self.canSaveEditor(original: group, isNew: isNew, current: current) else { return false }
                    if isNew {
                        store.addGroup(updated)
                    } else {
                        store.updateGroup(updated)
                    }
                    selectedSection = .nodes
                    return true
                }
            case let .importText(prefill):
                ImportTextSheet(importService: importService, initialText: prefill) { saveResult in
                    switch saveResult {
                    case let .importText(result):
                        store.applyImport(result)
                        selectedSection = .nodes
                        importNotice = ProfileImportNotice(title: "Import Complete", message: result.summary)
                    case let .subscription(subscription, result, sourceAtPreview):
                        let outcome = store.saveSubscriptionPreview(result, for: subscription, sourceAtPreview: sourceAtPreview)
                        if case let .applied(summary) = outcome {
                            selectedSection = .subscriptions
                            importNotice = ProfileImportNotice(title: sourceAtPreview == nil ? "Subscription Added" : "Subscription Updated", message: summary)
                        } else {
                            handleRefreshOutcome(outcome, for: sourceAtPreview ?? subscription)
                        }
                    }
                }
            case .securityReview:
                if let pending = pendingSecurityRefresh {
                    NavigationStack {
                        List {
                            Section("\(pending.subscription.name) · \(pending.changes.count) changed nodes") {
                                ForEach(pending.changes.indices, id: \.self) { index in
                                    let change = pending.changes[index]
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(change.profileName).font(.headline)
                                        ForEach(change.details, id: \.field) { detail in
                                            VStack(alignment: .leading, spacing: 3) {
                                                Text(detail.field.rawValue).font(.subheadline.weight(.semibold))
                                                Text("Current: \(detail.before)")
                                                Text("Proposed: \(detail.after)")
                                            }
                                            .font(.footnote)
                                            .textSelection(.enabled)
                                            .padding(.vertical, 3)
                                        }
                                    }
                                }
                            }
                        }
                        .navigationTitle("Review Security Changes")
                        .navigationBarTitleDisplayMode(.inline)
                        .toolbar {
                            ToolbarItem(placement: .cancellationAction) {
                                Button("Cancel") {
                                    pendingSecurityRefresh = nil
                                    activeSheet = nil
                                }
                            }
                            ToolbarItem(placement: .confirmationAction) {
                                Button("Apply", role: .destructive) {
                                    applySecurityRefreshOnDismiss = true
                                    activeSheet = nil
                                }
                            }
                        }
                    }
                    .interactiveDismissDisabled()
                }
            case .scanner:
                QRCodeScannerSheet { payload in
                    activeSheet = nil
                    DispatchQueue.main.async {
                        activeSheet = .importText(prefill: payload)
                    }
                }
            }
        }
        .alert(item: $importNotice) { notice in
            Alert(
                title: Text(notice.title),
                message: Text(notice.message),
                dismissButton: .default(Text("OK")),
            )
        }
        .searchable(text: $searchText, prompt: "Search nodes, groups, subscriptions")
        .insecureTLSImportConfirmation(
            isPresented: $showInsecureRefreshConfirmation,
            profileNames: pendingInsecureRefresh?.insecureProfileNames ?? [],
            onCancel: { pendingInsecureRefresh = nil },
        ) {
            applyPendingInsecureRefresh()
        }
        .onAppear {
            presentPendingSheet()
        }
        .onChange(of: store.pendingExternalImportText) {
            presentPendingSheet()
        }
        // A payload that arrived while a sheet was up is consumed when the
        // presentation ends. The one-turn defer lets an already-scheduled
        // re-present (the scanner→import handoff) claim the sheet first;
        // Pending security reviews take priority once the sheet is available.
        .onChange(of: canPresentPendingSheet) { _, canPresent in
            if canPresent {
                DispatchQueue.main.async {
                    presentPendingSheet()
                }
            }
        }
        .sheet(item: $shareQRItem) { item in
            ProfileShareQRSheet(profileName: item.profileName, link: item.link)
        }
    }

    /// Copies with a short pasteboard expiry: share links carry credentials,
    /// and a forgotten clipboard entry shouldn't hold them indefinitely.
    private func copyShareLink(_ link: String) {
        UIPasteboard.general.setItems(
            [[UTType.utf8PlainText.identifier: link]],
            options: [.expirationDate: Date.now.addingTimeInterval(180)],
        )
    }

    private var canPresentPendingSheet: Bool {
        activeSheet == nil && shareQRItem == nil && !applySecurityRefreshOnDismiss
            && !showInsecureRefreshConfirmation && importNotice == nil
    }

    /// Routes a `hop://` URL payload into the standard import sheet: prefilled
    /// for review, never applied directly — external apps don't get to skip
    /// the preview or the allow-insecure confirmation.
    private func presentPendingSheet() {
        guard canPresentPendingSheet else { return }
        if pendingSecurityRefresh != nil {
            activeSheet = .securityReview
            return
        }
        guard let text = store.pendingExternalImportText else { return }
        store.pendingExternalImportText = nil
        activeSheet = .importText(prefill: text)
    }

    /// Case-insensitive match against the trimmed search text; an empty search
    /// shows everything.
    private var searchNeedle: String {
        searchText.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var visibleProfiles: [ProxyProfile] {
        let needle = searchNeedle
        guard !needle.isEmpty else {
            return store.profiles
        }
        return store.profiles.filter {
            $0.name.localizedCaseInsensitiveContains(needle)
                || $0.endpoint.host.localizedCaseInsensitiveContains(needle)
        }
    }

    private var visibleGroups: [ProxyGroup] {
        let needle = searchNeedle
        guard !needle.isEmpty else {
            return store.groups
        }
        return store.groups.filter { $0.name.localizedCaseInsensitiveContains(needle) }
    }

    private var visibleSubscriptions: [SubscriptionSource] {
        let needle = searchNeedle
        guard !needle.isEmpty else {
            return store.subscriptions
        }
        return store.subscriptions.filter {
            $0.name.localizedCaseInsensitiveContains(needle)
                || $0.url.localizedCaseInsensitiveContains(needle)
        }
    }

    private var nodesSection: some View {
        let profiles = visibleProfiles
        return Section {
            if store.profiles.isEmpty {
                ContentUnavailableView {
                    Label("No Nodes", systemImage: "server.rack")
                } description: {
                    Text("Import links, configs, or subscriptions.")
                } actions: {
                    let layout = dynamicTypeSize.isAccessibilitySize
                        ? AnyLayout(VStackLayout(spacing: 12))
                        : AnyLayout(HStackLayout(spacing: 8))
                    layout {
                        Button("Import") {
                            activeSheet = .importText(prefill: "")
                        }
                        .buttonStyle(.borderedProminent)
                        Button("New Node") {
                            activeSheet = .profile(Self.newProfile(), isNew: true)
                        }
                        .buttonStyle(.bordered)
                    }
                    .controlSize(.large)
                }
                .fixedSize(horizontal: false, vertical: true)
            } else if profiles.isEmpty {
                ContentUnavailableView.search(text: searchText)
            } else {
                ForEach(profiles) { profile in
                    Button {
                        store.selectedTarget = .profile(profile.id)
                    } label: {
                        ProfileRow(profile: profile, isSelected: store.selectedTarget == .profile(profile.id), latency: store.latency(for: profile.id))
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(store.selectedTarget == .profile(profile.id) ? .isSelected : [])
                    .contextMenu {
                        Button("Edit", systemImage: "pencil") {
                            activeSheet = .profile(profile, isNew: false)
                        }
                        if let link = ProxyShareLink.shareLink(for: profile) {
                            // Share actions embed the node's credentials —
                            // that is the point of sharing a node — and only
                            // run from this explicit menu.
                            Button("Copy Share Link", systemImage: "doc.on.doc") {
                                copyShareLink(link)
                            }
                            ShareLink(item: link) {
                                Label("Share Link", systemImage: "square.and.arrow.up")
                            }
                            Button("Show QR Code", systemImage: "qrcode") {
                                shareQRItem = ShareQRItem(profileName: profile.name, link: link)
                            }
                        } else if let reason = ProxyShareLink.unavailableReason(for: profile) {
                            Button("Share Link Unavailable", systemImage: "info.circle") {
                                importNotice = ProfileImportNotice(title: "Share Link Unavailable", message: reason)
                            }
                        }
                    }
                    .swipeActions(edge: .leading, allowsFullSwipe: true) {
                        Button {
                            Task { await store.testLatency(for: profile) }
                        } label: {
                            Label("Test", systemImage: "bolt.horizontal.circle")
                        }
                        .tint(.green)
                    }
                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                        Button(role: .destructive) {
                            store.deleteProfile(id: profile.id)
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }

                        Button {
                            activeSheet = .profile(profile, isNew: false)
                        } label: {
                            Label("Edit", systemImage: "pencil")
                        }
                        .tint(.blue)
                    }
                }
            }
        } header: {
            HStack {
                Text("Nodes")
                Spacer()
                if profiles.count > 1 {
                    // Tests what the (possibly searched) list shows, so the
                    // button never probes nodes the user can't see.
                    Button("Test All") {
                        Task { await store.testAllLatencies(profiles) }
                    }
                    .controlSize(.small)
                    .font(.caption)
                    .disabled(store.isTestingLatency)
                }
            }
        }
    }

    private var groupsSection: some View {
        let groups = visibleGroups
        return Section {
            if groups.isEmpty {
                ContentUnavailableView.search(text: searchText)
            } else {
                ForEach(groups) { group in
                    Button {
                        if group.isEnabled {
                            store.selectedTarget = .group(group.id)
                        }
                    } label: {
                        ProxyGroupRow(group: group, isSelected: store.selectedTarget == .group(group.id))
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(store.selectedTarget == .group(group.id) ? .isSelected : [])
                    .contextMenu {
                        Button("Edit", systemImage: "pencil") {
                            activeSheet = .group(group, isNew: false)
                        }
                    }
                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                        Button(role: .destructive) {
                            store.deleteGroup(id: group.id)
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }

                        Button {
                            activeSheet = .group(group, isNew: false)
                        } label: {
                            Label("Edit", systemImage: "pencil")
                        }
                        .tint(.blue)
                    }
                }
            }
        } header: {
            Text("Proxy Groups")
        }
    }

    private var subscriptionsSection: some View {
        let subscriptions = visibleSubscriptions
        return Section {
            if store.subscriptions.isEmpty {
                ContentUnavailableView {
                    Label("No Subscriptions", systemImage: "link")
                } description: {
                    Text("Import a subscription URL.")
                } actions: {
                    Button("Import Subscription") {
                        activeSheet = .importText(prefill: "")
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                }
                .fixedSize(horizontal: false, vertical: true)
            } else if subscriptions.isEmpty {
                ContentUnavailableView.search(text: searchText)
            } else {
                ForEach(subscriptions) { subscription in
                    let isRefreshing = store.refreshingSubscriptionIDs.contains(subscription.id)
                    HStack(spacing: 12) {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(subscription.name)
                                .font(.body.weight(.semibold))
                            Text(subscription.redactedDisplayURL)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                            if let summary = subscription.lastImportSummary {
                                Text(summary)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }

                        Spacer(minLength: 8)

                        if isRefreshing {
                            ProgressView()
                                .controlSize(.small)
                        } else {
                            Button {
                                refreshSubscription(subscription)
                            } label: {
                                Label("Refresh", systemImage: "arrow.clockwise")
                                    .labelStyle(.iconOnly)
                            }
                            .controlSize(.small)
                            .accessibilityLabel("Refresh \(subscription.name)")
                        }
                    }
                    .disabled(isRefreshing)
                    .swipeActions(edge: .leading, allowsFullSwipe: true) {
                        Button {
                            refreshSubscription(subscription)
                        } label: {
                            Label("Refresh", systemImage: "arrow.clockwise")
                        }
                        .tint(.blue)
                        .disabled(isRefreshing)
                    }
                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                        Button(role: .destructive) {
                            store.deleteSubscription(id: subscription.id)
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }
                        .disabled(isRefreshing)
                    }
                }
            }
        } header: {
            Text("Subscriptions")
        } footer: {
            Text("Pinned TLS, REALITY, PQ, and VLESS authentication changes require review.")
        }
    }

    private func applyPendingInsecureRefresh() {
        guard let pending = pendingInsecureRefresh else {
            return
        }
        pendingInsecureRefresh = nil
        let outcome = store.confirmInsecureSubscriptionRefresh(
            pending.result,
            reviewedProfileNames: pending.insecureProfileNames,
            for: pending.subscription,
        )
        handleRefreshOutcome(outcome, for: pending.subscription)
    }

    private func applyPendingSecurityRefresh() {
        guard let pending = pendingSecurityRefresh else {
            return
        }
        pendingSecurityRefresh = nil
        let outcome = store.confirmSecuritySubscriptionRefresh(
            pending.result,
            reviewedChanges: pending.changes,
            reviewedInsecureProfileNames: pending.reviewedInsecureProfileNames,
            for: pending.subscription,
        )
        handleRefreshOutcome(outcome, for: pending.subscription)
    }

    private func refreshSubscription(_ subscription: SubscriptionSource) {
        guard !store.refreshingSubscriptionIDs.contains(subscription.id) else {
            return
        }
        // An unresolved review keeps its confirmation slot until the user
        // decides; re-present it rather than racing another refresh outcome
        // into the same slot (which would silently drop one of them).
        if pendingInsecureRefresh != nil {
            showInsecureRefreshConfirmation = true
            return
        }
        if pendingSecurityRefresh != nil {
            presentPendingSheet()
            return
        }
        Task {
            await handleRefreshOutcome(store.refreshSubscription(subscription), for: subscription)
        }
    }

    /// Shown instead of silently discarding a refresh whose confirmation slot
    /// is occupied by another subscription's unresolved review.
    private func deferredReviewNotice(for subscription: SubscriptionSource) -> ProfileImportNotice {
        ProfileImportNotice(
            title: "Refresh Needs Review",
            message: "Finish the pending review, then refresh \(subscription.name) again to review its changes.",
        )
    }

    private func handleRefreshOutcome(
        _ outcome: SubscriptionRefreshOutcome,
        for subscription: SubscriptionSource,
    ) {
        switch outcome {
        case let .applied(summary):
            selectedSection = .subscriptions
            importNotice = ProfileImportNotice(title: "Subscription Refreshed", message: summary)
        case let .needsInsecureConfirmation(result, newInsecureNames):
            guard pendingInsecureRefresh == nil, pendingSecurityRefresh == nil else {
                importNotice = deferredReviewNotice(for: subscription)
                return
            }
            pendingInsecureRefresh = PendingInsecureRefresh(
                result: result,
                subscription: subscription,
                insecureProfileNames: newInsecureNames,
            )
            showInsecureRefreshConfirmation = true
        case let .needsSecurityConfirmation(result, changes, reviewedInsecureProfileNames):
            // `applyPendingInsecureRefresh` clears its slot before this chained
            // outcome arrives, so both slots empty means no other refresh's
            // review is being overwritten.
            guard pendingInsecureRefresh == nil, pendingSecurityRefresh == nil else {
                importNotice = deferredReviewNotice(for: subscription)
                return
            }
            pendingSecurityRefresh = PendingSecurityRefresh(
                result: result,
                subscription: subscription,
                changes: changes,
                reviewedInsecureProfileNames: reviewedInsecureProfileNames,
            )
            // When this follows the allow-insecure alert, let that presentation
            // finish dismissing before presenting the security review.
            DispatchQueue.main.async {
                presentPendingSheet()
            }
        case let .failed(message):
            importNotice = ProfileImportNotice(title: "Refresh Failed", message: message)
        }
    }

    static func canSaveEditor<Value: Encodable>(original: Value, isNew: Bool, current: Value?) -> Bool {
        if isNew {
            return current == nil
        }
        guard let current else { return false }
        // Credential spelling is byte-sensitive. Swift String equality folds
        // canonically equivalent Unicode even if the provider changed bytes.
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let before = try? encoder.encode(original), let now = try? encoder.encode(current) else { return false }
        return before == now
    }

    static func newProfile() -> ProxyProfile {
        ProxyProfile(
            name: "New VLESS Node",
            endpoint: Endpoint(host: "", port: 443),
            options: .vless(VLESSOptions(uuid: "", flow: nil)),
            security: .tls(TLSOptions()),
        )
    }

    private static func newGroup(profiles: [ProxyProfile]) -> ProxyGroup {
        ProxyGroup(
            name: "New Group",
            type: .select,
            members: profiles.map { .profile($0.id) },
            defaultTarget: profiles.first.map { .profile($0.id) },
        )
    }
}

private enum ProfilesSection: CaseIterable {
    case nodes
    case subscriptions

    var title: String {
        switch self {
        case .nodes:
            "Nodes"
        case .subscriptions:
            "Subscriptions"
        }
    }
}

private enum ProfilesSheet: Identifiable {
    case profile(ProxyProfile, isNew: Bool)
    case group(ProxyGroup, isNew: Bool)
    case importText(prefill: String)
    case scanner
    case securityReview

    var id: String {
        switch self {
        case let .profile(profile, _):
            "profile-\(profile.id.uuidString)"
        case let .group(group, _):
            "group-\(group.id.uuidString)"
        case let .importText(prefill):
            // The prefill participates in identity so a hop:// payload arriving
            // while the sheet is already open re-presents it with the new text
            // instead of being silently dropped (sheet(item:) keys on `id`).
            prefill.isEmpty ? "import-text" : "import-text-\(prefill.hashValue)"
        case .scanner:
            "scanner"
        case .securityReview:
            "security-review"
        }
    }
}

/// A refresh parked behind the blocking allow-insecure confirmation because it
/// introduces new insecure nodes.
private struct PendingInsecureRefresh {
    let result: ImportResult
    let subscription: SubscriptionSource
    /// Names shown in the confirmation. Refreshes list only the *newly*
    /// insecure nodes — matched nodes that were already allow-insecure are not
    /// a new decision.
    let insecureProfileNames: [String]
}

private struct PendingSecurityRefresh {
    let result: ImportResult
    let subscription: SubscriptionSource
    let changes: [SubscriptionSecurityChange]
    let reviewedInsecureProfileNames: [String]
}

private struct ProfileImportNotice: Identifiable {
    let id = UUID()
    let title: String
    let message: String
}

private struct ShareQRItem: Identifiable {
    var id: String {
        link
    }

    let profileName: String
    let link: String
}

private struct ProfileRow: View {
    let profile: ProxyProfile
    let isSelected: Bool
    let latency: NodeLatencyResult?

    var body: some View {
        GlassEffectContainer(spacing: 8) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(profile.name)
                        .font(.body.weight(.semibold))
                        .lineLimit(1)
                        .truncationMode(.tail)
                    Spacer()
                    if latency != nil || isSelected {
                        HStack(spacing: 8) {
                            if let latency {
                                LatencyBadge(result: latency)
                            }
                            if isSelected {
                                ActiveBadge()
                            }
                        }
                    }
                }
                ProfileSecuritySummary(profile: profile)
                ForEach(profile.importRuntimeWarnings, id: \.self) { warning in
                    Label(warning, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .padding(.vertical, 2)
        .animation(.snappy, value: isSelected)
    }
}

private struct LatencyBadge: View {
    let result: NodeLatencyResult

    var body: some View {
        switch result {
        case .testing:
            HStack(spacing: 4) {
                ProgressView()
                    .controlSize(.mini)
                Text("Testing")
                    .font(.caption2.weight(.semibold))
            }
            .foregroundStyle(.secondary)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .glassEffect(.regular.tint(Color.secondary.opacity(0.14)), in: .capsule)
            .accessibilityLabel("Testing latency")
        case let .success(milliseconds):
            let color: Color = switch milliseconds {
            case ..<150:
                .green
            case ..<400:
                .orange
            default:
                .red
            }

            StatusPill("\(milliseconds) ms", tint: color, systemImage: "bolt.horizontal.fill")
                .accessibilityLabel("Latency \(milliseconds) milliseconds")
        case .udpOnly:
            StatusPill("UDP · use ICMP", tint: .secondary, systemImage: "info.circle")
                .accessibilityLabel("UDP-only node. Select ICMP in latency settings to test the host.")
        case let .failure(reason):
            StatusPill("Failed", tint: .red, systemImage: "exclamationmark.triangle.fill")
                .accessibilityLabel("Latency test failed. \(reason)")
        }
    }
}

private struct ProxyGroupRow: View {
    let group: ProxyGroup
    let isSelected: Bool

    var body: some View {
        GlassEffectContainer(spacing: 8) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(group.name)
                        .font(.body.weight(.semibold))
                        .lineLimit(1)
                    Spacer()
                    if isSelected {
                        ActiveBadge()
                    }
                }

                HStack(spacing: 6) {
                    Text(group.type.displayName)
                    Text("·")
                    Text("\(group.members.count) members")
                    if let latency = group.lastLatencyMilliseconds {
                        StatusPill("\(latency) ms", tint: .secondary, systemImage: "bolt.horizontal.fill")
                    }
                }
                .font(.subheadline)
                .foregroundStyle(group.isEnabled ? Color.secondary : Color.orange)

                if let warning = group.warning {
                    Text(warning)
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .lineLimit(1)
                }
            }
        }
        .padding(.vertical, 2)
        .animation(.snappy, value: isSelected)
    }
}

#Preview {
    NavigationStack {
        ProfilesView()
    }
    .environment(HopStore.preview)
}
