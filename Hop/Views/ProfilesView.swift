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
    @State private var showSecurityRefreshConfirmation = false
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
                            activeSheet = .profile(Self.newProfile())
                        }
                        Button("New Group", systemImage: "rectangle.stack.badge.plus") {
                            activeSheet = .group(Self.newGroup(profiles: store.profiles))
                        }
                    }
                } label: {
                    Label("Add", systemImage: "plus.circle")
                }
            }
        }
        .sheet(item: $activeSheet) { sheet in
            switch sheet {
            case let .profile(profile):
                ProfileEditorView(profile: profile, isNew: !store.profiles.contains(where: { $0.id == profile.id })) { updatedProfile in
                    if store.profiles.contains(where: { $0.id == updatedProfile.id }) {
                        store.updateProfile(updatedProfile)
                    } else {
                        store.addProfile(updatedProfile)
                    }
                    selectedSection = .nodes
                }
            case let .group(group):
                ProxyGroupEditorView(group: group) { updatedGroup in
                    if store.groups.contains(where: { $0.id == updatedGroup.id }) {
                        store.updateGroup(updatedGroup)
                    } else {
                        store.addGroup(updatedGroup)
                    }
                    selectedSection = .nodes
                }
            case let .importText(prefill):
                ImportTextSheet(importService: importService, initialText: prefill) { saveResult in
                    switch saveResult {
                    case let .importText(result):
                        store.applyImport(result)
                        selectedSection = .nodes
                        importNotice = ProfileImportNotice(title: "Import Complete", message: result.summary)
                    case let .subscription(subscription, result):
                        saveImportedSubscription(subscription, result: result, addedTitle: "Subscription Added")
                    }
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
        .confirmationDialog(
            "Apply Security Changes?",
            isPresented: $showSecurityRefreshConfirmation,
            titleVisibility: .visible,
        ) {
            Button("Apply Reviewed Changes", role: .destructive) {
                applyPendingSecurityRefresh()
            }
            Button("Cancel", role: .cancel) {
                pendingSecurityRefresh = nil
            }
        } message: {
            Text(pendingSecurityRefresh?.confirmationMessage ?? "")
        }
        .onAppear {
            consumePendingExternalImport()
        }
        .onChange(of: store.pendingExternalImportText) {
            consumePendingExternalImport()
        }
        // A payload that arrived while a sheet was up is consumed when the
        // presentation ends. The one-turn defer lets an already-scheduled
        // re-present (the scanner→import handoff) claim the sheet first;
        // `consumePendingExternalImport` re-checks and keeps the payload.
        .onChange(of: activeSheet == nil && shareQRItem == nil) { _, canPresent in
            if canPresent {
                DispatchQueue.main.async {
                    consumePendingExternalImport()
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

    /// Routes a `hop://` URL payload into the standard import sheet: prefilled
    /// for review, never applied directly — external apps don't get to skip
    /// the preview or the allow-insecure confirmation.
    private func consumePendingExternalImport() {
        guard let text = store.pendingExternalImportText else {
            return
        }
        // A payload can arrive while another sheet is presented. Setting the
        // sheet state mid-presentation can drop the import sheet entirely —
        // losing the payload — and force-dismissing would destroy an edit in
        // progress. Leave the payload in the store; the presentation observer
        // retries once the current sheet closes.
        guard activeSheet == nil, shareQRItem == nil else {
            return
        }
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
                            activeSheet = .profile(Self.newProfile())
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
                        ProfileRow(profile: profile, isSelected: store.selectedTarget == .profile(profile.id), latency: store.nodeLatencies[profile.id])
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(store.selectedTarget == .profile(profile.id) ? .isSelected : [])
                    .contextMenu {
                        Button("Edit", systemImage: "pencil") {
                            activeSheet = .profile(profile)
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
                            activeSheet = .profile(profile)
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
                    .disabled(store.nodeLatencies.values.contains(.testing))
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
                            activeSheet = .group(group)
                        }
                    }
                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                        Button(role: .destructive) {
                            store.deleteGroup(id: group.id)
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }

                        Button {
                            activeSheet = .group(group)
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

    /// Sheet flows already ran the allow-insecure confirmation before handing
    /// the result over; manual refreshes gate new insecure nodes separately.
    private func saveImportedSubscription(_ subscription: SubscriptionSource, result: ImportResult, addedTitle: String) {
        let result = result
            .droppingRules()
            .requiringSubscriptionGroupReview()
        if let existing = store.subscriptions.first(where: { normalizedSubscriptionURL($0.url) == normalizedSubscriptionURL(subscription.url) }) {
            var refreshedSubscription = subscription
            refreshedSubscription.id = existing.id
            if isDefaultSubscriptionName(subscription.name, for: subscription.url) {
                refreshedSubscription.name = existing.name
            }

            if store.applySubscriptionRefresh(result, updating: refreshedSubscription) {
                selectedSection = .subscriptions
                importNotice = ProfileImportNotice(
                    title: "Subscription Updated",
                    message: "\(result.summary)\n\nMatching nodes updated, not duplicated.",
                )
            } else {
                importNotice = ProfileImportNotice(
                    title: "Subscription Not Updated",
                    message: "Subscription storage limit exceeded.",
                )
            }
        } else {
            addNewSubscription(subscription, result: result, addedTitle: addedTitle)
        }
    }

    private func addNewSubscription(_ subscription: SubscriptionSource, result: ImportResult, addedTitle: String) {
        if store.applySubscriptionImport(result, adding: subscription) {
            selectedSection = .subscriptions
            importNotice = ProfileImportNotice(title: addedTitle, message: result.summary)
        } else {
            importNotice = ProfileImportNotice(
                title: "Subscription Not Added",
                message: "Subscription storage limit exceeded.",
            )
        }
    }

    private func normalizedSubscriptionURL(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard var components = URLComponents(string: trimmed) else {
            return trimmed
        }
        components.scheme = components.scheme?.lowercased()
        components.host = components.host?.lowercased()
        return components.url?.absoluteString ?? trimmed
    }

    private func isDefaultSubscriptionName(_ name: String, for urlString: String) -> Bool {
        guard let url = URL(string: urlString) else {
            return name == "Subscription"
        }
        return name == (url.host() ?? "Subscription")
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
            showSecurityRefreshConfirmation = true
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
                showSecurityRefreshConfirmation = true
            }
        case let .failed(message):
            importNotice = ProfileImportNotice(title: "Refresh Failed", message: message)
        }
    }

    private static func newProfile() -> ProxyProfile {
        ProxyProfile(
            name: "New VLESS Node",
            endpoint: Endpoint(host: "example.com", port: 443),
            options: .vless(VLESSOptions(uuid: "", flow: nil)),
            security: .tls(TLSOptions(serverName: "example.com")),
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
    case profile(ProxyProfile)
    case group(ProxyGroup)
    case importText(prefill: String)
    case scanner

    var id: String {
        switch self {
        case let .profile(profile):
            "profile-\(profile.id.uuidString)"
        case let .group(group):
            "group-\(group.id.uuidString)"
        case let .importText(prefill):
            // The prefill participates in identity so a hop:// payload arriving
            // while the sheet is already open re-presents it with the new text
            // instead of being silently dropped (sheet(item:) keys on `id`).
            prefill.isEmpty ? "import-text" : "import-text-\(prefill.hashValue)"
        case .scanner:
            "scanner"
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

    var confirmationMessage: String {
        let shown = changes.prefix(6).map(\.summary).joined(separator: "\n")
        let remainder = changes.count > 6 ? "\n…and \(changes.count - 6) more." : ""
        return "Security changes on \(changes.count) node\(changes.count == 1 ? "" : "s"). Apply only if expected:\n\n\(shown)\(remainder)"
    }
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
        case .failure:
            StatusPill("Failed", tint: .red, systemImage: "exclamationmark.triangle.fill")
                .accessibilityLabel("Latency test failed")
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
