import SwiftUI
import UniformTypeIdentifiers

struct ProfilesView: View {
    @Environment(HopStore.self) private var store
    @State private var selectedSection: ProfilesSection = .nodes
    @State private var activeSheet: ProfilesSheet?
    @State private var importNotice: ProfileImportNotice?
    @State private var searchText = ""
    /// A refresh held back because it would add new allow-insecure nodes;
    /// applied only after the user confirms.
    @State private var pendingInsecureRefresh: PendingInsecureRefresh?
    @State private var showInsecureRefreshConfirmation = false
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
                groupsSection
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
                        Button("Paste Links, Config, or Subscription", systemImage: "doc.on.clipboard") {
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
                .buttonStyle(.glass)
            }
        }
        .sheet(item: $activeSheet) { sheet in
            switch sheet {
            case let .profile(profile):
                ProfileEditorView(profile: profile) { updatedProfile in
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
                        saveImportedSubscription(subscription, result: result, addedTitle: "Subscription URL Imported")
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
        ) {
            applyPendingInsecureRefresh()
        }
        .onAppear {
            consumePendingExternalImport()
        }
        .onChange(of: store.pendingExternalImportText) {
            consumePendingExternalImport()
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
                ContentUnavailableView("No Nodes", systemImage: "server.rack", description: Text("Import or add a proxy node."))
            } else if profiles.isEmpty {
                ContentUnavailableView.search(text: searchText)
            } else {
                ForEach(profiles) { profile in
                    ProfileRow(profile: profile, isSelected: store.selectedTarget == .profile(profile.id), latency: store.nodeLatencies[profile.id])
                        .contentShape(Rectangle())
                        .onTapGesture {
                            store.selectedTarget = .profile(profile.id)
                        }
                        .contextMenu {
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
                    .buttonStyle(.glass)
                    .controlSize(.small)
                    .font(.caption)
                    .disabled(store.nodeLatencies.values.contains(.testing))
                }
            }
        } footer: {
            Text("Existing nodes live here. Use Import/Add for new nodes or subscriptions.")
        }
    }

    private var groupsSection: some View {
        let groups = visibleGroups
        return Section {
            if store.groups.isEmpty {
                ContentUnavailableView("No Groups", systemImage: "rectangle.stack", description: Text("Create a manual or URL-tested proxy group."))
            } else if groups.isEmpty {
                ContentUnavailableView.search(text: searchText)
            } else {
                ForEach(groups) { group in
                    ProxyGroupRow(group: group, isSelected: store.selectedTarget == .group(group.id))
                        .contentShape(Rectangle())
                        .onTapGesture {
                            if group.isEnabled {
                                store.selectedTarget = .group(group.id)
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
        } footer: {
            Text("Existing groups live with nodes because both can be selected as active proxy targets.")
        }
    }

    private var subscriptionsSection: some View {
        let subscriptions = visibleSubscriptions
        return Section {
            if store.subscriptions.isEmpty {
                ContentUnavailableView(
                    "No Subscriptions",
                    systemImage: "link",
                    description: Text("Use + to add a subscription URL or scan a QR code."),
                )
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
                            .buttonStyle(.glass)
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
            Text("Refresh downloads the subscription again and updates matching nodes/groups in place instead of appending duplicates.")
        }
    }

    private func applyPendingInsecureRefresh() {
        guard let pending = pendingInsecureRefresh else {
            return
        }
        pendingInsecureRefresh = nil
        store.confirmInsecureSubscriptionRefresh(pending.result, for: pending.subscription)
        selectedSection = .subscriptions
        importNotice = ProfileImportNotice(title: "Subscription Updated", message: pending.result.summary)
    }

    /// Sheet flows already ran the allow-insecure confirmation before handing
    /// the result over; manual refreshes gate new insecure nodes separately.
    private func saveImportedSubscription(_ subscription: SubscriptionSource, result: ImportResult, addedTitle: String) {
        if let existing = store.subscriptions.first(where: { normalizedSubscriptionURL($0.url) == normalizedSubscriptionURL(subscription.url) }) {
            var refreshedSubscription = subscription
            refreshedSubscription.id = existing.id
            if isDefaultSubscriptionName(subscription.name, for: subscription.url) {
                refreshedSubscription.name = existing.name
            }

            store.applySubscriptionRefresh(result, updating: refreshedSubscription)
            selectedSection = .subscriptions
            importNotice = ProfileImportNotice(
                title: "Subscription Updated",
                message: "\(result.summary)\n\nExisting subscription URL refreshed in place; matching nodes were updated instead of duplicated.",
            )
        } else {
            addNewSubscription(subscription, result: result, addedTitle: addedTitle)
        }
    }

    private func addNewSubscription(_ subscription: SubscriptionSource, result: ImportResult, addedTitle: String) {
        store.applyImport(result)
        store.addSubscription(subscription)
        selectedSection = .subscriptions
        importNotice = ProfileImportNotice(title: addedTitle, message: result.summary)
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
        Task {
            switch await store.refreshSubscription(subscription) {
            case let .applied(summary):
                importNotice = ProfileImportNotice(title: "Subscription Refreshed", message: summary)
            case let .needsInsecureConfirmation(result, newInsecureNames):
                pendingInsecureRefresh = PendingInsecureRefresh(result: result, subscription: subscription, insecureProfileNames: newInsecureNames)
                showInsecureRefreshConfirmation = true
            case let .failed(message):
                importNotice = ProfileImportNotice(title: "Could Not Refresh Subscription", message: message)
            }
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
