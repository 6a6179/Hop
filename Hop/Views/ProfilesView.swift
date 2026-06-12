import SwiftUI
import UniformTypeIdentifiers

struct ProfilesView: View {
    @Environment(HopStore.self) private var store
    @State private var selectedSection: ProfilesSection = .nodes
    @State private var activeSheet: ProfilesSheet?
    @State private var importNotice: ProfileImportNotice?
    @State private var isHandlingScannedPayload = false
    @State private var searchText = ""
    /// An import held back because it would save allow-insecure nodes —
    /// QR-scanned payloads and subscription refreshes that introduce new
    /// insecure nodes; applied only after the user confirms (the sheet flows
    /// gate themselves).
    @State private var pendingInsecureScan: PendingInsecureScan?
    @State private var showInsecureScanConfirmation = false
    @State private var shareQRItem: ShareQRItem?

    private let importService = ProxyImportService()

    var body: some View {
        List {
            Section {
                Picker("Profile Section", selection: $selectedSection) {
                    ForEach(ProfilesSection.allCases) { section in
                        Text(section.title).tag(section)
                    }
                }
                .pickerStyle(.segmented)
            }

            if isHandlingScannedPayload {
                Section {
                    HStack(spacing: 12) {
                        ProgressView()
                        Text("Importing scanned code...")
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                }
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
                        Button("Paste Links or Config", systemImage: "doc.on.clipboard") {
                            activeSheet = .importText(prefill: "")
                        }
                        Button("Add Subscription URL", systemImage: "link.badge.plus") {
                            activeSheet = .addSubscription
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
            case .addSubscription:
                AddSubscriptionSheet(importService: importService) { subscription, result in
                    saveImportedSubscription(subscription, result: result, addedTitle: "Subscription Added", confirmedInsecureNodes: true)
                }
            case let .importText(prefill):
                ImportTextSheet(importService: importService, initialText: prefill) { saveResult in
                    switch saveResult {
                    case let .importText(result):
                        store.applyImport(result)
                        selectedSection = .nodes
                        importNotice = ProfileImportNotice(title: "Import Complete", message: result.summary)
                    case let .subscription(subscription, result):
                        saveImportedSubscription(subscription, result: result, addedTitle: "Subscription URL Imported", confirmedInsecureNodes: true)
                    }
                }
            case .scanner:
                QRCodeScannerSheet { payload in
                    activeSheet = nil
                    handleScannedPayload(payload)
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
            isPresented: $showInsecureScanConfirmation,
            profileNames: pendingInsecureScan?.insecureProfileNames ?? [],
        ) {
            applyPendingInsecureScan()
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
    private func matchesSearch(_ candidates: String...) -> Bool {
        let needle = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else {
            return true
        }
        return candidates.contains { $0.lowercased().contains(needle) }
    }

    private var visibleProfiles: [ProxyProfile] {
        store.profiles.filter { matchesSearch($0.name, $0.endpoint.host) }
    }

    private var visibleGroups: [ProxyGroup] {
        store.groups.filter { matchesSearch($0.name) }
    }

    private var visibleSubscriptions: [SubscriptionSource] {
        store.subscriptions.filter { matchesSearch($0.name, $0.url) }
    }

    private var nodesSection: some View {
        Section {
            if store.profiles.isEmpty {
                ContentUnavailableView("No Nodes", systemImage: "server.rack", description: Text("Import or add a proxy node."))
            } else if visibleProfiles.isEmpty {
                ContentUnavailableView.search(text: searchText)
            } else {
                ForEach(visibleProfiles) { profile in
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
                if visibleProfiles.count > 1 {
                    // Tests what the (possibly searched) list shows, so the
                    // button never probes nodes the user can't see.
                    Button("Test All") {
                        Task { await store.testAllLatencies(visibleProfiles) }
                    }
                    .font(.caption)
                    .disabled(store.nodeLatencies.values.contains(.testing))
                }
            }
        } footer: {
            Text("Existing nodes live here. Use Import/Add for new nodes or subscriptions.")
        }
    }

    private var groupsSection: some View {
        Section {
            if store.groups.isEmpty {
                ContentUnavailableView("No Groups", systemImage: "rectangle.stack", description: Text("Create a manual or URL-tested proxy group."))
            } else if visibleGroups.isEmpty {
                ContentUnavailableView.search(text: searchText)
            } else {
                ForEach(visibleGroups) { group in
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
        Section {
            if store.subscriptions.isEmpty {
                ContentUnavailableView(
                    "No Subscriptions",
                    systemImage: "link",
                    description: Text("Use + to add a subscription URL or scan a QR code."),
                )
            } else if visibleSubscriptions.isEmpty {
                ContentUnavailableView.search(text: searchText)
            } else {
                ForEach(visibleSubscriptions) { subscription in
                    let isRefreshing = store.refreshingSubscriptionIDs.contains(subscription.id)
                    HStack(spacing: 12) {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(subscription.name)
                                .font(.body.weight(.semibold))
                            Text(subscription.url)
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
                            .buttonStyle(.borderless)
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

    private func handleScannedPayload(_ payload: String) {
        let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            importNotice = ProfileImportNotice(title: "Empty Code", message: "The scanned code did not contain importable text.")
            return
        }

        switch ProfileImportPayloadDetector().detect(trimmed) {
        case let .subscription(url):
            importScannedSubscription(url)
        case let .importText(importText):
            importScannedText(importText)
        case nil:
            importNotice = ProfileImportNotice(title: "Empty Code", message: "The scanned code did not contain importable text.")
        }
    }

    private func importScannedText(_ text: String) {
        do {
            let result = try importService.importText(text)
            guard result.insecureTLSProfileNames.isEmpty else {
                pendingInsecureScan = PendingInsecureScan(result: result, action: .importText)
                showInsecureScanConfirmation = true
                return
            }
            applyScannedImport(result)
        } catch {
            importNotice = ProfileImportNotice(title: "Could Not Import Code", message: error.localizedDescription)
        }
    }

    private func applyScannedImport(_ result: ImportResult) {
        store.applyImport(result)
        selectedSection = .nodes
        importNotice = ProfileImportNotice(title: "Scanned Import Complete", message: result.summary)
    }

    private func applyPendingInsecureScan() {
        guard let pending = pendingInsecureScan else {
            return
        }
        pendingInsecureScan = nil
        switch pending.action {
        case .importText:
            applyScannedImport(pending.result)
        case let .addSubscription(subscription, addedTitle):
            addNewSubscription(subscription, result: pending.result, addedTitle: addedTitle)
        case let .refreshSubscription(subscription):
            store.confirmInsecureSubscriptionRefresh(pending.result, for: subscription)
            selectedSection = .subscriptions
            importNotice = ProfileImportNotice(title: "Subscription Updated", message: pending.result.summary)
        }
    }

    private func importScannedSubscription(_ url: URL) {
        isHandlingScannedPayload = true
        Task {
            do {
                let result = try await importService.importSubscription(url: url)
                let subscription = SubscriptionSource(
                    name: url.host() ?? "Subscription",
                    url: url.absoluteString,
                    lastUpdatedAt: .now,
                    lastImportSummary: result.summary,
                )
                await MainActor.run {
                    saveImportedSubscription(subscription, result: result, addedTitle: "Scanned Subscription Added")
                    isHandlingScannedPayload = false
                }
            } catch {
                await MainActor.run {
                    isHandlingScannedPayload = false
                    importNotice = ProfileImportNotice(title: "Could Not Import Subscription", message: error.localizedDescription)
                }
            }
        }
    }

    /// `confirmedInsecureNodes` is true for the sheet flows, which already ran
    /// the allow-insecure confirmation before handing the result over; the
    /// QR-scan path passes false so insecure nodes get gated here. The
    /// existing-subscription branch is a refresh: matched nodes are protected
    /// by the merger's downgrade guards, but *new* allow-insecure nodes still
    /// need the blocking confirmation before they are saved.
    private func saveImportedSubscription(_ subscription: SubscriptionSource, result: ImportResult, addedTitle: String, confirmedInsecureNodes: Bool = false) {
        if let existing = store.subscriptions.first(where: { normalizedSubscriptionURL($0.url) == normalizedSubscriptionURL(subscription.url) }) {
            var refreshedSubscription = subscription
            refreshedSubscription.id = existing.id
            if isDefaultSubscriptionName(subscription.name, for: subscription.url) {
                refreshedSubscription.name = existing.name
            }

            let newInsecureNames = SubscriptionRefreshMerger.newInsecureProfileNames(existing: store.profiles, imported: result.profiles)
            guard confirmedInsecureNodes || newInsecureNames.isEmpty else {
                pendingInsecureScan = PendingInsecureScan(result: result, action: .refreshSubscription(refreshedSubscription), insecureProfileNames: newInsecureNames)
                showInsecureScanConfirmation = true
                return
            }

            store.applySubscriptionRefresh(result, updating: refreshedSubscription)
            selectedSection = .subscriptions
            importNotice = ProfileImportNotice(
                title: "Subscription Updated",
                message: "\(result.summary)\n\nExisting subscription URL refreshed in place; matching nodes were updated instead of duplicated.",
            )
        } else if confirmedInsecureNodes || result.insecureTLSProfileNames.isEmpty {
            addNewSubscription(subscription, result: result, addedTitle: addedTitle)
        } else {
            pendingInsecureScan = PendingInsecureScan(result: result, action: .addSubscription(subscription, addedTitle: addedTitle))
            showInsecureScanConfirmation = true
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
                pendingInsecureScan = PendingInsecureScan(result: result, action: .refreshSubscription(subscription), insecureProfileNames: newInsecureNames)
                showInsecureScanConfirmation = true
            case let .failed(message):
                importNotice = ProfileImportNotice(title: "Could Not Refresh Subscription", message: message)
            }
        }
    }

    private static func newProfile() -> ProxyProfile {
        ProxyProfile(
            name: "New VLESS Node",
            endpoint: Endpoint(host: "example.com", port: 443),
            proto: .vless,
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

private enum ProfilesSection: String, CaseIterable, Identifiable {
    case nodes
    case subscriptions

    var id: String {
        rawValue
    }

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
    case addSubscription
    case importText(prefill: String)
    case scanner

    var id: String {
        switch self {
        case let .profile(profile):
            "profile-\(profile.id.uuidString)"
        case let .group(group):
            "group-\(group.id.uuidString)"
        case .addSubscription:
            "add-subscription"
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

/// An import parked behind the blocking allow-insecure confirmation: a
/// QR-scanned payload, a scanned subscription, or a refresh that introduces
/// new insecure nodes. `action` says how to apply it once confirmed.
private struct PendingInsecureScan {
    enum Action {
        case importText
        case addSubscription(SubscriptionSource, addedTitle: String)
        case refreshSubscription(SubscriptionSource)
    }

    var result: ImportResult
    var action: Action
    /// Names shown in the confirmation. Refreshes list only the *newly*
    /// insecure nodes — matched nodes that were already allow-insecure are not
    /// a new decision.
    var insecureProfileNames: [String]

    init(result: ImportResult, action: Action, insecureProfileNames: [String]? = nil) {
        self.result = result
        self.action = action
        self.insecureProfileNames = insecureProfileNames ?? result.insecureTLSProfileNames
    }
}

private struct ProfileImportNotice: Identifiable {
    var id = UUID()
    var title: String
    var message: String
}

private struct ShareQRItem: Identifiable {
    var id: String {
        link
    }

    var profileName: String
    var link: String
}

private struct ProfileRow: View {
    var profile: ProxyProfile
    var isSelected: Bool
    var latency: NodeLatencyResult?

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Text(profile.name)
                    .font(.body.weight(.semibold))
                    .lineLimit(1)
                    .truncationMode(.tail)
                Spacer()
                if let latency {
                    LatencyBadge(result: latency)
                }
                if isSelected {
                    ActiveBadge()
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
        .padding(.vertical, 2)
        .animation(.snappy, value: isSelected)
    }
}

private struct LatencyBadge: View {
    var result: NodeLatencyResult

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
            .accessibilityLabel("Testing latency")
        case let .success(milliseconds):
            badge(text: "\(milliseconds) ms", color: color(for: milliseconds), systemImage: "bolt.horizontal.fill")
                .accessibilityLabel("Latency \(milliseconds) milliseconds")
        case .failure:
            badge(text: "Failed", color: .red, systemImage: "exclamationmark.triangle.fill")
                .accessibilityLabel("Latency test failed")
        }
    }

    private func badge(text: String, color: Color, systemImage: String) -> some View {
        HStack(spacing: 4) {
            Image(systemName: systemImage)
                .font(.caption2)
            Text(text)
                .font(.caption2.weight(.semibold))
        }
        .foregroundStyle(color)
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(color.opacity(0.14), in: Capsule())
    }

    private func color(for milliseconds: Int) -> Color {
        switch milliseconds {
        case ..<150:
            .green
        case ..<400:
            .orange
        default:
            .red
        }
    }
}

private struct ProxyGroupRow: View {
    var group: ProxyGroup
    var isSelected: Bool

    var body: some View {
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
                    Text("·")
                    Text("\(latency) ms")
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
