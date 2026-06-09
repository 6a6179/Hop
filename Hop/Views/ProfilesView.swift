import SwiftUI
import VisionKit

struct ProfilesView: View {
    @Environment(HopStore.self) private var store
    @State private var selectedSection: ProfilesSection = .nodes
    @State private var activeSheet: ProfilesSheet?
    @State private var importNotice: ProfileImportNotice?
    @State private var isHandlingScannedPayload = false
    @State private var refreshingSubscriptionIDs: Set<SubscriptionSource.ID> = []

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
                            activeSheet = .importText
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
                    saveImportedSubscription(subscription, result: result, addedTitle: "Subscription Added")
                }
            case .importText:
                ImportTextSheet(importService: importService) { saveResult in
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
    }

    private var nodesSection: some View {
        Section {
            if store.profiles.isEmpty {
                ContentUnavailableView("No Nodes", systemImage: "server.rack", description: Text("Import or add a proxy node."))
            } else {
                ForEach(store.profiles) { profile in
                    ProfileRow(profile: profile, isSelected: store.selectedTarget == .profile(profile.id), latency: store.nodeLatencies[profile.id])
                        .contentShape(Rectangle())
                        .onTapGesture {
                            store.selectedTarget = .profile(profile.id)
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
            Text("Nodes")
        } footer: {
            Text("Existing nodes live here. Use Import/Add for new nodes or subscriptions.")
        }
    }

    private var groupsSection: some View {
        Section {
            if store.groups.isEmpty {
                ContentUnavailableView("No Groups", systemImage: "rectangle.stack", description: Text("Create a manual or URL-tested proxy group."))
            } else {
                ForEach(store.groups) { group in
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
            } else {
                ForEach(store.subscriptions) { subscription in
                    let isRefreshing = refreshingSubscriptionIDs.contains(subscription.id)
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
            store.applyImport(result)
            selectedSection = .nodes
            importNotice = ProfileImportNotice(title: "Scanned Import Complete", message: result.summary)
        } catch {
            importNotice = ProfileImportNotice(title: "Could Not Import Code", message: error.localizedDescription)
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

    private func saveImportedSubscription(_ subscription: SubscriptionSource, result: ImportResult, addedTitle: String) {
        if let existing = store.subscriptions.first(where: { normalizedSubscriptionURL($0.url) == normalizedSubscriptionURL(subscription.url) }) {
            var refreshedSubscription = subscription
            refreshedSubscription.id = existing.id
            if isDefaultSubscriptionName(subscription.name, for: subscription.url) {
                refreshedSubscription.name = existing.name
            }
            store.applySubscriptionRefresh(result)
            store.updateSubscription(refreshedSubscription)
            selectedSection = .subscriptions
            importNotice = ProfileImportNotice(
                title: "Subscription Updated",
                message: "\(result.summary)\n\nExisting subscription URL refreshed in place; matching nodes were updated instead of duplicated.",
            )
        } else {
            store.applyImport(result)
            store.addSubscription(subscription)
            selectedSection = .subscriptions
            importNotice = ProfileImportNotice(title: addedTitle, message: result.summary)
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
        guard !refreshingSubscriptionIDs.contains(subscription.id) else {
            return
        }
        guard let url = URL(string: subscription.url) else {
            importNotice = ProfileImportNotice(title: "Could Not Refresh Subscription", message: "The subscription URL is invalid.")
            return
        }

        refreshingSubscriptionIDs.insert(subscription.id)
        Task {
            do {
                let result = try await importService.importSubscription(url: url)
                var refreshedSubscription = subscription
                refreshedSubscription.lastUpdatedAt = .now
                refreshedSubscription.lastImportSummary = result.summary
                await MainActor.run {
                    store.applySubscriptionRefresh(result)
                    store.updateSubscription(refreshedSubscription)
                    refreshingSubscriptionIDs.remove(subscription.id)
                    importNotice = ProfileImportNotice(title: "Subscription Refreshed", message: result.summary)
                }
            } catch {
                await MainActor.run {
                    refreshingSubscriptionIDs.remove(subscription.id)
                    importNotice = ProfileImportNotice(title: "Could Not Refresh Subscription", message: error.localizedDescription)
                }
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
    case importText
    case scanner

    var id: String {
        switch self {
        case let .profile(profile):
            "profile-\(profile.id.uuidString)"
        case let .group(group):
            "group-\(group.id.uuidString)"
        case .addSubscription:
            "add-subscription"
        case .importText:
            "import-text"
        case .scanner:
            "scanner"
        }
    }
}

private struct ProfileImportNotice: Identifiable {
    var id = UUID()
    var title: String
    var message: String
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

private struct ImportPreviewView: View {
    var result: ImportResult

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            LabeledContent("Nodes", value: "\(result.profiles.count)")
            LabeledContent("Groups", value: "\(result.groups.count)")
            LabeledContent("Rules", value: "\(result.rules.count)")
            LabeledContent("Warnings", value: "\(result.warnings.count)")

            ForEach(result.warnings.prefix(4)) { warning in
                Text(warning.message)
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .lineLimit(2)
            }
        }
    }
}

private enum ImportTextSaveResult {
    case importText(ImportResult)
    case subscription(SubscriptionSource, ImportResult)
}

private struct AddSubscriptionSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var urlString = ""
    @State private var errorMessage: String?
    @State private var isLoading = false

    var importService: ProxyImportService
    var onSave: (SubscriptionSource, ImportResult) -> Void

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    ProfileTextField("Name", text: $name, prompt: "Airport")
                    ProfileTextField("URL", text: $urlString, prompt: "https://example.com/sub")
                } header: {
                    Text("Subscription")
                } footer: {
                    Text("HTTPS subscriptions are downloaded once now. Plain and base64 encoded payloads are supported.")
                }

                Section {
                    Button {
                        addSubscription()
                    } label: {
                        if isLoading {
                            Label("Importing...", systemImage: "arrow.down.circle")
                        } else {
                            Label("Add Subscription & Import", systemImage: "link.badge.plus")
                        }
                    }
                    .disabled(isLoading || subscriptionURL == nil)
                }

                if let errorMessage {
                    Section {
                        Text(errorMessage)
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Add Subscription")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                    .disabled(isLoading)
                }
            }
        }
    }

    private var subscriptionURL: URL? {
        URL(string: urlString.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private func addSubscription() {
        guard let url = subscriptionURL else {
            return
        }
        isLoading = true
        errorMessage = nil
        Task {
            do {
                let result = try await importService.importSubscription(url: url)
                let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
                let subscription = SubscriptionSource(
                    name: trimmedName.isEmpty ? url.host() ?? "Subscription" : trimmedName,
                    url: url.absoluteString,
                    lastUpdatedAt: .now,
                    lastImportSummary: result.summary,
                )
                await MainActor.run {
                    onSave(subscription, result)
                    dismiss()
                }
            } catch {
                await MainActor.run {
                    errorMessage = error.localizedDescription
                    isLoading = false
                }
            }
        }
    }
}

private struct ImportTextSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var importText = ""
    @State private var importResult: ImportResult?
    @State private var importError: String?
    @State private var detectedSubscriptionURL: URL?
    @State private var isLoading = false

    var importService: ProxyImportService
    var onSave: (ImportTextSaveResult) -> Void

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Paste node links, subscription text, or Shadowrocket .conf", text: $importText, axis: .vertical)
                        .lineLimit(6 ... 14)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()

                    Button {
                        previewImport()
                    } label: {
                        if isLoading {
                            Label("Previewing...", systemImage: "arrow.down.circle")
                        } else {
                            Label("Preview Import", systemImage: "eye")
                        }
                    }
                    .disabled(isLoading || importText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                } header: {
                    Text("Paste Import")
                } footer: {
                    Text("Subscription URLs are detected and saved as subscriptions. Proxy share links and base64/plain payloads are imported as nodes, groups, or rules.")
                }

                if let importResult {
                    Section(detectedSubscriptionURL == nil ? "Import Preview" : "Subscription Preview") {
                        if let detectedSubscriptionURL {
                            LabeledContent("URL") {
                                Text(detectedSubscriptionURL.absoluteString)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                        }
                        ImportPreviewView(result: importResult)
                    }
                }

                if let importError {
                    Section {
                        Text(importError)
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Import")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                    .disabled(isLoading)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        guard let importResult else {
                            return
                        }
                        if let detectedSubscriptionURL {
                            onSave(.subscription(
                                SubscriptionSource(
                                    name: detectedSubscriptionURL.host() ?? "Subscription",
                                    url: detectedSubscriptionURL.absoluteString,
                                    lastUpdatedAt: .now,
                                    lastImportSummary: importResult.summary,
                                ),
                                importResult,
                            ))
                        } else {
                            onSave(.importText(importResult))
                        }
                        dismiss()
                    }
                    .disabled(isLoading || (importResult?.isEmpty ?? true))
                }
            }
        }
    }

    private func previewImport() {
        let trimmed = importText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let payload = ProfileImportPayloadDetector().detect(trimmed) else {
            importResult = nil
            detectedSubscriptionURL = nil
            importError = ProxyLinkParseError.invalidURL.localizedDescription
            return
        }

        importError = nil
        importResult = nil
        detectedSubscriptionURL = nil

        switch payload {
        case let .subscription(url):
            isLoading = true
            Task {
                do {
                    let result = try await importService.importSubscription(url: url)
                    await MainActor.run {
                        detectedSubscriptionURL = url
                        importResult = result
                        isLoading = false
                    }
                } catch {
                    await MainActor.run {
                        importError = error.localizedDescription
                        isLoading = false
                    }
                }
            }
        case let .importText(text):
            do {
                importResult = try importService.importText(text)
            } catch {
                importError = error.localizedDescription
            }
        }
    }
}

private struct QRCodeScannerSheet: View {
    @Environment(\.dismiss) private var dismiss

    var onPayload: (String) -> Void

    var body: some View {
        NavigationStack {
            Group {
                if DataScannerViewController.isSupported, DataScannerViewController.isAvailable {
                    QRCodeScannerRepresentable { payload in
                        onPayload(payload)
                        dismiss()
                    }
                } else {
                    ContentUnavailableView(
                        "Scanner Unavailable",
                        systemImage: "camera.viewfinder",
                        description: Text("Camera scanning is unavailable on this device or camera access is not allowed. Use + > Paste Links or Config instead."),
                    )
                    .padding()
                }
            }
            .navigationTitle("Scan Code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
            }
        }
    }
}

private struct QRCodeScannerRepresentable: UIViewControllerRepresentable {
    var onPayload: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onPayload: onPayload)
    }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let controller = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            recognizesMultipleItems: false,
            isHighFrameRateTrackingEnabled: false,
            isPinchToZoomEnabled: true,
            isGuidanceEnabled: true,
            isHighlightingEnabled: true,
        )
        controller.delegate = context.coordinator
        try? controller.startScanning()
        return controller
    }

    func updateUIViewController(_: DataScannerViewController, context _: Context) {}

    static func dismantleUIViewController(_ uiViewController: DataScannerViewController, coordinator _: Coordinator) {
        uiViewController.stopScanning()
    }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private var didScan = false
        private let onPayload: (String) -> Void

        init(onPayload: @escaping (String) -> Void) {
            self.onPayload = onPayload
        }

        func dataScanner(_ dataScanner: DataScannerViewController, didTapOn item: RecognizedItem) {
            handle([item], dataScanner: dataScanner)
        }

        func dataScanner(_ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems _: [RecognizedItem]) {
            handle(addedItems, dataScanner: dataScanner)
        }

        private func handle(_ items: [RecognizedItem], dataScanner: DataScannerViewController) {
            guard !didScan else { return }
            for item in items {
                guard case let .barcode(barcode) = item,
                      let payload = barcode.payloadStringValue?.trimmingCharacters(in: .whitespacesAndNewlines),
                      !payload.isEmpty
                else {
                    continue
                }
                didScan = true
                dataScanner.stopScanning()
                onPayload(payload)
                return
            }
        }
    }
}

private struct ProxyGroupEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(HopStore.self) private var store
    @State private var draft: ProxyGroupEditorDraft

    var onSave: (ProxyGroup) -> Void

    init(group: ProxyGroup, onSave: @escaping (ProxyGroup) -> Void) {
        _draft = State(initialValue: ProxyGroupEditorDraft(group: group))
        self.onSave = onSave
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Basics") {
                    ProfileTextField("Name", text: $draft.name, capitalization: .words, autocorrectionDisabled: false)
                    Picker("Type", selection: $draft.type) {
                        Text("Manual Select").tag(ProxyGroupType.select)
                        Text("URL Test").tag(ProxyGroupType.urlTest)
                        if draft.type == .unsupported {
                            Text("Unsupported").tag(ProxyGroupType.unsupported)
                        }
                    }
                    Toggle("Enabled", isOn: $draft.isEnabled)
                }

                Section {
                    ForEach(store.profiles) { profile in
                        Toggle(profile.name, isOn: memberBinding(for: .profile(profile.id)))
                    }

                    ForEach(store.groups.filter { $0.id != draft.id }) { group in
                        Toggle(group.name, isOn: memberBinding(for: .group(group.id)))
                    }
                } header: {
                    Text("Members")
                } footer: {
                    Text("Groups can contain nodes and other groups. Avoid circular group nesting.")
                }

                Section("Default") {
                    Picker("Default", selection: $draft.defaultTarget) {
                        Text("First Member").tag(OutboundTarget?.none)
                        ForEach(draft.members, id: \.id) { target in
                            Text(store.displayName(for: target)).tag(Optional(target))
                        }
                    }
                }

                if draft.type == .urlTest {
                    Section("URL Test") {
                        ProfileTextField("URL", text: $draft.url, prompt: "https://www.gstatic.com/generate_204")
                        ProfileTextField("Interval", text: $draft.intervalSeconds, prompt: "600", keyboardType: .numberPad)
                        ProfileTextField("Tolerance", text: $draft.toleranceMilliseconds, prompt: "50", keyboardType: .numberPad)
                    }
                }

                if let warning = draft.warning {
                    Section {
                        Text(warning)
                            .foregroundStyle(.orange)
                    }
                }
            }
            .navigationTitle("Edit Group")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        guard let group = draft.group else {
                            return
                        }
                        onSave(group)
                        dismiss()
                    }
                    .disabled(draft.group == nil)
                }
            }
        }
    }

    private func memberBinding(for target: OutboundTarget) -> Binding<Bool> {
        Binding {
            draft.members.contains(target)
        } set: { isSelected in
            if isSelected, !draft.members.contains(target) {
                draft.members.append(target)
            } else if !isSelected {
                draft.members.removeAll { $0 == target }
                if draft.defaultTarget == target {
                    draft.defaultTarget = nil
                }
            }
        }
    }
}

private struct ProfileEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var draft: ProfileEditorDraft

    var onSave: (ProxyProfile) -> Void

    init(profile: ProxyProfile, onSave: @escaping (ProxyProfile) -> Void) {
        _draft = State(initialValue: ProfileEditorDraft(profile: profile))
        self.onSave = onSave
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Basics") {
                    ProfileTextField("Name", text: $draft.name, capitalization: .words, autocorrectionDisabled: false)
                    Picker("Protocol", selection: $draft.proto) {
                        ForEach(ProxyProtocol.allCases) { proto in
                            Text(proto.displayName).tag(proto)
                        }
                    }
                    ProfileTextField("Host", text: $draft.host)
                    ProfileTextField("Port", text: $draft.port, prompt: "443", keyboardType: .numberPad)
                }

                credentialsSection
                securitySection
                transportSection

                if let validationMessage = draft.validationMessage {
                    Section {
                        Label(validationMessage, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                }
            }
            .navigationTitle("Edit Profile")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }

                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        guard let profile = draft.profile else {
                            return
                        }
                        onSave(profile)
                        dismiss()
                    }
                    .disabled(draft.profile == nil)
                }
            }
        }
    }

    private var credentialsSection: some View {
        Section("Credentials") {
            switch draft.proto {
            case .vless:
                ProfileTextField("UUID", text: $draft.vlessUUID)
                ProfileTextField("Flow", text: $draft.vlessFlow, prompt: "xtls-rprx-vision")
                ProfileTextField("Encryption/Auth", text: $draft.vlessEncryption, prompt: "none")
                if draft.hasVLESSEncryption {
                    Label("\(draft.vlessEncryptionAuthLabel) is saved for compatibility, but Hop's current sing-box/libbox engine cannot run non-none VLESS Encryption/Auth yet.", systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                } else {
                    Text("Paste a full Xray VLESS encryption string here if your node uses X25519 or ML-KEM-768 auth.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            case .trojan:
                ProfileTextField("Password", text: $draft.trojanPassword)
            case .hysteria2:
                ProfileTextField("Password", text: $draft.hysteriaPassword)
                ProfileTextField("Obfuscation", text: $draft.hysteriaObfs, prompt: "salamander")
                ProfileTextField("Obfs Password", text: $draft.hysteriaObfsPassword)
            case .tuic:
                ProfileTextField("UUID", text: $draft.tuicUUID)
                ProfileTextField("Password", text: $draft.tuicPassword)
                ProfileTextField("Congestion Control", text: $draft.tuicCongestionControl, prompt: "bbr")
            case .shadowsocks:
                ProfileTextField("Method", text: $draft.shadowsocksMethod, prompt: "2022-blake3-aes-128-gcm")
                ProfileTextField("Password", text: $draft.shadowsocksPassword)
            case .vmess:
                ProfileTextField("UUID", text: $draft.vmessUUID)
                ProfileTextField("Security", text: $draft.vmessSecurity, prompt: "auto")
                ProfileTextField("Alter ID", text: $draft.vmessAlterID, prompt: "0", keyboardType: .numberPad)
            case .http:
                ProfileTextField("Username", text: $draft.httpUsername)
                ProfileTextField("Password", text: $draft.httpPassword)
            case .socks:
                ProfileTextField("Username", text: $draft.socksUsername)
                ProfileTextField("Password", text: $draft.socksPassword)
            case .wireGuard:
                ProfileTextField("Private Key", text: $draft.wireGuardPrivateKey)
                ProfileTextField("Peer Public Key", text: $draft.wireGuardPeerPublicKey)
                ProfileTextField("Local Addresses", text: $draft.wireGuardLocalAddresses, prompt: "10.0.0.2/32, fd00::2/128")
            case .anyTLS:
                ProfileTextField("Password", text: $draft.anyTLSPassword)
            }
        }
    }

    private var securitySection: some View {
        Section("Security") {
            Picker("Security", selection: $draft.securityLayer) {
                ForEach(SecurityLayer.allCases) { layer in
                    Text(layer.displayName).tag(layer)
                }
            }

            switch draft.securityLayer {
            case .none:
                Label("No TLS or REALITY will be configured.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.secondary)
            case .tls:
                ProfileTextField("Server Name / SNI", text: $draft.tlsServerName)
                MultiSelectMenu("ALPN", options: ProfileEditorChoices.alpn, selection: $draft.tlsALPN)
                UTLSFingerprintPicker(selection: $draft.tlsFingerprint)
                Toggle("Allow Insecure", isOn: $draft.tlsAllowInsecure)
                if draft.tlsAllowInsecure {
                    Label("Disables TLS certificate verification. Traffic to this server can be intercepted.", systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                }
            case .reality:
                ProfileTextField("Public Key", text: $draft.realityPublicKey)
                ProfileTextField("Short ID", text: $draft.realityShortID)
                ProfileTextField("Server Name / SNI", text: $draft.realityServerName)
                ProfileTextField("SpiderX (spx)", text: $draft.realitySpiderX, prompt: "/")
                Text("SpiderX is the REALITY crawler path from share links. Leave blank only if your server expects the default.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                ProfileTextField("ML-DSA-65 Verify", text: $draft.realityMLDSA65Verify)
                if draft.hasRealityMLDSA65Verify {
                    Label("pqv / ML-DSA-65 is preserved in this profile, but Hop's bundled sing-box/libbox engine cannot enforce it yet.", systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                }
                MultiSelectMenu("ALPN", options: ProfileEditorChoices.alpn, selection: $draft.tlsALPN)
                Text("ALPN is a Hop profile setting emitted to sing-box. 3X-UI may not expose REALITY ALPN; configure the server separately if it needs ALPN.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                UTLSFingerprintPicker(selection: $draft.realityFingerprint)
            }
        }
    }

    private var transportSection: some View {
        Section("Transport") {
            Picker("Type", selection: $draft.transportType) {
                ForEach(TransportType.allCases) { type in
                    Text(type.displayName).tag(type)
                }
            }

            switch draft.transportType {
            case .tcp, .quic:
                EmptyView()
            case .websocket, .httpUpgrade:
                ProfileTextField("Path", text: $draft.transportPath, prompt: "/")
                ProfileTextField("Host Header", text: $draft.transportHost)
            case .grpc:
                ProfileTextField("Service Name", text: $draft.transportServiceName)
            }
        }
    }
}

private struct ProfileTextField: View {
    var title: String
    @Binding var text: String
    var prompt: String
    var keyboardType: UIKeyboardType
    var capitalization: TextInputAutocapitalization
    var autocorrectionDisabled: Bool

    init(
        _ title: String,
        text: Binding<String>,
        prompt: String = "",
        keyboardType: UIKeyboardType = .default,
        capitalization: TextInputAutocapitalization = .never,
        autocorrectionDisabled: Bool = true,
    ) {
        self.title = title
        _text = text
        self.prompt = prompt
        self.keyboardType = keyboardType
        self.capitalization = capitalization
        self.autocorrectionDisabled = autocorrectionDisabled
    }

    var body: some View {
        LabeledContent(title) {
            TextField(prompt, text: $text)
                .multilineTextAlignment(.trailing)
                .keyboardType(keyboardType)
                .textInputAutocapitalization(capitalization)
                .autocorrectionDisabled(autocorrectionDisabled)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(maxWidth: 220)
        }
    }
}

private struct UTLSFingerprintPicker: View {
    @Binding var selection: String

    var body: some View {
        Picker("uTLS Fingerprint", selection: $selection) {
            ForEach(options, id: \.self) { option in
                Text(ProfileEditorChoices.utlsFingerprintTitle(option)).tag(option)
            }
        }
    }

    private var options: [String] {
        let current = selection.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !current.isEmpty, !ProfileEditorChoices.utlsFingerprints.contains(current) else {
            return ProfileEditorChoices.utlsFingerprints
        }
        return [current] + ProfileEditorChoices.utlsFingerprints
    }
}

private struct MultiSelectMenu: View {
    var title: String
    var options: [String]
    @Binding var selection: Set<String>

    init(_ title: String, options: [String], selection: Binding<Set<String>>) {
        self.title = title
        self.options = options
        _selection = selection
    }

    var body: some View {
        Menu {
            ForEach(options, id: \.self) { option in
                Toggle(option, isOn: binding(for: option))
            }
        } label: {
            LabeledContent(title) {
                HStack(spacing: 4) {
                    Text(summary)
                    Image(systemName: "chevron.up.chevron.down")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .buttonStyle(.plain)
    }

    private var summary: String {
        let selected = options.filter { selection.contains($0) }
        return selected.isEmpty ? "None" : selected.joined(separator: ", ")
    }

    private func binding(for option: String) -> Binding<Bool> {
        Binding {
            selection.contains(option)
        } set: { isSelected in
            if isSelected {
                selection.insert(option)
            } else {
                selection.remove(option)
            }
        }
    }
}

private enum ProfileEditorChoices {
    static let utlsFingerprints = [
        "chrome",
        "firefox",
        "edge",
        "safari",
        "ios",
        "android",
        "random",
        "randomized",
    ]

    static let alpn = [
        "h2",
        "http/1.1",
        "h3",
    ]

    static func utlsFingerprintTitle(_ value: String) -> String {
        switch value {
        case "ios":
            "iOS"
        default:
            value.capitalized
        }
    }
}

private struct ProfileEditorDraft {
    var id: UUID
    var name: String
    var proto: ProxyProtocol
    var host: String
    var port: String

    var vlessUUID = ""
    var vlessFlow = ""
    var vlessEncryption = ""
    var trojanPassword = ""
    var hysteriaPassword = ""
    var hysteriaObfs = ""
    var hysteriaObfsPassword = ""
    var tuicUUID = ""
    var tuicPassword = ""
    var tuicCongestionControl = ""
    var shadowsocksMethod = ""
    var shadowsocksPassword = ""
    var vmessUUID = ""
    var vmessSecurity = "auto"
    var vmessAlterID = "0"
    var httpUsername = ""
    var httpPassword = ""
    var socksUsername = ""
    var socksPassword = ""
    var wireGuardPrivateKey = ""
    var wireGuardPeerPublicKey = ""
    var wireGuardLocalAddresses = ""
    var anyTLSPassword = ""

    var securityLayer: SecurityLayer
    var tlsServerName = ""
    var tlsALPN: Set<String> = []
    var tlsFingerprint = "chrome"
    var tlsAllowInsecure = false
    var realityPublicKey = ""
    var realityShortID = ""
    var realityServerName = ""
    var realitySpiderX = ""
    var realityMLDSA65Verify = ""
    var realityFingerprint = "chrome"

    var transportType: TransportType
    var transportPath = ""
    var transportHost = ""
    var transportServiceName = ""

    init(profile: ProxyProfile) {
        id = profile.id
        name = profile.name
        proto = profile.proto
        host = profile.endpoint.host
        port = String(profile.endpoint.port)
        securityLayer = profile.security.layer
        transportType = profile.transport.type

        switch profile.options {
        case let .vless(options):
            vlessUUID = options.uuid
            vlessFlow = options.flow ?? ""
            vlessEncryption = options.encryption ?? ""
        case let .trojan(options):
            trojanPassword = options.password
        case let .hysteria2(options):
            hysteriaPassword = options.password
            hysteriaObfs = options.obfs ?? ""
            hysteriaObfsPassword = options.obfsPassword ?? ""
        case let .tuic(options):
            tuicUUID = options.uuid
            tuicPassword = options.password
            tuicCongestionControl = options.congestionControl ?? ""
        case let .shadowsocks(options):
            shadowsocksMethod = options.method
            shadowsocksPassword = options.password
        case let .vmess(options):
            vmessUUID = options.uuid
            vmessSecurity = options.security
            vmessAlterID = String(options.alterID)
        case let .http(options):
            httpUsername = options.username ?? ""
            httpPassword = options.password ?? ""
        case let .socks(options):
            socksUsername = options.username ?? ""
            socksPassword = options.password ?? ""
        case let .wireGuard(options):
            wireGuardPrivateKey = options.privateKey
            wireGuardPeerPublicKey = options.peerPublicKey
            wireGuardLocalAddresses = options.localAddress.joined(separator: ", ")
        case let .anyTLS(options):
            anyTLSPassword = options.password
        }

        if let tls = profile.security.tls {
            tlsServerName = tls.serverName ?? ""
            tlsALPN = Set(tls.alpn)
            tlsFingerprint = tls.utlsFingerprint ?? "chrome"
            tlsAllowInsecure = tls.allowInsecure
        }

        if let reality = profile.security.reality {
            realityPublicKey = reality.publicKey
            realityShortID = reality.shortID ?? ""
            realityServerName = reality.serverName ?? ""
            realitySpiderX = reality.spiderX ?? ""
            realityMLDSA65Verify = reality.mldsa65Verify ?? ""
            realityFingerprint = reality.utlsFingerprint
        }

        transportPath = profile.transport.path ?? ""
        transportHost = profile.transport.host ?? ""
        transportServiceName = profile.transport.serviceName ?? ""
    }

    var validationMessage: String? {
        guard !trimmed(name).isEmpty else {
            return "Name is required."
        }
        guard !trimmed(host).isEmpty else {
            return "Host is required."
        }
        guard let portNumber = Int(trimmed(port)), (1 ... 65535).contains(portNumber) else {
            return "Port must be between 1 and 65535."
        }

        switch proto {
        case .vless:
            guard !trimmed(vlessUUID).isEmpty else { return "VLESS UUID is required." }
        case .trojan:
            guard !trimmed(trojanPassword).isEmpty else { return "Trojan password is required." }
        case .hysteria2:
            guard !trimmed(hysteriaPassword).isEmpty else { return "Hysteria2 password is required." }
        case .tuic:
            guard !trimmed(tuicUUID).isEmpty else { return "TUIC UUID is required." }
            guard !trimmed(tuicPassword).isEmpty else { return "TUIC password is required." }
        case .shadowsocks:
            guard !trimmed(shadowsocksMethod).isEmpty else { return "Shadowsocks method is required." }
            guard !trimmed(shadowsocksPassword).isEmpty else { return "Shadowsocks password is required." }
        case .vmess:
            guard !trimmed(vmessUUID).isEmpty else { return "VMess UUID is required." }
            guard Int(trimmed(vmessAlterID)) != nil else { return "VMess Alter ID must be a number." }
        case .http, .socks:
            break
        case .wireGuard:
            guard !trimmed(wireGuardPrivateKey).isEmpty else { return "WireGuard private key is required." }
            guard !trimmed(wireGuardPeerPublicKey).isEmpty else { return "WireGuard peer public key is required." }
            guard !list(from: wireGuardLocalAddresses).isEmpty else { return "WireGuard local address is required." }
        case .anyTLS:
            guard !trimmed(anyTLSPassword).isEmpty else { return "AnyTLS password is required." }
        }

        if securityLayer == .reality, trimmed(realityPublicKey).isEmpty {
            return "REALITY public key is required."
        }

        return nil
    }

    var profile: ProxyProfile? {
        guard validationMessage == nil, let portNumber = Int(trimmed(port)) else {
            return nil
        }

        return ProxyProfile(
            id: id,
            name: trimmed(name),
            endpoint: Endpoint(host: trimmed(host), port: portNumber),
            proto: proto,
            options: protocolOptions,
            security: securityOptions,
            transport: transportOptions,
        )
    }

    private var protocolOptions: ProtocolOptions {
        switch proto {
        case .vless:
            .vless(VLESSOptions(uuid: trimmed(vlessUUID), flow: optional(vlessFlow), encryption: optional(vlessEncryption)))
        case .trojan:
            .trojan(TrojanOptions(password: trimmed(trojanPassword)))
        case .hysteria2:
            .hysteria2(Hysteria2Options(password: trimmed(hysteriaPassword), obfs: optional(hysteriaObfs), obfsPassword: optional(hysteriaObfsPassword)))
        case .tuic:
            .tuic(TUICOptions(uuid: trimmed(tuicUUID), password: trimmed(tuicPassword), congestionControl: optional(tuicCongestionControl)))
        case .shadowsocks:
            .shadowsocks(ShadowsocksOptions(method: trimmed(shadowsocksMethod), password: trimmed(shadowsocksPassword)))
        case .vmess:
            .vmess(VMessOptions(uuid: trimmed(vmessUUID), security: trimmed(vmessSecurity).isEmpty ? "auto" : trimmed(vmessSecurity), alterID: Int(trimmed(vmessAlterID)) ?? 0))
        case .http:
            .http(HTTPOptions(username: optional(httpUsername), password: optional(httpPassword)))
        case .socks:
            .socks(SOCKSOptions(username: optional(socksUsername), password: optional(socksPassword)))
        case .wireGuard:
            .wireGuard(WireGuardOptions(privateKey: trimmed(wireGuardPrivateKey), peerPublicKey: trimmed(wireGuardPeerPublicKey), localAddress: list(from: wireGuardLocalAddresses)))
        case .anyTLS:
            .anyTLS(AnyTLSOptions(password: trimmed(anyTLSPassword)))
        }
    }

    private var securityOptions: ProxySecurity {
        switch securityLayer {
        case .none:
            .none
        case .tls:
            .tls(TLSOptions(serverName: optional(tlsServerName), alpn: selectedALPN, allowInsecure: tlsAllowInsecure, utlsFingerprint: optional(tlsFingerprint) ?? "chrome"))
        case .reality:
            .reality(
                RealityOptions(
                    publicKey: trimmed(realityPublicKey),
                    shortID: optional(realityShortID),
                    serverName: optional(realityServerName),
                    spiderX: optional(realitySpiderX),
                    mldsa65Verify: optional(realityMLDSA65Verify),
                    utlsFingerprint: optional(realityFingerprint) ?? "chrome",
                ),
                alpn: selectedALPN,
            )
        }
    }

    private var transportOptions: TransportOptions {
        TransportOptions(
            type: transportType,
            path: optional(transportPath),
            host: optional(transportHost),
            serviceName: optional(transportServiceName),
        )
    }

    private var selectedALPN: [String] {
        ProfileEditorChoices.alpn.filter { tlsALPN.contains($0) }
    }

    private func optional(_ value: String) -> String? {
        let value = trimmed(value)
        return value.isEmpty ? nil : value
    }

    var hasVLESSEncryption: Bool {
        VLESSOptions(uuid: "", flow: nil, encryption: vlessEncryption).normalizedEncryption != nil
    }

    var vlessEncryptionAuthLabel: String {
        VLESSOptions(uuid: "", flow: nil, encryption: vlessEncryption).encryptionAuthLabel
    }

    var hasRealityMLDSA65Verify: Bool {
        !trimmed(realityMLDSA65Verify).isEmpty
    }

    private func list(from value: String) -> [String] {
        value
            .split(separator: ",")
            .map { trimmed(String($0)) }
            .filter { !$0.isEmpty }
    }

    private func trimmed(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

private struct ProxyGroupEditorDraft {
    var id: UUID
    var name: String
    var type: ProxyGroupType
    var members: [OutboundTarget]
    var defaultTarget: OutboundTarget?
    var url: String
    var intervalSeconds: String
    var toleranceMilliseconds: String
    var isEnabled: Bool
    var importedType: String?
    var warning: String?
    var lastLatencyMilliseconds: Int?

    init(group: ProxyGroup) {
        id = group.id
        name = group.name
        type = group.type
        members = group.members
        defaultTarget = group.defaultTarget
        url = group.testOptions.url
        intervalSeconds = String(group.testOptions.intervalSeconds)
        toleranceMilliseconds = String(group.testOptions.toleranceMilliseconds)
        isEnabled = group.isEnabled
        importedType = group.importedType
        warning = group.warning
        lastLatencyMilliseconds = group.lastLatencyMilliseconds
    }

    var group: ProxyGroup? {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty,
              !members.isEmpty,
              let interval = Int(intervalSeconds.trimmingCharacters(in: .whitespacesAndNewlines)),
              let tolerance = Int(toleranceMilliseconds.trimmingCharacters(in: .whitespacesAndNewlines))
        else {
            return nil
        }

        let trimmedURL = url.trimmingCharacters(in: .whitespacesAndNewlines)

        return ProxyGroup(
            id: id,
            name: trimmedName,
            type: type,
            members: members,
            defaultTarget: defaultTarget,
            testOptions: ProxyGroupTestOptions(
                // Keep the editor in agreement with the import path and config
                // builder: a disallowed/empty probe URL falls back to the default
                // so the persisted state never holds an SSRF-style probe target.
                url: ImportPolicy.isAllowedProbeURL(trimmedURL) ? trimmedURL : ProxyGroupTestOptions.defaultURL,
                intervalSeconds: ImportPolicy.clampURLTestInterval(interval),
                toleranceMilliseconds: ImportPolicy.clampURLTestTolerance(tolerance),
            ),
            isEnabled: isEnabled,
            importedType: importedType,
            warning: warning,
            lastLatencyMilliseconds: lastLatencyMilliseconds,
        )
    }
}

#Preview {
    NavigationStack {
        ProfilesView()
    }
    .environment(HopStore.preview)
}
