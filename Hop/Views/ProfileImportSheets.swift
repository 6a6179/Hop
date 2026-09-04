import SwiftUI
import VisionKit

/// What an `ImportTextSheet` save produced: pasted text parsed into items, or
/// a detected subscription URL plus its fetched items.
enum ImportTextSaveResult {
    case importText(ImportResult)
    case subscription(SubscriptionSource, ImportResult)
}

extension View {
    /// Blocking confirmation shown before saving imported nodes that disable
    /// TLS certificate verification. The preview's warning rows are advisory;
    /// this makes the security downgrade an explicit user decision. Shared by
    /// the import sheets and the QR-scan flow in `ProfilesView`.
    func insecureTLSImportConfirmation(
        isPresented: Binding<Bool>,
        profileNames: [String],
        onCancel: @escaping () -> Void = {},
        onConfirm: @escaping () -> Void,
    ) -> some View {
        alert("Disable Certificate Verification?", isPresented: isPresented) {
            Button("Import Anyway", role: .destructive, action: onConfirm)
            Button("Cancel", role: .cancel, action: onCancel)
        } message: {
            Text("TLS verification is off for \(profileNames.count) node\(profileNames.count == 1 ? "" : "s"). Traffic can be intercepted.\n\n\(profileNames.prefix(5).joined(separator: ", "))\(profileNames.count > 5 ? ", …" : "")")
        }
    }
}

struct ImportTextDraft {
    var text: String {
        didSet {
            guard text != oldValue else { return }
            result = nil
            error = nil
            subscriptionURL = nil
        }
    }

    var result: ImportResult?
    var error: String?
    var subscriptionURL: URL?

    mutating func finishPreview(_ result: ImportResult, subscriptionURL: URL?, for input: String) throws {
        try Task.checkCancellation()
        guard text == input else { return }
        self.result = result
        self.subscriptionURL = subscriptionURL
        error = nil
    }
}

struct ImportTextSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var draft: ImportTextDraft
    @State private var isLoading = false
    @State private var previewTask: Task<Void, Never>?
    @State private var showInsecureTLSConfirmation = false

    let importService: ProxyImportService
    let onSave: (ImportTextSaveResult) -> Void

    /// `initialText` prefills the field (URL-scheme imports); the payload
    /// still goes through the same preview and confirmation gates as pasted
    /// text — prefilled is not pre-trusted.
    init(importService: ProxyImportService, initialText: String = "", onSave: @escaping (ImportTextSaveResult) -> Void) {
        self.importService = importService
        self.onSave = onSave
        _draft = State(initialValue: ImportTextDraft(text: initialText))
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Paste links, a subscription URL, or config text", text: $draft.text, axis: .vertical)
                        .lineLimit(6 ... 14)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .disabled(isLoading)

                    Button {
                        previewImport()
                    } label: {
                        if isLoading {
                            HStack {
                                ProgressView()
                                Text("Previewing…")
                            }
                        } else {
                            Label("Preview Import", systemImage: "eye")
                        }
                    }
                    .disabled(isLoading || trimmedImportText.isEmpty)
                } header: {
                    Text("Links or Config")
                } footer: {
                    Text("Preview fetches subscription URLs.")
                }

                if let importResult = draft.result {
                    Section(draft.subscriptionURL == nil ? "Import Preview" : "Subscription Preview") {
                        if let detectedSubscriptionURL = draft.subscriptionURL {
                            LabeledContent("URL") {
                                Text(SubscriptionSource(name: "Subscription", url: detectedSubscriptionURL.absoluteString).redactedDisplayURL)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                        }
                        ImportPreviewView(result: importResult)
                    }
                }

                if let importError = draft.error {
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
                        cancelPreview()
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        guard let importResult = draft.result else {
                            return
                        }
                        if importResult.insecureTLSProfileNames.isEmpty {
                            save(importResult)
                        } else {
                            showInsecureTLSConfirmation = true
                        }
                    }
                    .disabled(isLoading || (draft.result?.isEmpty ?? true))
                }
            }
            .insecureTLSImportConfirmation(
                isPresented: $showInsecureTLSConfirmation,
                profileNames: draft.result?.insecureTLSProfileNames ?? [],
            ) {
                if let importResult = draft.result {
                    save(importResult)
                }
            }
            .onAppear {
                autoPreviewPrefill()
            }
            .onDisappear {
                cancelPreview()
            }
        }
    }

    /// Prefilled share links (a tapped vless://… link, a scanned QR) parse
    /// locally, so preview them immediately — one tap less. Subscription URLs
    /// are NOT auto-fetched: opening a link must never trigger a network
    /// request to an arbitrary server without an explicit user action.
    private func autoPreviewPrefill() {
        let trimmed = trimmedImportText
        guard !trimmed.isEmpty, draft.result == nil, draft.error == nil, !isLoading else {
            return
        }
        guard case .importText = ProfileImportPayloadDetector.detect(trimmed) else {
            return
        }
        previewImport()
    }

    private func save(_ importResult: ImportResult) {
        if let detectedSubscriptionURL = draft.subscriptionURL {
            let importResult = importResult
                .droppingRules()
                .requiringSubscriptionGroupReview()
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

    private func previewImport() {
        cancelPreview()
        let input = draft.text
        let trimmed = trimmedImportText
        guard let payload = ProfileImportPayloadDetector.detect(trimmed) else {
            draft.result = nil
            draft.subscriptionURL = nil
            draft.error = ProxyLinkParseError.invalidURL.localizedDescription
            return
        }

        draft.error = nil
        draft.result = nil
        draft.subscriptionURL = nil

        isLoading = true
        previewTask = Task { @MainActor in
            do {
                let result: ImportResult
                let subscriptionURL: URL?
                switch payload {
                case let .subscription(url):
                    result = try await importService.importSubscription(url: url)
                        .droppingRules()
                        .requiringSubscriptionGroupReview()
                    subscriptionURL = url
                case let .importText(text):
                    result = try await importService.importTextOffMain(text)
                    subscriptionURL = nil
                }
                try draft.finishPreview(result, subscriptionURL: subscriptionURL, for: input)
            } catch {
                guard !Task.isCancelled, draft.text == input else { return }
                draft.error = error.localizedDescription
            }
            guard !Task.isCancelled else { return }
            isLoading = false
            previewTask = nil
        }
    }

    private func cancelPreview() {
        previewTask?.cancel()
        previewTask = nil
        isLoading = false
    }

    private var trimmedImportText: String {
        draft.text.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

private struct ImportPreviewView: View {
    @Environment(HopStore.self) private var store
    let result: ImportResult

    var body: some View {
        if !result.profiles.isEmpty {
            LabeledContent("Nodes", value: "\(result.profiles.count)")
            ForEach(result.profiles.prefix(3)) { profile in
                nodeRow(profile)
            }
            if result.profiles.count > 3 {
                DisclosureGroup("More Nodes (\(result.profiles.count - 3))") {
                    ForEach(result.profiles.dropFirst(3)) { profile in
                        nodeRow(profile)
                    }
                }
            }
        }

        if !result.groups.isEmpty {
            DisclosureGroup("Groups (\(result.groups.count))") {
                ForEach(result.groups) { group in
                    DisclosureGroup(group.name) {
                        LabeledContent("Type", value: group.type.displayName)
                        LabeledContent("Status", value: group.isEnabled ? "Enabled" : "Disabled")
                        LabeledContent("Default", value: group.defaultTarget.map(targetName) ?? "First Member")
                        DisclosureGroup("Members (\(group.members.count))") {
                            ForEach(Array(group.members.enumerated()), id: \.offset) { _, target in
                                Text(targetName(target))
                            }
                        }
                        if let warning = group.warning {
                            warningRow(warning)
                        }
                    }
                }
            }
        }

        if !result.rules.isEmpty {
            DisclosureGroup("Rules (\(result.rules.count))") {
                ForEach(result.rules) { rule in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(rule.value)
                        Text("\(rule.kind.displayName) → \(targetName(rule.target))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .fixedSize(horizontal: false, vertical: true)
                }
            }
        }

        if let warning = result.warnings.first {
            warningRow(warning.message)
            if result.warnings.count > 1 {
                DisclosureGroup("More Warnings (\(result.warnings.count - 1))") {
                    ForEach(result.warnings.dropFirst()) { warning in
                        warningRow(warning.message)
                    }
                }
            }
        }
    }

    private func nodeRow(_ profile: ProxyProfile) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(profile.name)
                .font(.body.weight(.semibold))
            Text("\(profile.proto.displayName) · \(profile.endpoint.host):\(profile.endpoint.port)")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    private func warningRow(_ message: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle")
            .font(.footnote)
            .foregroundStyle(.orange)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func targetName(_ target: OutboundTarget) -> String {
        switch target {
        case let .profile(id):
            result.profiles.first { $0.id == id }?.name ?? store.displayName(for: target)
        case let .group(id):
            result.groups.first { $0.id == id }?.name ?? store.displayName(for: target)
        default:
            store.displayName(for: target)
        }
    }
}

struct QRCodeScannerSheet: View {
    @Environment(\.dismiss) private var dismiss

    let onPayload: (String) -> Void

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
                        description: Text("Camera unavailable or access denied. Use + → Paste or Import."),
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
    let onPayload: (String) -> Void

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
