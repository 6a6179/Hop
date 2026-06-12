import SwiftUI
import VisionKit

/// What an `ImportTextSheet` save produced: pasted text parsed into items, or
/// a detected subscription URL plus its fetched items.
enum ImportTextSaveResult {
    case importText(ImportResult)
    case subscription(SubscriptionSource, ImportResult)
}

struct AddSubscriptionSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var urlString = ""
    @State private var errorMessage: String?
    @State private var isLoading = false
    @State private var showInsecureTLSConfirmation = false
    @State private var pendingSave: (subscription: SubscriptionSource, result: ImportResult)?

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
            .insecureTLSImportConfirmation(
                isPresented: $showInsecureTLSConfirmation,
                profileNames: pendingSave?.result.insecureTLSProfileNames ?? [],
            ) {
                if let pendingSave {
                    onSave(pendingSave.subscription, pendingSave.result)
                    dismiss()
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
                    if result.insecureTLSProfileNames.isEmpty {
                        onSave(subscription, result)
                        dismiss()
                    } else {
                        pendingSave = (subscription, result)
                        isLoading = false
                        showInsecureTLSConfirmation = true
                    }
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

extension View {
    /// Blocking confirmation shown before saving imported nodes that disable
    /// TLS certificate verification. The preview's warning rows are advisory;
    /// this makes the security downgrade an explicit user decision. Shared by
    /// the import sheets and the QR-scan flow in `ProfilesView`.
    func insecureTLSImportConfirmation(
        isPresented: Binding<Bool>,
        profileNames: [String],
        onConfirm: @escaping () -> Void,
    ) -> some View {
        alert("Disable Certificate Verification?", isPresented: isPresented) {
            Button("Import Anyway", role: .destructive, action: onConfirm)
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("\(profileNames.count == 1 ? "1 node turns" : "\(profileNames.count) nodes turn") off TLS certificate verification (allow-insecure), so traffic to \(profileNames.count == 1 ? "it" : "them") can be intercepted: \(profileNames.prefix(5).joined(separator: ", "))\(profileNames.count > 5 ? ", …" : "")")
        }
    }
}

struct ImportTextSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var importText: String
    @State private var importResult: ImportResult?
    @State private var importError: String?
    @State private var detectedSubscriptionURL: URL?
    @State private var isLoading = false
    @State private var showInsecureTLSConfirmation = false

    var importService: ProxyImportService
    var onSave: (ImportTextSaveResult) -> Void

    /// `initialText` prefills the field (URL-scheme imports); the payload
    /// still goes through the same preview and confirmation gates as pasted
    /// text — prefilled is not pre-trusted.
    init(importService: ProxyImportService, initialText: String = "", onSave: @escaping (ImportTextSaveResult) -> Void) {
        self.importService = importService
        self.onSave = onSave
        _importText = State(initialValue: initialText)
    }

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
                        if importResult.insecureTLSProfileNames.isEmpty {
                            save(importResult)
                        } else {
                            showInsecureTLSConfirmation = true
                        }
                    }
                    .disabled(isLoading || (importResult?.isEmpty ?? true))
                }
            }
            .insecureTLSImportConfirmation(
                isPresented: $showInsecureTLSConfirmation,
                profileNames: importResult?.insecureTLSProfileNames ?? [],
            ) {
                if let importResult {
                    save(importResult)
                }
            }
            .onAppear {
                autoPreviewPrefill()
            }
        }
    }

    /// Prefilled share links (a tapped vless://… link, a scanned QR) parse
    /// locally, so preview them immediately — one tap less. Subscription URLs
    /// are NOT auto-fetched: opening a link must never trigger a network
    /// request to an arbitrary server without an explicit user action.
    private func autoPreviewPrefill() {
        let trimmed = importText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, importResult == nil, importError == nil, !isLoading else {
            return
        }
        guard case .importText = ProfileImportPayloadDetector().detect(trimmed) else {
            return
        }
        previewImport()
    }

    private func save(_ importResult: ImportResult) {
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

struct QRCodeScannerSheet: View {
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
