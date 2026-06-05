import SwiftUI

struct ProfilesView: View {
    @Environment(HopStore.self) private var store
    @State private var selectedSection: ProfilesSection = .nodes
    @State private var importText = ""
    @State private var importError: String?
    @State private var importResult: ImportResult?
    @State private var editingProfile: ProxyProfile?
    @State private var editingGroup: ProxyGroup?
    @State private var subscriptionName = ""
    @State private var subscriptionURL = ""
    @State private var isLoadingSubscription = false

    private let importService = ProxyImportService()

    var body: some View {
        @Bindable var store = store

        List {
            Section {
                Picker("Profile Section", selection: $selectedSection) {
                    ForEach(ProfilesSection.allCases) { section in
                        Text(section.title).tag(section)
                    }
                }
                .pickerStyle(.segmented)
            }

            switch selectedSection {
            case .nodes:
                nodesSection
            case .groups:
                groupsSection
            case .subscriptions:
                subscriptionsSection
            case .importText:
                importSection
            }
        }
        .navigationTitle("Profiles")
        .navigationBarTitleDisplayMode(.inline)
        .sensoryFeedback(.selection, trigger: store.selectedTarget)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button("Add Node", systemImage: "plus") {
                        editingProfile = ProxyProfile(
                            name: "New VLESS Node",
                            endpoint: Endpoint(host: "example.com", port: 443),
                            proto: .vless,
                            options: .vless(VLESSOptions(uuid: "", flow: nil)),
                            security: .tls(TLSOptions(serverName: "example.com")),
                        )
                    }
                    Button("Add Group", systemImage: "rectangle.stack.badge.plus") {
                        editingGroup = ProxyGroup(
                            name: "New Group",
                            type: .select,
                            members: store.profiles.map { .profile($0.id) },
                            defaultTarget: store.profiles.first.map { .profile($0.id) },
                        )
                    }
                } label: {
                    Label("Add", systemImage: "plus")
                }
            }
        }
        .sheet(item: $editingProfile) { profile in
            ProfileEditorView(profile: profile) { updatedProfile in
                if store.profiles.contains(where: { $0.id == updatedProfile.id }) {
                    store.updateProfile(updatedProfile)
                } else {
                    store.addProfile(updatedProfile)
                }
            }
        }
        .sheet(item: $editingGroup) { group in
            ProxyGroupEditorView(group: group) { updatedGroup in
                if store.groups.contains(where: { $0.id == updatedGroup.id }) {
                    store.updateGroup(updatedGroup)
                } else {
                    store.addGroup(updatedGroup)
                }
            }
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
                                editingProfile = profile
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
            Text("Supports VLESS+REALITY, Trojan+TLS, Hysteria2+TLS, TUIC+TLS, Shadowsocks, VMess, HTTP, and SOCKS where sing-box supports them.")
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
                                editingGroup = group
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
            Text("Manual groups generate sing-box selectors. URL Test groups generate sing-box urltest outbounds.")
        }
    }

    @ViewBuilder
    private var subscriptionsSection: some View {
        Section {
            ProfileTextField("Name", text: $subscriptionName, prompt: "Airport")
            ProfileTextField("URL", text: $subscriptionURL, prompt: "https://example.com/sub")

            Button(isLoadingSubscription ? "Updating..." : "Add Subscription & Import") {
                importSubscription()
            }
            .disabled(isLoadingSubscription || URL(string: subscriptionURL.trimmingCharacters(in: .whitespacesAndNewlines)) == nil)
        } header: {
            Text("Add Subscription")
        } footer: {
            Text("Plain and base64 encoded subscriptions are supported.")
        }

        Section("Subscriptions") {
            if store.subscriptions.isEmpty {
                ContentUnavailableView("No Subscriptions", systemImage: "link", description: Text("Add a subscription URL to import nodes."))
            } else {
                ForEach(store.subscriptions) { subscription in
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
                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                        Button(role: .destructive) {
                            store.deleteSubscription(id: subscription.id)
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }
                    }
                }
            }
        }
    }

    private var importSection: some View {
        Section {
            TextField("Paste links, subscription text, or Shadowrocket .conf", text: $importText, axis: .vertical)
                .lineLimit(5 ... 12)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()

            Button("Preview Import") {
                previewImport()
            }
            .disabled(importText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

            if let importResult {
                ImportPreviewView(result: importResult)
                Button("Save Imported Items") {
                    store.applyImport(importResult)
                    self.importResult = nil
                    importText = ""
                    importError = nil
                    selectedSection = .nodes
                }
                .disabled(importResult.isEmpty)
            }

            if let importError {
                Text(importError)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        } header: {
            Text("Import")
        } footer: {
            Text("Accepts Shadowrocket-compatible node links, base64/plain subscriptions, and .conf files with Proxy, Proxy Group, and Rule sections.")
        }
    }

    private func previewImport() {
        do {
            importResult = try importService.importText(importText)
            importError = nil
        } catch {
            importResult = nil
            importError = error.localizedDescription
        }
    }

    private func importSubscription() {
        guard let url = URL(string: subscriptionURL.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            return
        }
        isLoadingSubscription = true
        Task {
            do {
                let result = try await importService.importSubscription(url: url)
                let name = subscriptionName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? url.host() ?? "Subscription" : subscriptionName.trimmingCharacters(in: .whitespacesAndNewlines)
                await MainActor.run {
                    store.applyImport(result)
                    store.addSubscription(
                        SubscriptionSource(
                            name: name,
                            url: url.absoluteString,
                            lastUpdatedAt: .now,
                            lastImportSummary: result.summary,
                        ),
                    )
                    subscriptionName = ""
                    subscriptionURL = ""
                    isLoadingSubscription = false
                }
            } catch {
                await MainActor.run {
                    importError = error.localizedDescription
                    isLoadingSubscription = false
                }
            }
        }
    }
}

private enum ProfilesSection: String, CaseIterable, Identifiable {
    case nodes
    case groups
    case subscriptions
    case importText

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .nodes:
            "Nodes"
        case .groups:
            "Groups"
        case .subscriptions:
            "Subs"
        case .importText:
            "Import"
        }
    }
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
                ProfileTextField("Spider X", text: $draft.realitySpiderX, prompt: "/")
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
            .vless(VLESSOptions(uuid: trimmed(vlessUUID), flow: optional(vlessFlow)))
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
                    utlsFingerprint: optional(realityFingerprint) ?? "chrome",
                ),
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
                url: trimmedURL.isEmpty ? ProxyGroupTestOptions.defaultURL : trimmedURL,
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
