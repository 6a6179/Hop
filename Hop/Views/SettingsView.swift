import SwiftUI

struct SettingsView: View {
    @Environment(HopStore.self) private var store
    @State private var showingSettingsReset = false

    var body: some View {
        @Bindable var store = store

        Form {
            Section("Appearance") {
                Picker("Theme", selection: $store.settings.appearance) {
                    ForEach(AppAppearance.allCases, id: \.self) { appearance in
                        Text(appearance.displayName).tag(appearance)
                    }
                }
            }

            Section {
                Toggle("Protocol Sniffing", isOn: $store.settings.sniffTraffic)
                Toggle("Strict Route", isOn: $store.settings.strictRoute)
                Toggle(isOn: $store.settings.killSwitch) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Kill Switch")
                        Text("Blocks traffic on VPN drops. May block Wi-Fi sign-in.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
                Toggle(isOn: $store.settings.connectOnDemand) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Connect On Demand")
                        Text("Manual disconnect pauses this until next connect.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            } header: {
                Text("Tunnel")
            } footer: {
                Text("Applies on next connect.")
            }

            Section {
                Toggle("Auto-Refresh Subscriptions", isOn: $store.settings.autoRefreshSubscriptions)
            } header: {
                Text("Subscriptions")
            } footer: {
                Text("Refreshes after 24h on app open. Providers see your IP; new insecure nodes need manual review.")
            }

            Section {
                Picker("Resolver", selection: $store.settings.dnsPreset) {
                    ForEach(DNSPreset.allCases, id: \.self) { resolver in
                        Text(resolver.displayName).tag(resolver)
                    }
                }

                Picker("Strategy", selection: $store.settings.dnsStrategy) {
                    ForEach(DNSStrategy.allCases, id: \.self) { strategy in
                        Text(strategy.displayName).tag(strategy)
                    }
                }

                Toggle("Route DNS Through Proxy", isOn: $store.settings.proxyDNS)
                    .disabled(store.settings.dnsPreset == .system)
            } header: {
                Text("DNS")
            } footer: {
                Text("Custom resolvers use DNS-over-HTTPS.")
            }

            Section {
                NavigationLink("View Logs") {
                    LogsView()
                }

                Picker("Level", selection: $store.settings.logLevel) {
                    ForEach(ConfigLogLevel.allCases, id: \.self) { level in
                        Text(level.displayName).tag(level)
                    }
                }

                Picker("Keep", selection: $store.settings.logRetention) {
                    ForEach(LogRetention.allCases, id: \.self) { retention in
                        Text(retention.displayName).tag(retention)
                    }
                }

                Button(role: .destructive) {
                    store.clearLogs()
                } label: {
                    Text("Clear Logs")
                }
            } header: {
                Text("Logs")
            } footer: {
                Text("Level applies on next connect.")
            }

            Section {
                Picker("Method", selection: $store.settings.latencyTestMethod) {
                    ForEach(LatencyTestMethod.allCases, id: \.self) { method in
                        Text(method.displayName).tag(method)
                    }
                }
            } header: {
                Text("Latency Test")
            } footer: {
                Text(store.settings.latencyTestMethod.footnote)
            }

            Section("Data") {
                NavigationLink("Advanced Xray") {
                    XrayAdvancedSettingsView()
                }

                Button(role: .destructive) {
                    showingSettingsReset = true
                } label: {
                    Text("Reset Settings")
                }
            }

            Section("About") {
                LabeledContent("Mode", value: "Packet tunnel")
                LabeledContent("Engine", value: "Xray-core v26.6.27")
            }
        }
        .navigationTitle("Settings")
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog("Reset settings to defaults?", isPresented: $showingSettingsReset, titleVisibility: .visible) {
            Button("Reset Settings", role: .destructive) {
                store.resetSettings()
            }
        }
    }
}

private struct XrayAdvancedSettingsView: View {
    @Environment(HopStore.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State private var json = "{}"
    @State private var didLoad = false

    var body: some View {
        let validation = advancedValidation

        Form {
            Section {
                TextEditor(text: $json)
                    .font(.system(.caption, design: .monospaced))
                    .frame(minHeight: 360)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            } footer: {
                Text("Client overrides only. Hop manages listeners and logging.")
            }

            if let errorMessage = validation.errorMessage {
                Section {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
            }
        }
        .navigationTitle("Advanced Xray")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") {
                    // Revalidate on the explicit save action so a stale
                    // rendered button can never admit changed JSON.
                    guard let document = advancedValidation.document else { return }
                    var settings = store.settings
                    settings.xrayAdvanced = document.isEmpty ? nil : document
                    store.settings = settings
                    dismiss()
                }
                .disabled(validation.document == nil)
            }
        }
        .onAppear {
            guard !didLoad else { return }
            didLoad = true
            json = store.settings.xrayAdvanced?.jsonString ?? "{}"
        }
    }

    private var advancedValidation: (document: XrayAdvancedDocument?, errorMessage: String?) {
        do {
            let document = try XrayAdvancedDocument(jsonString: json)
            var candidateSettings = store.settings
            candidateSettings.xrayAdvanced = document.isEmpty ? nil : document
            if let issue = XrayConfigBuilder().validationIssues(
                profiles: [],
                groups: [],
                selectedTarget: .direct,
                routingMode: .direct,
                rules: [],
                settings: candidateSettings,
            ).first {
                return (nil, "\(issue.path): \(issue.message)")
            }
            return (document, nil)
        } catch {
            return (nil, error.localizedDescription)
        }
    }
}

#Preview {
    NavigationStack {
        SettingsView()
    }
    .environment(HopStore.preview)
}
