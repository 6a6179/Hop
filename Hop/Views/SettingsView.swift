import SwiftUI

struct SettingsView: View {
    @Environment(HopStore.self) private var store
    @State private var showingSettingsReset = false

    var body: some View {
        @Bindable var store = store

        Form {
            Section("Appearance") {
                Picker("Theme", selection: $store.settings.appearance) {
                    ForEach(AppAppearance.allCases) { appearance in
                        Text(appearance.displayName).tag(appearance)
                    }
                }
            }

            Section {
                Toggle("Protocol Sniffing", isOn: $store.settings.sniffTraffic)
                Toggle("Strict Route", isOn: $store.settings.strictRoute)
                Toggle("Kill Switch", isOn: $store.settings.killSwitch)
                Toggle("Connect On Demand", isOn: $store.settings.connectOnDemand)
            } header: {
                Text("Tunnel")
            } footer: {
                Text("Applied the next time you connect. Sniffing enables protocol and SNI based rules; strict route reduces traffic falling outside the tunnel route. Kill switch forces all traffic through the tunnel and blocks it if the tunnel drops — this can interrupt connectivity on captive-portal networks. Connect on demand lets iOS start and keep the tunnel up automatically; disconnecting manually pauses it until your next connect.")
            }

            Section {
                Toggle("Auto-Refresh Subscriptions", isOn: $store.settings.autoRefreshSubscriptions)
            } header: {
                Text("Subscriptions")
            } footer: {
                Text("Refreshes subscriptions older than 24 hours when the app returns to the foreground. Each refresh contacts the subscription server, which can observe your current network address. Refreshes that would add nodes with TLS verification disabled are skipped and need a manual refresh to review.")
            }

            Section {
                Picker("Resolver", selection: $store.settings.dnsPreset) {
                    ForEach(DNSPreset.allCases) { resolver in
                        Text(resolver.displayName).tag(resolver)
                    }
                }

                Picker("Strategy", selection: $store.settings.dnsStrategy) {
                    ForEach(DNSStrategy.allCases) { strategy in
                        Text(strategy.displayName).tag(strategy)
                    }
                }

                Toggle("Route DNS Through Proxy", isOn: $store.settings.proxyDNS)
                    .disabled(store.settings.dnsPreset == .system)
            } header: {
                Text("DNS")
            } footer: {
                Text("System uses the device resolver. Other resolvers use DNS-over-HTTPS for tunnel DNS.")
            }

            Section {
                Picker("Level", selection: $store.settings.logLevel) {
                    ForEach(ConfigLogLevel.allCases) { level in
                        Text(level.displayName).tag(level)
                    }
                }

                Picker("Keep", selection: $store.settings.logRetention) {
                    ForEach(LogRetention.allCases) { retention in
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
                Text("The log level applies the next time you connect.")
            }

            Section {
                Picker("Method", selection: $store.settings.latencyTestMethod) {
                    ForEach(LatencyTestMethod.allCases) { method in
                        Text(method.displayName).tag(method)
                    }
                }
            } header: {
                Text("Latency Test")
            } footer: {
                Text(store.settings.latencyTestMethod.footnote)
            }

            Section("Data") {
                Button(role: .destructive) {
                    showingSettingsReset = true
                } label: {
                    Text("Reset Settings")
                }
            }

            Section("About") {
                LabeledContent("Mode", value: "Packet tunnel")
                LabeledContent("Engine", value: "sing-box/libbox")
                Text("Hop is original software and does not copy Shadowrocket assets, branding, or App Store metadata.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Settings")
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog("Reset settings?", isPresented: $showingSettingsReset, titleVisibility: .visible) {
            Button("Reset Settings", role: .destructive) {
                store.resetSettings()
            }
        } message: {
            Text("This returns Settings to the default values.")
        }
    }
}

#Preview {
    NavigationStack {
        SettingsView()
    }
    .environment(HopStore.preview)
}
