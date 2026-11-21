import SwiftUI

enum AppTab: Hashable {
    case dashboard
    case profiles
    case rules
    case settings
}

struct AppShellView: View {
    @Environment(HopStore.self) private var store
    @Environment(\.scenePhase) private var scenePhase
    @State private var selectedTab: AppTab = .dashboard

    var body: some View {
        TabView(selection: $selectedTab) {
            NavigationStack {
                DashboardView {
                    selectedTab = .profiles
                }
            }
            .tabItem {
                Label("Dashboard", systemImage: "gauge")
            }
            .tag(AppTab.dashboard)

            NavigationStack {
                ProfilesView()
            }
            .tabItem {
                Label("Profiles", systemImage: "server.rack")
            }
            .tag(AppTab.profiles)

            NavigationStack {
                RulesView()
            }
            .tabItem {
                Label("Rules", systemImage: "arrow.triangle.branch")
            }
            .tag(AppTab.rules)

            NavigationStack {
                SettingsView()
            }
            .tabItem {
                Label("Settings", systemImage: "gearshape")
            }
            .tag(AppTab.settings)
        }
        .preferredColorScheme(preferredColorScheme)
        .onChange(of: scenePhase, initial: true) { _, phase in
            if phase == .active {
                Task { await store.tunnel.refreshStatus() }
                Task { await store.autoRefreshStaleSubscriptions() }
            }
        }
        .onChange(of: store.pendingExternalImportText, initial: true) { _, payload in
            if payload != nil {
                selectedTab = .profiles
            }
        }
        .alert(
            "Xray Migration Complete",
            isPresented: Binding(
                get: { store.pendingXrayMigrationReport != nil },
                set: {
                    if !$0 {
                        store.acknowledgeXrayMigration()
                    }
                },
            ),
        ) {
            Button("Review Profiles") {
                selectedTab = .profiles
                store.acknowledgeXrayMigration()
            }
            Button("OK") {
                store.acknowledgeXrayMigration()
            }
        } message: {
            Text(store.pendingXrayMigrationReport?.message ?? "Saved configuration upgraded for Xray.")
        }
        .alert(
            "Changes Not Saved",
            isPresented: Binding(
                get: { store.persistenceError != nil },
                set: {
                    if !$0 {
                        store.persistenceError = nil
                    }
                },
            ),
        ) {
            Button("Retry") { store.persist() }
            Button("Dismiss", role: .cancel) { store.persistenceError = nil }
        } message: {
            Text("Retry saving before closing Hop.")
        }
    }

    /// Proxy share-link schemes Hop registers for (Info.plist
    /// `CFBundleURLTypes`): tapping such a link in a browser or scanning a
    /// share QR with the system Camera opens Hop with the whole link as the
    /// import payload. Mirrors the Xray-compatible schemes parsed by
    /// `ProxyImportService`.
    static let proxyLinkSchemes: Set<String> = [
        "vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "socks", "socks5", "socks5+tls", "wireguard", "wg",
    ]

    /// Accepts `hop://import?url=<https-subscription>`,
    /// `hop://import?text=<payload>`, and bare proxy share links
    /// (`vless://…`, `ss://…`, …). Payloads are attacker-controllable (any
    /// app can open a URL), so they are never applied directly: each lands in
    /// the same preview-and-confirm import sheet as pasted text, with every
    /// import gate intact.
    static func importPayload(from url: URL) -> String? {
        guard let scheme = url.scheme?.lowercased() else {
            return nil
        }
        if proxyLinkSchemes.contains(scheme) {
            return url.absoluteString
        }
        guard scheme == "hop",
              url.host()?.lowercased() == "import",
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        else {
            return nil
        }
        let items = components.queryItems ?? []
        if let text = items.first(where: { $0.name == "text" })?.value, !text.isEmpty {
            return text
        }
        if let subscription = items.first(where: { $0.name == "url" })?.value, !subscription.isEmpty {
            return subscription
        }
        return nil
    }

    private var preferredColorScheme: ColorScheme? {
        switch store.settings.appearance {
        case .system:
            nil
        case .light:
            .light
        case .dark:
            .dark
        }
    }
}

struct LibraryRecoveryView: View {
    let message: String?
    let retry: () async -> Void
    let reset: () async throws -> Void
    @State private var confirmingReset = false
    @State private var busy = false
    @State private var resetError: String?

    var body: some View {
        ContentUnavailableView {
            Label("Library Unavailable", systemImage: "lock.doc")
        } description: {
            Text(message ?? "Hop couldn’t open your saved library. Unlock your device and try again.")
        } actions: {
            Button("Retry") {
                busy = true
                Task {
                    await retry()
                    busy = false
                }
            }.buttonStyle(.borderedProminent)
            Button("Reset Library", role: .destructive) { confirmingReset = true }
            if let resetError {
                Text("Reset failed. \(resetError)")
            }
        }
        .disabled(busy)
        .alert("Erase the saved library?", isPresented: $confirmingReset) {
            Button("Cancel", role: .cancel) {}
            Button("Erase Library", role: .destructive) {
                busy = true
                Task {
                    defer { busy = false }
                    do { try await reset() }
                    catch { resetError = error.localizedDescription }
                }
            }
        } message: {
            Text("This stops Hop’s VPN, removes its saved VPN configuration, and permanently erases your profiles, subscriptions, routing rules, settings, and credentials.")
        }
    }
}

#Preview {
    AppShellView()
        .environment(HopStore.preview)
}
