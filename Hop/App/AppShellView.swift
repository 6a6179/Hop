import SwiftUI

enum AppTab: Hashable {
    case dashboard
    case profiles
    case rules
    case logs
    case settings
}

struct AppShellView: View {
    @Environment(HopStore.self) private var store
    @Environment(\.scenePhase) private var scenePhase
    @State private var selectedTab: AppTab = .dashboard

    var body: some View {
        TabView(selection: $selectedTab) {
            NavigationStack {
                DashboardView()
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
                LogsView()
            }
            .tabItem {
                Label("Logs", systemImage: "doc.text.magnifyingglass")
            }
            .tag(AppTab.logs)

            NavigationStack {
                SettingsView()
            }
            .tabItem {
                Label("Settings", systemImage: "gearshape")
            }
            .tag(AppTab.settings)
        }
        .preferredColorScheme(preferredColorScheme)
        .onChange(of: scenePhase) { _, phase in
            if phase == .active {
                Task { await store.autoRefreshStaleSubscriptions() }
            }
        }
        .onOpenURL { url in
            handleExternalURL(url)
        }
    }

    /// Proxy share-link schemes Hop registers for (Info.plist
    /// `CFBundleURLTypes`): tapping such a link in a browser or scanning a
    /// share QR with the system Camera opens Hop with the whole link as the
    /// import payload. Mirrors the schemes `ProxyImportService` parses, plus
    /// `ssr` so those links produce a clear "unsupported" message instead of
    /// nothing happening.
    static let proxyLinkSchemes: Set<String> = [
        "vless", "vmess", "trojan", "ss", "ssr", "hysteria2", "hy2", "tuic", "socks", "socks5",
    ]

    /// Accepts `hop://import?url=<https-subscription>`,
    /// `hop://import?text=<payload>`, and bare proxy share links
    /// (`vless://…`, `ss://…`, …). Payloads are attacker-controllable (any
    /// app can open a URL), so they are never applied directly: each lands in
    /// the same preview-and-confirm import sheet as pasted text, with every
    /// import gate intact.
    private func handleExternalURL(_ url: URL) {
        guard let payload = Self.importPayload(from: url) else {
            return
        }
        store.pendingExternalImportText = payload
        selectedTab = .profiles
    }

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

#Preview {
    AppShellView()
        .environment(HopStore.preview)
}
