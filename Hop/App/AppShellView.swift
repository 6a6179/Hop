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

    /// `hop://import?url=<https-subscription>` or `hop://import?text=<payload>`.
    /// The payload is attacker-controllable (any app can open the URL), so it
    /// is never applied directly: it lands in the same preview-and-confirm
    /// import sheet as pasted text, with every import gate intact.
    private func handleExternalURL(_ url: URL) {
        guard let payload = Self.importPayload(from: url) else {
            return
        }
        store.pendingExternalImportText = payload
        selectedTab = .profiles
    }

    static func importPayload(from url: URL) -> String? {
        guard url.scheme?.lowercased() == "hop",
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
