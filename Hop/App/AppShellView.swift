import SwiftUI

struct AppShellView: View {
    @Environment(HopStore.self) private var store

    var body: some View {
        TabView {
            NavigationStack {
                DashboardView()
            }
            .tabItem {
                Label("Dashboard", systemImage: "gauge")
            }

            NavigationStack {
                ProfilesView()
            }
            .tabItem {
                Label("Profiles", systemImage: "server.rack")
            }

            NavigationStack {
                RulesView()
            }
            .tabItem {
                Label("Rules", systemImage: "arrow.triangle.branch")
            }

            NavigationStack {
                LogsView()
            }
            .tabItem {
                Label("Logs", systemImage: "doc.text.magnifyingglass")
            }

            NavigationStack {
                SettingsView()
            }
            .tabItem {
                Label("Settings", systemImage: "gearshape")
            }
        }
        .preferredColorScheme(preferredColorScheme)
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
