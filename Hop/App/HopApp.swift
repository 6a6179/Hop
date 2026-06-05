import SwiftUI

@main
struct HopApp: App {
    @State private var store = HopStore()

    var body: some Scene {
        WindowGroup {
            AppShellView()
                .environment(store)
        }
    }
}
