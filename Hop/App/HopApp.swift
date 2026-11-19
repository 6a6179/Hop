import SwiftUI

@main
struct HopApp: App {
    @State private var store = HopStore()

    var body: some Scene {
        WindowGroup {
            if store.libraryLoadFailed {
                LibraryRecoveryView(
                    retry: { store = HopStore() },
                    reset: {
                        guard store.resetUnreadableLibrary() else { return false }
                        store = HopStore()
                        return !store.libraryLoadFailed
                    },
                )
            } else {
                AppShellView()
                    .environment(store)
            }
        }
    }
}
