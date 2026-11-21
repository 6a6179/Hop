import SwiftUI

@main
struct HopApp: App {
    @State private var store: HopStore?
    @State private var openingLibrary = false
    @State private var pendingImport: String?

    var body: some Scene {
        WindowGroup {
            Group {
                if let store, store.libraryLoadFailed {
                    LibraryRecoveryView(
                        message: store.libraryRecoveryMessage,
                        retry: { await openLibrary() },
                        reset: {
                            try await store.resetUnreadableLibrary()
                            await openLibrary()
                        },
                    )
                } else if let store {
                    AppShellView().environment(store)
                } else {
                    ProgressView("Opening library…")
                        .task { await openLibrary() }
                }
            }
            .onOpenURL { url in
                guard let payload = AppShellView.importPayload(from: url) else { return }
                if let store, !store.libraryLoadFailed {
                    store.pendingExternalImportText = payload
                } else {
                    pendingImport = payload
                }
            }
        }
    }

    private func openLibrary() async {
        guard !openingLibrary else { return }
        openingLibrary = true
        defer { openingLibrary = false }
        let opened = await HopStore.openLibrary()
        if !opened.libraryLoadFailed {
            opened.pendingExternalImportText = pendingImport
            pendingImport = nil
        }
        store = opened
    }
}
