import SwiftUI

struct LogsView: View {
    @Environment(HopStore.self) private var store

    var body: some View {
        let logs = store.tunnel.logs
        let exportText = """
        Hop Logs
        Exported: \(Date.now.formatted(date: .abbreviated, time: .standard))

        \(logs.joined(separator: "\n"))
        """

        Group {
            if logs.isEmpty {
                ContentUnavailableView("No Logs", systemImage: "doc.plaintext", description: Text("Connect the tunnel to see activity here."))
            } else {
                // A lazy List virtualizes rows, so only the visible lines are laid
                // out. (Rendering the whole log as one selectable Text laid out
                // every entry on every update and lagged the tab.)
                List {
                    // Indices avoid materializing a fresh `Array(enumerated())`
                    // copy of the whole log on every append-triggered render.
                    ForEach(logs.indices, id: \.self) { index in
                        Text(logs[index])
                            .font(.system(.footnote, design: .monospaced))
                            .textSelection(.enabled)
                            .listRowInsets(EdgeInsets(top: 3, leading: 16, bottom: 3, trailing: 16))
                            .listRowSeparator(.hidden)
                    }
                }
                .listStyle(.plain)
            }
        }
        .navigationTitle("Logs")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            await store.tunnel.syncExtensionLogs()
        }
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button {
                    Task {
                        await store.tunnel.syncExtensionLogs()
                    }
                } label: {
                    Label("Refresh Logs", systemImage: "arrow.clockwise")
                }
            }

            ToolbarItem(placement: .topBarTrailing) {
                ShareLink(item: exportText) {
                    Label("Export Logs", systemImage: "square.and.arrow.up")
                }
                .disabled(logs.isEmpty)
            }
        }
    }
}

#Preview {
    NavigationStack {
        LogsView()
    }
    .environment(HopStore.preview)
}
