import SwiftUI

struct LogsView: View {
    @Environment(HopStore.self) private var store

    var body: some View {
        Group {
            if store.tunnel.logs.isEmpty {
                ContentUnavailableView("No Logs", systemImage: "doc.plaintext", description: Text("Connect the tunnel to see activity here."))
            } else {
                // A lazy List virtualizes rows, so only the visible lines are laid
                // out. (Rendering the whole log as one selectable Text laid out
                // every entry on every update and lagged the tab.)
                List {
                    ForEach(Array(store.tunnel.logs.enumerated()), id: \.offset) { _, line in
                        Text(line)
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
            store.tunnel.syncExtensionLogs()
        }
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button {
                    store.tunnel.syncExtensionLogs()
                } label: {
                    Label("Refresh Logs", systemImage: "arrow.clockwise")
                }
            }

            ToolbarItem(placement: .topBarTrailing) {
                ShareLink(item: exportText) {
                    Label("Export Logs", systemImage: "square.and.arrow.up")
                }
                .disabled(store.tunnel.logs.isEmpty)
            }
        }
    }

    private var exportText: String {
        """
        Hop Logs
        Exported: \(Date.now.formatted(date: .abbreviated, time: .standard))

        \(store.tunnel.logs.joined(separator: "\n"))
        """
    }
}

#Preview {
    NavigationStack {
        LogsView()
    }
    .environment(HopStore.preview)
}
