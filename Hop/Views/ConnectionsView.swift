import SwiftUI

struct ConnectionsView: View {
    @Environment(HopStore.self) private var store
    @State private var filter: ConnectionFilter = .active
    @State private var sort: ConnectionSort = .recent
    @State private var searchText = ""

    var body: some View {
        // Filter + sort once per render; telemetry pushes a connections batch
        // about every second while this view is visible, and `body` references
        // the visible list twice (empty check + ForEach).
        let visibleConnections = visibleConnections
        return List {
            Section {
                Picker("Filter", selection: $filter) {
                    ForEach(ConnectionFilter.allCases) { filter in
                        Text(filter.title).tag(filter)
                    }
                }
                .pickerStyle(.segmented)

                Picker("Sort", selection: $sort) {
                    ForEach(ConnectionSort.allCases) { sort in
                        Text(sort.title).tag(sort)
                    }
                }
            } footer: {
                if store.tunnel.state.isConnected {
                    Text(statusText)
                } else {
                    Text("Connect the tunnel to receive live connection events.")
                }
            }

            Section("Connections") {
                if visibleConnections.isEmpty {
                    ContentUnavailableView(emptyTitle, systemImage: "link", description: Text(emptyDescription))
                } else {
                    ForEach(visibleConnections) { connection in
                        NavigationLink {
                            ConnectionDetailView(connection: connection)
                        } label: {
                            ConnectionRow(connection: connection)
                        }
                        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                            if connection.isActive {
                                Button(role: .destructive) {
                                    store.tunnel.closeConnection(id: connection.id)
                                } label: {
                                    Label("Close", systemImage: "xmark.circle")
                                }
                            }
                        }
                    }
                }
            }
        }
        .navigationTitle("Connections")
        .navigationBarTitleDisplayMode(.inline)
        // The per-connection event stream is subscribed only while this view
        // is on screen; the initial batch after subscribing carries the full
        // current state, so the list repopulates on re-entry.
        .onAppear {
            store.tunnel.beginConnectionsMonitoring()
        }
        .onDisappear {
            store.tunnel.endConnectionsMonitoring()
        }
        .searchable(text: $searchText, prompt: "Search host, rule, outbound")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Close All", role: .destructive) {
                    store.tunnel.closeAllConnections()
                }
                .disabled(activeConnectionCount == 0)
            }
        }
    }

    private var visibleConnections: [TunnelConnectionSnapshot] {
        let needle = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return store.tunnel.connections
            .filter { connection in
                switch filter {
                case .active:
                    connection.isActive
                case .closed:
                    !connection.isActive
                case .all:
                    true
                }
            }
            .filter { connection in
                needle.isEmpty || connection.searchableText.contains(needle)
            }
            .sorted { lhs, rhs in
                switch sort {
                case .recent:
                    lhs.createdAt > rhs.createdAt
                case .currentTraffic:
                    lhs.currentTrafficBytes > rhs.currentTrafficBytes
                case .totalTraffic:
                    lhs.totalTrafficBytes > rhs.totalTrafficBytes
                }
            }
    }

    private var activeConnectionCount: Int {
        store.tunnel.connections.filter(\.isActive).count
    }

    private var statusText: String {
        let active = activeConnectionCount
        let total = store.tunnel.connections.count
        if let error = store.tunnel.telemetryError {
            return "Telemetry unavailable: \(error)"
        }
        if store.tunnel.telemetryIsConnected {
            return "\(active) active · \(total) total observed"
        }
        return "Waiting for live telemetry from the tunnel."
    }

    private var emptyTitle: String {
        if !searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return "No Matches"
        }
        return switch filter {
        case .active:
            "No Active Connections"
        case .closed:
            "No Closed Connections"
        case .all:
            "No Connections"
        }
    }

    private var emptyDescription: String {
        if store.tunnel.state.isConnected {
            "Traffic will appear here after apps use the tunnel."
        } else {
            "Connect the tunnel first."
        }
    }
}

private struct ConnectionRow: View {
    var connection: TunnelConnectionSnapshot

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 8) {
                Text(connection.displayTitle)
                    .font(.body.weight(.semibold))
                    .lineLimit(1)
                    .truncationMode(.middle)

                Spacer()

                Text(connection.isActive ? "Active" : "Closed")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(connection.isActive ? .green : .secondary)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 3)
                    .background((connection.isActive ? Color.green : Color.secondary).opacity(0.14), in: Capsule())
            }

            HStack(spacing: 10) {
                Label(connection.network.uppercased(), systemImage: "network")
                Label(connection.outboundDisplayName, systemImage: "arrowshape.turn.up.right")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .lineLimit(1)

            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("↑ \(connection.uplinkBytesPerSecond.formatted(.byteCount(style: .file)))/s")
                    Text("↓ \(connection.downlinkBytesPerSecond.formatted(.byteCount(style: .file)))/s")
                }

                VStack(alignment: .leading, spacing: 2) {
                    Text("Σ ↑ \(connection.uplinkTotalBytes.formatted(.byteCount(style: .file)))")
                    Text("Σ ↓ \(connection.downlinkTotalBytes.formatted(.byteCount(style: .file)))")
                }

                Spacer()
            }
            .font(.caption.monospacedDigit())
            .foregroundStyle(.secondary)
        }
        .padding(.vertical, 3)
        .accessibilityElement(children: .combine)
    }
}

private struct ConnectionDetailView: View {
    var connection: TunnelConnectionSnapshot

    var body: some View {
        List {
            Section("Endpoint") {
                LabeledContent("Destination", value: connection.displayTitle)
                if !connection.domain.isEmpty {
                    LabeledContent("Domain", value: connection.domain)
                }
                LabeledContent("Network", value: connection.network.uppercased())
                if !connection.protocolName.isEmpty {
                    LabeledContent("Protocol", value: connection.protocolName)
                }
            }

            Section("Routing") {
                LabeledContent("Inbound", value: connection.inboundDisplayName)
                LabeledContent("Outbound", value: connection.outboundDisplayName)
                if !connection.rule.isEmpty {
                    LabeledContent("Rule", value: connection.rule)
                }
                if !connection.chain.isEmpty {
                    LabeledContent("Chain", value: connection.chain.joined(separator: " → "))
                }
            }

            Section("Traffic") {
                LabeledContent("Upload Speed", value: "\(connection.uplinkBytesPerSecond.formatted(.byteCount(style: .file)))/s")
                LabeledContent("Download Speed", value: "\(connection.downlinkBytesPerSecond.formatted(.byteCount(style: .file)))/s")
                LabeledContent("Uploaded", value: connection.uplinkTotalBytes.formatted(.byteCount(style: .file)))
                LabeledContent("Downloaded", value: connection.downlinkTotalBytes.formatted(.byteCount(style: .file)))
            }

            Section("Timing") {
                LabeledContent("Opened") {
                    Text(connection.createdAt, style: .time)
                }
                if let closedAt = connection.closedAt {
                    LabeledContent("Closed") {
                        Text(closedAt, style: .time)
                    }
                } else {
                    LabeledContent("Status", value: "Active")
                }
            }
        }
        .navigationTitle("Connection")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private enum ConnectionFilter: String, CaseIterable, Identifiable {
    case active
    case closed
    case all

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .active:
            "Active"
        case .closed:
            "Closed"
        case .all:
            "All"
        }
    }
}

private enum ConnectionSort: String, CaseIterable, Identifiable {
    case recent
    case currentTraffic
    case totalTraffic

    var id: String {
        rawValue
    }

    var title: String {
        switch self {
        case .recent:
            "Recent"
        case .currentTraffic:
            "Speed"
        case .totalTraffic:
            "Total"
        }
    }
}

private extension TunnelConnectionSnapshot {
    var displayTitle: String {
        if !displayDestination.isEmpty {
            return displayDestination
        }
        if !domain.isEmpty {
            return domain
        }
        return destination.isEmpty ? "Unknown Destination" : destination
    }

    var inboundDisplayName: String {
        [inboundType, inbound]
            .filter { !$0.isEmpty }
            .joined(separator: " / ")
    }

    var outboundDisplayName: String {
        if !chain.isEmpty {
            return chain.joined(separator: " / ")
        }
        return [outboundType, outbound]
            .filter { !$0.isEmpty }
            .joined(separator: " / ")
    }

    var currentTrafficBytes: Int64 {
        uplinkBytesPerSecond + downlinkBytesPerSecond
    }

    var totalTrafficBytes: Int64 {
        uplinkTotalBytes + downlinkTotalBytes
    }
}

#Preview {
    NavigationStack {
        ConnectionsView()
    }
    .environment(HopStore.preview)
}
