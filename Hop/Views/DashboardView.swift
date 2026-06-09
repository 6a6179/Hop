import SwiftUI

struct DashboardView: View {
    @Environment(HopStore.self) private var store
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        @Bindable var store = store
        let visualState = TunnelVisualState(store.tunnel.state)

        Form {
            Section {
                VStack(spacing: 12) {
                    ConnectionStatusRow(
                        state: store.tunnel.state,
                        profileName: store.selectedTargetDisplayName,
                    )

                    Button {
                        Task {
                            if store.tunnel.state.isConnected {
                                await store.tunnel.disconnect()
                            } else {
                                await store.tunnel.connect(
                                    target: store.selectedTarget ?? store.defaultTarget,
                                    profiles: store.profiles,
                                    groups: store.groups,
                                    routingMode: store.routingMode,
                                    rules: store.rules,
                                    settings: store.settings,
                                )
                            }
                        }
                    } label: {
                        ConnectButtonLabel(visualState: visualState)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .tint(visualState.buttonTint)
                    .disabled(visualState.isInFlight || store.profiles.isEmpty)
                }
                .listRowInsets(EdgeInsets(top: 16, leading: 16, bottom: 16, trailing: 16))
            }

            Section("Outbound") {
                Picker("Active", selection: $store.selectedTarget) {
                    if !store.groups.isEmpty {
                        Section("Groups") {
                            ForEach(store.groups.filter(\.isEnabled)) { group in
                                Text(group.name).tag(Optional(OutboundTarget.group(group.id)))
                            }
                        }
                    }

                    Section("Nodes") {
                        ForEach(store.profiles) { profile in
                            Text(profile.name).tag(Optional(OutboundTarget.profile(profile.id)))
                        }
                    }
                }

                if let profile = store.selectedProfile, store.selectedGroup == nil {
                    LabeledContent("Protocol") {
                        Text("\(profile.proto.displayName) · \(profile.displaySecurity)")
                            .foregroundStyle(.secondary)
                    }
                    LabeledContent("Server", value: "\(profile.endpoint.host):\(profile.endpoint.port)")
                } else if let group = store.selectedGroup {
                    LabeledContent("Type", value: group.type.displayName)
                    LabeledContent("Members", value: "\(group.members.count)")
                } else {
                    Label {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("No outbound selected")
                            Text("Select or import a proxy profile or group before connecting.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    } icon: {
                        Image(systemName: "server.rack")
                            .foregroundStyle(.secondary)
                    }
                }
            }

            Section("Routing & Traffic") {
                Picker("Mode", selection: $store.routingMode) {
                    ForEach(RoutingMode.allCases) { mode in
                        Text(mode.title).tag(mode)
                    }
                }

                LabeledContent("Speed") {
                    Text(speedSummary)
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                }

                LabeledContent("Transferred") {
                    Text(transferSummary)
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                }

                NavigationLink {
                    ConnectionsView()
                } label: {
                    LabeledContent("Connections") {
                        Text(connectionsSummary)
                            .foregroundStyle(.secondary)
                    }
                }

                if let telemetryError = store.tunnel.telemetryError, store.tunnel.state.isConnected {
                    Text("Telemetry unavailable: \(telemetryError)")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                }
            }
        }
        .animation(reduceMotion ? nil : .default, value: visualState)
        .navigationTitle("Hop")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var speedSummary: String {
        let uplink = store.tunnel.counters.uplinkBytesPerSecond.formattedBytes
        let downlink = store.tunnel.counters.downlinkBytesPerSecond.formattedBytes
        return "↑ \(uplink)/s · ↓ \(downlink)/s"
    }

    private var transferSummary: String {
        let uplink = store.tunnel.counters.uplinkBytes.formattedBytes
        let downlink = store.tunnel.counters.downlinkBytes.formattedBytes
        return "↑ \(uplink) · ↓ \(downlink)"
    }

    private var connectionsSummary: String {
        // From the always-on status stream, not the connection list — the
        // per-connection event stream only runs while ConnectionsView is open.
        "\(store.tunnel.counters.activeConnections) active"
    }
}

private extension Int64 {
    var formattedBytes: String {
        formatted(.byteCount(style: .file))
    }
}

private enum TunnelVisualState: Equatable {
    case disconnected
    case connecting
    case connected
    case disconnecting
    case failed

    init(_ state: TunnelConnectionState) {
        switch state {
        case .disconnected:
            self = .disconnected
        case .connecting:
            self = .connecting
        case .connected:
            self = .connected
        case .disconnecting:
            self = .disconnecting
        case .failed:
            self = .failed
        }
    }

    var accent: Color {
        switch self {
        case .connected:
            .green
        case .connecting:
            .blue
        case .disconnecting:
            .orange
        case .failed:
            .red
        case .disconnected:
            .secondary
        }
    }

    var buttonTitle: String {
        switch self {
        case .connected:
            "Disconnect"
        case .connecting:
            "Connecting"
        case .disconnecting:
            "Disconnecting"
        case .failed, .disconnected:
            "Connect"
        }
    }

    var buttonSymbol: String {
        switch self {
        case .connected, .disconnecting:
            "stop.circle.fill"
        case .connecting:
            "ellipsis.circle.fill"
        case .failed, .disconnected:
            "play.circle.fill"
        }
    }

    var buttonTint: Color {
        switch self {
        case .connected, .disconnecting:
            .red
        default:
            .accentColor
        }
    }

    var badgeSymbol: String {
        switch self {
        case .connected:
            "checkmark"
        case .connecting:
            "ellipsis"
        case .disconnecting:
            "minus"
        case .failed:
            "exclamationmark"
        case .disconnected:
            "xmark"
        }
    }

    var isInFlight: Bool {
        self == .connecting || self == .disconnecting
    }
}

private struct ConnectionStatusRow: View {
    var state: TunnelConnectionState
    var profileName: String

    var body: some View {
        HStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 4) {
                Text(state.title)
                    .font(.title2.weight(.semibold))
                    .lineLimit(1)
                    .allowsTightening(true)
                    .truncationMode(.tail)
                Text(profileName)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .layoutPriority(1)

            Spacer(minLength: 12)

            TunnelStateIcon(state: state)
        }
        .accessibilityElement(children: .combine)
    }
}

private struct TunnelStateIcon: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var state: TunnelConnectionState

    private var visualState: TunnelVisualState {
        TunnelVisualState(state)
    }

    var body: some View {
        ZStack {
            if visualState.isInFlight, !reduceMotion {
                ActivityHalo(color: visualState.accent)
                    .transition(.opacity)
            } else {
                Circle()
                    .strokeBorder(visualState.accent.opacity(visualState == .connected ? 0.42 : 0.22), lineWidth: 2)
                    .scaleEffect(visualState == .connected ? 1.04 : 0.94)
                    .opacity(visualState == .disconnected ? 0.55 : 1)
            }

            Circle()
                .fill(visualState.accent.opacity(visualState == .disconnected ? 0.08 : 0.14))

            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 30, weight: .semibold))
                .foregroundStyle(visualState.accent.opacity(visualState == .disconnected ? 0.66 : 0.92))
                .symbolRenderingMode(.hierarchical)
                .scaleEffect(visualState == .connected ? 1.04 : 0.96)

            StatusBadge(visualState: visualState)
                .id(visualState.badgeSymbol)
                .offset(x: 19, y: 19)
                .transition(.scale(scale: 0.62).combined(with: .opacity))
        }
        .frame(width: 60, height: 60)
        .contentShape(.circle)
        .accessibilityLabel(Text(state.title))
        .animation(reduceMotion ? nil : .spring(response: 0.42, dampingFraction: 0.82), value: visualState)
    }
}

private struct ActivityHalo: View {
    var color: Color

    var body: some View {
        TimelineView(.animation) { context in
            let degrees = context.date.timeIntervalSinceReferenceDate * 190

            Circle()
                .trim(from: 0.12, to: 0.82)
                .stroke(
                    AngularGradient(
                        colors: [
                            color.opacity(0.08),
                            color.opacity(0.94),
                            color.opacity(0.08),
                        ],
                        center: .center,
                    ),
                    style: StrokeStyle(lineWidth: 3, lineCap: .round),
                )
                .rotationEffect(.degrees(degrees))
        }
    }
}

private struct StatusBadge: View {
    var visualState: TunnelVisualState

    var body: some View {
        ZStack {
            Circle()
                .fill(visualState.accent)

            Image(systemName: visualState.badgeSymbol)
                .font(.system(size: 11, weight: .black, design: .rounded))
                .foregroundStyle(.white)
                .symbolRenderingMode(.monochrome)
        }
        .frame(width: 22, height: 22)
    }
}

private struct ConnectButtonLabel: View {
    var visualState: TunnelVisualState

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: visualState.buttonSymbol)
                .imageScale(.large)
            Text(visualState.buttonTitle)
                .fontWeight(.semibold)
        }
        .font(.headline)
        .frame(maxWidth: .infinity, minHeight: 42)
        .contentShape(.rect)
    }
}

#Preview {
    NavigationStack {
        DashboardView()
    }
    .environment(HopStore.preview)
}
