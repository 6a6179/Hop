import SwiftUI

struct DashboardView: View {
    @Environment(HopStore.self) private var store
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        @Bindable var store = store
        let state = store.tunnel.state
        let enabledGroups = store.groups.filter(\.isEnabled)
        let selectedTarget = store.selectedTarget
        let connectionActionDisabled = state.isInFlight || store.profiles.isEmpty || selectedTarget == nil

        Form {
            Section {
                ConnectWidget(
                    state: state,
                    profileName: store.selectedTargetDisplayName,
                    routingMode: store.routingMode,
                    isDisabled: connectionActionDisabled,
                    isMissingProfiles: store.profiles.isEmpty,
                ) {
                    Task {
                        if store.tunnel.state.isConnected {
                            await store.tunnel.disconnect()
                        } else if let selectedTarget {
                            await store.tunnel.connect(
                                target: selectedTarget,
                                profiles: store.profiles,
                                groups: store.groups,
                                routingMode: store.routingMode,
                                rules: store.rules,
                                settings: store.settings,
                            )
                        }
                    }
                }
                .listRowInsets(EdgeInsets(top: 8, leading: 0, bottom: 8, trailing: 0))
                .listRowBackground(Color.clear)
            }

            Section("Outbound") {
                Picker("Mode", selection: $store.routingMode) {
                    ForEach(RoutingMode.allCases, id: \.self) { mode in
                        Text(mode.title).tag(mode)
                    }
                }

                Picker("Active", selection: $store.selectedTarget) {
                    Text("Direct").tag(Optional(OutboundTarget.direct))

                    if !enabledGroups.isEmpty {
                        Section("Groups") {
                            ForEach(enabledGroups) { group in
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
        }
        .contentMargins(.top, 8, for: .scrollContent)
        .listSectionSpacing(.compact)
        .scrollContentBackground(.hidden)
        .background {
            LinearGradient(
                colors: [
                    state.accent.opacity(0.16),
                    Color(uiColor: .systemGroupedBackground),
                ],
                startPoint: .top,
                endPoint: .center,
            )
            .ignoresSafeArea()
        }
        .animation(reduceMotion ? nil : .easeInOut(duration: 0.25), value: state)
        .navigationTitle("Hop")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private extension TunnelConnectionState {
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
            "Stopping"
        case .failed, .disconnected:
            "Connect"
        }
    }

    var buttonSymbol: String {
        "power"
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

    var buttonAccessibilityLabel: String {
        switch self {
        case .connected:
            "Disconnect from selected profile"
        case .connecting:
            "Connecting to selected profile"
        case .disconnecting:
            "Disconnecting from selected profile"
        case .failed, .disconnected:
            "Connect to selected profile"
        }
    }
}

private struct ConnectWidget: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    let state: TunnelConnectionState
    let profileName: String
    let routingMode: RoutingMode
    let isDisabled: Bool
    let isMissingProfiles: Bool
    let action: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .center, spacing: 14) {
                ConnectionStatusGlyph(state: state, size: 50)

                ConnectionStatusText(
                    state: state,
                    profileName: profileName,
                    routingMode: routingMode,
                )
            }

            Button(action: action) {
                ConnectButtonLabel(state: state)
            }
            .buttonStyle(.plain)
            .background(state.buttonTint.opacity(isDisabled ? 0.55 : 1), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
            .disabled(isDisabled)
            .accessibilityLabel(Text(state.buttonAccessibilityLabel))

            if isMissingProfiles {
                Label("Import a profile before connecting.", systemImage: "server.rack")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .background {
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [
                            state.accent.opacity(state == .disconnected ? 0.10 : 0.18),
                            Color(uiColor: .secondarySystemGroupedBackground),
                        ],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing,
                    ),
                )
        }
        .overlay {
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .strokeBorder(state.accent.opacity(state == .disconnected ? 0.12 : 0.22))
        }
        .shadow(color: state.accent.opacity(0.08), radius: 14, y: 8)
        .animation(reduceMotion ? nil : .easeInOut(duration: 0.25), value: state)
    }
}

private struct ConnectionStatusText: View {
    let state: TunnelConnectionState
    let profileName: String
    let routingMode: RoutingMode

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(state.title)
                .font(.title2.weight(.semibold))
                .lineLimit(1)
                .allowsTightening(true)
                .minimumScaleFactor(0.85)
                .truncationMode(.tail)
            Text(profileName)
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Text("\(routingMode.title) routing")
                .font(.caption.weight(.semibold))
                .foregroundStyle(state.accent)
                .lineLimit(1)
        }
        .layoutPriority(1)
        .accessibilityElement(children: .combine)
    }
}

private struct ConnectionStatusGlyph: View {
    let state: TunnelConnectionState
    let size: CGFloat

    init(state: TunnelConnectionState, size: CGFloat = 24) {
        self.state = state
        self.size = size
    }

    var body: some View {
        let badgeSize = max(11, size * 0.46)

        ZStack {
            Circle()
                .fill(state.accent.opacity(state == .disconnected ? 0.10 : 0.16))

            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: size * 0.58, weight: .semibold))
                .foregroundStyle(state.accent.opacity(state == .disconnected ? 0.56 : 0.86))
                .symbolRenderingMode(.hierarchical)
        }
        .frame(width: size, height: size)
        .overlay(alignment: .bottomTrailing) {
            Circle()
                .fill(state.accent)
                .frame(width: badgeSize, height: badgeSize)
                .overlay {
                    Image(systemName: state.badgeSymbol)
                        .font(.system(size: badgeSize * 0.52, weight: .black, design: .rounded))
                        .foregroundStyle(.white)
                }
                .offset(x: size * 0.08, y: size * 0.08)
        }
        .contentShape(.circle)
        .accessibilityHidden(true)
    }
}

private struct ConnectButtonLabel: View {
    let state: TunnelConnectionState

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: state.buttonSymbol)
                .font(.caption.weight(.semibold))
            Text(state.buttonTitle)
        }
        .font(.headline.weight(.semibold))
        .foregroundStyle(.white)
        .lineLimit(1)
        .padding(.horizontal, 16)
        .frame(maxWidth: .infinity, minHeight: 50)
        .contentShape(.rect)
    }
}

#Preview {
    NavigationStack {
        DashboardView()
    }
    .environment(HopStore.preview)
}
