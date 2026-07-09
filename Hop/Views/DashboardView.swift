import SwiftUI

struct DashboardView: View {
    @Environment(HopStore.self) private var store
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private let openProfiles: () -> Void

    init(openProfiles: @escaping () -> Void = {}) {
        self.openProfiles = openProfiles
    }

    var body: some View {
        @Bindable var store = store
        let state = store.tunnel.state
        let enabledGroups = store.groups.filter(\.isEnabled)
        let selectedTarget = store.selectedTarget
        let needsProfile = store.profiles.isEmpty && !state.isConnected
        let connectionActionDisabled = state.isInFlight || (!state.isConnected && !needsProfile && selectedTarget == nil)

        Form {
            Section {
                ConnectWidget(
                    state: state,
                    profileName: store.selectedTargetDisplayName,
                    routingMode: store.routingMode,
                    isDisabled: connectionActionDisabled,
                    showsSetupAction: needsProfile,
                ) {
                    Task {
                        if store.tunnel.state.isConnected {
                            await store.tunnel.disconnect()
                        } else if needsProfile {
                            openProfiles()
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
                .listRowInsets(EdgeInsets(top: 18, leading: 16, bottom: 16, trailing: 16))
            }

            Section("Outbound") {
                Picker("Mode", selection: $store.routingMode) {
                    ForEach(RoutingMode.allCases, id: \.self) { mode in
                        Text(mode.title).tag(mode)
                    }
                }

                if store.profiles.isEmpty {
                    LabeledContent("Outbound") {
                        Text("Not configured")
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Picker("Outbound", selection: $store.selectedTarget) {
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
                    } else if selectedTarget == nil {
                        Label("Select an outbound before connecting.", systemImage: "server.rack")
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
                    state.accent.opacity(0.10),
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
}

private struct ConnectWidget: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    let state: TunnelConnectionState
    let profileName: String
    let routingMode: RoutingMode
    let isDisabled: Bool
    let showsSetupAction: Bool
    let action: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            let statusLayout = dynamicTypeSize.isAccessibilitySize
                ? AnyLayout(VStackLayout(alignment: .leading, spacing: 12))
                : AnyLayout(HStackLayout(alignment: .center, spacing: 14))

            statusLayout {
                ConnectionStatusGlyph(state: state, size: 46)

                ConnectionStatusText(
                    state: state,
                    profileName: profileName,
                    routingMode: routingMode,
                    showsSetupAction: showsSetupAction,
                )
            }

            Button(action: action) {
                ConnectButtonLabel(state: state, showsSetupAction: showsSetupAction)
            }
            .buttonStyle(.plain)
            .background(buttonTint.opacity(isDisabled ? 0.45 : 1), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .disabled(isDisabled)
            .accessibilityLabel(actionAccessibilityLabel)
            .accessibilityHint(isDisabled && !state.isInFlight ? "Select an outbound before connecting." : "")
        }
        .animation(reduceMotion ? nil : .easeInOut(duration: 0.25), value: state)
    }

    private var buttonTint: Color {
        showsSetupAction ? .accentColor : state.buttonTint
    }

    private var actionAccessibilityLabel: Text {
        if showsSetupAction {
            Text("Open Profiles to add a profile")
        } else if state.isConnected {
            Text("Disconnect VPN")
        } else {
            Text("Connect VPN")
        }
    }
}

private struct ConnectionStatusText: View {
    let state: TunnelConnectionState
    let profileName: String
    let routingMode: RoutingMode
    let showsSetupAction: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(state.title)
                .font(.title2.weight(.semibold))
                .lineLimit(1)
                .allowsTightening(true)
                .minimumScaleFactor(0.85)
                .truncationMode(.tail)
            Text(showsSetupAction ? "Add a profile to begin" : profileName)
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
            if !showsSetupAction {
                Text("\(routingMode.title) routing")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(state.accent)
                    .lineLimit(1)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
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
    let showsSetupAction: Bool

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: showsSetupAction ? "plus" : state.buttonSymbol)
                .font(.caption.weight(.semibold))
            Text(showsSetupAction ? "Add Profile" : state.buttonTitle)
        }
        .font(.headline.weight(.semibold))
        .foregroundStyle(.white)
        .lineLimit(2)
        .multilineTextAlignment(.center)
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
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
