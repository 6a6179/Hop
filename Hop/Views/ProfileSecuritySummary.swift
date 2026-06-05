import SwiftUI

struct ProfileSecuritySummary: View {
    var profile: ProxyProfile

    var body: some View {
        HStack(spacing: 10) {
            ProtocolBadge(proto: profile.proto)

            Spacer(minLength: 8)

            Text(endpointText)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .multilineTextAlignment(.trailing)
        }
    }

    private var endpointText: String {
        "\(profile.endpoint.host):\(profile.endpoint.port)"
    }
}

private struct ProtocolBadge: View {
    var proto: ProxyProtocol

    var body: some View {
        Text(proto.displayName)
            .font(.caption.weight(.semibold))
            .lineLimit(1)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .foregroundStyle(proto.badgeTint)
            .background(proto.badgeTint.opacity(0.14), in: Capsule())
            .overlay {
                Capsule()
                    .strokeBorder(proto.badgeTint.opacity(0.18), lineWidth: 0.5)
            }
    }
}

private extension ProxyProtocol {
    var badgeTint: Color {
        switch self {
        case .vless:
            .blue
        case .trojan:
            .purple
        case .hysteria2:
            .orange
        case .tuic:
            .teal
        case .shadowsocks:
            .cyan
        case .vmess:
            .pink
        case .http:
            .indigo
        case .socks:
            .brown
        case .wireGuard:
            .mint
        case .anyTLS:
            .red
        }
    }
}
