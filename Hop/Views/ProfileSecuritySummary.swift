import SwiftUI

struct ProfileSecuritySummary: View {
    let profile: ProxyProfile

    var body: some View {
        HStack(spacing: 10) {
            StatusPill(profile.proto.displayName, tint: profile.proto.badgeTint, font: .caption.weight(.semibold))

            Spacer(minLength: 8)

            Text("\(profile.endpoint.host):\(profile.endpoint.port)")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .multilineTextAlignment(.trailing)
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
