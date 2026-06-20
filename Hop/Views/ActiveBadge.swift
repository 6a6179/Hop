import SwiftUI

/// Small green "Active" capsule shown on the selected node, group, or
/// configuration row.
struct ActiveBadge: View {
    var body: some View {
        StatusPill("Active", tint: .green, dot: true)
            .accessibilityLabel("Active")
            .transition(.scale(scale: 0.7, anchor: .trailing).combined(with: .opacity))
    }
}

struct StatusPill: View {
    let text: String
    let tint: Color
    let systemImage: String?
    let dot: Bool
    let font: Font

    init(
        _ text: String,
        tint: Color,
        systemImage: String? = nil,
        dot: Bool = false,
        font: Font = .caption2.weight(.semibold),
    ) {
        self.text = text
        self.tint = tint
        self.systemImage = systemImage
        self.dot = dot
        self.font = font
    }

    var body: some View {
        HStack(spacing: 4) {
            if dot {
                Circle()
                    .fill(tint)
                    .frame(width: 6, height: 6)
            }

            if let systemImage {
                Image(systemName: systemImage)
                    .font(.caption2)
            }

            Text(text)
                .font(font)
        }
        .lineLimit(1)
        .foregroundStyle(tint)
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .glassEffect(.regular.tint(tint.opacity(0.14)), in: .capsule)
    }
}
