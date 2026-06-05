import SwiftUI

/// Small green "Active" capsule shown on the selected node, group, or
/// configuration row.
struct ActiveBadge: View {
    var label = "Active"

    var body: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(.green)
                .frame(width: 6, height: 6)
            Text(label)
                .font(.caption2.weight(.semibold))
        }
        .foregroundStyle(.green)
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(.green.opacity(0.14), in: Capsule())
        .accessibilityLabel(label)
        .transition(.scale(scale: 0.7, anchor: .trailing).combined(with: .opacity))
    }
}
