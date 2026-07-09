import CoreImage.CIFilterBuiltins
import SwiftUI

/// A node's share link rendered as a QR code, for moving a profile to another
/// device's scanner. The link — and therefore the QR — contains the node's
/// credentials; the footer says so.
struct ProfileShareQRSheet: View {
    @Environment(\.dismiss) private var dismiss

    let profileName: String
    private let qrImage: UIImage?
    private static let qrContext = CIContext()

    init(profileName: String, link: String) {
        self.profileName = profileName
        qrImage = Self.qrImage(for: link)
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                if let image = qrImage {
                    Image(uiImage: image)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(maxWidth: 280)
                        .padding(12)
                        .background(Color.white, in: RoundedRectangle(cornerRadius: 16))
                        .accessibilityLabel("QR code for \(profileName)")
                } else {
                    ContentUnavailableView(
                        "Could Not Generate Code",
                        systemImage: "qrcode",
                        description: Text("The share link is too long to encode as a QR code."),
                    )
                }

                Label("This code contains the node's credentials. Anyone who scans it can use — and inspect — this node.", systemImage: "exclamationmark.triangle")
                    .font(.footnote)
                    .foregroundStyle(.orange)
                    .padding(12)
                    .glassEffect(.regular.tint(.orange.opacity(0.12)), in: .rect(cornerRadius: 16))
                    .padding(.horizontal)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .navigationTitle(profileName)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
        .presentationDetents([.medium, .large])
    }

    private static func qrImage(for link: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(link.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else {
            return nil
        }
        // Scale the tiny module matrix up without smoothing.
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 12, y: 12))
        guard let cgImage = qrContext.createCGImage(scaled, from: scaled.extent) else {
            return nil
        }
        return UIImage(cgImage: cgImage)
    }
}
