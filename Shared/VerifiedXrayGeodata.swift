import CryptoKit
import Foundation

/// The checksum-verified, memory-bounded Xray geodata bundle shipped in both
/// Hop executables. Adding a category requires regenerating `Geodata/*.dat`
/// and reviewing the physical-device memory matrix.
enum VerifiedXrayGeodata {
    struct Asset: Sendable {
        let name: String
        let maximumBytes: Int
        let sha256: String

        var fileName: String {
            "\(name).dat"
        }
    }

    static let geoSiteCategories: Set<String> = ["category-ir"]
    static let geoIPCategories: Set<String> = ["cn", "ir", "private"]

    static let assets = [
        Asset(
            name: "geoip",
            maximumBytes: 256 * 1024,
            sha256: "6c7ecd14515ee22f50a796f87fb28220353e2ef7a267846e7f8766289d58e841",
        ),
        Asset(
            name: "geosite",
            maximumBytes: 64 * 1024,
            sha256: "21bf8b6e0233cb481a6f40dbe09b850981642598d848be8500ce0281019f5d8c",
        ),
    ]

    /// Returns the directory Xray may use only after both bundled assets pass
    /// their reviewed size and digest checks. The files are copied to the
    /// bundle root so Xray can resolve `geoip.dat` and `geosite.dat` together.
    static func assetDirectory(in bundle: Bundle) throws -> String {
        guard let directory = bundle.resourceURL else {
            throw VerifiedXrayGeodataError.missingResourceDirectory
        }

        for asset in assets {
            guard let url = bundle.url(forResource: asset.name, withExtension: "dat") else {
                throw VerifiedXrayGeodataError.missingAsset(asset.fileName)
            }
            guard url.deletingLastPathComponent().standardizedFileURL == directory.standardizedFileURL else {
                throw VerifiedXrayGeodataError.assetOutsideResourceDirectory(asset.fileName)
            }

            let data = try Data(contentsOf: url, options: .mappedIfSafe)
            guard data.count <= asset.maximumBytes else {
                throw VerifiedXrayGeodataError.assetTooLarge(asset.fileName, data.count)
            }
            let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            guard digest == asset.sha256 else {
                throw VerifiedXrayGeodataError.checksumMismatch(asset.fileName)
            }
        }
        return directory.path
    }
}

enum VerifiedXrayGeodataError: LocalizedError {
    case missingResourceDirectory
    case missingAsset(String)
    case assetOutsideResourceDirectory(String)
    case assetTooLarge(String, Int)
    case checksumMismatch(String)

    var errorDescription: String? {
        switch self {
        case .missingResourceDirectory:
            "The Xray geodata resource directory is unavailable."
        case let .missingAsset(name):
            "The verified Xray geodata asset \(name) is missing."
        case let .assetOutsideResourceDirectory(name):
            "The Xray geodata asset \(name) is not in the bundle resource directory."
        case let .assetTooLarge(name, bytes):
            "The Xray geodata asset \(name) exceeds its memory envelope (\(bytes) bytes)."
        case let .checksumMismatch(name):
            "The Xray geodata asset \(name) failed its checksum."
        }
    }
}
