import Foundation

/// The sole versioned Swift/Go bridge request. Both app validation and tunnel
/// runtime use this JSON shape; no Go-owned reference crosses the boundary.
struct XrayBridgeRequest: Codable, Sendable {
    var version: Int = 1
    var method: String
    var configJSON: String?
    var assetDirectory: String?
    var tunFD: Int32?

    init(
        method: String,
        configJSON: String? = nil,
        assetDirectory: String? = nil,
        tunFD: Int32? = nil,
    ) {
        self.method = method
        self.configJSON = configJSON
        self.assetDirectory = assetDirectory
        self.tunFD = tunFD
    }
}

struct XrayBridgeResponse: Codable, Sendable {
    struct Failure: Codable, Sendable {
        var code: String

        /// Bridge messages can contain values echoed from a fully resolved
        /// configuration. Keep only the fixed machine code in Swift-facing
        /// diagnostics; unknown codes are not safe display text either.
        var safeCode: String {
            Self.sanitizedCode(code)
        }

        static func sanitizedCode(_ code: String?) -> String {
            guard let code else {
                return "unknown"
            }
            return switch code {
            case "bridge_panic", "invalid_request", "unsupported_version",
                 "unknown_method", "invalid_config", "validation_cleanup_failed",
                 "already_running", "start_failed", "stop_failed":
                code
            default:
                "unknown"
            }
        }
    }

    var version: Int
    var ok: Bool
    var result: JSONValue?
    var error: Failure?
}
