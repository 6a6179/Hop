import Foundation

/// The sole versioned Swift/Go bridge request. Both app validation and tunnel
/// runtime use this JSON shape; no Go-owned reference crosses the boundary.
struct XrayBridgeRequest: Codable, Sendable {
    static let coreVersion = "v26.11.9"

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

        private enum CodingKeys: String, CodingKey { case code }
        private enum DiagnosticKeys: String, CodingKey { case message }

        init(from decoder: Decoder) throws {
            let fields = try decoder.container(keyedBy: CodingKeys.self)
            code = try fields.decode(String.self, forKey: .code)
            guard code == "invalid_config" else { return }
            let diagnostics = try decoder.container(keyedBy: DiagnosticKeys.self)
            guard let message = try? diagnostics.decode(String.self, forKey: .message) else { return }
            // Match only the pinned core's terminal diagnosis. Other error text
            // can include live credentials and must never reach logs or the UI.
            if message.hasSuffix(" > infra/conf: vless without TLS or other encryption is prohibited unless the server address is a private IP or domain") {
                code = "vless_transport_security_required"
            } else if message.hasSuffix(" > infra/conf: trojan without TLS is prohibited unless the server address is a private IP or domain") {
                code = "trojan_transport_security_required"
            }
        }

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
                 "unknown_method", "invalid_config", "vless_transport_security_required",
                 "trojan_transport_security_required", "validation_cleanup_failed",
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
