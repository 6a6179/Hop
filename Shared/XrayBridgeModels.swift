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
        var message: String
    }

    var version: Int
    var ok: Bool
    var result: JSONValue?
    var error: Failure?
}
