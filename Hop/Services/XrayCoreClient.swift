import Foundation

#if canImport(LibXray)
    @preconcurrency import LibXray
#endif

enum XrayCoreClient {
    static func validate(configJSON: String) async throws {
        let assetDirectory = try VerifiedXrayGeodata.assetDirectory(in: .main)
        try await Task.detached(priority: .userInitiated) {
            #if canImport(LibXray)
                let request = XrayBridgeRequest(
                    method: "validate",
                    configJSON: configJSON,
                    assetDirectory: assetDirectory,
                )
                let requestData = try JSONEncoder().encode(request)
                guard let requestJSON = String(data: requestData, encoding: .utf8) else {
                    throw XrayCoreClientError.invalidBridgeEncoding
                }
                let rawResponse = stringValue(LibXrayInvoke(requestJSON))
                guard let responseData = rawResponse.data(using: .utf8) else {
                    throw XrayCoreClientError.invalidBridgeEncoding
                }
                guard let response = try? JSONDecoder().decode(XrayBridgeResponse.self, from: responseData) else {
                    throw XrayCoreClientError.invalidBridgeEncoding
                }
                guard response.version == 1 else {
                    throw XrayCoreClientError.unsupportedBridgeVersion(response.version)
                }
                guard response.ok else {
                    throw XrayCoreClientError.validationFailed(code: response.error?.safeCode ?? "unknown")
                }
            #else
                throw XrayCoreClientError.frameworkUnavailable
            #endif
        }.value
    }

    #if canImport(LibXray)
        private static func stringValue(_ value: String) -> String {
            value
        }

        private static func stringValue(_ value: String?) -> String {
            value ?? ""
        }
    #endif
}

enum XrayCoreClientError: LocalizedError {
    case frameworkUnavailable
    case invalidBridgeEncoding
    case unsupportedBridgeVersion(Int)
    case validationFailed(code: String)

    var errorDescription: String? {
        switch self {
        case .frameworkUnavailable:
            "LibXray.xcframework is unavailable in this build."
        case .invalidBridgeEncoding:
            "The Xray validation bridge returned invalid data."
        case let .unsupportedBridgeVersion(version):
            "The Xray bridge returned unsupported API version \(version)."
        case let .validationFailed(code):
            "Xray configuration validation failed (\(XrayBridgeResponse.Failure.sanitizedCode(code))). Review the selected profile's settings."
        }
    }
}
