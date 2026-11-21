import Foundation

enum ProfileImportPayloadDetector {
    /// Fields emitted by Hop's pathless HTTPS node links. A token or other
    /// subscription parameter still goes to the subscription preview.
    private static let proxyQueryFields: Set<String> = [
        "security", "sni", "alpn", "fp", "pcs", "vcn", "ech", "curves", "minver", "maxver",
        "ciphers", "sessionresumption", "pbk", "sid", "spx", "pqv", "type", "path", "host",
        "servicename", "authority", "mode", "xhttpextra", "kcp", "finalmask", "mux", "sockopt",
    ]

    enum Payload: Equatable {
        case importText(String)
        case subscription(URL)
    }

    static func detect(_ rawValue: String) -> Payload? {
        let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }

        if let subscriptionURL = subscriptionURL(from: trimmed) {
            return .subscription(subscriptionURL)
        }

        return .importText(trimmed)
    }

    private static func subscriptionURL(from value: String) -> URL? {
        guard value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              let components = URLComponents(string: value),
              components.scheme?.lowercased() == "https",
              components.host?.isEmpty == false,
              components.user == nil,
              components.password == nil
        else {
            return nil
        }

        let path = components.percentEncodedPath
        if components.port != nil, path.isEmpty || path == "/" {
            if components.percentEncodedQuery == nil {
                return nil
            }
            if components.fragment != nil,
               let items = components.queryItems, !items.isEmpty,
               items.allSatisfy({ proxyQueryFields.contains($0.name.lowercased()) })
            {
                return nil
            }
        }

        return components.url ?? URL(string: value)
    }
}
