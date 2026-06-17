import Foundation

enum ProfileImportPayloadDetector {
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
        guard let components = URLComponents(string: value),
              components.scheme?.lowercased() == "https",
              components.host?.isEmpty == false,
              components.user == nil,
              components.password == nil
        else {
            return nil
        }

        let path = components.percentEncodedPath
        let hasSubscriptionPathOrQuery = (!path.isEmpty && path != "/") || components.percentEncodedQuery != nil
        if components.port != nil, !hasSubscriptionPathOrQuery {
            return nil
        }

        return components.url ?? URL(string: value)
    }
}
