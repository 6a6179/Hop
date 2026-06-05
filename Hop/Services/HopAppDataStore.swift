import Foundation

struct HopAppData: Codable {
    var profiles: [ProxyProfile]
    var groups: [ProxyGroup]
    var subscriptions: [SubscriptionSource]
    var routingMode: RoutingMode
    var selectedTarget: OutboundTarget?
    var settings: AppSettings
    var logs: [String]
    var ruleConfigurations: [RuleConfiguration]?
    var activeRuleConfigurationID: UUID?
    /// Legacy single rule list from before named configurations. Read on load to
    /// migrate; never written by current builds (optionals are omitted on encode).
    var rules: [RoutingRule]?

    init(
        profiles: [ProxyProfile],
        groups: [ProxyGroup],
        subscriptions: [SubscriptionSource],
        routingMode: RoutingMode,
        selectedTarget: OutboundTarget?,
        settings: AppSettings,
        logs: [String],
        ruleConfigurations: [RuleConfiguration]? = nil,
        activeRuleConfigurationID: UUID? = nil,
        rules: [RoutingRule]? = nil,
    ) {
        self.profiles = profiles
        self.groups = groups
        self.subscriptions = subscriptions
        self.routingMode = routingMode
        self.selectedTarget = selectedTarget
        self.settings = settings
        self.logs = logs
        self.ruleConfigurations = ruleConfigurations
        self.activeRuleConfigurationID = activeRuleConfigurationID
        self.rules = rules
    }
}

struct HopAppDataStore {
    var url: URL = RuntimeEnvironment.stateFileURL
    var secretStore: SecretStore = .shared

    func load() -> HopAppData? {
        guard let data = try? Data(contentsOf: url),
              var decoded = try? JSONDecoder.hop.decode(HopAppData.self, from: data)
        else {
            return nil
        }

        // Legacy plaintext state (written before the Keychain migration) still
        // carries inline secrets — detect that so we can migrate it in place.
        let hadInlineSecrets = decoded.profiles.contains { !$0.secretFieldValues.isEmpty }
        decoded.profiles = decoded.profiles.map { $0.hydratingSecrets(from: secretStore) }
        if hadInlineSecrets {
            save(decoded) // move secrets to the Keychain and rewrite the JSON without them
        }
        return decoded
    }

    func save(_ data: HopAppData) {
        do {
            // Move secrets into the Keychain and strip them from the JSON so
            // credentials, UUIDs, and private keys are never written in cleartext.
            secretStore.replaceAll(with: data.profiles.flatMap(\.keychainSecretItems))
            var redacted = data
            redacted.profiles = data.profiles.map { $0.redactingSecrets() }

            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            let encoded = try JSONEncoder.hop.encode(redacted)
            // Defense-in-depth: protect the (now secret-free) state at rest too.
            try encoded.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } catch {
            assertionFailure("Unable to persist Hop app data: \(error)")
        }
    }
}

private extension JSONEncoder {
    static var hop: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }
}

private extension JSONDecoder {
    static var hop: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}
