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
    var url: URL
    var secretStore: SecretStore
    var authenticationStore: SecretStore
    /// Shared across value copies of this store; see `SecretWriteCache`.
    private let secretWriteCache = SecretWriteCache()

    init(
        url: URL = RuntimeEnvironment.stateFileURL,
        secretStore: SecretStore = .shared,
        authenticationStore: SecretStore = .runtime,
    ) {
        self.url = url
        self.secretStore = secretStore
        self.authenticationStore = authenticationStore
    }

    func load() -> HopAppData? {
        guard let data = try? Data(contentsOf: url) else {
            return nil
        }

        let hadAuthenticationSecret = !authenticationStore.appStateAuthenticationSecret().isEmpty
        guard !hadAuthenticationSecret || isAuthenticated(data) else {
            NSLog("Hop: app state authentication failed")
            return nil
        }

        guard var decoded = try? JSONDecoder.hop.decode(HopAppData.self, from: data) else {
            return nil
        }

        // Legacy/plaintext state (written before Keychain migration for
        // profiles, or before subscription URLs were treated as bearer
        // secrets) still carries inline values — detect that so we can migrate
        // it in place.
        let hadInlineProfileSecrets = decoded.profiles.contains { !$0.secretFieldValues.isEmpty }
        let hadInlineSubscriptionURLs = decoded.subscriptions.contains { !$0.url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        decoded.profiles = decoded.profiles.map { $0.hydratingSecrets(from: secretStore) }
        decoded.subscriptions = decoded.subscriptions.map { $0.hydratingSecrets(from: secretStore) }
        if !hadAuthenticationSecret || hadInlineProfileSecrets || hadInlineSubscriptionURLs {
            save(decoded) // move secrets to the Keychain and rewrite the JSON without them
        }
        return decoded
    }

    func save(_ data: HopAppData) {
        do {
            // Move secrets into the Keychain and strip them from the JSON so
            // credentials, UUIDs, and private keys are never written in
            // cleartext. `replaceAll` costs one Keychain round-trip per secret
            // plus an enumerate-and-prune pass — with hundreds of imported
            // profiles that dominates every save — so it runs only when the
            // secret set actually changed since the last write. Most saves
            // (log updates, settings, rule edits) change no secret at all.
            // The first save after launch always writes, so a Keychain that
            // drifted while the app was not running heals on next persist.
            let secretItems = data.profiles.flatMap(\.keychainSecretItems) + data.subscriptions.compactMap(\.keychainURLItem)
            if secretWriteCache.changedSinceLastWrite(secretItems) {
                if !secretStore.replaceAll(with: secretItems) {
                    // A write failed inside the Keychain. Drop the cache so the
                    // next save retries the full set instead of skipping forever
                    // on a state that never actually landed.
                    secretWriteCache.invalidate()
                }
            }
            var redacted = data
            redacted.profiles = data.profiles.map { $0.redactingSecrets() }
            redacted.subscriptions = data.subscriptions.map { $0.redactingSecrets() }

            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            let encoded = try JSONEncoder.hop.encode(redacted)
            guard let signature = signature(for: encoded) else {
                NSLog("Hop: unable to authenticate app state; skipping save")
                return
            }
            // Defense-in-depth: protect the (now secret-free) state at rest too.
            try encoded.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            try Data(signature.utf8).write(to: signatureURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } catch {
            assertionFailure("Unable to persist Hop app data: \(error)")
        }
    }

    private var signatureURL: URL {
        TunnelConfigAuthenticator.signatureURL(forConfigURL: url)
    }

    private func signature(for data: Data) -> String? {
        let secret = authenticationStore.ensureAppStateAuthenticationSecret()
        guard !secret.isEmpty, authenticationStore.appStateAuthenticationSecret() == secret else {
            return nil
        }
        return TunnelConfigAuthenticator.signature(for: data, secret: secret)
    }

    private func isAuthenticated(_ data: Data) -> Bool {
        let secret = authenticationStore.appStateAuthenticationSecret()
        guard !secret.isEmpty,
              let signature = try? String(contentsOf: signatureURL, encoding: .utf8)
        else {
            return false
        }
        return TunnelConfigAuthenticator.isValidSignature(signature, for: data, secret: secret)
    }
}

/// Remembers the secret set most recently handed to `SecretStore.replaceAll`
/// so unchanged saves can skip the Keychain entirely. A reference type shared
/// across value copies of `HopAppDataStore`; saves are serialized on
/// `HopStore`'s persist queue, and the lock covers the one load-time migration
/// save that runs before that queue is in play.
private final class SecretWriteCache: @unchecked Sendable {
    private let lock = NSLock()
    private var lastWritten: [String: String]?

    /// Records `items` as the latest intended Keychain state and reports
    /// whether they differ from the previous write (always true for the first).
    func changedSinceLastWrite(_ items: [(key: String, value: String)]) -> Bool {
        let dictionary = Dictionary(items, uniquingKeysWith: { _, last in last })
        lock.lock()
        defer { lock.unlock() }
        if lastWritten == dictionary {
            return false
        }
        lastWritten = dictionary
        return true
    }

    /// Forgets the recorded state after a failed Keychain write, so the next
    /// save runs `replaceAll` again rather than treating the failed state as
    /// already written.
    func invalidate() {
        lock.lock()
        defer { lock.unlock() }
        lastWritten = nil
    }
}

private extension JSONEncoder {
    static var hop: JSONEncoder {
        let encoder = JSONEncoder()
        #if DEBUG
            // Human-readable state files help debugging, but pretty-printing and
            // key-sorting roughly double encode time for a file only the app reads.
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        #endif
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
