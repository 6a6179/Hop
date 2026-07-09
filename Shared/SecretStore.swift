import Foundation
import Security

/// Pluggable backing store for secrets, so the Keychain integration can be
/// swapped for an in-memory backend in tests (the Keychain is unavailable to
/// unsigned simulator unit tests).
protocol SecretBackend: Sendable {
    func value(forKey key: String) -> String?
    /// Returns whether the write landed in the backing store, so callers that
    /// cache "already written" state (`HopAppDataStore`) can retry after a
    /// silent Keychain failure instead of skipping forever.
    func setValue(_ value: String, forKey key: String) -> Bool
    /// Returns whether the key is absent afterwards (deleting a missing key
    /// counts as success).
    func removeValue(forKey key: String) -> Bool
    func removeAll()
    /// All stored keys; lets `replaceAll` prune stale items without a blanket
    /// delete-everything-first pass.
    func allKeys() -> [String]
}

/// Store for proxy secrets (passwords, UUIDs, private keys), shared between the
/// Hop app and the HopTunnel packet-tunnel extension via a Keychain access
/// group at runtime.
struct SecretStore {
    static let defaultService = "cat.string.hop.secrets"

    /// Separate Keychain service for runtime/inter-process secrets (for
    /// example, App Group configuration authentication keys). Kept apart from `defaultService` so a
    /// profile save's `replaceAll` — which rewrites the *profile* secret set —
    /// never evicts these.
    static let runtimeService = "cat.string.hop.runtime"

    /// Group suffix; the team/app-identifier prefix is prepended at runtime to
    /// match the `$(AppIdentifierPrefix)cat.string.hop` entitlement entry.
    static let sharedAccessGroupSuffix = "cat.string.hop"

    private let backend: SecretBackend

    init(backend: SecretBackend) {
        self.backend = backend
    }

    init(service: String = SecretStore.defaultService, accessGroup: String? = SecretStore.resolvedSharedAccessGroup()) {
        self.init(backend: KeychainSecretBackend(service: service, accessGroup: accessGroup))
    }

    static let shared = SecretStore()

    /// Shared store for runtime secrets that must outlive profile-secret
    /// rewrites (see `runtimeService`).
    static let runtime = SecretStore(service: runtimeService)

    func value(forKey key: String) -> String? {
        backend.value(forKey: key)
    }

    @discardableResult
    func setValue(_ value: String, forKey key: String) -> Bool {
        backend.setValue(value, forKey: key)
    }

    @discardableResult
    func removeValue(forKey key: String) -> Bool {
        backend.removeValue(forKey: key)
    }

    func removeAll() {
        backend.removeAll()
    }

    /// Replaces the stored set: writes/updates the provided items first, then
    /// prunes keys that are no longer present, so secrets for deleted profiles
    /// do not linger. Upsert-before-prune keeps every still-valid secret
    /// readable throughout — the Keychain has no cross-item transactions, and a
    /// clear-then-rewrite pass would give the tunnel extension a window where
    /// `SecretResolver` finds nothing and fails a concurrent start/reload.
    /// Returns false if any write or prune failed; the set may then be partial.
    @discardableResult
    func replaceAll(with items: [(key: String, value: String)]) -> Bool {
        var allSucceeded = true
        for item in items {
            allSucceeded = backend.setValue(item.value, forKey: item.key) && allSucceeded
        }
        let keep = Set(items.map(\.key))
        for key in backend.allKeys() where !keep.contains(key) {
            allSucceeded = backend.removeValue(forKey: key) && allSucceeded
        }
        return allSucceeded
    }

    /// Keychain account for the HMAC key that authenticates the App Group
    /// tunnel config file before the extension resolves secret tokens from it.
    static let tunnelConfigAuthenticationKey = "tunnel-config-authentication-key"

    func tunnelConfigAuthenticationSecret() -> String {
        value(forKey: Self.tunnelConfigAuthenticationKey) ?? ""
    }

    @discardableResult
    func ensureTunnelConfigAuthenticationSecret() -> String {
        ensureRuntimeSecret(forKey: Self.tunnelConfigAuthenticationKey)
    }

    static let appStateAuthenticationKey = "app-state-authentication-key"

    func appStateAuthenticationSecret() -> String {
        value(forKey: Self.appStateAuthenticationKey) ?? ""
    }

    @discardableResult
    func ensureAppStateAuthenticationSecret() -> String {
        ensureRuntimeSecret(forKey: Self.appStateAuthenticationKey)
    }

    private func ensureRuntimeSecret(forKey key: String) -> String {
        if let existing = value(forKey: key), !existing.isEmpty {
            return existing
        }
        let secret = Self.randomSecret()
        setValue(secret, forKey: key)
        return secret
    }

    private static func randomSecret() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = bytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
        }
        if status == errSecSuccess {
            return Data(bytes).base64EncodedString()
        }
        // Extremely unlikely fallback if the system RNG call fails; still
        // unpredictable enough for a local auth token / MAC key.
        return UUID().uuidString + UUID().uuidString
    }

    // MARK: - Access-group resolution

    /// The shared access group string to pass to `SecItem`, fully prefixed with
    /// the team/app-identifier prefix. `nil` on the simulator and wherever the
    /// prefix cannot be determined (the store then uses a process-local keychain).
    static func resolvedSharedAccessGroup() -> String? {
        #if targetEnvironment(simulator)
            return nil
        #else
            guard let prefix = KeychainSecretBackend.appIdentifierPrefix(service: defaultService) else {
                return nil
            }
            return prefix + sharedAccessGroupSuffix
        #endif
    }
}

/// `SecItem`-backed secret store. Falls back to a process-local keychain when
/// the access-group entitlement is unavailable (unsigned builds), so single
/// processes still work; cross-process sharing on device requires the
/// `keychain-access-groups` entitlement on both targets.
struct KeychainSecretBackend: SecretBackend {
    let service: String
    let accessGroup: String?

    /// Emitted once (lazily, the first time it's referenced) when a Keychain
    /// operation falls back to the process-local keychain because the shared
    /// access-group entitlement is missing. Turns a silent misconfiguration —
    /// where the app writes secrets the tunnel extension can never read — into
    /// a diagnosable one, without logging per item.
    private static let didLogEntitlementFallback: Void = {
        NSLog("Hop: keychain-access-groups entitlement unavailable; using a process-local keychain. App↔tunnel secret sharing requires the shared access group on both targets.")
    }()

    func value(forKey key: String) -> String? {
        read(account: key, includeGroup: accessGroup != nil)
    }

    func setValue(_ value: String, forKey key: String) -> Bool {
        write(account: key, data: Data(value.utf8), includeGroup: accessGroup != nil)
    }

    func removeValue(forKey key: String) -> Bool {
        delete(account: key, includeGroup: accessGroup != nil)
    }

    func removeAll() {
        _ = delete(account: nil, includeGroup: accessGroup != nil)
    }

    func allKeys() -> [String] {
        keys(includeGroup: accessGroup != nil)
    }

    private func keys(includeGroup: Bool) -> [String] {
        var query = baseQuery(account: nil, includeGroup: includeGroup)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecMissingEntitlement, includeGroup {
            _ = Self.didLogEntitlementFallback
            return keys(includeGroup: false)
        }
        guard status == errSecSuccess, let items = result as? [[String: Any]] else {
            return []
        }
        return items.compactMap { $0[kSecAttrAccount as String] as? String }
    }

    private func read(account: String, includeGroup: Bool) -> String? {
        var query = baseQuery(account: account, includeGroup: includeGroup)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecMissingEntitlement, includeGroup {
            _ = Self.didLogEntitlementFallback
            return read(account: account, includeGroup: false)
        }
        guard status == errSecSuccess, let data = item as? Data else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    private func write(account: String, data: Data, includeGroup: Bool) -> Bool {
        let query = baseQuery(account: account, includeGroup: includeGroup)
        // Set the accessibility on update as well as add, so an item created
        // with a weaker class by an earlier build can't survive a value rewrite
        // with the wrong protection.
        var status = SecItemUpdate(query as CFDictionary, [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ] as CFDictionary)

        if status == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecValueData as String] = data
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            status = SecItemAdd(addQuery as CFDictionary, nil)
        }

        if status == errSecMissingEntitlement, includeGroup {
            _ = Self.didLogEntitlementFallback
            return write(account: account, data: data, includeGroup: false)
        }
        return status == errSecSuccess
    }

    private func delete(account: String?, includeGroup: Bool) -> Bool {
        let query = baseQuery(account: account, includeGroup: includeGroup)
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecMissingEntitlement, includeGroup {
            _ = Self.didLogEntitlementFallback
            return delete(account: account, includeGroup: false)
        }
        // Deleting something already gone is the desired end state.
        return status == errSecSuccess || status == errSecItemNotFound
    }

    private func baseQuery(account: String?, includeGroup: Bool) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        if let account {
            query[kSecAttrAccount as String] = account
        }
        if includeGroup, let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }

    /// Discovers the team/app-identifier prefix (e.g. `ABCDE12345.`) by writing a
    /// throwaway item with no explicit access group and reading back the group
    /// the system assigned it.
    static func appIdentifierPrefix(service: String) -> String? {
        let account = "cat.string.hop.accessgroup.probe"
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(base as CFDictionary)

        var addQuery = base
        addQuery[kSecValueData as String] = Data("probe".utf8)
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        guard SecItemAdd(addQuery as CFDictionary, nil) == errSecSuccess else {
            return nil
        }
        defer { SecItemDelete(base as CFDictionary) }

        var copyQuery = base
        copyQuery[kSecReturnAttributes as String] = true
        copyQuery[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(copyQuery as CFDictionary, &item) == errSecSuccess,
              let attributes = item as? [String: Any],
              let group = attributes[kSecAttrAccessGroup as String] as? String,
              let dot = group.firstIndex(of: ".")
        else {
            return nil
        }
        return String(group[...dot]) // prefix including the trailing dot
    }
}
