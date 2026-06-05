import Foundation
import Security

/// Pluggable backing store for secrets, so the Keychain integration can be
/// swapped for an in-memory backend in tests (the Keychain is unavailable to
/// unsigned simulator unit tests).
protocol SecretBackend: Sendable {
    func value(forKey key: String) -> String?
    func setValue(_ value: String, forKey key: String)
    func removeValue(forKey key: String)
    func removeAll()
}

/// Store for proxy secrets (passwords, UUIDs, private keys), shared between the
/// Hop app and the HopTunnel packet-tunnel extension via a Keychain access
/// group at runtime.
struct SecretStore {
    static let defaultService = "cat.string.hop.secrets"

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

    func value(forKey key: String) -> String? {
        backend.value(forKey: key)
    }

    func setValue(_ value: String, forKey key: String) {
        backend.setValue(value, forKey: key)
    }

    func removeValue(forKey key: String) {
        backend.removeValue(forKey: key)
    }

    func removeAll() {
        backend.removeAll()
    }

    /// Atomically replaces the stored set: clears everything, then writes the
    /// provided items. Ensures secrets for deleted profiles do not linger.
    func replaceAll(with items: [(key: String, value: String)]) {
        backend.removeAll()
        for item in items {
            backend.setValue(item.value, forKey: item.key)
        }
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

    func value(forKey key: String) -> String? {
        read(account: key, includeGroup: accessGroup != nil)
    }

    func setValue(_ value: String, forKey key: String) {
        write(account: key, data: Data(value.utf8), includeGroup: accessGroup != nil)
    }

    func removeValue(forKey key: String) {
        delete(account: key, includeGroup: accessGroup != nil)
    }

    func removeAll() {
        delete(account: nil, includeGroup: accessGroup != nil)
    }

    private func read(account: String, includeGroup: Bool) -> String? {
        var query = baseQuery(account: account, includeGroup: includeGroup)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecMissingEntitlement, includeGroup {
            return read(account: account, includeGroup: false)
        }
        guard status == errSecSuccess, let data = item as? Data else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    private func write(account: String, data: Data, includeGroup: Bool) {
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
            write(account: account, data: data, includeGroup: false)
        }
    }

    private func delete(account: String?, includeGroup: Bool) {
        let query = baseQuery(account: account, includeGroup: includeGroup)
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecMissingEntitlement, includeGroup {
            delete(account: account, includeGroup: false)
        }
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
