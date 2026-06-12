import Foundation
@testable import Hop

/// In-memory `SecretBackend` for tests. The real Keychain is unavailable to
/// unsigned simulator unit tests, so tests exercise the secret logic
/// (redaction, tokenization, migration, store semantics) against this backend.
final class InMemorySecretBackend: SecretBackend, @unchecked Sendable {
    private var storage: [String: String] = [:]
    private let lock = NSLock()

    /// Number of `removeAll` calls.
    private(set) var removeAllCount = 0

    /// Number of `allKeys` calls. `SecretStore.replaceAll` scans the stored
    /// keys exactly once per `HopAppDataStore.save`, so this counts state
    /// persists in tests.
    private(set) var allKeysCount = 0

    func value(forKey key: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return storage[key]
    }

    @discardableResult
    func setValue(_ value: String, forKey key: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        storage[key] = value
        return true
    }

    @discardableResult
    func removeValue(forKey key: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        storage[key] = nil
        return true
    }

    func removeAll() {
        lock.lock()
        defer { lock.unlock() }
        storage.removeAll()
        removeAllCount += 1
    }

    func allKeys() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        allKeysCount += 1
        return Array(storage.keys)
    }
}

extension SecretStore {
    /// A fresh, isolated in-memory store for tests.
    static func inMemory() -> SecretStore {
        SecretStore(backend: InMemorySecretBackend())
    }
}

/// Backend whose first `setValue` fails (returning false and storing nothing),
/// for exercising the secret-write retry path in `HopAppDataStore`.
final class FailOnceSecretBackend: SecretBackend, @unchecked Sendable {
    private let inner = InMemorySecretBackend()
    private let lock = NSLock()
    private var didFail = false

    func value(forKey key: String) -> String? {
        inner.value(forKey: key)
    }

    func setValue(_ value: String, forKey key: String) -> Bool {
        lock.lock()
        let shouldFail = !didFail
        didFail = true
        lock.unlock()
        if shouldFail {
            return false
        }
        return inner.setValue(value, forKey: key)
    }

    func removeValue(forKey key: String) -> Bool {
        inner.removeValue(forKey: key)
    }

    func removeAll() {
        inner.removeAll()
    }

    func allKeys() -> [String] {
        inner.allKeys()
    }
}
