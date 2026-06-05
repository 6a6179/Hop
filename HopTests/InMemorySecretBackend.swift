import Foundation
@testable import Hop

/// In-memory `SecretBackend` for tests. The real Keychain is unavailable to
/// unsigned simulator unit tests, so tests exercise the secret logic
/// (redaction, tokenization, migration, store semantics) against this backend.
final class InMemorySecretBackend: SecretBackend, @unchecked Sendable {
    private var storage: [String: String] = [:]
    private let lock = NSLock()

    func value(forKey key: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return storage[key]
    }

    func setValue(_ value: String, forKey key: String) {
        lock.lock()
        defer { lock.unlock() }
        storage[key] = value
    }

    func removeValue(forKey key: String) {
        lock.lock()
        defer { lock.unlock() }
        storage[key] = nil
    }

    func removeAll() {
        lock.lock()
        defer { lock.unlock() }
        storage.removeAll()
    }
}

extension SecretStore {
    /// A fresh, isolated in-memory store for tests.
    static func inMemory() -> SecretStore {
        SecretStore(backend: InMemorySecretBackend())
    }
}
