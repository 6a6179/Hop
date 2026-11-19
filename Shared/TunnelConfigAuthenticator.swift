import CryptoKit
import Darwin
import Foundation

/// HMACs the App Group tunnel config before the extension resolves any secret
/// tokens from it. App Group containers are a sharing boundary, not an
/// integrity boundary: another process with the same group could otherwise
/// tamper `hop-xray.json`, reuse the current nonce-bearing tokens, and make
/// the extension resolve Keychain credentials into attacker-controlled config.
enum TunnelConfigAuthenticator {
    static func signatureURL(forConfigURL url: URL) -> URL {
        url.appendingPathExtension("mac")
    }

    static func snapshotSignature(for data: Data, nonce: String, secret: String) -> String? {
        snapshotMAC(for: data, nonce: nonce, secret: secret).map { Data($0).base64EncodedString() }
    }

    static func readSnapshot(at url: URL, nonce: String, secret: String) throws -> String {
        let encodedMAC = try readFile(at: signatureURL(forConfigURL: url), limit: 44)
        guard encodedMAC.count == 44, let mac = Data(base64Encoded: encodedMAC), mac.count == 32 else {
            throw TunnelSnapshotError.invalidSignature
        }
        let data = try readFile(at: url, limit: TunnelMemoryPolicy.maximumConfigurationBytes)
        guard let expected = snapshotMAC(for: data, nonce: nonce, secret: secret), expected == mac else {
            throw TunnelSnapshotError.invalidSignature
        }
        guard let config = String(data: data, encoding: .utf8) else { throw TunnelSnapshotError.invalidFile }
        return config
    }

    private static func snapshotMAC(for data: Data, nonce: String, secret: String) -> HMAC<SHA256>.MAC? {
        guard let key = symmetricKey(from: secret), let id = UUID(uuidString: nonce) else { return nil }
        var mac = HMAC<SHA256>(key: key)
        // On Demand may reuse a snapshot compiled by an older app. A core can
        // accept obsolete JSON while silently ignoring a routing or TLS field.
        mac.update(data: Data("Hop tunnel snapshot v3\u{0}\(XrayBridgeRequest.coreVersion)\u{0}\(id.uuidString)\u{0}".utf8))
        mac.update(data: data)
        return mac.finalize()
    }

    /// Inspect the opened file and cap the read itself in case its size changes.
    private static func readFile(at url: URL, limit: Int) throws -> Data {
        let fd = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { throw TunnelSnapshotError.invalidFile }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? handle.close() }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_size <= limit else { throw TunnelSnapshotError.invalidFile }
        var data = Data()
        while let chunk = try handle.read(upToCount: limit + 1 - data.count), !chunk.isEmpty {
            data.append(chunk)
            guard data.count <= limit else { throw TunnelSnapshotError.invalidFile }
        }
        return data
    }

    /// The app-state envelope and its legacy reader use these unscoped operations.
    static func signature(for data: Data, secret: String) -> String? {
        guard let key = symmetricKey(from: secret) else {
            return nil
        }
        let mac = HMAC<SHA256>.authenticationCode(for: data, using: key)
        return Data(mac).base64EncodedString()
    }

    static func isValidSignature(_ signature: String, for data: Data, secret: String) -> Bool {
        guard let key = symmetricKey(from: secret),
              let mac = Data(base64Encoded: signature.trimmingCharacters(in: .whitespacesAndNewlines))
        else {
            return false
        }
        return HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: data, using: key)
    }

    private static func symmetricKey(from secret: String) -> SymmetricKey? {
        let trimmed = secret.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        if let decoded = Data(base64Encoded: trimmed), !decoded.isEmpty {
            return SymmetricKey(data: decoded)
        }
        return SymmetricKey(data: Data(trimmed.utf8))
    }
}

private enum TunnelSnapshotError: LocalizedError {
    case invalidFile
    case invalidSignature

    var errorDescription: String? {
        switch self {
        case .invalidFile: "Cannot read the tunnel settings within the file limits. Reconnect from Hop."
        case .invalidSignature: "Tunnel settings failed the integrity check. Reconnect from Hop."
        }
    }
}
