import CryptoKit
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
