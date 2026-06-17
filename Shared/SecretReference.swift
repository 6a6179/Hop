import Foundation

/// Token format that lets the app emit a sing-box config with secret
/// *references* instead of secret values, which the tunnel extension resolves
/// from the shared Keychain at start time. This keeps credentials out of the
/// generated config on disk and out of IPC/provider configuration.
///
/// Every token carries a `nonce` that is generated fresh for each tunnel start
/// (see `TunnelController.connect`). The resolver only substitutes tokens that
/// bear the current run's nonce. Untrusted imported fields (server address,
/// transport path, SNI, …) are serialized into the same config verbatim, so
/// without the nonce a crafted field like `##HOP_SECRET:<other-uuid>.password##`
/// would otherwise be resolved into another profile's Keychain secret and
/// shipped to an attacker-controlled server. The nonce is unknowable at import
/// time, so such injected tokens never match and are left inert. (CWE-200)
enum HopSecret {
    /// Stable Keychain account for a profile's secret field. Uses a `.`
    /// separator (not `/`) so the token survives `JSONSerialization`, which
    /// escapes forward slashes as `\/`.
    static func key(profileID: UUID, fieldRaw: String) -> String {
        "\(profileID.uuidString).\(fieldRaw)"
    }

    /// Keychain account for a subscription URL. Subscription URLs commonly
    /// carry bearer tokens in their path or query, so they are stored beside
    /// profile credentials instead of in the on-disk app-state JSON.
    static func subscriptionURLKey(subscriptionID: UUID) -> String {
        "subscription.\(subscriptionID.uuidString).url"
    }

    /// The placeholder embedded in a config in place of a secret value, bound
    /// to the current run's `nonce` so it cannot be forged from import data.
    static func token(forKey key: String, nonce: String) -> String {
        "##HOP_SECRET:\(nonce):\(key)##"
    }

    /// Matches a quoted token (a JSON string value) bearing `nonce` and
    /// captures its key. The nonce is matched literally (escaped), so only
    /// tokens this run emitted are resolvable.
    static func tokenPattern(nonce: String) -> String {
        "\"##HOP_SECRET:\(NSRegularExpression.escapedPattern(for: nonce)):([^\"#]+)##\""
    }
}

/// Replaces secret tokens in a generated config with the real values resolved
/// from a `SecretStore`. Runs in the packet-tunnel extension at start time.
enum SecretResolver {
    /// Returns the config with every secret token bearing `nonce` replaced by
    /// its resolved value (JSON-escaped), plus the number of *nonce-matching*
    /// tokens that could not be resolved (for diagnostics / fail-closed checks).
    /// Tokens with a missing or foreign nonce are not matched and are left in
    /// place untouched — they are treated as inert literal text, never resolved.
    static func resolve(_ config: String, nonce: String, using store: SecretStore = .shared) -> (config: String, unresolved: Int) {
        guard !nonce.isEmpty, let regex = try? NSRegularExpression(pattern: HopSecret.tokenPattern(nonce: nonce)) else {
            return (config, 0)
        }

        let text = config as NSString
        let matches = regex.matches(in: config, range: NSRange(location: 0, length: text.length))
        guard !matches.isEmpty else {
            return (config, 0)
        }

        var result = ""
        var cursor = 0
        var unresolved = 0

        for match in matches {
            let full = match.range(at: 0)
            result += text.substring(with: NSRange(location: cursor, length: full.location - cursor))

            let key = text.substring(with: match.range(at: 1))
            if let value = store.value(forKey: key) {
                result += jsonStringLiteral(value)
            } else {
                unresolved += 1
                result += "\"\""
            }
            cursor = full.location + full.length
        }
        result += text.substring(from: cursor)

        return (result, unresolved)
    }

    /// Encodes a string as a JSON string literal (including surrounding quotes),
    /// so arbitrary secret characters (quotes, backslashes) embed safely.
    static func jsonStringLiteral(_ value: String) -> String {
        guard let data = try? JSONEncoder().encode(value),
              let encoded = String(data: data, encoding: .utf8)
        else { return "\"\"" }
        return encoded
    }
}
