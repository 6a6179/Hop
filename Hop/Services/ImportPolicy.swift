import Foundation

/// Centralized security policy for untrusted import data: subscription/link
/// text, Shadowrocket `.conf` content, and the individual values parsed out of
/// them.
///
/// Every limit and validation rule that protects the importer (and, by
/// extension, the privileged tunnel) from malicious or oversized input lives
/// here so the policy is auditable in one place rather than scattered across
/// the parser, views, and config builder.
enum ImportPolicy {
    // MARK: - Resource limits

    /// Maximum bytes accepted from a subscription response or pasted payload.
    static let maxPayloadBytes = 5 * 1024 * 1024 // 5 MB

    /// Maximum bytes accepted after a base64 decode. Decoded text can be larger
    /// than its encoded form, and nested decodes compound, so this is bounded
    /// independently of `maxPayloadBytes`.
    static let maxDecodedBytes = 8 * 1024 * 1024 // 8 MB

    /// Maximum number of lines/tokens scanned from a single payload.
    static let maxLines = 20000

    /// Maximum number of importable items (profiles + groups + rules) accepted
    /// from one import. Anything beyond this is dropped with a warning.
    static let maxImportedItems = 5000

    /// Maximum number of recursive base64 unwraps before giving up. Guards the
    /// `importText` re-entry path against deeply nested encoded payloads.
    static let maxDecodeDepth = 3

    // MARK: - Regex safety

    /// Maximum length of an import-supplied regular-expression pattern
    /// (`policy-regex-filter`, `DOMAIN-REGEX`). Caps the search space a crafted
    /// pattern can explore and blocks pathological inputs outright.
    static let maxRegexPatternLength = 512

    // MARK: - URL-test scheduling bounds

    static let minURLTestIntervalSeconds = 10
    static let maxURLTestIntervalSeconds = 86400 // 24h
    static let minURLTestToleranceMilliseconds = 0
    static let maxURLTestToleranceMilliseconds = 30000

    // MARK: - Network / SSRF policy

    /// Subscriptions are fetched by the app, so they must be transport-secure.
    static let allowedSubscriptionSchemes: Set<String> = ["https"]

    /// URL-test probe URLs are executed by the sing-box engine; `generate_204`
    /// endpoints are commonly plain HTTP, so both schemes are permitted, but
    /// the destination is still restricted to public hosts.
    static let allowedProbeSchemes: Set<String> = ["http", "https"]

    static let subscriptionRequestTimeout: TimeInterval = 30

    private static let disallowedHostnames: Set<String> = [
        "localhost",
        "metadata",
        "metadata.google.internal",
        "instance-data",
        "instance-data.ec2.internal",
    ]

    private static let disallowedHostSuffixes = [
        ".localhost",
        ".local",
        ".internal",
        ".lan",
        ".home.arpa",
    ]

    // MARK: - Validation entry points

    /// Validates a subscription URL before the app performs a device-context
    /// fetch. Rejects cleartext transports and local/private/metadata
    /// destinations (CWE-918 / cleartext config injection).
    static func validateSubscriptionURL(_ url: URL) throws {
        guard let scheme = url.scheme?.lowercased(), allowedSubscriptionSchemes.contains(scheme) else {
            throw ProxyLinkParseError.insecureSubscriptionURL
        }
        guard let host = url.host, !host.isEmpty else {
            throw ProxyLinkParseError.missingHost
        }
        if isDisallowedRemoteHost(host) || resolvedAddressesAreDisallowed(host) {
            throw ProxyLinkParseError.disallowedSubscriptionHost
        }
    }

    /// Resolves `host` and reports whether ANY resolved address is private or
    /// reserved. Catches alternate IP encodings (`2130706433`, `127.1`,
    /// `0x7f000001`) that `inet_pton` rejects but the system resolver — and thus
    /// `URLSession` — accepts, plus hostnames that point at internal addresses.
    /// Resolution failures are treated as "not disallowed": an unresolvable host
    /// can't be an SSRF target and the fetch fails on its own. This narrows but
    /// does not fully eliminate DNS rebinding (the resolver may answer
    /// differently at connect time); the subscription fetcher's redirect
    /// re-validation is the companion control.
    static func resolvedAddressesAreDisallowed(_ host: String) -> Bool {
        var trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("["), trimmed.hasSuffix("]") {
            trimmed = String(trimmed.dropFirst().dropLast())
        }
        guard !trimmed.isEmpty else {
            return true
        }

        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var info: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(trimmed, nil, &hints, &info) == 0 else {
            return false
        }
        defer { freeaddrinfo(info) }

        var node = info
        while let current = node {
            defer { node = current.pointee.ai_next }
            guard let sockaddrPointer = current.pointee.ai_addr else {
                continue
            }
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if current.pointee.ai_family == AF_INET {
                sockaddrPointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    var address = sin.pointee.sin_addr
                    _ = inet_ntop(AF_INET, &address, &buffer, socklen_t(buffer.count))
                }
                if isPrivateOrReservedIPv4(String(cString: buffer)) {
                    return true
                }
            } else if current.pointee.ai_family == AF_INET6 {
                sockaddrPointer.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                    var address = sin6.pointee.sin6_addr
                    _ = inet_ntop(AF_INET6, &address, &buffer, socklen_t(buffer.count))
                }
                if isPrivateOrReservedIPv6(String(cString: buffer)) {
                    return true
                }
            }
        }
        return false
    }

    /// Whether a URL-test probe URL is safe to emit into tunnel config. Callers
    /// fall back to a known-good default (and warn) when this returns `false`.
    static func isAllowedProbeURL(_ string: String) -> Bool {
        guard let url = URL(string: string.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = url.scheme?.lowercased(),
              allowedProbeSchemes.contains(scheme),
              let host = url.host, !host.isEmpty
        else {
            return false
        }
        return !isDisallowedRemoteHost(host)
    }

    /// Whether an import-supplied regex is bounded enough to evaluate safely.
    /// Combines a length cap, a nested-quantifier reject, and a compile
    /// pre-flight (CWE-1333). The length+compile check alone is insufficient: a
    /// 7-byte pattern like `(a+)+` compiles and is catastrophic.
    static func isSafeRegexPattern(_ pattern: String) -> Bool {
        guard !pattern.isEmpty, pattern.utf8.count <= maxRegexPatternLength else {
            return false
        }
        guard !hasNestedQuantifier(pattern) else {
            return false
        }
        return (try? NSRegularExpression(pattern: pattern)) != nil
    }

    /// Conservatively detects a repetition nested inside another repetition
    /// (regex "star height" > 1) — e.g. `(a+)+`, `(a*)*`, `(.+)+`, `(a+|b+)+` —
    /// the shapes that backtrack catastrophically against non-matching input.
    /// `NSRegularExpression` (ICU) is a backtracking engine, so the app-side
    /// `policy-regex-filter` match against attacker-controlled profile names is
    /// the real ReDoS sink; the engine-side `domain_regex` path uses RE2 and is
    /// linear, but it is filtered through here too for consistency. May reject
    /// some benign patterns; a rejection is treated as "too risky to evaluate".
    static func hasNestedQuantifier(_ pattern: String) -> Bool {
        let chars = Array(pattern)
        var index = 0
        var inCharacterClass = false
        // For each currently-open group, whether it contains an unbounded
        // quantifier somewhere inside.
        var groupContainsUnbounded: [Bool] = []

        func isUnboundedQuantifier(at position: Int) -> Bool {
            guard position < chars.count else { return false }
            switch chars[position] {
            case "*", "+":
                return true
            case "{":
                // `{n,}` is unbounded; `{n}` and `{n,m}` are bounded.
                var cursor = position + 1
                var sawComma = false
                var sawUpperBound = false
                while cursor < chars.count, chars[cursor] != "}" {
                    if chars[cursor] == "," {
                        sawComma = true
                    } else if sawComma, chars[cursor].isNumber {
                        sawUpperBound = true
                    }
                    cursor += 1
                }
                return sawComma && !sawUpperBound
            default:
                return false
            }
        }

        func markEnclosingGroupUnbounded() {
            if !groupContainsUnbounded.isEmpty {
                groupContainsUnbounded[groupContainsUnbounded.count - 1] = true
            }
        }

        while index < chars.count {
            let character = chars[index]
            if character == "\\" {
                index += 2 // skip the escaped character
                continue
            }
            if inCharacterClass {
                if character == "]" { inCharacterClass = false }
                index += 1
                continue
            }
            switch character {
            case "[":
                inCharacterClass = true
            case "(":
                groupContainsUnbounded.append(false)
            case ")":
                let innerWasUnbounded = groupContainsUnbounded.popLast() ?? false
                if isUnboundedQuantifier(at: index + 1) {
                    if innerWasUnbounded {
                        return true // (…unbounded…)<unbounded>
                    }
                    markEnclosingGroupUnbounded() // a quantified group counts as a quantifier in its parent
                }
            case "*", "+":
                markEnclosingGroupUnbounded()
            case "{" where isUnboundedQuantifier(at: index):
                markEnclosingGroupUnbounded()
            default:
                break
            }
            index += 1
        }
        return false
    }

    static func clampURLTestInterval(_ seconds: Int) -> Int {
        min(max(seconds, minURLTestIntervalSeconds), maxURLTestIntervalSeconds)
    }

    static func clampURLTestTolerance(_ milliseconds: Int) -> Int {
        min(max(milliseconds, minURLTestToleranceMilliseconds), maxURLTestToleranceMilliseconds)
    }

    // MARK: - Redaction

    /// Produces a credential-free description of an import line for warnings and
    /// logs. Proxy links and Shadowrocket lines embed passwords, UUIDs, keys,
    /// and tokens, so the raw text must never reach persistent/exportable logs
    /// (CWE-532).
    static func redactForLog(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return "[redacted]"
        }

        // URL-style links: keep only the scheme and the (non-secret) fragment
        // label; drop userinfo, host, query, and path which can all carry
        // secrets.
        if let components = URLComponents(string: trimmed), let scheme = components.scheme {
            if let label = components.fragment?.removingPercentEncoding, !label.isEmpty {
                return "\(scheme):// [redacted] (\(label))"
            }
            return "\(scheme):// [redacted]"
        }

        // Shadowrocket "Name = type, host, port, secrets..." lines: keep the
        // user-facing name only.
        if let name = trimmed.split(separator: "=", maxSplits: 1).first {
            let cleaned = name.trimmingCharacters(in: .whitespacesAndNewlines)
            if !cleaned.isEmpty {
                return "\(cleaned) = [redacted]"
            }
        }

        return "[redacted]"
    }

    // MARK: - Host classification

    static func isDisallowedRemoteHost(_ host: String) -> Bool {
        var normalized = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        // A trailing dot is a valid absolute-FQDN form ("localhost.",
        // "evil.internal.") that resolves identically to the dotless name but
        // would otherwise slip past the exact-hostname and suffix checks below.
        while normalized.hasSuffix(".") {
            normalized.removeLast()
        }
        guard !normalized.isEmpty else {
            return true
        }

        let bare = normalized.hasPrefix("[") && normalized.hasSuffix("]")
            ? String(normalized.dropFirst().dropLast())
            : normalized

        if disallowedHostnames.contains(normalized) || disallowedHostnames.contains(bare) {
            return true
        }
        for suffix in disallowedHostSuffixes where normalized.hasSuffix(suffix) {
            return true
        }
        if isPrivateOrReservedIPv4(bare) {
            return true
        }
        if isPrivateOrReservedIPv6(bare) {
            return true
        }
        return false
    }

    private static func isPrivateOrReservedIPv4(_ host: String) -> Bool {
        var addr = in_addr()
        guard inet_pton(AF_INET, host, &addr) == 1 else {
            return false
        }
        let value = UInt32(bigEndian: addr.s_addr)
        let a = (value >> 24) & 0xFF
        let b = (value >> 16) & 0xFF

        switch a {
        case 0: // "this" network / 0.0.0.0
            return true
        case 10: // 10.0.0.0/8 private
            return true
        case 100 where (64 ... 127).contains(b): // 100.64.0.0/10 CGNAT
            return true
        case 127: // loopback
            return true
        case 169 where b == 254: // link-local
            return true
        case 172 where (16 ... 31).contains(b): // 172.16.0.0/12 private
            return true
        case 192 where b == 168: // 192.168.0.0/16 private
            return true
        case 192 where b == 0: // 192.0.0.0/24 + 192.0.2.0/24 test net
            return true
        case 198 where (18 ... 19).contains(b): // 198.18.0.0/15 benchmark
            return true
        case 198 where b == 51: // 198.51.100.0/24 test net
            return true
        case 203 where b == 0: // 203.0.113.0/24 test net
            return true
        case 224 ... 255: // multicast + reserved + broadcast
            return true
        default:
            return false
        }
    }

    private static func isPrivateOrReservedIPv6(_ host: String) -> Bool {
        var addr = in6_addr()
        guard inet_pton(AF_INET6, host, &addr) == 1 else {
            return false
        }
        let bytes = withUnsafeBytes(of: &addr) { Array($0) }
        guard bytes.count == 16 else {
            return false
        }

        if bytes.allSatisfy({ $0 == 0 }) { // :: unspecified
            return true
        }
        if bytes.dropLast().allSatisfy({ $0 == 0 }), bytes.last == 1 { // ::1 loopback
            return true
        }
        if (bytes[0] & 0xFE) == 0xFC { // fc00::/7 unique local
            return true
        }
        if bytes[0] == 0xFE, (bytes[1] & 0xC0) == 0x80 { // fe80::/10 link-local
            return true
        }
        if bytes[0] == 0xFF { // ff00::/8 multicast
            return true
        }
        // ::ffff:0:0/96 IPv4-mapped — classify the embedded IPv4 address.
        if bytes[0 ..< 10].allSatisfy({ $0 == 0 }), bytes[10] == 0xFF, bytes[11] == 0xFF {
            return isPrivateOrReservedIPv4("\(bytes[12]).\(bytes[13]).\(bytes[14]).\(bytes[15])")
        }
        return false
    }
}
