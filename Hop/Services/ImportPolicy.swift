import Foundation

/// Centralized security policy for untrusted import data: subscription/link
/// text, compatible `.conf` content, and the individual values parsed out of
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

    /// Maximum encoded size retained across all subscription-owned profiles,
    /// groups, and source records. Manual objects are outside this remote-data
    /// budget and are never deleted to make room for a subscription.
    static let maxRetainedSubscriptionBytes = maxDecodedBytes

    /// Maximum Keychain items projected from subscription-owned profiles and
    /// source URLs. This independently bounds credential enumeration work.
    static let maxRetainedSubscriptionSecretItems = maxImportedItems * 8

    /// Maximum number of recursive base64 unwraps before giving up. Guards the
    /// `importText` re-entry path against deeply nested encoded payloads.
    static let maxDecodeDepth = 3

    /// Hop's optional wireguard:// multi-peer extension is intentionally much
    /// smaller than a general import payload (four peers maximum).
    static let maxWireGuardPeerListBytes = 16 * 1024

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

    /// URL-test probe URLs are executed by the Xray observatory; `generate_204`
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
        guard let addresses = resolvedAddresses(host) else {
            return false
        }
        return addresses.contains(where: isPrivateOrReservedAddress)
    }

    /// Resolves once and returns the concrete public IP address latency probes
    /// should use. Binding the probe to this address closes the DNS-rebinding
    /// gap between a precheck and the later TCP/TLS/ICMP connection.
    static func resolvedPublicAddressForProbe(_ host: String) -> String? {
        guard !isDisallowedRemoteHost(host),
              let addresses = resolvedAddresses(host),
              !addresses.isEmpty,
              !addresses.contains(where: isPrivateOrReservedAddress)
        else {
            return nil
        }
        return addresses.first
    }

    /// Whether `host` is an IPv4 or IPv6 literal rather than a DNS name.
    static func isIPAddressLiteral(_ host: String) -> Bool {
        let host = unbracketedHost(host)
        var ipv4 = in_addr()
        if inet_pton(AF_INET, host, &ipv4) == 1 {
            return true
        }
        var ipv6 = in6_addr()
        return inet_pton(AF_INET6, host, &ipv6) == 1
    }

    /// Imported secondary destinations may use only public, non-reserved IP
    /// literals. Hostnames deliberately return false so callers must choose an
    /// explicit hostname policy rather than accidentally treating them as IPs.
    static func isPublicIPAddressLiteral(_ host: String) -> Bool {
        let host = unbracketedHost(host)
        return isIPAddressLiteral(host) && !isPrivateOrReservedAddress(host)
    }

    private static func unbracketedHost(_ host: String) -> String {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("["), trimmed.hasSuffix("]") else {
            return trimmed
        }
        return String(trimmed.dropFirst().dropLast())
    }

    private static func resolvedAddresses(_ host: String) -> [String]? {
        var trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("["), trimmed.hasSuffix("]") {
            trimmed = String(trimmed.dropFirst().dropLast())
        }
        guard !trimmed.isEmpty else {
            return []
        }
        if isPrivateOrReservedAddress(trimmed) {
            return [trimmed]
        }

        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var info: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(trimmed, nil, &hints, &info) == 0 else {
            return nil
        }
        defer { freeaddrinfo(info) }

        var result: [String] = []
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
                result.append(string(fromNullTerminatedBuffer: buffer))
            } else if current.pointee.ai_family == AF_INET6 {
                sockaddrPointer.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                    var address = sin6.pointee.sin6_addr
                    _ = inet_ntop(AF_INET6, &address, &buffer, socklen_t(buffer.count))
                }
                result.append(string(fromNullTerminatedBuffer: buffer))
            }
        }
        return result
    }

    private static func isPrivateOrReservedAddress(_ address: String) -> Bool {
        isPrivateOrReservedIPv4(address) || isPrivateOrReservedIPv6(address)
    }

    private static func string(fromNullTerminatedBuffer buffer: [CChar]) -> String {
        let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
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
        return !isDisallowedRemoteHost(host) && !resolvedAddressesAreDisallowed(host)
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
                if character == "]" {
                    inCharacterClass = false
                }
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
                } else if innerWasUnbounded {
                    // An unquantified group still carries its inner unbounded
                    // repetition into the parent, or `((a+)b)+` would close the
                    // middle group "clean" and slip past the outer `+`.
                    markEnclosingGroupUnbounded()
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

    // MARK: - Display-name hygiene

    /// Maximum length kept from an imported display name.
    static let maxImportedNameLength = 80

    /// Cleans an attacker-controllable display name for rendering in lists,
    /// logs, and — critically — the blocking allow-insecure confirmation
    /// alert: collapses all whitespace runs to single spaces, strips control
    /// and invisible Unicode formatting characters (bidirectional overrides
    /// like U+202E can visually reverse alert text, zero-width characters can
    /// hide it — CWE-451), and caps the length so one name can't push the
    /// rest of an alert off screen.
    static func sanitizeImportedName(_ name: String, fallback: String = "Imported") -> String {
        let collapsed = name
            .split(whereSeparator: \.isWhitespace)
            .joined(separator: " ")
        var cleaned = String.UnicodeScalarView()
        for scalar in collapsed.unicodeScalars {
            switch scalar.properties.generalCategory {
            case .control, .format, .surrogate, .privateUse, .unassigned:
                continue
            default:
                cleaned.append(scalar)
            }
        }
        let capped = String(String(cleaned).prefix(maxImportedNameLength))
            .trimmingCharacters(in: .whitespaces)
        return capped.isEmpty ? fallback : capped
    }

    // MARK: - Redaction

    /// Produces a credential-free description of an import line for warnings and
    /// logs. Proxy links and `.conf` proxy lines embed passwords, UUIDs, keys,
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

        // Configuration "Name = type, host, port, secrets..." lines: keep the
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
        let c = (value >> 8) & 0xFF

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
        case 192 where b == 88 && c == 99: // deprecated 6to4 relay anycast
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

        func embeddedIPv4IsReserved() -> Bool {
            isPrivateOrReservedIPv4("\(bytes[12]).\(bytes[13]).\(bytes[14]).\(bytes[15])")
        }

        // Go treats mapped and NAT64 well-known-prefix addresses as IPv4
        // destinations. Preserve public embeddings, but never let either form
        // disguise a private, metadata, documentation, or otherwise reserved
        // IPv4 address.
        if bytes[0 ..< 10].allSatisfy({ $0 == 0 }), bytes[10] == 0xFF, bytes[11] == 0xFF {
            return embeddedIPv4IsReserved()
        }
        if bytes[0] == 0x00, bytes[1] == 0x64,
           bytes[2] == 0xFF, bytes[3] == 0x9B,
           bytes[4 ..< 12].allSatisfy({ $0 == 0 })
        { // 64:ff9b::/96 globally reachable translation prefix
            return embeddedIPv4IsReserved()
        }

        // IANA currently assigns ordinary globally routable IPv6 unicast only
        // from 2000::/3. Everything else is reserved, scoped, multicast, or a
        // special-purpose block handled above.
        guard (bytes[0] & 0xE0) == 0x20 else {
            return true
        }

        if bytes[0] == 0x20, bytes[1] == 0x01,
           (bytes[2] & 0xFE) == 0
        { // 2001::/23 IETF protocol assignments
            return true
        }
        if bytes[0] == 0x20, bytes[1] == 0x01,
           bytes[2] == 0x0D, bytes[3] == 0xB8
        { // 2001:db8::/32 documentation
            return true
        }
        if bytes[0] == 0x20, bytes[1] == 0x02 { // 2002::/16 deprecated 6to4
            return true
        }
        if bytes[0] == 0x26, bytes[1] == 0x20,
           bytes[2] == 0x00, bytes[3] == 0x4F,
           bytes[4] == 0x80, bytes[5] == 0x00
        { // 2620:4f:8000::/48 special-purpose AS112 service
            return true
        }
        if bytes[0] == 0x3F { // IANA-reserved 3f00::/8, including 3fff::/20 documentation
            return true
        }
        return false
    }
}
