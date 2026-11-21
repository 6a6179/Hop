import Foundation

/// HTTP/1.x response framing for the one GET on a pinned TLS connection.
struct SubscriptionHTTPResponse {
    enum Result {
        case body(Data)
        case redirect(String)
    }

    private enum Phase {
        case status, headers, closeDelimited, fixed(Int), chunkSize, chunk(Int), chunkEnding, trailers, finished
    }

    private var phase = Phase.status
    private var status = 0
    private var fields: [String: [String]] = [:]
    private var line = [UInt8]()
    private var headerBytes = 0
    private var chunkFramingBytes = 0
    private var body = Data()
    private var encoding = "identity"
    private(set) var setCookieHeaders: [String] = []

    /// Bounds the whole header/trailer section, including informational responses.
    private static let maxHeaderBytes = 64 * 1024
    /// A maximum-size body can legally arrive one byte per chunk (five framing bytes each).
    private static let maxChunkFramingBytes = 5 * ImportPolicy.maxPayloadBytes + maxHeaderBytes

    mutating func receive(_ data: Data, endOfStream: Bool) throws -> Result? {
        var cursor = data.startIndex
        while cursor < data.endIndex {
            switch phase {
            case let .fixed(remaining), let .chunk(remaining):
                let count = min(remaining, data.endIndex - cursor)
                let end = cursor + count
                body.append(contentsOf: data[cursor ..< end])
                cursor = end
                if case .fixed = phase {
                    if count == remaining {
                        guard cursor == data.endIndex else { throw ProxyLinkParseError.subscriptionUnavailable }
                        return try finish()
                    }
                    phase = .fixed(remaining - count)
                } else {
                    phase = count == remaining ? .chunkEnding : .chunk(remaining - count)
                }
            case .closeDelimited:
                guard data.endIndex - cursor <= ImportPolicy.maxPayloadBytes - body.count else {
                    throw ProxyLinkParseError.payloadTooLarge
                }
                body.append(contentsOf: data[cursor...])
                cursor = data.endIndex
            case .finished:
                throw ProxyLinkParseError.subscriptionUnavailable
            default:
                let byte = data[cursor]
                cursor += 1
                if let result = try receiveLineByte(byte) {
                    // A redirect body is discarded when its connection is closed.
                    if case .body = result, cursor != data.endIndex {
                        throw ProxyLinkParseError.subscriptionUnavailable
                    }
                    return result
                }
            }
        }

        if endOfStream {
            guard case .closeDelimited = phase else { throw ProxyLinkParseError.incompleteSubscriptionInventory }
            return try finish()
        }
        return nil
    }

    private mutating func finish() throws -> Result {
        guard status != 205 || body.isEmpty else { throw ProxyLinkParseError.subscriptionUnavailable }
        phase = .finished
        if status == 204 || status == 205 {
            return .body(Data())
        }
        return try .body(SubscriptionHTTPContent.decode(body, encoding: encoding))
    }

    private mutating func receiveLineByte(_ byte: UInt8) throws -> Result? {
        switch phase {
        case .chunkSize, .chunkEnding:
            chunkFramingBytes += 1
            guard chunkFramingBytes <= Self.maxChunkFramingBytes, line.count < 8192 else {
                throw ProxyLinkParseError.payloadTooLarge
            }
        default:
            headerBytes += 1
            guard headerBytes <= Self.maxHeaderBytes else { throw ProxyLinkParseError.payloadTooLarge }
        }
        if byte != 10 {
            guard line.last != 13 else { throw ProxyLinkParseError.subscriptionUnavailable }
            if case .chunkEnding = phase, byte != 13 {
                throw ProxyLinkParseError.subscriptionUnavailable
            }
            line.append(byte)
            return nil
        }
        guard line.popLast() == 13 else { throw ProxyLinkParseError.subscriptionUnavailable }
        defer { line.removeAll(keepingCapacity: true) }
        switch phase {
        case .status:
            let parts = String(decoding: line, as: UTF8.self).split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            guard parts.count >= 2, parts[0] == "HTTP/1.1" || parts[0] == "HTTP/1.0",
                  parts[1].utf8.count == 3, parts[1].utf8.allSatisfy({ (48 ... 57).contains($0) }),
                  let code = Int(parts[1]), (100 ..< 600).contains(code), line.allSatisfy(Self.fieldByte)
            else { throw ProxyLinkParseError.subscriptionUnavailable }
            status = code
            phase = .headers
        case .headers:
            if line.isEmpty {
                return try finishHeaders()
            }
            let (key, value) = try Self.field(line)
            fields[key, default: []].append(value)
        case .chunkSize:
            let size = try Self.chunkSize(line)
            guard size <= ImportPolicy.maxPayloadBytes - body.count else { throw ProxyLinkParseError.payloadTooLarge }
            phase = size == 0 ? .trailers : .chunk(size)
        case .chunkEnding:
            guard line.isEmpty else { throw ProxyLinkParseError.subscriptionUnavailable }
            phase = .chunkSize
        case .trailers:
            if line.isEmpty {
                return try finish()
            }
            let (key, _) = try Self.field(line)
            if key == "content-range" {
                throw ProxyLinkParseError.incompleteSubscriptionInventory
            }
            guard !["content-length", "transfer-encoding", "content-encoding", "location"].contains(key) else {
                throw ProxyLinkParseError.subscriptionUnavailable
            }
        default:
            throw ProxyLinkParseError.subscriptionUnavailable
        }
        return nil
    }

    private mutating func finishHeaders() throws -> Result? {
        if (100 ..< 200).contains(status) {
            guard status != 101, fields["content-length"] == nil, fields["transfer-encoding"] == nil else {
                throw ProxyLinkParseError.subscriptionUnavailable
            }
            fields.removeAll(keepingCapacity: true)
            phase = .status
            return nil
        }
        setCookieHeaders = fields["set-cookie"] ?? []
        if [301, 302, 303, 307, 308].contains(status) {
            guard let locations = fields["location"], locations.count == 1, let location = locations.first, !location.isEmpty else {
                throw ProxyLinkParseError.subscriptionUnavailable
            }
            phase = .finished
            return .redirect(location)
        }
        guard (200 ..< 300).contains(status) else { throw ProxyLinkParseError.subscriptionUnavailable }
        guard status != 206, status != 226, fields["content-range"] == nil else {
            throw ProxyLinkParseError.incompleteSubscriptionInventory
        }
        if let codings = list("content-encoding") {
            guard codings.count == 1, let coding = codings.first, ["identity", "gzip", "x-gzip", "deflate"].contains(coding) else {
                throw ProxyLinkParseError.subscriptionUnavailable
            }
            encoding = coding
        }
        if let transfer = list("transfer-encoding") {
            guard transfer == ["chunked"], fields["content-length"] == nil, status != 204 else {
                throw ProxyLinkParseError.subscriptionUnavailable
            }
            phase = .chunkSize
        } else if let lengths = list("content-length") {
            let sizes = try lengths.map { try Self.size($0.utf8, radix: 10) }
            guard let size = sizes.first, sizes.allSatisfy({ $0 == size }), status != 204 || size == 0 else {
                throw ProxyLinkParseError.subscriptionUnavailable
            }
            if size == 0 {
                return try finish()
            }
            body.reserveCapacity(size)
            phase = .fixed(size)
        } else if status == 204 {
            return try finish()
        } else {
            phase = .closeDelimited
        }
        return nil
    }

    private func list(_ key: String) -> [String]? {
        fields[key]?.flatMap { field in
            field.split(separator: ",", omittingEmptySubsequences: false).map {
                $0.trimmingCharacters(in: CharacterSet(charactersIn: " \t")).lowercased()
            }
        }
    }

    private static func field(_ line: [UInt8]) throws -> (String, String) {
        guard let colon = line.firstIndex(of: 58), colon > 0, line[..<colon].allSatisfy(tokenByte),
              line[(colon + 1)...].allSatisfy(fieldByte)
        else { throw ProxyLinkParseError.subscriptionUnavailable }
        let name = String(decoding: line[..<colon], as: UTF8.self).lowercased()
        let value = String(decoding: line[(colon + 1)...], as: UTF8.self)
        return (name, value.trimmingCharacters(in: CharacterSet(charactersIn: " \t")))
    }

    private static func fieldByte(_ byte: UInt8) -> Bool {
        byte == 9 || (byte >= 32 && byte != 127)
    }

    private static func tokenByte(_ byte: UInt8) -> Bool {
        switch byte {
        case 48 ... 57, 65 ... 90, 97 ... 122, 33, 35 ... 39, 42, 43, 45, 46, 94, 95, 96, 124, 126: true
        default: false
        }
    }

    private static func size(_ bytes: some Collection<UInt8>, radix: Int) throws -> Int {
        guard !bytes.isEmpty else { throw ProxyLinkParseError.subscriptionUnavailable }
        var value = 0
        for byte in bytes {
            let digit: Int
            switch byte {
            case 48 ... 57: digit = Int(byte) - 48
            case 65 ... 70 where radix == 16: digit = Int(byte) - 55
            case 97 ... 102 where radix == 16: digit = Int(byte) - 87
            default: throw ProxyLinkParseError.subscriptionUnavailable
            }
            guard value <= (ImportPolicy.maxPayloadBytes - digit) / radix else { throw ProxyLinkParseError.payloadTooLarge }
            value = value * radix + digit
        }
        return value
    }

    private static func chunkSize(_ line: [UInt8]) throws -> Int {
        let digits = line.prefix { $0 != 59 && $0 != 32 && $0 != 9 }
        let size = try size(digits, radix: 16)
        var rest = line.dropFirst(digits.count)
        func skipWhitespace() {
            rest = rest.drop { $0 == 32 || $0 == 9 }
        }
        func consumeToken() throws {
            let token = rest.prefix(while: tokenByte)
            guard !token.isEmpty else { throw ProxyLinkParseError.subscriptionUnavailable }
            rest = rest.dropFirst(token.count)
        }
        while !rest.isEmpty {
            skipWhitespace()
            guard rest.popFirst() == 59 else { throw ProxyLinkParseError.subscriptionUnavailable }
            skipWhitespace()
            try consumeToken()
            skipWhitespace()
            if rest.first == 61 {
                rest.removeFirst()
                skipWhitespace()
                if rest.first != 34 {
                    try consumeToken()
                    continue
                }
                rest.removeFirst()
                while let byte = rest.first, byte != 34 {
                    rest.removeFirst()
                    if byte == 92 {
                        guard let quoted = rest.popFirst(), fieldByte(quoted) else { throw ProxyLinkParseError.subscriptionUnavailable }
                    } else if !fieldByte(byte) {
                        throw ProxyLinkParseError.subscriptionUnavailable
                    }
                }
                guard rest.popFirst() == 34 else { throw ProxyLinkParseError.subscriptionUnavailable }
            }
        }
        return size
    }
}
