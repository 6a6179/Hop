import Foundation
import zlib

enum SubscriptionHTTPContent {
    static func decode(_ data: Data, encoding: String) throws -> Data {
        guard data.count <= ImportPolicy.maxPayloadBytes else { throw ProxyLinkParseError.payloadTooLarge }

        let windowBits: Int32
        switch encoding.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "", "identity":
            return data
        case "gzip", "x-gzip":
            windowBits = MAX_WBITS + 16
        case "deflate":
            windowBits = MAX_WBITS
        default:
            throw ProxyLinkParseError.subscriptionUnavailable
        }

        var stream = z_stream()
        guard inflateInit2_(&stream, windowBits, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            throw ProxyLinkParseError.subscriptionUnavailable
        }
        defer { inflateEnd(&stream) }

        return try data.withUnsafeBytes { input in
            stream.next_in = UnsafeMutablePointer(mutating: input.bindMemory(to: Bytef.self).baseAddress)
            stream.avail_in = uInt(input.count)
            var decoded = Data()
            var chunk = [UInt8](repeating: 0, count: 16 * 1024)
            return try chunk.withUnsafeMutableBufferPointer { buffer in
                guard let bytes = buffer.baseAddress else { throw ProxyLinkParseError.subscriptionUnavailable }
                while true {
                    stream.next_out = bytes
                    stream.avail_out = uInt(buffer.count)
                    let status = inflate(&stream, Z_NO_FLUSH)
                    guard status == Z_OK || status == Z_STREAM_END else { throw ProxyLinkParseError.subscriptionUnavailable }
                    let produced = buffer.count - Int(stream.avail_out)
                    guard produced <= ImportPolicy.maxPayloadBytes - decoded.count else {
                        throw ProxyLinkParseError.payloadTooLarge
                    }
                    decoded.append(bytes, count: produced)
                    if status == Z_STREAM_END {
                        if stream.avail_in == 0 {
                            return decoded
                        }
                        // Gzip permits consecutive members. Deflate ends after one zlib stream.
                        guard windowBits == MAX_WBITS + 16, inflateReset(&stream) == Z_OK else {
                            throw ProxyLinkParseError.subscriptionUnavailable
                        }
                    }
                }
            }
        }
    }
}
