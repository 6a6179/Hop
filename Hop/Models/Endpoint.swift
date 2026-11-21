import Darwin
import Foundation

struct Endpoint: Hashable, Codable {
    var host: String
    var port: Int

    static func isValidWireGuardHost(_ host: String) -> Bool {
        if host.hasPrefix("[") && host.hasSuffix("]") {
            return ipAddressWidth(String(host.dropFirst().dropLast())) == 128
        }
        if ipAddressWidth(host) != nil {
            return true
        }
        let name = host.hasSuffix(".") ? host.dropLast() : host[...]
        guard !name.isEmpty, name.utf8.count <= 253,
              !name.allSatisfy({ $0.isNumber || $0 == "." })
        else { return false }
        return name.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            (1 ... 63).contains(label.utf8.count) && label.first != "-" && label.last != "-"
                && label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
        }
    }

    static func hostBits(inCIDR value: String) -> Int? {
        let parts = value.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, let bits = Int(parts[1]), String(bits) == parts[1],
              let width = ipAddressWidth(String(parts[0])), (0 ... width).contains(bits)
        else { return nil }
        return width - bits
    }

    static func ipAddressWidth(_ address: String) -> Int? {
        guard !address.utf8.contains(0), !address.contains("%") else { return nil }
        // Darwin accepts zero-padded IPv4 octets. The core's Go IP parser rejects them.
        if address.contains("."), let dotted = address.split(separator: ":").last,
           dotted.split(separator: ".").contains(where: { $0.count > 1 && $0.first == "0" })
        {
            return nil
        }
        if address.contains(":") {
            var ipv6 = in6_addr()
            return inet_pton(AF_INET6, address, &ipv6) == 1 ? 128 : nil
        }
        var ipv4 = in_addr()
        return inet_pton(AF_INET, address, &ipv4) == 1 ? 32 : nil
    }
}
