import SwiftUI

struct WireGuardPeerDraft: Identifiable {
    let id: UUID
    var publicKey: String
    var preSharedKey: String
    var host: String
    var port: String
    var allowedIPs: String
    var keepAlive: String
    var usesProfileEndpoint: Bool

    private let original: WireGuardPeer

    init(peer: WireGuardPeer = WireGuardPeer(publicKey: "")) {
        original = peer
        id = peer.id
        publicKey = peer.publicKey
        preSharedKey = peer.preSharedKey ?? ""
        host = peer.endpoint?.host ?? ""
        port = peer.endpoint.map { String($0.port) } ?? ""
        allowedIPs = peer.allowedIPs?.joined(separator: ", ") ?? ""
        keepAlive = peer.keepAliveSeconds.map(String.init) ?? ""
        usesProfileEndpoint = peer.endpoint == nil
    }

    func makePeer() throws -> WireGuardPeer {
        guard !publicKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw ValidationError.invalid("Enter the peer public key.")
        }
        var peer = original
        peer.publicKey = publicKey
        peer.preSharedKey = preSharedKey == (original.preSharedKey ?? "")
            ? original.preSharedKey : preSharedKey.isEmpty ? nil : preSharedKey
        if usesProfileEndpoint {
            peer.endpoint = nil
        } else {
            let host = host.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !host.isEmpty else { throw ValidationError.invalid("Enter the peer host.") }
            guard let port = Int(port.trimmingCharacters(in: .whitespacesAndNewlines)), (1 ... 65535).contains(port) else {
                throw ValidationError.invalid("Peer port: use 1–65535.")
            }
            if host != original.endpoint?.host || port != original.endpoint?.port {
                peer.endpoint = Endpoint(host: host, port: port)
            }
        }
        if allowedIPs != (original.allowedIPs?.joined(separator: ", ") ?? "") {
            let addresses = allowedIPs.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
            peer.allowedIPs = addresses.isEmpty ? nil : addresses
        }
        let keepAlive = keepAlive.trimmingCharacters(in: .whitespacesAndNewlines)
        if keepAlive.isEmpty {
            peer.keepAliveSeconds = nil
        } else {
            guard let seconds = Int(keepAlive), (0 ... 65535).contains(seconds) else {
                throw ValidationError.invalid("Peer keepalive: use 0–65535 seconds.")
            }
            peer.keepAliveSeconds = seconds
        }
        return peer
    }

    private enum ValidationError: LocalizedError {
        case invalid(String)

        var errorDescription: String? {
            switch self {
            case let .invalid(message): message
            }
        }
    }
}

struct WireGuardPeerFields: View {
    @Binding var peers: [WireGuardPeerDraft]

    var body: some View {
        ForEach($peers) { $peer in
            let id = peer.id
            let number = (peers.firstIndex { $0.id == id } ?? 0) + 2
            DisclosureGroup("Peer \(number)") {
                ProfileTextField("Public Key", text: $peer.publicKey)
                ProfileTextField("Pre-shared Key", text: $peer.preSharedKey, isSecure: true)
                Toggle("Use Node Endpoint", isOn: $peer.usesProfileEndpoint)
                if !peer.usesProfileEndpoint {
                    ProfileTextField("Host", text: $peer.host)
                    ProfileTextField("Port", text: $peer.port, keyboardType: .numberPad)
                }
                ProfileTextField("Allowed IPs", text: $peer.allowedIPs, prompt: "0.0.0.0/0, ::/0")
                ProfileTextField("Keepalive (s)", text: $peer.keepAlive, keyboardType: .numberPad)
                Button("Remove Peer", role: .destructive) {
                    peers.removeAll { $0.id == id }
                }
            }
        }
        Button("Add Peer", systemImage: "plus") {
            peers.append(WireGuardPeerDraft())
        }
        .disabled(peers.count >= IOSRuntimeLimits.default.maxWireGuardPeers - 1)
    }
}
