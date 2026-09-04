@testable import Hop
import XCTest

@MainActor
final class WireGuardPeerDraftTests: XCTestCase {
    func testUntouchedPeersRoundTripIncludingOptionalValues() throws {
        let peers = [
            WireGuardPeer(publicKey: "public-key"),
            WireGuardPeer(publicKey: " public-key ", preSharedKey: "", allowedIPs: []),
            WireGuardPeer(
                publicKey: "public-key",
                endpoint: Endpoint(host: "peer.example.com", port: 51820),
                preSharedKey: " opaque key ",
                allowedIPs: ["10.0.0.0/8", " ::/0 "],
                keepAliveSeconds: 0,
            ),
        ]
        for peer in peers {
            let draft = WireGuardPeerDraft(peer: peer)
            XCTAssertEqual(draft.id, peer.id)
            XCTAssertEqual(try draft.makePeer(), peer)
        }
    }

    func testAddEditAndRemoveKeepOtherPeerIdentities() throws {
        let first = WireGuardPeer(publicKey: "first-key")
        var drafts = [WireGuardPeerDraft(peer: first)]
        drafts.append(WireGuardPeerDraft())
        let newID = drafts[1].id
        XCTAssertNotEqual(newID, first.id)
        drafts[1].publicKey = "new-key"
        drafts[1].preSharedKey = "new-secret"
        drafts[1].allowedIPs = "10.1.0.0/16, ::/0"
        drafts[1].keepAlive = "25"
        let added = try drafts[1].makePeer()
        XCTAssertEqual(added.id, newID)
        XCTAssertEqual(added.allowedIPs, ["10.1.0.0/16", "::/0"])
        XCTAssertEqual(added.keepAliveSeconds, 25)
        XCTAssertEqual(added.preSharedKey, "new-secret")
        drafts.removeAll { $0.id == newID }
        XCTAssertEqual(try drafts.map { try $0.makePeer() }, [first])
    }

    func testEndpointEditingAndFallbackKeepStableIdentity() throws {
        var draft = WireGuardPeerDraft(peer: WireGuardPeer(publicKey: "public-key"))
        let id = draft.id
        draft.usesProfileEndpoint = false
        draft.host = " peer.example.com "
        draft.port = "65535"
        XCTAssertEqual(try draft.makePeer().endpoint, Endpoint(host: "peer.example.com", port: 65535))
        draft.usesProfileEndpoint = true
        XCTAssertNil(try draft.makePeer().endpoint)
        XCTAssertEqual(try draft.makePeer().id, id)
    }

    func testRejectsMissingKeyOrEndpointAndInvalidNumbers() throws {
        var draft = WireGuardPeerDraft()
        XCTAssertThrowsError(try draft.makePeer())
        draft.publicKey = " \n "
        XCTAssertThrowsError(try draft.makePeer())
        draft.publicKey = "public-key"
        draft.usesProfileEndpoint = false
        draft.port = "51820"
        XCTAssertThrowsError(try draft.makePeer())
        draft.host = "peer.example.com"
        for port in ["", "0", "-1", "65536", "1.5", "abc", "999999999999999999999999"] {
            draft.port = port
            XCTAssertThrowsError(try draft.makePeer(), port)
        }
        for port in ["1", "65535"] {
            draft.port = port
            XCTAssertNoThrow(try draft.makePeer())
        }
        for keepAlive in ["-1", "65536", "1.5", "abc", "999999999999999999999999"] {
            draft.keepAlive = keepAlive
            XCTAssertThrowsError(try draft.makePeer(), keepAlive)
        }
        for keepAlive in ["", "0", "65535"] {
            draft.keepAlive = keepAlive
            XCTAssertNoThrow(try draft.makePeer())
        }
    }
}
