import Foundation
@testable import Hop
import XCTest

final class ProxyGroupEditorPerformanceTests: XCTestCase {
    @MainActor
    func testResolvedGroupValidatesProbeURLAwayFromMainAndPreservesFallbackPolicy() async throws {
        let candidateURL = "https://probe.example/generate_204"
        let draft = ProxyGroupEditorDraft(group: ProxyGroup(
            name: "Fast Group",
            type: .urlTest,
            members: [.profile(UUID())],
            testOptions: ProxyGroupTestOptions(url: candidateURL),
        ))

        let rejectedResult = await draft.resolvedGroup { value in
            XCTAssertFalse(Thread.isMainThread)
            XCTAssertEqual(value, candidateURL)
            return false
        }
        let rejected = try XCTUnwrap(rejectedResult)
        XCTAssertEqual(rejected.testOptions.url, ProxyGroupTestOptions.defaultURL)

        let acceptedResult = await draft.resolvedGroup { value in
            XCTAssertFalse(Thread.isMainThread)
            XCTAssertEqual(value, candidateURL)
            return true
        }
        let accepted = try XCTUnwrap(acceptedResult)
        XCTAssertEqual(accepted.testOptions.url, candidateURL)
    }

    func testURLTestGroupRejectsBuiltInMembersAndClearsManualDefault() throws {
        let member = OutboundTarget.profile(UUID())
        var draft = ProxyGroupEditorDraft(group: ProxyGroup(name: "A", type: .select, members: [member, .direct], defaultTarget: member))
        draft.type = .urlTest
        XCTAssertFalse(draft.isStructurallyValid)
        draft.members = [member, .reject]
        XCTAssertNil(draft.makeGroup(probeURLIsAllowed: true))
        draft.members = [member]
        XCTAssertNil(try XCTUnwrap(draft.makeGroup(probeURLIsAllowed: true)).defaultTarget)
    }
}
