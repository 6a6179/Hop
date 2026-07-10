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
            members: [.direct],
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
}
