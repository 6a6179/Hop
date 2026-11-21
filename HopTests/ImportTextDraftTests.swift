import Foundation
@testable import Hop
import XCTest

final class ImportTextDraftTests: XCTestCase {
    func testPreviewPublishesOnlyForUnchangedInput() throws {
        let input = "https://example.com/subscription"
        let url = try XCTUnwrap(URL(string: input))
        let result = ImportResult(warnings: [ImportWarning(message: "Review this node")])
        var draft = ImportTextDraft(text: input, error: "Old error")

        let fetchedSource = SubscriptionSource(name: "Test", url: input)
        try draft.finishPreview(result, subscriptionURL: url, sourceAtPreview: fetchedSource, for: input)
        XCTAssertEqual(draft.result, result)
        XCTAssertEqual(draft.subscriptionURL, url)
        XCTAssertEqual(draft.sourceAtPreview, fetchedSource)
        XCTAssertNil(draft.error)

        draft.text = "trojan://different@example.com:443"
        try draft.finishPreview(result, subscriptionURL: url, for: input)
        XCTAssertNil(draft.result)
        XCTAssertNil(draft.subscriptionURL)
        XCTAssertNil(draft.sourceAtPreview)
    }

    func testCancelledPreviewCannotPublishResult() async throws {
        try await Task {
            withUnsafeCurrentTask { $0?.cancel() }
            var draft = ImportTextDraft(text: "original")
            XCTAssertThrowsError(try draft.finishPreview(ImportResult(), subscriptionURL: nil, for: "original")) {
                XCTAssertTrue($0 is CancellationError)
            }
            XCTAssertNil(draft.result)
        }.value
    }

    func testEditingInputInvalidatesPreviewAndSubscriptionURL() throws {
        let text = "https://example.com/subscription"
        let url = try XCTUnwrap(URL(string: text))
        let result = ImportResult(profiles: [])
        var draft = ImportTextDraft(text: text, result: result, error: "Old preview error", subscriptionURL: url)

        draft.text = text
        XCTAssertNotNil(draft.result)
        XCTAssertEqual(draft.subscriptionURL, url)

        draft.text = "trojan://different@example.com:443"
        XCTAssertNil(draft.result)
        XCTAssertNil(draft.subscriptionURL)
        XCTAssertNil(draft.error)

        draft.result = result
        draft.text = ""
        XCTAssertNil(draft.result)
    }
}
