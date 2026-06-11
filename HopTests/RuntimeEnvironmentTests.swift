@testable import Hop
import XCTest

final class RuntimeEnvironmentTests: XCTestCase {
    func testSelectAppGroupPrefersCommonOpenGroup() {
        let selected = RuntimeEnvironment.selectAppGroup(
            appGroups: ["group.app.only", RuntimeEnvironment.fallbackAppGroup],
            tunnelGroups: ["group.tunnel.only", RuntimeEnvironment.fallbackAppGroup],
            canOpen: { $0 == RuntimeEnvironment.fallbackAppGroup },
        )

        XCTAssertEqual(selected, RuntimeEnvironment.fallbackAppGroup)
    }

    func testSelectAppGroupUsesCommonProvisionedGroupWhenSourceGroupIsNotAvailable() {
        let selected = RuntimeEnvironment.selectAppGroup(
            appGroups: ["group.app.only", "group.shared"],
            tunnelGroups: ["group.tunnel.only", "group.shared"],
            canOpen: { $0 == "group.shared" },
        )

        XCTAssertEqual(selected, "group.shared")
    }

    func testSelectAppGroupDoesNotChooseAppOnlyGroupWhenTunnelProfileListsDifferentGroup() {
        let selected = RuntimeEnvironment.selectAppGroup(
            appGroups: ["group.app.only"],
            tunnelGroups: ["group.tunnel.only"],
            canOpen: { $0 == "group.app.only" },
        )

        XCTAssertEqual(selected, RuntimeEnvironment.fallbackAppGroup)
    }

    func testSelectAppGroupPrefersSourceSharedGroupWhenTunnelProfileIsUnavailable() {
        let selected = RuntimeEnvironment.selectAppGroup(
            appGroups: ["group.app"],
            tunnelGroups: [],
            canOpen: { $0 == RuntimeEnvironment.fallbackAppGroup || $0 == "group.app" },
        )

        XCTAssertEqual(selected, RuntimeEnvironment.fallbackAppGroup)
    }

    func testSelectAppGroupFallsBackToAppGroupsWhenTunnelProfileAndSourceGroupAreUnavailable() {
        let selected = RuntimeEnvironment.selectAppGroup(
            appGroups: ["group.app"],
            tunnelGroups: [],
            canOpen: { $0 == "group.app" },
        )

        XCTAssertEqual(selected, "group.app")
    }

    func testAppGroupProfileMismatchErrorReturnsNilWhenTunnelProfileIsUnavailable() {
        XCTAssertNil(RuntimeEnvironment.appGroupProfileMismatchError(
            appGroups: ["group.app"],
            tunnelGroups: [],
        ))
    }

    func testAppGroupProfileMismatchErrorReportsDisjointProfiles() throws {
        let error = try XCTUnwrap(RuntimeEnvironment.appGroupProfileMismatchError(
            appGroups: ["group.app.only"],
            tunnelGroups: ["group.tunnel.only"],
        ))

        XCTAssertTrue(error.localizedDescription.contains("do not share an App Group"))
        XCTAssertTrue(error.localizedDescription.contains("group.app.only"))
        XCTAssertTrue(error.localizedDescription.contains("group.tunnel.only"))
    }

    func testInlineResolvedConfigIsUsedWhenTunnelProfileIsUnavailable() {
        XCTAssertTrue(RuntimeEnvironment.shouldUseInlineResolvedTunnelConfiguration(
            appGroups: ["group.app"],
            tunnelGroups: [],
            selectedAppGroup: "group.app",
        ))
    }

    func testSharedConfigFileIsUsedForSourceGroupWhenTunnelProfileIsUnavailable() {
        XCTAssertFalse(RuntimeEnvironment.shouldUseInlineResolvedTunnelConfiguration(
            appGroups: [RuntimeEnvironment.fallbackAppGroup],
            tunnelGroups: [],
            selectedAppGroup: RuntimeEnvironment.fallbackAppGroup,
        ))
    }

    func testSharedConfigFileIsUsedWhenSelectedGroupIsConfirmedOnBothProfiles() {
        XCTAssertFalse(RuntimeEnvironment.shouldUseInlineResolvedTunnelConfiguration(
            appGroups: ["group.app.only", RuntimeEnvironment.fallbackAppGroup],
            tunnelGroups: ["group.tunnel.only", RuntimeEnvironment.fallbackAppGroup],
            selectedAppGroup: RuntimeEnvironment.fallbackAppGroup,
        ))
    }

    func testInlineResolvedConfigIsUsedWhenSelectedGroupIsAppOnly() {
        XCTAssertTrue(RuntimeEnvironment.shouldUseInlineResolvedTunnelConfiguration(
            appGroups: ["group.app.only"],
            tunnelGroups: ["group.tunnel.only"],
            selectedAppGroup: "group.app.only",
        ))
    }
}
