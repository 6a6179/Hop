@testable import Hop
import XCTest

final class TunnelMemoryPolicyTests: XCTestCase {
    func testResourceLimitsStayBelowExtensionCeiling() {
        XCTAssertEqual(TunnelMemoryPolicy.maximumConfigurationBytes, 512 * 1024)
        XCTAssertEqual(TunnelMemoryPolicy.watchdogSampleMilliseconds, 250)
        XCTAssertEqual(TunnelMemoryPolicy.softResetBytes, 40 * 1024 * 1024)
        XCTAssertEqual(TunnelMemoryPolicy.softLimitBytes, 42 * 1024 * 1024)
        XCTAssertEqual(TunnelMemoryPolicy.hardLimitBytes, 46 * 1024 * 1024)
    }

    func testSoftLimitCollectsOnlyOnFirstCrossing() {
        let first = TunnelMemoryPolicy.decision(
            footprintBytes: TunnelMemoryPolicy.softLimitBytes,
            softWarningActive: false,
        )
        XCTAssertEqual(first, .init(action: .collectAndWarn, softWarningActive: true))

        let repeated = TunnelMemoryPolicy.decision(
            footprintBytes: TunnelMemoryPolicy.softLimitBytes,
            softWarningActive: true,
        )
        XCTAssertEqual(repeated, .init(action: .none, softWarningActive: true))
    }

    func testSoftWarningUsesFortyMiBHysteresis() {
        let atReset = TunnelMemoryPolicy.decision(
            footprintBytes: TunnelMemoryPolicy.softResetBytes,
            softWarningActive: true,
        )
        XCTAssertEqual(atReset, .init(action: .none, softWarningActive: true))

        let belowReset = TunnelMemoryPolicy.decision(
            footprintBytes: TunnelMemoryPolicy.softResetBytes - 1,
            softWarningActive: true,
        )
        XCTAssertEqual(belowReset, .init(action: .none, softWarningActive: false))
    }

    func testHardLimitAlwaysStops() {
        for warningActive in [false, true] {
            let decision = TunnelMemoryPolicy.decision(
                footprintBytes: TunnelMemoryPolicy.hardLimitBytes,
                softWarningActive: warningActive,
            )
            XCTAssertEqual(decision.action, .stop)
        }
    }
}
