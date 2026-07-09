@testable import Hop
import XCTest

final class VerifiedXrayGeodataTests: XCTestCase {
    func testReviewedCategoriesMatchMemoryBoundedAssets() {
        XCTAssertEqual(VerifiedXrayGeodata.geoIPCategories, ["cn", "ir", "private"])
        XCTAssertEqual(VerifiedXrayGeodata.geoSiteCategories, ["category-ir"])
        XCTAssertEqual(VerifiedXrayGeodata.assets.map(\.fileName), ["geoip.dat", "geosite.dat"])
    }

    func testAppAndTunnelBundlesContainVerifiedAssetsAtResourceRoot() throws {
        let appBundle = try XCTUnwrap(
            Bundle.allBundles.first { $0.bundleIdentifier == "cat.string.hop" },
            "The hosted test must expose Hop.app.",
        )
        XCTAssertEqual(try VerifiedXrayGeodata.assetDirectory(in: appBundle), appBundle.resourceURL?.path)

        let plugInsURL = try XCTUnwrap(appBundle.builtInPlugInsURL)
        let tunnelBundle = try XCTUnwrap(Bundle(url: plugInsURL.appendingPathComponent("HopTunnel.appex")))
        XCTAssertEqual(try VerifiedXrayGeodata.assetDirectory(in: tunnelBundle), tunnelBundle.resourceURL?.path)
    }
}
