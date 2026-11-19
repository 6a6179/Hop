@testable import Hop
import XCTest

@MainActor
final class XrayFieldsEditorTests: XCTestCase {
    func testPersistedAdvancedSettingsMigrateOnlyTheReviewedSchema() throws {
        for version in ["v26.6.27", "v26.7.28", "v26.11.9", "future"] {
            let expected = version == "future" ? version : "v26.11.9"
            let original = XrayAdvancedDocument(schemaVersion: version, values: ["dns": .object(["serveStale": .bool(true)])])
            let restored = try JSONDecoder().decode(XrayAdvancedDocument.self, from: JSONEncoder().encode(original))
            XCTAssertEqual(restored.schemaVersion, expected)
            XCTAssertEqual(restored.values, original.values)
            var settings = AppSettings.defaults
            settings.xrayAdvanced = restored
            let issues = XrayConfigBuilder().validationIssues(profiles: [], groups: [], selectedTarget: .direct, routingMode: .direct, rules: [], settings: settings)
            XCTAssertEqual(issues.isEmpty, version != "future")
        }
    }

    func testAdvancedEditorsRetainUnknownVersionUntilOverridesAreRemoved() throws {
        var profile = SampleData.trojanTLS
        profile.xrayAdvanced = XrayAdvancedDocument(schemaVersion: "future", values: ["targetStrategy": .string("AsIs")])
        var draft = ProfileEditorDraft(profile: profile)
        draft.name = "Renamed"
        XCTAssertNil(draft.validation.profile)
        draft.xrayAdvancedJSON = "{}"
        let cleared = try XCTUnwrap(draft.validation.profile)
        XCTAssertNil(cleared.xrayAdvanced)

        var settings = AppSettings.defaults
        settings.xrayAdvanced = XrayAdvancedDocument(schemaVersion: "future", values: ["dns": .object(["serveStale": .bool(true)])])
        let input = try AdvancedSettingsInput(json: XCTUnwrap(settings.xrayAdvanced?.jsonString), schemaVersion: "future", settings: settings)
        XCTAssertNil(input.validate().document)
        XCTAssertTrue(AdvancedSettingsInput(json: "{}", schemaVersion: "future", settings: settings).validate().document?.isEmpty == true)
    }

    func testBundledSchemaResolvesFieldsAndFiltersUnsafeOptions() throws {
        let schema = XrayFormSchema.shared
        let tls = try XCTUnwrap(schema.definition("TLSConfig"))
        let fields = schema.fields(tls, value: nil, context: "TLSConfig")
        XCTAssertNotNil(fields["certificates"])
        XCTAssertTrue(try XrayFormSchema.available(XCTUnwrap(fields["certificates"]?.objectValue)))
        XCTAssertFalse(try XrayFormSchema.available(XCTUnwrap(fields["masterKeyLog"]?.objectValue)))
        XCTAssertFalse(try XrayFormSchema.available(XCTUnwrap(fields["echServerKeys"]?.objectValue)))
        let realm = try schema.fields(XCTUnwrap(schema.definition("Realm")), value: nil, context: "Realm")
        XCTAssertFalse(try XrayFormSchema.available(XCTUnwrap(realm["tlsConfig"]?.objectValue)))
        XCTAssertTrue(XrayFormSchema.includes("ALPN", allowedKeys: ["alpn"], excludedKeys: []))
        XCTAssertFalse(XrayFormSchema.includes("ALPN", allowedKeys: nil, excludedKeys: ["alpn"]))
        XCTAssertEqual(schema.resolve(["$ref": .string("#/definitions/WireGuardPeerConfig")])["fields"]?.objectValue?["preSharedKey"]?.objectValue?["annotations"]?.arrayValue?.contains(.string("secret")), true)
    }

    func testEditorPreservesLegacyXDNSResolversUntilBuilderValidation() throws {
        let schema = XrayFormSchema.shared
        let legacy: JSONValue = .object(["resolvers": .array([.string("example.org+udp://1.1.1.1:53")])])
        XCTAssertNil(schema.validationError(definition: "XDNS", value: legacy))
        let definition = try XCTUnwrap(schema.definition("XDNS"))
        let native = schema.fields(definition, value: nil, context: "XDNS")
        XCTAssertEqual(native["resolvers"]?.objectValue?["items"]?.objectValue?["$ref"], .string("#/definitions/XDNSResolver"))
    }

    func testScalarEditingAndObjectMutationPreserveExactValues() {
        let integer: [String: JSONValue] = ["jsonTypes": .array([.string("integer")])]
        let range: [String: JSONValue] = ["jsonTypes": .array([.string("integer"), .string("string")])]
        XCTAssertEqual(XrayFormSchema.scalar("12", schema: integer, original: .number(1)), .number(12))
        XCTAssertEqual(XrayFormSchema.scalar("12x", schema: integer, original: .number(1)), .string("12x"))
        XCTAssertEqual(XrayFormSchema.scalar("1.5", schema: integer, original: .number(1)), .string("1.5"))
        XCTAssertEqual(XrayFormSchema.scalar("inf", schema: integer, original: nil), .string("inf"))
        XCTAssertEqual(XrayFormSchema.scalar("12", schema: range, original: .string("1")), .string("12"))
        XCTAssertEqual(XrayFormSchema.scalar("1-4", schema: range, original: .number(1)), .string("1-4"))
        let value: JSONValue = .object(["password": .string(" secret\n"), "X-Custom": .array([.null, .bool(false)]), "mtu": .number(1200)])
        let edited = XrayFormSchema.setting("mtu", to: .number(1300), in: value)
        XCTAssertEqual(edited?.objectValue?["password"], value.objectValue?["password"])
        XCTAssertEqual(edited?.objectValue?["X-Custom"], value.objectValue?["X-Custom"])
        XCTAssertEqual(XrayFormSchema.setting("mtu", to: nil, in: edited)?.objectValue?["X-Custom"], value.objectValue?["X-Custom"])
    }

    func testDynamicShapesResolveMaskAndRawHeaderSettings() throws {
        let schema = XrayFormSchema.shared
        let mask = try XCTUnwrap(schema.definition("Mask"))
        let tcp = schema.fields(mask, value: .object(["type": .string("fragment")]), context: "FinalMask.tcp.0")
        XCTAssertEqual(tcp["settings"]?.objectValue?["$ref"], .string("#/definitions/FragmentMask"))
        XCTAssertFalse(tcp["type"]?.objectValue?["enum"]?.arrayValue?.contains(.string("salamander")) ?? true)
        let udp = schema.fields(mask, value: .object(["type": .string("salamander")]), context: "FinalMask.udp.0")
        XCTAssertNotNil(udp["settings"]?.objectValue?["$ref"])
        let raw = try schema.fields(XCTUnwrap(schema.definition("TCPConfig")), value: .object(["header": .object(["type": .string("http")])]), context: "TCPConfig")
        XCTAssertNotNil(raw["header"]?.objectValue?["fields"]?.objectValue?["request"])
    }

    func testMaskPickerOmitsUnsupportedNovemberVariantsAndTheirSettings() throws {
        let schema = XrayFormSchema.shared
        let mask = try XCTUnwrap(schema.definition("Mask"))
        for (family, rejected) in [("tcp", "filter"), ("tcp", "xmc"), ("udp", "filter")] {
            let fields = schema.fields(mask, value: .object(["type": .string(rejected)]), context: "FinalMask.\(family).0")
            let choices = try XCTUnwrap(fields["type"]?.objectValue?["enum"]?.arrayValue)
            XCTAssertFalse(choices.contains(.string(rejected)))
            let settings = try XCTUnwrap(fields["settings"]?.objectValue)
            XCTAssertNil(settings["$ref"])
            XCTAssertFalse(XrayFormSchema.available(settings))
        }
    }

    func testValidationRejectsInvalidDraftNumbersRecursively() {
        let schema = XrayFormSchema.shared
        XCTAssertNil(schema.validationError(definition: "SocketConfig", value: .object(["tcpKeepAliveIdle": .number(30)])))
        XCTAssertNotNil(schema.validationError(definition: "SocketConfig", value: .object(["tcpKeepAliveIdle": .string("3x")])))
        XCTAssertNotNil(schema.validationError(definition: "SocketConfig", value: .object(["TCPKeepAliveIdle": .string("3x")])))
        XCTAssertNotNil(schema.validationError(definition: "FinalMask", value: .object(["quicParams": .object(["maxIncomingStreams": .string("bad")])])))
        XCTAssertNotNil(schema.validationError(definition: "WireGuardConfig", value: .object(["peers": .array([.object(["keepAlive": .string("bad")])])])))
        XCTAssertNil(schema.validationError(definition: "SocketConfig", value: .object(["tcpKeepAliveIdle": .string("bad")]), excludedKeys: ["tcpKeepAliveIdle"]))
        XCTAssertNil(schema.validationError(definition: "SocketConfig", value: .object(["futureKey": .array([.string("preserve")])])))
    }

    func testLabelsAreShortAndSecretsStayMasked() {
        XCTAssertEqual(XrayFormSchema.label("mldsa65Verify"), "ML-DSA Verify Key")
        XCTAssertEqual(XrayFormSchema.label("tcpKeepAliveIdle"), "TCP Keep Alive Idle")
        XCTAssertEqual(XrayFormSchema.label("sessionIDKey"), "Session ID Key")
        XCTAssertEqual(XrayFormSchema.label("allowedIPs"), "Allowed IPs")
        XCTAssertTrue(XrayFormSchema.isSecret("password", schema: [:]))
        XCTAssertTrue(XrayFormSchema.isSecret("Authorization", schema: [:]))
        XCTAssertTrue(XrayFormSchema.isSecret("Set-Cookie", schema: [:]))
        for key in ["X-API-Key", "secrets", "template", "script", "texturesSignature"] {
            XCTAssertTrue(XrayFormSchema.isSecret(key, schema: [:]))
        }
        XCTAssertTrue(XrayFormSchema.isSecret("key", schema: ["annotations": .array([.string("secret")])]))
        XCTAssertFalse(XrayFormSchema.isSecret("publicKey", schema: [:]))
    }
}
