import SwiftUI

/// Native controls over the same value tree consumed by the config builder.
struct XrayFieldsEditor: View {
    let definition: String
    @Binding var value: JSONValue?
    var allowedKeys: Set<String>?
    var excludedKeys: Set<String> = []

    var body: some View {
        if let schema = XrayFormSchema.shared.definition(definition) {
            XrayObjectFields(
                schema: schema, value: $value, context: definition,
                allowedKeys: allowedKeys, excludedKeys: excludedKeys,
            )
        } else {
            Text("Fields unavailable").foregroundStyle(.secondary)
        }
    }
}

struct XrayFormSchema {
    static let shared: XrayFormSchema = {
        guard let url = Bundle.main.url(forResource: "xray-client-schema-v26.6.27", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let document = try? JSONDecoder().decode(JSONValue.self, from: data)
        else { return XrayFormSchema(document: [:]) }
        return XrayFormSchema(document: document.objectValue ?? [:])
    }()

    let document: [String: JSONValue]

    func definition(_ name: String) -> [String: JSONValue]? {
        guard let fields = document["definitions"]?.objectValue?[name]?.objectValue else { return nil }
        return fields.merging(["$ref": .string("#/definitions/\(name)")]) { _, new in new }
    }

    func resolve(_ schema: [String: JSONValue]) -> [String: JSONValue] {
        guard let ref = schema["$ref"]?.stringValue?.split(separator: "/").last,
              let target = definition(String(ref)) else { return schema }
        return target.merging(schema) { _, new in new }
    }

    func fields(_ schema: [String: JSONValue], value: JSONValue?, context: String) -> [String: JSONValue] {
        let resolved = resolve(schema)
        var fields = resolved["fields"]?.objectValue ?? [:]
        let name = resolved["$ref"]?.stringValue?.split(separator: "/").last
        if name == "Mask" {
            let family = context.lowercased().contains(".tcp") ? "tcpTypes" : "udpTypes"
            let variants = document["finalMask"]?.objectValue?[family]?.objectValue ?? [:]
            fields["type"] = .object(["jsonTypes": .array([.string("string")]), "enum": .array(variants.keys.sorted().map(JSONValue.string))])
            fields["settings"] = .object(["jsonTypes": .array([.string("object")])])
            if let type = Self.lookup("type", in: value?.objectValue ?? [:])?.stringValue,
               let ref = variants[type]?.objectValue?["settingsRef"]
            {
                fields["settings"] = .object(["$ref": ref, "jsonTypes": .array([.string("object")])])
            }
        }
        if name == "TCPConfig" {
            let variants = document["dynamicShapes"]?.objectValue?["rawHeader"]?.objectValue?["variants"]?.objectValue ?? [:]
            let headerValue = Self.lookup("header", in: value?.objectValue ?? [:])?.objectValue ?? [:]
            let type = Self.lookup("type", in: headerValue)?.stringValue ?? "none"
            var header = resolve(variants[type]?.objectValue ?? [:])
            var headerFields = header["fields"]?.objectValue ?? [:]
            headerFields["type"] = .object(["jsonTypes": .array([.string("string")]), "enum": .array(variants.keys.sorted().map(JSONValue.string))])
            header["fields"] = .object(headerFields)
            header["jsonTypes"] = .array([.string("object")])
            fields["header"] = .object(header)
        }
        if name == "SplitHTTPConfig" {
            fields["extra"] = .object(["$ref": .string("#/definitions/SplitHTTPConfig"), "jsonTypes": .array([.string("object")])])
            let excluded = context.contains(".extra") ? ["host", "path", "mode", "extra", "downloadSettings"] : ["downloadSettings"]
            for key in excluded {
                var field = fields[key]?.objectValue ?? [:]
                field["applicability"] = .string("excluded-client-overridden")
                fields[key] = .object(field)
            }
        }
        if name == "SocketConfig" {
            fields["tcpFastOpen"] = .object(["jsonTypes": .array([.string("boolean"), .string("integer")])])
        }
        if ["TCPItem", "UDPItem", "NoiseItem", "CustomTransformArg"].contains(name) {
            let key = name == "CustomTransformArg" ? "bytes" : "packet"
            let type = Self.lookup("type", in: value?.objectValue ?? [:])?.stringValue ?? "array"
            let types: [String] = type.isEmpty || type == "array" ? ["array", "string"] : ["string"]
            fields[key] = .object(["jsonTypes": .array(types.map(JSONValue.string)), "items": .object(["jsonTypes": .array([.string("integer")])])])
            fields["type"] = .object(["jsonTypes": .array([.string("string")]), "enum": .array(["array", "str", "hex", "base64"].map(JSONValue.string))])
        }
        return fields
    }

    static func available(_ schema: [String: JSONValue]) -> Bool {
        let applicability = schema["applicability"]?.stringValue ?? "client"
        return !applicability.hasPrefix("server-only") && !applicability.hasPrefix("excluded") && !applicability.contains("legacy-alias")
    }

    func validationError(
        definition name: String, value: JSONValue?,
        allowedKeys: Set<String>? = nil, excludedKeys: Set<String> = [],
    ) -> String? {
        guard let value else { return nil }
        guard let schema = definition(name) else { return "Fields unavailable." }
        guard let object = value.objectValue else { return "\(name): use a JSON object." }
        let selected = object.filter { key, _ in
            Self.includes(key, allowedKeys: allowedKeys, excludedKeys: excludedKeys)
        }
        return validationError(schema: schema, value: .object(selected), context: name, title: name)
    }

    private func validationError(schema: [String: JSONValue], value: JSONValue, context: String, title: String) -> String? {
        let resolved = resolve(schema)
        let types = Self.types(resolved)
        let matches = types.contains("any") || types.contains { type in
            switch (type, value) {
            case ("string", .string), ("boolean", .bool), ("object", .object), ("array", .array), ("null", .null): true
            case let ("integer", .number(number)): number.isFinite && number.rounded() == number
            case let ("number", .number(number)): number.isFinite
            default: false
            }
        }
        guard matches else { return "\(title): expected \(types.joined(separator: " or "))." }
        switch value {
        case let .object(object):
            let fields = fields(resolved, value: value, context: context)
            for key in object.keys.sorted() {
                guard let child = Self.field(key, in: fields) ?? resolved["additionalProperties"]?.objectValue else { continue }
                if let error = validationError(schema: child, value: object[key]!, context: "\(context).\(key)", title: Self.label(key)) {
                    return error
                }
            }
        case let .array(items):
            if let child = resolved["items"]?.objectValue {
                for (index, item) in items.enumerated() {
                    if let error = validationError(schema: child, value: item, context: "\(context).\(index)", title: "\(title) \(index + 1)") {
                        return error
                    }
                }
            }
        default: break
        }
        return nil
    }

    static func includes(_ key: String, allowedKeys: Set<String>?, excludedKeys: Set<String>) -> Bool {
        let matches: (String) -> Bool = { $0.caseInsensitiveCompare(key) == .orderedSame }
        return !excludedKeys.contains(where: matches) && (allowedKeys?.contains(where: matches) ?? true)
    }

    static func setting(_ key: String, to newValue: JSONValue?, in value: JSONValue?) -> JSONValue? {
        var object = value?.objectValue ?? [:]
        object[key] = newValue
        return object.isEmpty ? nil : .object(object)
    }

    static func field(_ key: String, in fields: [String: JSONValue]) -> [String: JSONValue]? {
        lookup(key, in: fields)?.objectValue
    }

    private static func lookup(_ key: String, in object: [String: JSONValue]) -> JSONValue? {
        object[key] ?? object.first { $0.key.caseInsensitiveCompare(key) == .orderedSame }?.value
    }

    static func types(_ schema: [String: JSONValue]) -> [String] {
        schema["jsonTypes"]?.arrayValue?.compactMap(\.stringValue) ?? ["any"]
    }

    static func defaultValue(_ schema: [String: JSONValue]) -> JSONValue {
        if let first = schema["enum"]?.arrayValue?.first {
            return first
        }
        switch types(schema).first {
        case "object": return .object([:])
        case "array": return .array([])
        case "integer", "number": return .number(0)
        case "boolean": return .bool(false)
        default: return .string("")
        }
    }

    static func scalar(_ text: String, schema: [String: JSONValue], original: JSONValue?) -> JSONValue {
        let types = types(schema)
        let numeric = types.contains("integer") || types.contains("number")
        if types.contains("string"), case .string = original {
            return .string(text)
        }
        if numeric, let number = Double(text), number.isFinite,
           !types.contains("integer") || number.rounded() == number
        {
            return .number(number)
        }
        // Keep invalid input visible and let the builder reject its type on Save.
        return .string(text)
    }

    static func text(_ value: JSONValue?) -> String {
        switch value {
        case let .string(text): text
        case let .number(number): String(format: "%.17g", number)
        case let .bool(value): String(value)
        default: ""
        }
    }

    static func isSecret(_ key: String, schema: [String: JSONValue]) -> Bool {
        schema["annotations"]?.arrayValue?.contains(.string("secret")) == true ||
            ["password", "pass", "privatekey", "secretkey", "presharedkey", "auth", "encryption", "authorization", "proxy-authorization", "cookie", "set-cookie"].contains(key.lowercased())
    }

    static func label(_ key: String) -> String {
        let labels = [
            "testpre": "Preconnections", "testseed": "Vision Padding",
            "mldsa65Verify": "ML-DSA Verify Key", "serverName": "SNI", "alpn": "ALPN", "mtu": "MTU",
            "id": "UUID", "user": "Username", "pass": "Password", "secretKey": "Private Key",
            "allowedIPs": "Allowed IPs", "noKernelTun": "Userspace TUN", "tcpFastOpen": "TCP Fast Open",
            "echConfigList": "ECH Config", "echSockopt": "ECH Socket", "pinnedPeerCertSha256": "Certificate Pins",
            "verifyPeerCertByName": "Verify Names", "enableSessionResumption": "Session Resumption",
            "disableSystemRoot": "Disable System Roots", "curvePreferences": "Curves", "mldsa65Seed": "ML-DSA Seed",
            "noGRPCHeader": "No gRPC Header", "noSSEHeader": "No SSE Header", "tcpMptcp": "MPTCP",
            "scMaxEachPostBytes": "Max POST Bytes", "scMaxBufferedPosts": "Buffered POSTs",
            "scMinPostsIntervalMs": "POST Interval (ms)", "scStreamUpServerSecs": "Stream Duration (s)",
            "initConnectionReceiveWindow": "Initial Conn. Window", "maxConnectionReceiveWindow": "Max Conn. Window",
            "initStreamReceiveWindow": "Initial Stream Window", "maxStreamReceiveWindow": "Max Stream Window",
            "hMaxReusableSecs": "Max Reuse (s)", "hMaxRequestTimes": "Max Requests", "cMaxReuseTimes": "Max Reuses",
            "hKeepAlivePeriod": "Keepalive", "disablePathMTUDiscovery": "Disable PMTU Discovery",
            "quicParams": "QUIC", "finalmask": "FinalMask", "xmux": "XMUX", "tti": "TTI", "url": "URL",
        ]
        if let label = labels[key] {
            return label
        }
        return key.replacingOccurrences(of: "([A-Z]+)([A-Z][a-z])", with: "$1 $2", options: .regularExpression)
            .replacingOccurrences(of: "([a-z0-9])([A-Z])", with: "$1 $2", options: .regularExpression)
            .replacingOccurrences(of: "_", with: " ")
            .split(separator: " ").map { part in
                let acronyms = ["tcp", "udp", "tls", "ip", "ipv4", "ipv6", "dns", "http", "id", "ocsp", "bbr", "sni", "sse"]
                return acronyms.contains(part.lowercased()) ? part.uppercased() : part.prefix(1).uppercased() + part.dropFirst()
            }.joined(separator: " ")
    }
}

private struct XrayObjectFields: View {
    let schema: [String: JSONValue]
    @Binding var value: JSONValue?
    let context: String
    var allowedKeys: Set<String>?
    var excludedKeys: Set<String> = []
    var secure = false
    @State private var addingEntry = false
    @State private var entryName = ""

    private var resolved: [String: JSONValue] {
        XrayFormSchema.shared.resolve(schema)
    }

    private var fields: [String: JSONValue] {
        XrayFormSchema.shared.fields(schema, value: value, context: context)
    }

    private var object: [String: JSONValue] {
        value?.objectValue ?? [:]
    }

    private var isMap: Bool {
        resolved["additionalProperties"] != nil
    }

    private var visibleKeys: [String] {
        object.keys.filter(included).sorted()
    }

    private var missingKeys: [String] {
        fields.keys.filter { key in
            included(key) && !object.keys.contains { $0.caseInsensitiveCompare(key) == .orderedSame } &&
                XrayFormSchema.available(fields[key]?.objectValue ?? [:])
        }.sorted()
    }

    var body: some View {
        ForEach(visibleKeys, id: \.self) { key in
            let field = XrayFormSchema.field(key, in: fields) ?? resolved["additionalProperties"]?.objectValue ?? [:]
            HStack(alignment: .top) {
                if XrayFormSchema.available(field) {
                    XrayValueField(
                        title: isMap ? key : XrayFormSchema.label(key), schema: field,
                        value: binding(key), context: "\(context).\(key)",
                        secure: secure || XrayFormSchema.isSecret(key, schema: field),
                    )
                } else {
                    LabeledContent(XrayFormSchema.label(key), value: "Unsupported").foregroundStyle(.secondary)
                }
                Button(role: .destructive) { binding(key).wrappedValue = nil } label: {
                    Image(systemName: "minus.circle").padding(.top, 3)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Remove \(XrayFormSchema.label(key))")
            }
        }
        if !missingKeys.isEmpty {
            Menu {
                ForEach(missingKeys, id: \.self) { key in
                    Button(XrayFormSchema.label(key)) {
                        binding(key).wrappedValue = XrayFormSchema.defaultValue(XrayFormSchema.shared.resolve(fields[key]?.objectValue ?? [:]))
                    }
                }
            } label: { Label("Add Field", systemImage: "plus.circle") }
        }
        if isMap {
            Button { addingEntry = true } label: { Label("Add Entry", systemImage: "plus.circle") }
                .alert("Add Entry", isPresented: $addingEntry) {
                    TextField("Name", text: $entryName).textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button("Add") {
                        binding(entryName).wrappedValue = XrayFormSchema.defaultValue(resolved["additionalProperties"]?.objectValue ?? [:])
                        entryName = ""
                    }.disabled(entryName.isEmpty || object[entryName] != nil)
                    Button("Cancel", role: .cancel) { entryName = "" }
                }
        }
    }

    private func included(_ key: String) -> Bool {
        XrayFormSchema.includes(key, allowedKeys: allowedKeys, excludedKeys: excludedKeys)
    }

    private func binding(_ key: String) -> Binding<JSONValue?> {
        Binding(get: { object[key] }, set: { new in
            value = XrayFormSchema.setting(key, to: new, in: value)
        })
    }
}

private struct XrayValueField: View {
    let title: String
    let schema: [String: JSONValue]
    @Binding var value: JSONValue?
    let context: String
    var secure = false

    private var resolved: [String: JSONValue] {
        XrayFormSchema.shared.resolve(schema)
    }

    private var types: [String] {
        XrayFormSchema.types(resolved)
    }

    private var kind: String {
        switch value {
        case .object: "object"
        case .array: "array"
        case .bool: "boolean"
        case .string: "string"
        case .number: "number"
        default: types.first ?? "string"
        }
    }

    var body: some View {
        // Type erasure terminates the recursive object/array view type.
        AnyView(content)
    }

    @ViewBuilder private var content: some View {
        if kind == "object" {
            DisclosureGroup(title) {
                XrayObjectFields(schema: resolved, value: $value, context: context, secure: secure)
            }
        } else if kind == "array" {
            DisclosureGroup(title) {
                ForEach(Array((value?.arrayValue ?? []).indices), id: \.self) { index in
                    HStack(alignment: .top) {
                        XrayValueField(
                            title: "Item \(index + 1)", schema: resolved["items"]?.objectValue ?? [:],
                            value: item(index), context: "\(context).\(index)", secure: secure,
                        )
                        Button(role: .destructive) { item(index).wrappedValue = nil } label: { Image(systemName: "minus.circle") }
                            .buttonStyle(.borderless).accessibilityLabel("Remove item \(index + 1)")
                    }
                }
                Button {
                    value = .array((value?.arrayValue ?? []) + [XrayFormSchema.defaultValue(XrayFormSchema.shared.resolve(resolved["items"]?.objectValue ?? [:]))])
                } label: { Label("Add Item", systemImage: "plus.circle") }
            }
        } else if kind == "boolean" {
            Toggle(title, isOn: Binding(get: { value == .bool(true) }, set: { value = .bool($0) }))
            if types.contains("integer") {
                Button("Use Number") { value = .number(0) }.font(.caption)
            }
        } else if let options = resolved["enum"]?.arrayValue?.compactMap(\.stringValue), !options.isEmpty {
            let current = value?.stringValue ?? ""
            Picker(title, selection: Binding(get: { current }, set: { value = .string($0) })) {
                if !options.contains(current) {
                    Text(current).tag(current)
                }
                ForEach(options, id: \.self) { Text($0.isEmpty ? "Default" : $0).tag($0) }
            }
        } else {
            ProfileTextField(title, text: Binding(
                get: { XrayFormSchema.text(value) },
                set: { value = XrayFormSchema.scalar($0, schema: resolved, original: value) },
            ), keyboardType: types == ["integer"] || types == ["number"] ? .numbersAndPunctuation : .default, isSecure: secure)
            if types.contains("boolean") {
                Button("Use Toggle") { value = .bool(false) }.font(.caption)
            }
        }
    }

    private func item(_ index: Int) -> Binding<JSONValue?> {
        Binding(get: {
            let items = value?.arrayValue ?? []
            return items.indices.contains(index) ? items[index] : nil
        }, set: { new in
            var items = value?.arrayValue ?? []
            guard items.indices.contains(index) else { return }
            if let new {
                items[index] = new
            } else {
                items.remove(at: index)
            }
            value = .array(items)
        })
    }
}
