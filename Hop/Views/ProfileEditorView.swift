import SwiftUI

/// Form for creating or editing a single proxy node. Works on a string-typed
/// draft and only produces a `ProxyProfile` when validation passes.
struct ProfileEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var draft: ProfileEditorDraft

    let isNew: Bool
    let onSave: (ProxyProfile) -> Void

    init(profile: ProxyProfile, isNew: Bool = false, onSave: @escaping (ProxyProfile) -> Void) {
        _draft = State(initialValue: ProfileEditorDraft(profile: profile))
        self.isNew = isNew
        self.onSave = onSave
    }

    var body: some View {
        let validation = draft.validation

        NavigationStack {
            Form {
                if let validationMessage = validation.message {
                    Section {
                        Label(validationMessage, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }

                Section("Basics") {
                    ProfileTextField("Name", text: $draft.name, capitalization: .words, autocorrectionDisabled: false)
                    Picker("Protocol", selection: $draft.proto) {
                        ForEach(ProfileEditorChoices.supportedProtocols, id: \.self) { proto in
                            Text(proto.displayName).tag(proto)
                        }
                    }
                    ProfileTextField(draft.proto == .wireGuard ? "Peer Host" : "Host", text: $draft.host)
                    ProfileTextField(draft.proto == .wireGuard ? "Peer Port" : "Port", text: $draft.port, prompt: "443", keyboardType: .numberPad)
                }

                credentialsSection
                if draft.proto != .wireGuard {
                    securitySection
                }
                transportSection
                connectionSection

                Section {
                    DisclosureGroup("Raw JSON") {
                        TextEditor(text: $draft.xrayAdvancedJSON)
                            .font(.system(.caption, design: .monospaced))
                            .frame(minHeight: 140)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .accessibilityLabel("Advanced Xray JSON")
                    }
                }
            }
            .navigationTitle(isNew ? "New Node" : "Edit Node")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }

                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        // Revalidate on the explicit save action so a stale
                        // rendered button can never admit a changed draft.
                        guard let profile = draft.validation.profile else {
                            return
                        }
                        onSave(profile)
                        dismiss()
                    }
                    .disabled(validation.profile == nil)
                }
            }
        }
    }

    private var credentialsSection: some View {
        Section("Credentials") {
            switch draft.proto {
            case .vless:
                // UUIDs are bearer credentials (possession authenticates), so
                // they get the same SecureField treatment as passwords.
                ProfileTextField("UUID", text: $draft.vlessUUID, isSecure: true)
                ProfileTextField("Flow", text: $draft.vlessFlow, prompt: "xtls-rprx-vision")
                ProfileTextField("Encryption / Auth", text: $draft.vlessEncryption, prompt: "none", isSecure: true)
            case .trojan:
                ProfileTextField("Password", text: $draft.trojanPassword, isSecure: true)
            case .hysteria2:
                ProfileTextField("Password", text: $draft.hysteriaPassword, isSecure: true)
                ProfileTextField("Obfuscation", text: $draft.hysteriaObfs, prompt: "salamander")
                ProfileTextField("Obfs Password", text: $draft.hysteriaObfsPassword, isSecure: true)
                ProfileTextField("Upload", text: $draft.hysteriaUp, prompt: "20 mbps")
                ProfileTextField("Download", text: $draft.hysteriaDown, prompt: "100 mbps")
                ProfileTextField("Port Hopping", text: $draft.hysteriaPorts, prompt: "20000-50000")
                ProfileTextField("Hop Interval (s)", text: $draft.hysteriaHopInterval, prompt: "30", keyboardType: .numberPad)
                ProfileTextField("UDP Idle (s)", text: $draft.hysteriaUDPIdleTimeout, prompt: "60", keyboardType: .numberPad)
            case .tuic:
                ProfileTextField("UUID", text: $draft.tuicUUID, isSecure: true)
                ProfileTextField("Password", text: $draft.tuicPassword, isSecure: true)
                ProfileTextField("Congestion Control", text: $draft.tuicCongestionControl, prompt: "bbr")
            case .shadowsocks:
                ProfileTextField("Method", text: $draft.shadowsocksMethod, prompt: "2022-blake3-aes-128-gcm")
                ProfileTextField("Password", text: $draft.shadowsocksPassword, isSecure: true)
            case .vmess:
                ProfileTextField("UUID", text: $draft.vmessUUID, isSecure: true)
                ProfileTextField("Security", text: $draft.vmessSecurity, prompt: "auto")
                if draft.vmessAlterID != "0" {
                    Button("Use VMess AEAD") { draft.vmessAlterID = "0" }
                }
            case .http:
                ProfileTextField("Username", text: $draft.httpUsername)
                ProfileTextField("Password", text: $draft.httpPassword, isSecure: true)
            case .socks:
                ProfileTextField("Username", text: $draft.socksUsername)
                ProfileTextField("Password", text: $draft.socksPassword, isSecure: true)
            case .wireGuard:
                ProfileTextField("Private Key", text: $draft.wireGuardPrivateKey, isSecure: true)
                ProfileTextField("Peer Public Key", text: $draft.wireGuardPeerPublicKey)
                ProfileTextField("Pre-shared Key", text: $draft.wireGuardPreSharedKey, prompt: "optional", isSecure: true)
                ProfileTextField("Local Addresses", text: $draft.wireGuardLocalAddresses, prompt: "10.0.0.2/32, fd00::2/128")
                ProfileTextField("Allowed IPs", text: $draft.wireGuardAllowedIPs, prompt: "0.0.0.0/0, ::/0")
                ProfileTextField("Reserved Bytes", text: $draft.wireGuardReserved, prompt: "0, 0, 0")
                ProfileTextField("Keepalive (s)", text: $draft.wireGuardKeepAlive, prompt: "25", keyboardType: .numberPad)
                ProfileTextField("MTU", text: $draft.wireGuardMTU, prompt: "1280", keyboardType: .numberPad)
                ProfileTextField("Domain Strategy", text: $draft.wireGuardDomainStrategy, prompt: "ForceIP")
                if draft.wireGuardHasExplicitEndpoint {
                    DisclosureGroup("Node Endpoint") {
                        ProfileTextField("Host", text: $draft.wireGuardFallbackHost)
                        ProfileTextField("Port", text: $draft.wireGuardFallbackPort, keyboardType: .numberPad)
                    }
                }
                WireGuardPeerFields(peers: $draft.extraWireGuardPeers)
            case .anyTLS:
                ProfileTextField("Password", text: $draft.anyTLSPassword, isSecure: true)
            }
            if let definition = draft.protocolDefinition {
                advancedFields("More Options", definition: definition, path: ["settings"], allowedKeys: XrayConfigBuilder.editorProtocolKeys(draft.proto))
            }
        }
    }

    private var securitySection: some View {
        Section("Security") {
            Picker("Security", selection: $draft.securityLayer) {
                ForEach(SecurityLayer.allCases, id: \.self) { layer in
                    Text(layer.displayName).tag(layer)
                }
            }

            switch draft.securityLayer {
            case .none:
                Label("TLS off", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.secondary)
            case .tls:
                ProfileTextField("SNI", text: $draft.tlsServerName, prompt: "example.com")
                ProfileTextField("ALPN", text: $draft.tlsALPN, prompt: "h2, http/1.1")
                UTLSFingerprintPicker(selection: $draft.tlsFingerprint)
                DisclosureGroup("More Options") {
                    ProfileTextField("SHA-256 Pins", text: $draft.tlsPinnedCertificates, prompt: "hex, comma-separated")
                    ProfileTextField("Verify Names", text: $draft.tlsVerifyNames, prompt: "example.com")
                    ProfileTextField("ECH Config", text: $draft.tlsECHConfigList, prompt: "base64", isSecure: true)
                    ProfileTextField("Curves", text: $draft.tlsCurves, prompt: "X25519MLKEM768")
                    ProfileTextField("Min TLS", text: $draft.tlsMinVersion, prompt: "1.2")
                    ProfileTextField("Max TLS", text: $draft.tlsMaxVersion, prompt: "1.3")
                    ProfileTextField("Cipher Suites", text: $draft.tlsCipherSuites, prompt: "optional")
                    Toggle("Session Resumption", isOn: $draft.tlsSessionResumption)
                    existingAdvancedFields(definition: "TLSConfig", path: ["streamSettings", "tlsSettings"])
                }
                if draft.tlsAllowInsecure, draft.tlsPinnedCertificates.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    Label("Insecure TLS blocked. Verify TLS or add a certificate pin.", systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.red)
                    Button("Use Verified TLS") {
                        draft.tlsAllowInsecure = false
                    }
                }
            case .reality:
                ProfileTextField("Public Key", text: $draft.realityPublicKey)
                ProfileTextField("Short ID", text: $draft.realityShortID)
                ProfileTextField("SNI", text: $draft.realityServerName, prompt: "camouflage domain")
                ProfileTextField("Spider Path", text: $draft.realitySpiderX, prompt: "/")
                ProfileTextField("ML-DSA Verify Key", text: $draft.realityMLDSA65Verify, isSecure: true)
                UTLSFingerprintPicker(selection: $draft.realityFingerprint)
                existingAdvancedFields(definition: "REALITYConfig", path: ["streamSettings", "realitySettings"])
            }
        }
    }

    private var transportSection: some View {
        Section("Transport") {
            if draft.proto == .hysteria2 {
                LabeledContent("Type", value: "Hysteria2")
            } else if draft.proto == .wireGuard {
                LabeledContent("Type", value: "WireGuard")
            } else {
                Picker("Type", selection: $draft.transportType) {
                    ForEach(ProfileEditorChoices.supportedTransports, id: \.self) { type in
                        Text(type.displayName).tag(type)
                    }
                }

                switch draft.transportType {
                case .tcp, .mKCP, .hysteria, .quic:
                    EmptyView()
                case .websocket, .httpUpgrade:
                    ProfileTextField("Path", text: $draft.transportPath, prompt: "/")
                    ProfileTextField("Host Header", text: $draft.transportHost)
                case .grpc:
                    ProfileTextField("Service Name", text: $draft.transportServiceName)
                    ProfileTextField("Authority", text: $draft.transportHost)
                case .xhttp:
                    ProfileTextField("Path", text: $draft.transportPath, prompt: "/")
                    ProfileTextField("Host", text: $draft.transportHost)
                    ProfileTextField("Mode", text: $draft.xhttpMode, prompt: "auto")
                }
                if draft.transportType == .mKCP {
                    XrayFieldsEditor(definition: "KCPConfig", value: $draft.kcpFields, allowedKeys: XrayConfigBuilder.editorTransportKeys(.mKCP))
                }
                if draft.transportType == .xhttp, draft.xhttpExtra != nil {
                    DisclosureGroup("XHTTP Options") {
                        XrayFieldsEditor(definition: "SplitHTTPConfig", value: $draft.xhttpExtra, allowedKeys: draft.extraTransportKeys.subtracting(["extra"]))
                    }
                }
                if let definition = draft.transportDefinition,
                   draft.transportType != .mKCP || draft.advancedValue(at: ["streamSettings", draft.transportSettingsKey]) != nil
                {
                    advancedFields("More Options", definition: definition, path: ["streamSettings", draft.transportSettingsKey], allowedKeys: draft.extraTransportKeys)
                }
            }
        }
    }

    private var connectionSection: some View {
        Section("Connection") {
            if draft.proto != .wireGuard {
                DisclosureGroup("Multiplexing") {
                    if draft.muxFields != nil || draft.advancedValue(at: ["mux"]) == nil {
                        XrayFieldsEditor(definition: "MuxConfig", value: $draft.muxFields)
                        existingAdvancedFields(definition: "MuxConfig", path: ["mux"])
                    } else {
                        XrayFieldsEditor(definition: "MuxConfig", value: advancedBinding(["mux"]))
                    }
                }
                DisclosureGroup("Socket") {
                    if draft.socketOptions != nil {
                        XrayFieldsEditor(definition: "SocketConfig", value: $draft.socketOptions, allowedKeys: XrayConfigBuilder.editorSocketKeys)
                        existingAdvancedFields(definition: "SocketConfig", path: ["streamSettings", "sockopt"])
                    } else {
                        XrayFieldsEditor(definition: "SocketConfig", value: advancedBinding(["streamSettings", "sockopt"]), allowedKeys: XrayConfigBuilder.editorSocketKeys)
                    }
                }
                DisclosureGroup("FinalMask") {
                    if draft.finalMask != nil || draft.advancedValue(at: ["streamSettings", "finalmask"]) == nil {
                        XrayFieldsEditor(definition: "FinalMask", value: $draft.finalMask)
                        existingAdvancedFields(definition: "FinalMask", path: ["streamSettings", "finalmask"])
                    } else {
                        XrayFieldsEditor(definition: "FinalMask", value: advancedBinding(["streamSettings", "finalmask"]))
                    }
                }
            }
            advancedFields("Outbound", definition: "OutboundDetourConfig", path: [], allowedKeys: ["sendThrough", "targetStrategy", "proxySettings"])
        }
    }

    @ViewBuilder private func existingAdvancedFields(definition: String, path: [String]) -> some View {
        if let object = draft.advancedValue(at: path)?.objectValue, !object.isEmpty {
            advancedFields("Overrides", definition: definition, path: path, allowedKeys: Set(object.keys))
        }
    }

    private func advancedFields(_ title: String, definition: String, path: [String], allowedKeys: Set<String>) -> some View {
        DisclosureGroup(title) {
            XrayFieldsEditor(definition: definition, value: advancedBinding(path), allowedKeys: allowedKeys)
        }
        .disabled(!draft.hasValidAdvancedJSON)
    }

    private func advancedBinding(_ path: [String]) -> Binding<JSONValue?> {
        Binding(
            get: { draft.advancedValue(at: path) },
            set: { draft.setAdvancedValue($0, at: path) },
        )
    }
}

/// Trailing-aligned labeled text field shared by the profile, group, and
/// import forms.
struct ProfileTextField: View {
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    let title: String
    @Binding var text: String
    let prompt: String
    let keyboardType: UIKeyboardType
    let capitalization: TextInputAutocapitalization
    let autocorrectionDisabled: Bool
    let isSecure: Bool

    init(
        _ title: String,
        text: Binding<String>,
        prompt: String = "",
        keyboardType: UIKeyboardType = .default,
        capitalization: TextInputAutocapitalization = .never,
        autocorrectionDisabled: Bool = true,
        isSecure: Bool = false,
    ) {
        self.title = title
        _text = text
        self.prompt = prompt
        self.keyboardType = keyboardType
        self.capitalization = capitalization
        self.autocorrectionDisabled = autocorrectionDisabled
        self.isSecure = isSecure
    }

    var body: some View {
        let stacked = dynamicTypeSize.isAccessibilitySize
        let layout = stacked
            ? AnyLayout(VStackLayout(alignment: .leading, spacing: 6))
            : AnyLayout(HStackLayout(spacing: 12))

        layout {
            Text(title)
                .fixedSize(horizontal: !stacked, vertical: true)
                .accessibilityHidden(true)

            // Passwords and private keys render as `SecureField` so they stay masked.
            Group {
                if isSecure {
                    SecureField(prompt, text: $text)
                } else {
                    TextField(prompt, text: $text)
                }
            }
            .accessibilityLabel(title)
            .multilineTextAlignment(stacked ? .leading : .trailing)
            .keyboardType(keyboardType)
            .textInputAutocapitalization(capitalization)
            .autocorrectionDisabled(autocorrectionDisabled)
            .lineLimit(1)
            .truncationMode(.middle)
            .frame(maxWidth: .infinity, alignment: stacked ? .leading : .trailing)
        }
    }
}

private struct UTLSFingerprintPicker: View {
    @Binding var selection: String

    var body: some View {
        let current = selection.trimmingCharacters(in: .whitespacesAndNewlines)
        let options = if !current.isEmpty, !ProfileEditorChoices.utlsFingerprints.contains(current) {
            [current] + ProfileEditorChoices.utlsFingerprints
        } else {
            ProfileEditorChoices.utlsFingerprints
        }

        Picker("uTLS Fingerprint", selection: $selection) {
            ForEach(options, id: \.self) { option in
                Text(ProfileEditorChoices.utlsFingerprintTitle(option)).tag(option)
            }
        }
    }
}

private enum ProfileEditorChoices {
    static let supportedProtocols = ProxyProtocol.allCases.filter {
        $0 != .tuic && $0 != .anyTLS
    }

    static let supportedTransports = TransportType.allCases.filter { $0 != .quic && $0 != .hysteria }

    static let utlsFingerprints = [
        "chrome",
        "firefox",
        "edge",
        "safari",
        "ios",
        "android",
        "random",
        "randomized",
    ]

    static func utlsFingerprintTitle(_ value: String) -> String {
        switch value {
        case "ios":
            "iOS"
        default:
            value.capitalized
        }
    }
}

struct ProfileEditorValidation {
    let profile: ProxyProfile?
    let message: String?

    static func valid(_ profile: ProxyProfile) -> Self {
        Self(profile: profile, message: nil)
    }

    static func invalid(_ message: String) -> Self {
        Self(profile: nil, message: message)
    }
}

struct ProfileEditorDraft {
    let id: UUID
    let subscriptionID: UUID?
    var name: String
    var proto: ProxyProtocol {
        didSet {
            guard proto != oldValue else { return }
            switch proto {
            case .hysteria2:
                transportType = .hysteria
                securityLayer = .tls
            case .wireGuard:
                transportType = .tcp
                securityLayer = .none
            default:
                if transportType == .hysteria {
                    transportType = .tcp
                }
                if oldValue == .wireGuard {
                    securityLayer = .tls
                }
            }
        }
    }

    var host: String
    var port: String

    var vlessUUID = ""
    var vlessFlow = ""
    var vlessEncryption = ""
    var trojanPassword = ""
    var hysteriaPassword = ""
    var hysteriaObfs = ""
    var hysteriaObfsPassword = ""
    var hysteriaUp = ""
    var hysteriaDown = ""
    var hysteriaPorts = ""
    var hysteriaHopInterval = ""
    var hysteriaUDPIdleTimeout = ""
    var tuicUUID = ""
    var tuicPassword = ""
    var tuicCongestionControl = ""
    var shadowsocksMethod = ""
    var shadowsocksPassword = ""
    var vmessUUID = ""
    var vmessSecurity = "auto"
    var vmessAlterID = "0"
    var httpUsername = ""
    var httpPassword = ""
    var socksUsername = ""
    var socksPassword = ""
    var wireGuardPrivateKey = ""
    var wireGuardPeerPublicKey = ""
    var wireGuardPreSharedKey = ""
    var wireGuardLocalAddresses = ""
    var wireGuardAllowedIPs = ""
    var wireGuardReserved = ""
    var wireGuardKeepAlive = ""
    var wireGuardMTU = ""
    var wireGuardDomainStrategy = ""
    var wireGuardPeers: [WireGuardPeer]?
    var extraWireGuardPeers: [WireGuardPeerDraft] = []
    /// Explicit first-peer endpoints are edited independently of the fallback
    /// used by other peers whose endpoint is nil.
    var wireGuardHasExplicitEndpoint = false
    var wireGuardFallbackHost = ""
    var wireGuardFallbackPort = ""
    var anyTLSPassword = ""

    var securityLayer: SecurityLayer
    var tlsServerName = ""
    var tlsALPN = ""
    private var importedALPN: [String] = []
    var tlsFingerprint = "chrome"
    var tlsAllowInsecure = false
    var tlsPinnedCertificates = ""
    var tlsVerifyNames = ""
    var tlsECHConfigList = ""
    var tlsCurves = ""
    var tlsMinVersion = ""
    var tlsMaxVersion = ""
    var tlsCipherSuites = ""
    var tlsSessionResumption = false
    var realityPublicKey = ""
    var realityShortID = ""
    var realityServerName = ""
    var realityFingerprint = "chrome"
    var realitySpiderX = ""
    var realityMLDSA65Verify = ""

    var transportType: TransportType
    var transportPath = ""
    var transportHost = ""
    var transportServiceName = ""
    var xhttpMode = ""
    var xhttpExtra: JSONValue?
    var kcpFields: JSONValue?
    var finalMask: JSONValue?
    var muxFields: JSONValue?
    var socketOptions: JSONValue?
    var xrayAdvancedJSON = "{}"

    init(profile: ProxyProfile) {
        id = profile.id
        subscriptionID = profile.subscriptionID
        name = profile.name
        proto = profile.proto
        host = profile.endpoint.host
        port = String(profile.endpoint.port)
        securityLayer = profile.security.layer
        transportType = profile.transport.type

        switch profile.options {
        case let .vless(options):
            vlessUUID = options.uuid
            vlessFlow = options.flow ?? ""
            vlessEncryption = options.encryption ?? ""
        case let .trojan(options):
            trojanPassword = options.password
        case let .hysteria2(options):
            hysteriaPassword = options.password
            hysteriaObfs = options.obfs ?? ""
            hysteriaObfsPassword = options.obfsPassword ?? ""
            hysteriaUp = options.up ?? ""
            hysteriaDown = options.down ?? ""
            hysteriaPorts = options.ports ?? ""
            hysteriaHopInterval = options.hopIntervalSeconds.map(String.init) ?? ""
            hysteriaUDPIdleTimeout = options.udpIdleTimeoutSeconds.map(String.init) ?? ""
        case let .tuic(options):
            tuicUUID = options.uuid
            tuicPassword = options.password
            tuicCongestionControl = options.congestionControl ?? ""
        case let .shadowsocks(options):
            shadowsocksMethod = options.method
            shadowsocksPassword = options.password
        case let .vmess(options):
            vmessUUID = options.uuid
            vmessSecurity = options.security
            vmessAlterID = String(options.alterID)
        case let .http(options):
            httpUsername = options.username ?? ""
            httpPassword = options.password ?? ""
        case let .socks(options):
            socksUsername = options.username ?? ""
            socksPassword = options.password ?? ""
        case let .wireGuard(options):
            let firstPeer = options.effectivePeers.first
            if let endpoint = firstPeer?.endpoint {
                wireGuardHasExplicitEndpoint = true
                wireGuardFallbackHost = profile.endpoint.host
                wireGuardFallbackPort = String(profile.endpoint.port)
                host = endpoint.host
                port = String(endpoint.port)
            }
            wireGuardPrivateKey = options.privateKey
            wireGuardPeerPublicKey = firstPeer?.publicKey ?? options.peerPublicKey
            wireGuardPreSharedKey = firstPeer?.preSharedKey ?? ""
            wireGuardLocalAddresses = options.localAddress.joined(separator: ", ")
            wireGuardAllowedIPs = firstPeer?.allowedIPs?.joined(separator: ", ") ?? ""
            wireGuardReserved = options.reserved?.map(String.init).joined(separator: ", ") ?? ""
            wireGuardKeepAlive = firstPeer?.keepAliveSeconds.map(String.init) ?? ""
            wireGuardMTU = options.mtu.map(String.init) ?? ""
            wireGuardDomainStrategy = options.domainStrategy ?? ""
            wireGuardPeers = options.peers
            extraWireGuardPeers = (options.peers ?? []).dropFirst().map(WireGuardPeerDraft.init(peer:))
        case let .anyTLS(options):
            anyTLSPassword = options.password
        }

        if let tls = profile.security.tls {
            tlsServerName = tls.serverName ?? ""
            importedALPN = tls.alpn
            tlsALPN = tls.alpn.joined(separator: ", ")
            tlsFingerprint = tls.utlsFingerprint ?? "chrome"
            tlsAllowInsecure = tls.allowInsecure
            tlsPinnedCertificates = tls.pinnedPeerCertSHA256 ?? ""
            tlsVerifyNames = tls.verifyPeerCertByName ?? ""
            tlsECHConfigList = tls.echConfigList ?? ""
            tlsCurves = tls.curvePreferences.joined(separator: ", ")
            tlsMinVersion = tls.minVersion ?? ""
            tlsMaxVersion = tls.maxVersion ?? ""
            tlsCipherSuites = tls.cipherSuites ?? ""
            tlsSessionResumption = tls.enableSessionResumption
        }

        if let reality = profile.security.reality {
            realityPublicKey = reality.publicKey
            realityShortID = reality.shortID ?? ""
            realityServerName = reality.serverName ?? ""
            realityFingerprint = reality.utlsFingerprint
            realitySpiderX = reality.spiderX ?? ""
            realityMLDSA65Verify = reality.mldsa65Verify ?? ""
        }

        transportPath = profile.transport.path ?? ""
        transportHost = profile.transport.host ?? ""
        transportServiceName = profile.transport.serviceName ?? ""
        xhttpMode = profile.transport.xhttpMode ?? ""
        xhttpExtra = profile.transport.xhttpExtra
        kcpFields = profile.transport.kcp.flatMap(Self.encodeFields)
        finalMask = profile.transport.finalMask
        muxFields = profile.transport.mux.flatMap(Self.encodeFields)
        socketOptions = profile.transport.socketOptions
        xrayAdvancedJSON = profile.xrayAdvanced?.jsonString ?? "{}"
    }

    var validation: ProfileEditorValidation {
        guard !trimmed(name).isEmpty else {
            return .invalid("Enter a name.")
        }
        guard !trimmed(host).isEmpty else {
            return .invalid("Enter a host.")
        }
        guard let portNumber = Int(trimmed(port)), (1 ... 65535).contains(portNumber) else {
            return .invalid("Port: use 1–65535.")
        }

        switch proto {
        case .vless:
            guard !trimmed(vlessUUID).isEmpty else { return .invalid("Enter a VLESS UUID.") }
            if let encryptionError = Self.vlessEncryptionValidationError(optional(vlessEncryption)) {
                return .invalid(encryptionError)
            }
        case .trojan:
            guard !trojanPassword.isEmpty else { return .invalid("Enter a Trojan password.") }
        case .hysteria2:
            guard !hysteriaPassword.isEmpty else { return .invalid("Enter a Hysteria2 password.") }
        case .tuic:
            return .invalid("Xray v26.6.27 does not support TUIC.")
        case .shadowsocks:
            guard !trimmed(shadowsocksMethod).isEmpty else { return .invalid("Enter a Shadowsocks method.") }
            guard !shadowsocksPassword.isEmpty else { return .invalid("Enter a Shadowsocks password.") }
            guard Self.shadowsocksMethods.contains(trimmed(shadowsocksMethod).lowercased()) else {
                return .invalid("Unsupported Shadowsocks cipher.")
            }
        case .vmess:
            guard !trimmed(vmessUUID).isEmpty else { return .invalid("Enter a VMess UUID.") }
            guard Int(trimmed(vmessAlterID)) == 0 else { return .invalid("VMess requires Alter ID 0 (AEAD).") }
            guard Self.vmessSecurityValues.contains(trimmed(vmessSecurity).lowercased()) else {
                return .invalid("VMess security: auto, aes-128-gcm, or chacha20-poly1305.")
            }
        case .http, .socks:
            break
        case .wireGuard:
            guard !trimmed(wireGuardPrivateKey).isEmpty else { return .invalid("Enter a WireGuard private key.") }
            guard !trimmed(wireGuardPeerPublicKey).isEmpty else { return .invalid("Enter a WireGuard peer public key.") }
            guard !list(from: wireGuardLocalAddresses).isEmpty else { return .invalid("Enter a WireGuard local address.") }
        case .anyTLS:
            return .invalid("Xray v26.6.27 does not support AnyTLS.")
        }

        if securityLayer == .tls, tlsAllowInsecure, trimmed(tlsPinnedCertificates).isEmpty {
            return .invalid("Insecure TLS blocked. Verify TLS or add a certificate pin.")
        }

        if securityLayer == .reality, trimmed(realityPublicKey).isEmpty {
            return .invalid("Enter a REALITY public key.")
        }
        if securityLayer == .reality, trimmed(realityServerName).isEmpty {
            return .invalid("Enter a REALITY SNI.")
        }
        if proto == .hysteria2, securityLayer != .tls {
            return .invalid("Hysteria2 requires TLS.")
        }
        if transportType == .quic {
            return .invalid("QUIC was removed. Use XHTTP stream-one.")
        }
        if securityLayer == .reality, ![.tcp, .xhttp, .grpc].contains(transportType) {
            return .invalid("Use RAW, XHTTP, or gRPC with REALITY.")
        }
        if proto == .hysteria2, !trimmed(hysteriaObfs).isEmpty, hysteriaObfsPassword.isEmpty {
            return .invalid("Enter the Hysteria2 obfs password.")
        }
        if transportType == .xhttp, !trimmed(xhttpMode).isEmpty,
           !["auto", "packet-up", "stream-up", "stream-one"].contains(trimmed(xhttpMode).lowercased())
        {
            return .invalid("XHTTP mode: auto, packet-up, stream-up, or stream-one.")
        }
        if proto == .hysteria2 {
            if let error = validateOptionalInteger(hysteriaHopInterval, label: "Hop interval (s)", range: 5 ... 3600) {
                return .invalid(error)
            }
            if let error = validateOptionalInteger(hysteriaUDPIdleTimeout, label: "UDP idle timeout (s)", range: 2 ... 600) {
                return .invalid(error)
            }
        }
        if proto == .wireGuard {
            if let error = validateOptionalInteger(wireGuardKeepAlive, label: "WireGuard keepalive (s)", range: 0 ... 65535) {
                return .invalid(error)
            }
            if let error = validateOptionalInteger(wireGuardMTU, label: "WireGuard MTU", range: 576 ... 1500) {
                return .invalid(error)
            }
            let reserved = integerList(from: wireGuardReserved)
            if !trimmed(wireGuardReserved).isEmpty,
               wireGuardReserved.split(separator: ",", omittingEmptySubsequences: false).count != 3 ||
               reserved.count != 3 || reserved.contains(where: { !(0 ... 255).contains($0) })
            {
                return .invalid("WireGuard reserved bytes: enter three values, 0–255.")
            }
        }
        let fieldGroups: [(String, JSONValue?)] = [
            (protocolDefinition ?? "HysteriaClientConfig", advancedValue(at: ["settings"])),
            (transportDefinition ?? "HysteriaConfig", advancedValue(at: ["streamSettings", transportSettingsKey])),
            ("TLSConfig", advancedValue(at: ["streamSettings", "tlsSettings"])),
            ("REALITYConfig", advancedValue(at: ["streamSettings", "realitySettings"])),
            ("SplitHTTPConfig", transportType == .xhttp ? xhttpExtra : nil),
            ("KCPConfig", transportType == .mKCP ? kcpFields : nil),
            ("MuxConfig", proto == .wireGuard ? nil : muxFields),
            ("MuxConfig", advancedValue(at: ["mux"])),
            ("FinalMask", proto == .wireGuard ? nil : finalMask),
            ("FinalMask", advancedValue(at: ["streamSettings", "finalmask"])),
            ("SocketConfig", proto == .wireGuard ? nil : socketOptions),
            ("SocketConfig", advancedValue(at: ["streamSettings", "sockopt"])),
            ("OutboundDetourConfig", advancedValue(at: [])),
        ]
        for (definition, value) in fieldGroups {
            if let error = XrayFormSchema.shared.validationError(definition: definition, value: value) {
                return .invalid(error)
            }
        }
        do {
            let advanced = try XrayAdvancedDocument(jsonString: xrayAdvancedJSON)
            let candidate = try makeProfile(advanced: advanced.isEmpty ? nil : advanced)
            if let issue = XrayConfigBuilder().validationIssues(
                profiles: [candidate],
                groups: [],
                selectedTarget: .profile(candidate.id),
                routingMode: .global,
                rules: [],
            ).first {
                return .invalid("\(issue.path): \(issue.message)")
            }
            return .valid(candidate)
        } catch {
            return .invalid(error.localizedDescription)
        }
    }

    private func makeProfile(advanced: XrayAdvancedDocument?) throws -> ProxyProfile {
        try ProxyProfile(
            id: id,
            name: trimmed(name),
            endpoint: proto == .wireGuard && wireGuardHasExplicitEndpoint
                ? Endpoint(host: trimmed(wireGuardFallbackHost), port: Int(trimmed(wireGuardFallbackPort)) ?? 0)
                : editedEndpoint,
            options: protocolOptions,
            security: securityOptions,
            transport: transportOptions,
            subscriptionID: subscriptionID,
            xrayAdvanced: advanced,
        )
    }

    private var editedEndpoint: Endpoint {
        Endpoint(host: trimmed(host), port: Int(trimmed(port)) ?? 0)
    }

    private var protocolOptions: ProtocolOptions {
        get throws {
            switch proto {
            case .vless:
                .vless(VLESSOptions(uuid: trimmed(vlessUUID), flow: optional(vlessFlow), encryption: optional(vlessEncryption)))
            case .trojan:
                .trojan(TrojanOptions(password: trojanPassword))
            case .hysteria2:
                .hysteria2(Hysteria2Options(
                    password: hysteriaPassword,
                    obfs: optional(hysteriaObfs),
                    obfsPassword: optionalCredential(hysteriaObfsPassword),
                    up: optional(hysteriaUp),
                    down: optional(hysteriaDown),
                    ports: optional(hysteriaPorts),
                    hopIntervalSeconds: Int(trimmed(hysteriaHopInterval)),
                    udpIdleTimeoutSeconds: Int(trimmed(hysteriaUDPIdleTimeout)),
                ))
            case .tuic:
                .tuic(TUICOptions(uuid: trimmed(tuicUUID), password: tuicPassword, congestionControl: optional(tuicCongestionControl)))
            case .shadowsocks:
                .shadowsocks(ShadowsocksOptions(method: trimmed(shadowsocksMethod), password: shadowsocksPassword))
            case .vmess:
                .vmess(VMessOptions(uuid: trimmed(vmessUUID), security: optional(vmessSecurity) ?? "auto", alterID: Int(trimmed(vmessAlterID)) ?? 0))
            case .http:
                .http(HTTPOptions(username: optionalCredential(httpUsername), password: optionalCredential(httpPassword)))
            case .socks:
                .socks(SOCKSOptions(username: optionalCredential(socksUsername), password: optionalCredential(socksPassword)))
            case .wireGuard:
                try wireGuardProtocolOptions
            case .anyTLS:
                .anyTLS(AnyTLSOptions(password: anyTLSPassword))
            }
        }
    }

    private var wireGuardProtocolOptions: ProtocolOptions {
        get throws {
            let publicKey = trimmed(wireGuardPeerPublicKey)
            let preSharedKey = optional(wireGuardPreSharedKey)
            let allowedIPs = optionalList(from: wireGuardAllowedIPs)
            let keepAlive = Int(trimmed(wireGuardKeepAlive))
            var peers = wireGuardPeers
            if peers?.isEmpty == false {
                if peers?[0].endpoint != nil {
                    peers?[0].endpoint = editedEndpoint
                }
                peers?[0].publicKey = publicKey
                peers?[0].preSharedKey = preSharedKey
                peers?[0].allowedIPs = allowedIPs
                peers?[0].keepAliveSeconds = keepAlive
            }
            if !extraWireGuardPeers.isEmpty || peers?.isEmpty == false {
                let first = peers?.first ?? WireGuardPeer(publicKey: publicKey, preSharedKey: preSharedKey, allowedIPs: allowedIPs, keepAliveSeconds: keepAlive)
                peers = try [first] + (extraWireGuardPeers.map { try $0.makePeer() })
            }
            return .wireGuard(WireGuardOptions(
                privateKey: trimmed(wireGuardPrivateKey),
                peerPublicKey: publicKey,
                preSharedKey: peers == nil ? preSharedKey : nil,
                localAddress: list(from: wireGuardLocalAddresses),
                allowedIPs: allowedIPs,
                reserved: trimmed(wireGuardReserved).isEmpty ? nil : integerList(from: wireGuardReserved).map(UInt8.init),
                keepAliveSeconds: keepAlive,
                mtu: Int(trimmed(wireGuardMTU)),
                domainStrategy: optional(wireGuardDomainStrategy),
                peers: peers,
            ))
        }
    }

    private var securityOptions: ProxySecurity {
        switch securityLayer {
        case .none:
            .none
        case .tls:
            .tls(TLSOptions(
                serverName: optional(tlsServerName),
                alpn: selectedALPN,
                allowInsecure: false,
                utlsFingerprint: optional(tlsFingerprint) ?? "chrome",
                pinnedPeerCertSHA256: optional(tlsPinnedCertificates),
                verifyPeerCertByName: optional(tlsVerifyNames),
                echConfigList: optional(tlsECHConfigList),
                curvePreferences: list(from: tlsCurves),
                minVersion: optional(tlsMinVersion),
                maxVersion: optional(tlsMaxVersion),
                cipherSuites: optional(tlsCipherSuites),
                enableSessionResumption: tlsSessionResumption,
            ))
        case .reality:
            .reality(
                RealityOptions(
                    publicKey: trimmed(realityPublicKey),
                    shortID: optional(realityShortID),
                    serverName: optional(realityServerName),
                    spiderX: optional(realitySpiderX),
                    mldsa65Verify: optional(realityMLDSA65Verify),
                    utlsFingerprint: optional(realityFingerprint) ?? "chrome",
                ),
                alpn: selectedALPN,
            )
        }
    }

    private var transportOptions: TransportOptions {
        get throws {
            // Keep inactive edits in the draft, not in the saved runtime config.
            guard proto != .wireGuard else { return .tcp }
            return try TransportOptions(
                type: transportType,
                path: optional(transportPath),
                host: optional(transportHost),
                serviceName: optional(transportServiceName),
                xhttpMode: transportType == .xhttp ? optional(xhttpMode) : nil,
                xhttpExtra: transportType == .xhttp ? xhttpExtra : nil,
                kcp: transportType == .mKCP ? Self.decodeFields(XrayKCPOptions.self, from: kcpFields) : nil,
                finalMask: finalMask,
                mux: Self.decodeFields(XrayMuxOptions.self, from: muxFields, defaults: Self.encodeFields(XrayMuxOptions())),
                socketOptions: socketOptions,
            )
        }
    }

    private static func encodeFields(_ value: some Encodable) -> JSONValue? {
        try? JSONDecoder().decode(JSONValue.self, from: JSONEncoder().encode(value))
    }

    private static func decodeFields<T: Decodable>(_ type: T.Type, from value: JSONValue?, defaults: JSONValue? = nil) throws -> T? {
        guard let value else { return nil }
        let merged: JSONValue = if let object = value.objectValue, let defaults = defaults?.objectValue {
            .object(defaults.merging(object) { _, value in value })
        } else {
            value
        }
        return try JSONDecoder().decode(type, from: JSONEncoder().encode(merged))
    }

    var hasValidAdvancedJSON: Bool {
        (try? XrayAdvancedDocument(jsonString: xrayAdvancedJSON)) != nil
    }

    func advancedValue(at path: [String]) -> JSONValue? {
        guard let document = try? XrayAdvancedDocument(jsonString: xrayAdvancedJSON) else { return nil }
        return path.reduce(Optional(JSONValue.object(document.values))) { $0?.objectValue?[$1] }
    }

    mutating func setAdvancedValue(_ value: JSONValue?, at path: [String]) {
        guard let document = try? XrayAdvancedDocument(jsonString: xrayAdvancedJSON) else { return }
        func replacing(_ current: JSONValue?, path: ArraySlice<String>) -> JSONValue? {
            guard let key = path.first else { return value }
            var object = current?.objectValue ?? [:]
            object[key] = replacing(object[key], path: path.dropFirst())
            return object.isEmpty ? nil : .object(object)
        }
        xrayAdvancedJSON = XrayAdvancedDocument(replacing(.object(document.values), path: path[...])?.objectValue ?? [:]).jsonString
    }

    var protocolDefinition: String? {
        switch proto {
        case .vless: "VLessOutboundConfig"
        case .trojan: "TrojanClientConfig"
        case .shadowsocks: "ShadowsocksClientConfig"
        case .vmess: "VMessOutboundConfig"
        case .http: "HTTPClientConfig"
        case .socks: "SocksClientConfig"
        case .hysteria2, .wireGuard, .tuic, .anyTLS: nil
        }
    }

    var transportDefinition: String? {
        switch transportType {
        case .tcp: "TCPConfig"
        case .websocket: "WebSocketConfig"
        case .grpc: "GRPCConfig"
        case .httpUpgrade: "HttpUpgradeConfig"
        case .xhttp: "SplitHTTPConfig"
        case .mKCP: "KCPConfig"
        case .hysteria, .quic: nil
        }
    }

    var transportSettingsKey: String {
        switch transportType {
        case .tcp: "rawSettings"
        case .websocket: "wsSettings"
        case .grpc: "grpcSettings"
        case .httpUpgrade: "httpupgradeSettings"
        case .xhttp: "xhttpSettings"
        case .mKCP: "kcpSettings"
        case .hysteria: "hysteriaSettings"
        case .quic: "quicSettings"
        }
    }

    var extraTransportKeys: Set<String> {
        let typedKeys: Set<String> = switch transportType {
        case .websocket, .httpUpgrade: ["host", "path"]
        case .grpc: ["serviceName", "authority", "initial_windows_size"]
        case .xhttp: ["host", "path", "mode"]
        case .mKCP: ["mtu", "maxSendingWindow"]
        default: []
        }
        return XrayConfigBuilder.editorTransportKeys(transportType).subtracting(typedKeys)
    }

    private func optionalCredential(_ value: String) -> String? {
        value.isEmpty ? nil : value
    }

    private var selectedALPN: [String] {
        // ponytail: comma-separated editing; use token rows if comma-bearing ALPNs need editing.
        // Untouched imported tokens remain byte-for-byte intact, even when a
        // token contains the editor's comma delimiter or whitespace.
        tlsALPN == importedALPN.joined(separator: ", ") ? importedALPN : list(from: tlsALPN)
    }

    private func optional(_ value: String) -> String? {
        let value = trimmed(value)
        return value.isEmpty ? nil : value
    }

    private func list(from value: String) -> [String] {
        value
            .split(separator: ",")
            .map { trimmed(String($0)) }
            .filter { !$0.isEmpty }
    }

    private func optionalList(from value: String) -> [String]? {
        let values = list(from: value)
        return values.isEmpty ? nil : values
    }

    private func integerList(from value: String) -> [Int] {
        value
            .split(separator: ",")
            .compactMap { Int(trimmed(String($0))) }
    }

    private func validateOptionalInteger(_ value: String, label: String, range: ClosedRange<Int>) -> String? {
        let value = trimmed(value)
        guard !value.isEmpty else { return nil }
        guard let number = Int(value), range.contains(number) else {
            return "\(label): use \(range.lowerBound)–\(range.upperBound)."
        }
        return nil
    }

    private static let vmessSecurityValues: Set<String> = [
        "auto", "aes-128-gcm", "chacha20-poly1305",
    ]

    private static let shadowsocksMethods: Set<String> = [
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
        "aes-128-gcm",
        "aes-256-gcm",
        "chacha20-poly1305",
        "chacha20-ietf-poly1305",
        "xchacha20-poly1305",
        "xchacha20-ietf-poly1305",
    ]

    private static func vlessEncryptionValidationError(_ value: String?) -> String? {
        guard let value, !value.isEmpty, value.lowercased() != "none" else { return nil }
        let blocks = value.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard blocks.count >= 5,
              blocks[0].lowercased() == "mlkem768x25519plus",
              ["native", "xorpub", "random"].contains(blocks[1].lowercased()),
              ["0rtt", "1rtt"].contains(blocks[2].lowercased())
        else {
            return "VLESS Encryption: use mlkem768x25519plus client syntax."
        }
        guard blocks.count <= 23 else {
            return "VLESS Encryption: max 16 padding directives and 4 auth keys."
        }
        return nil
    }

    private func trimmed(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
