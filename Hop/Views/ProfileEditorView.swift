import SwiftUI

/// Form for creating or editing a single proxy node. Works on a string-typed
/// draft and only produces a `ProxyProfile` when validation passes.
struct ProfileEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var draft: ProfileEditorDraft

    let onSave: (ProxyProfile) -> Void

    init(profile: ProxyProfile, onSave: @escaping (ProxyProfile) -> Void) {
        _draft = State(initialValue: ProfileEditorDraft(profile: profile))
        self.onSave = onSave
    }

    var body: some View {
        let validation = draft.validation

        NavigationStack {
            Form {
                Section("Basics") {
                    ProfileTextField("Name", text: $draft.name, capitalization: .words, autocorrectionDisabled: false)
                    Picker("Protocol", selection: $draft.proto) {
                        ForEach(ProfileEditorChoices.supportedProtocols, id: \.self) { proto in
                            Text(proto.displayName).tag(proto)
                        }
                    }
                    ProfileTextField("Host", text: $draft.host)
                    ProfileTextField("Port", text: $draft.port, prompt: "443", keyboardType: .numberPad)
                }

                credentialsSection
                securitySection
                transportSection

                Section {
                    TextEditor(text: $draft.xrayAdvancedJSON)
                        .font(.system(.caption, design: .monospaced))
                        .frame(minHeight: 140)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                } header: {
                    Text("Advanced Xray JSON")
                } footer: {
                    Text("Optional client-only overrides for the pinned v26.6.27 schema. Typed fields, listeners, APIs, file paths, and un-tokenized secrets are rejected.")
                }

                if let validationMessage = validation.message {
                    Section {
                        Label(validationMessage, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                }
            }
            .navigationTitle("Edit Profile")
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
                ProfileTextField("Upload Rate", text: $draft.hysteriaUp, prompt: "20 mbps")
                ProfileTextField("Download Rate", text: $draft.hysteriaDown, prompt: "100 mbps")
                ProfileTextField("Port Hopping", text: $draft.hysteriaPorts, prompt: "20000-50000")
                ProfileTextField("Hop Interval", text: $draft.hysteriaHopInterval, prompt: "30", keyboardType: .numberPad)
                ProfileTextField("UDP Idle Timeout", text: $draft.hysteriaUDPIdleTimeout, prompt: "60", keyboardType: .numberPad)
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
                ProfileTextField("Alter ID", text: $draft.vmessAlterID, prompt: "0", keyboardType: .numberPad)
            case .http:
                ProfileTextField("Username", text: $draft.httpUsername)
                ProfileTextField("Password", text: $draft.httpPassword, isSecure: true)
            case .socks:
                ProfileTextField("Username", text: $draft.socksUsername)
                ProfileTextField("Password", text: $draft.socksPassword, isSecure: true)
            case .wireGuard:
                ProfileTextField("Private Key", text: $draft.wireGuardPrivateKey, isSecure: true)
                ProfileTextField("Peer Public Key", text: $draft.wireGuardPeerPublicKey)
                ProfileTextField("Pre-Shared Key", text: $draft.wireGuardPreSharedKey, prompt: "optional", isSecure: true)
                ProfileTextField("Local Addresses", text: $draft.wireGuardLocalAddresses, prompt: "10.0.0.2/32, fd00::2/128")
                ProfileTextField("Allowed IPs", text: $draft.wireGuardAllowedIPs, prompt: "0.0.0.0/0, ::/0")
                ProfileTextField("Reserved Bytes", text: $draft.wireGuardReserved, prompt: "0, 0, 0")
                ProfileTextField("Keepalive", text: $draft.wireGuardKeepAlive, prompt: "25", keyboardType: .numberPad)
                ProfileTextField("MTU", text: $draft.wireGuardMTU, prompt: "1280", keyboardType: .numberPad)
                ProfileTextField("Domain Strategy", text: $draft.wireGuardDomainStrategy, prompt: "ForceIP")
            case .anyTLS:
                ProfileTextField("Password", text: $draft.anyTLSPassword, isSecure: true)
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
                Label("No TLS or REALITY will be configured.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.secondary)
            case .tls:
                ProfileTextField("SNI", text: $draft.tlsServerName, prompt: "example.com")
                MultiSelectMenu("ALPN", options: ProfileEditorChoices.alpn, selection: $draft.tlsALPN)
                UTLSFingerprintPicker(selection: $draft.tlsFingerprint)
                ProfileTextField("Certificate SHA-256 Pins", text: $draft.tlsPinnedCertificates, prompt: "hex, comma-separated")
                ProfileTextField("Verify Certificate Names", text: $draft.tlsVerifyNames, prompt: "example.com")
                ProfileTextField("ECH Config", text: $draft.tlsECHConfigList, prompt: "inline base64", isSecure: true)
                ProfileTextField("TLS Curves", text: $draft.tlsCurves, prompt: "X25519MLKEM768")
                ProfileTextField("Minimum TLS", text: $draft.tlsMinVersion, prompt: "1.2")
                ProfileTextField("Maximum TLS", text: $draft.tlsMaxVersion, prompt: "1.3")
                ProfileTextField("Cipher Suites", text: $draft.tlsCipherSuites, prompt: "optional")
                Toggle("Session Resumption", isOn: $draft.tlsSessionResumption)
                if draft.tlsAllowInsecure {
                    Label("This legacy node used allowInsecure, which Xray rejects. Choose normal certificate validation or add a certificate pin, then save.", systemImage: "exclamationmark.triangle.fill")
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
                ProfileTextField("ML-DSA-65 Verify Key", text: $draft.realityMLDSA65Verify, prompt: "pqv", isSecure: true)
                Text("When supplied, ML-DSA-65 verification is enforced. REALITY still negotiates its supported hybrid key exchange; this setting does not force a PQ-only exchange.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                MultiSelectMenu("ALPN", options: ProfileEditorChoices.alpn, selection: $draft.tlsALPN)
                UTLSFingerprintPicker(selection: $draft.realityFingerprint)
            }
        }
    }

    private var transportSection: some View {
        Section("Transport") {
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
            case .xhttp:
                ProfileTextField("Path", text: $draft.transportPath, prompt: "/")
                ProfileTextField("Host", text: $draft.transportHost)
                ProfileTextField("Mode", text: $draft.xhttpMode, prompt: "auto")
            }
        }
    }
}

/// Trailing-aligned labeled text field shared by the profile, group, and
/// import forms.
struct ProfileTextField: View {
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
        // A plain HStack, not LabeledContent: LabeledContent wraps the value
        // onto its own full-width line when label + value don't fit, so long
        // values (hosts, keys) made rows grow to two lines. Here the row is
        // always one line — the label keeps its natural size and the field
        // squeezes and truncates in the middle instead.
        HStack(spacing: 12) {
            Text(title)
                .fixedSize(horizontal: true, vertical: false)

            // Passwords and private keys render as `SecureField` so they stay masked.
            Group {
                if isSecure {
                    SecureField(prompt, text: $text)
                } else {
                    TextField(prompt, text: $text)
                }
            }
            .multilineTextAlignment(.trailing)
            .keyboardType(keyboardType)
            .textInputAutocapitalization(capitalization)
            .autocorrectionDisabled(autocorrectionDisabled)
            .lineLimit(1)
            .truncationMode(.middle)
            .frame(maxWidth: .infinity, alignment: .trailing)
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

private struct MultiSelectMenu: View {
    let title: String
    let options: [String]
    @Binding var selection: Set<String>

    init(_ title: String, options: [String], selection: Binding<Set<String>>) {
        self.title = title
        self.options = options
        _selection = selection
    }

    var body: some View {
        let selected = options.filter { selection.contains($0) }
        let summary = selected.isEmpty ? "None" : selected.joined(separator: ", ")

        Menu {
            ForEach(options, id: \.self) { option in
                Toggle(option, isOn: binding(for: option))
            }
        } label: {
            LabeledContent(title) {
                HStack(spacing: 4) {
                    Text(summary)
                    Image(systemName: "chevron.up.chevron.down")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .buttonStyle(.plain)
    }

    private func binding(for option: String) -> Binding<Bool> {
        Binding {
            selection.contains(option)
        } set: { isSelected in
            if isSelected {
                selection.insert(option)
            } else {
                selection.remove(option)
            }
        }
    }
}

private enum ProfileEditorChoices {
    static let supportedProtocols = ProxyProtocol.allCases.filter {
        $0 != .tuic && $0 != .anyTLS
    }

    static let supportedTransports = TransportType.allCases.filter { $0 != .quic }

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

    static let alpn = [
        "h2",
        "http/1.1",
        "h3",
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

private struct ProfileEditorValidation {
    let profile: ProxyProfile?
    let message: String?

    static func valid(_ profile: ProxyProfile) -> Self {
        Self(profile: profile, message: nil)
    }

    static func invalid(_ message: String) -> Self {
        Self(profile: nil, message: message)
    }
}

private struct ProfileEditorDraft {
    let id: UUID
    let subscriptionID: UUID?
    var name: String
    var proto: ProxyProtocol
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
    /// Extra imported peers are not exposed by the compact editor yet, but
    /// must survive edits. The existing fields edit only the effective first peer.
    var wireGuardPeers: [WireGuardPeer]?
    var anyTLSPassword = ""

    var securityLayer: SecurityLayer
    var tlsServerName = ""
    var tlsALPN: Set<String> = []
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
    var kcpOptions: XrayKCPOptions?
    var finalMask: JSONValue?
    var muxOptions: XrayMuxOptions?
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
        case let .anyTLS(options):
            anyTLSPassword = options.password
        }

        if let tls = profile.security.tls {
            tlsServerName = tls.serverName ?? ""
            tlsALPN = Set(tls.alpn)
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
        kcpOptions = profile.transport.kcp
        finalMask = profile.transport.finalMask
        muxOptions = profile.transport.mux
        socketOptions = profile.transport.socketOptions
        xrayAdvancedJSON = profile.xrayAdvanced?.jsonString ?? "{}"
    }

    var validation: ProfileEditorValidation {
        guard !trimmed(name).isEmpty else {
            return .invalid("Name is required.")
        }
        guard !trimmed(host).isEmpty else {
            return .invalid("Host is required.")
        }
        guard let portNumber = Int(trimmed(port)), (1 ... 65535).contains(portNumber) else {
            return .invalid("Port must be between 1 and 65535.")
        }

        switch proto {
        case .vless:
            guard !trimmed(vlessUUID).isEmpty else { return .invalid("VLESS UUID is required.") }
            if let encryptionError = Self.vlessEncryptionValidationError(optional(vlessEncryption)) {
                return .invalid(encryptionError)
            }
        case .trojan:
            guard !trimmed(trojanPassword).isEmpty else { return .invalid("Trojan password is required.") }
        case .hysteria2:
            guard !trimmed(hysteriaPassword).isEmpty else { return .invalid("Hysteria2 password is required.") }
        case .tuic:
            return .invalid("TUIC is not supported by Xray-core v26.6.27.")
        case .shadowsocks:
            guard !trimmed(shadowsocksMethod).isEmpty else { return .invalid("Shadowsocks method is required.") }
            guard !trimmed(shadowsocksPassword).isEmpty else { return .invalid("Shadowsocks password is required.") }
            guard Self.shadowsocksMethods.contains(trimmed(shadowsocksMethod).lowercased()) else {
                return .invalid("This Shadowsocks cipher is not supported by the pinned Xray engine.")
            }
        case .vmess:
            guard !trimmed(vmessUUID).isEmpty else { return .invalid("VMess UUID is required.") }
            guard Int(trimmed(vmessAlterID)) == 0 else { return .invalid("Xray requires VMess Alter ID 0 (AEAD).") }
            guard Self.vmessSecurityValues.contains(trimmed(vmessSecurity).lowercased()) else {
                return .invalid("VMess security must be auto, aes-128-gcm, or chacha20-poly1305.")
            }
        case .http, .socks:
            break
        case .wireGuard:
            guard !trimmed(wireGuardPrivateKey).isEmpty else { return .invalid("WireGuard private key is required.") }
            guard !trimmed(wireGuardPeerPublicKey).isEmpty else { return .invalid("WireGuard peer public key is required.") }
            guard !list(from: wireGuardLocalAddresses).isEmpty else { return .invalid("WireGuard local address is required.") }
        case .anyTLS:
            return .invalid("AnyTLS is not supported by Xray-core v26.6.27.")
        }

        if tlsAllowInsecure {
            return .invalid("Xray rejects allowInsecure. Use verified TLS or add a certificate pin.")
        }

        if securityLayer == .reality, trimmed(realityPublicKey).isEmpty {
            return .invalid("REALITY public key is required.")
        }
        if securityLayer == .reality, trimmed(realityServerName).isEmpty {
            return .invalid("REALITY requires an SNI — the camouflage domain the handshake presents.")
        }
        if proto == .hysteria2, securityLayer != .tls {
            return .invalid("Hysteria2 requires TLS security.")
        }
        if transportType == .quic {
            return .invalid("Legacy QUIC transport was removed from Xray; use XHTTP stream-one instead.")
        }
        if securityLayer == .reality, ![.tcp, .xhttp, .grpc].contains(transportType) {
            return .invalid("REALITY is supported only with RAW, XHTTP, or gRPC.")
        }
        if proto == .hysteria2, !trimmed(hysteriaObfs).isEmpty, trimmed(hysteriaObfsPassword).isEmpty {
            return .invalid("Hysteria2 obfuscation requires an obfs password.")
        }
        if !trimmed(xhttpMode).isEmpty,
           !["auto", "packet-up", "stream-up", "stream-one"].contains(trimmed(xhttpMode).lowercased())
        {
            return .invalid("XHTTP mode must be auto, packet-up, stream-up, or stream-one.")
        }
        if let error = validateOptionalInteger(hysteriaHopInterval, label: "Hop interval", range: 5 ... 3600) {
            return .invalid(error)
        }
        if let error = validateOptionalInteger(hysteriaUDPIdleTimeout, label: "UDP idle timeout", range: 1 ... 3600) {
            return .invalid(error)
        }
        if let error = validateOptionalInteger(wireGuardKeepAlive, label: "WireGuard keepalive", range: 0 ... 65535) {
            return .invalid(error)
        }
        if let error = validateOptionalInteger(wireGuardMTU, label: "WireGuard MTU", range: 576 ... 9000) {
            return .invalid(error)
        }
        let reserved = integerList(from: wireGuardReserved)
        if !trimmed(wireGuardReserved).isEmpty,
           reserved.count != 3 || reserved.contains(where: { !(0 ... 255).contains($0) })
        {
            return .invalid("WireGuard reserved bytes must be three values from 0 to 255.")
        }
        do {
            let advanced = try XrayAdvancedDocument(jsonString: xrayAdvancedJSON)
            let candidate = makeProfile(advanced: advanced.isEmpty ? nil : advanced)
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

    private func makeProfile(advanced: XrayAdvancedDocument?) -> ProxyProfile {
        ProxyProfile(
            id: id,
            name: trimmed(name),
            endpoint: Endpoint(host: trimmed(host), port: Int(trimmed(port)) ?? 0),
            options: protocolOptions,
            security: securityOptions,
            transport: transportOptions,
            subscriptionID: subscriptionID,
            xrayAdvanced: advanced,
        )
    }

    private var protocolOptions: ProtocolOptions {
        switch proto {
        case .vless:
            .vless(VLESSOptions(uuid: trimmed(vlessUUID), flow: optional(vlessFlow), encryption: optional(vlessEncryption)))
        case .trojan:
            .trojan(TrojanOptions(password: trimmed(trojanPassword)))
        case .hysteria2:
            .hysteria2(Hysteria2Options(
                password: trimmed(hysteriaPassword),
                obfs: optional(hysteriaObfs),
                obfsPassword: optional(hysteriaObfsPassword),
                up: optional(hysteriaUp),
                down: optional(hysteriaDown),
                ports: optional(hysteriaPorts),
                hopIntervalSeconds: Int(trimmed(hysteriaHopInterval)),
                udpIdleTimeoutSeconds: Int(trimmed(hysteriaUDPIdleTimeout)),
            ))
        case .tuic:
            .tuic(TUICOptions(uuid: trimmed(tuicUUID), password: trimmed(tuicPassword), congestionControl: optional(tuicCongestionControl)))
        case .shadowsocks:
            .shadowsocks(ShadowsocksOptions(method: trimmed(shadowsocksMethod), password: trimmed(shadowsocksPassword)))
        case .vmess:
            .vmess(VMessOptions(uuid: trimmed(vmessUUID), security: optional(vmessSecurity) ?? "auto", alterID: Int(trimmed(vmessAlterID)) ?? 0))
        case .http:
            .http(HTTPOptions(username: optional(httpUsername), password: optional(httpPassword)))
        case .socks:
            .socks(SOCKSOptions(username: optional(socksUsername), password: optional(socksPassword)))
        case .wireGuard:
            wireGuardProtocolOptions
        case .anyTLS:
            .anyTLS(AnyTLSOptions(password: trimmed(anyTLSPassword)))
        }
    }

    private var wireGuardProtocolOptions: ProtocolOptions {
        let publicKey = trimmed(wireGuardPeerPublicKey)
        let preSharedKey = optional(wireGuardPreSharedKey)
        let allowedIPs = optionalList(from: wireGuardAllowedIPs)
        let keepAlive = Int(trimmed(wireGuardKeepAlive))
        var peers = wireGuardPeers
        if peers?.isEmpty == false {
            peers?[0].publicKey = publicKey
            peers?[0].preSharedKey = preSharedKey
            peers?[0].allowedIPs = allowedIPs
            peers?[0].keepAliveSeconds = keepAlive
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
        TransportOptions(
            type: transportType,
            path: optional(transportPath),
            host: optional(transportHost),
            serviceName: optional(transportServiceName),
            xhttpMode: optional(xhttpMode),
            xhttpExtra: xhttpExtra,
            kcp: kcpOptions,
            finalMask: finalMask,
            mux: muxOptions,
            socketOptions: socketOptions,
        )
    }

    private var selectedALPN: [String] {
        ProfileEditorChoices.alpn.filter { tlsALPN.contains($0) }
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
            return "\(label) must be between \(range.lowerBound) and \(range.upperBound)."
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
            return "VLESS Encryption must use the Xray mlkem768x25519plus client grammar."
        }
        guard blocks.count <= 23 else {
            return "VLESS Encryption exceeds the iOS limit of 16 padding directives and 4 authentication keys."
        }
        return nil
    }

    private func trimmed(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
