import SwiftUI

/// Form for creating or editing a single proxy node. Works on a string-typed
/// draft and only produces a `ProxyProfile` when validation passes.
struct ProfileEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var draft: ProfileEditorDraft

    var onSave: (ProxyProfile) -> Void

    init(profile: ProxyProfile, onSave: @escaping (ProxyProfile) -> Void) {
        _draft = State(initialValue: ProfileEditorDraft(profile: profile))
        self.onSave = onSave
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Basics") {
                    ProfileTextField("Name", text: $draft.name, capitalization: .words, autocorrectionDisabled: false)
                    Picker("Protocol", selection: $draft.proto) {
                        ForEach(ProxyProtocol.allCases) { proto in
                            Text(proto.displayName).tag(proto)
                        }
                    }
                    ProfileTextField("Host", text: $draft.host)
                    ProfileTextField("Port", text: $draft.port, prompt: "443", keyboardType: .numberPad)
                }

                credentialsSection
                securitySection
                transportSection

                if let validationMessage = draft.validationMessage {
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
                        guard let profile = draft.profile else {
                            return
                        }
                        onSave(profile)
                        dismiss()
                    }
                    .disabled(draft.profile == nil)
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
                ProfileTextField("Encryption/Auth", text: $draft.vlessEncryption, prompt: "none", isSecure: true)
                if draft.hasVLESSEncryption {
                    Label("\(draft.vlessEncryptionAuthLabel) is saved for compatibility, but Hop's current sing-box/libbox engine cannot run non-none VLESS Encryption/Auth yet.", systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                }
            case .trojan:
                ProfileTextField("Password", text: $draft.trojanPassword, isSecure: true)
            case .hysteria2:
                ProfileTextField("Password", text: $draft.hysteriaPassword, isSecure: true)
                ProfileTextField("Obfuscation", text: $draft.hysteriaObfs, prompt: "salamander")
                ProfileTextField("Obfs Password", text: $draft.hysteriaObfsPassword, isSecure: true)
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
            case .anyTLS:
                ProfileTextField("Password", text: $draft.anyTLSPassword, isSecure: true)
            }
        }
    }

    private var securitySection: some View {
        Section("Security") {
            Picker("Security", selection: $draft.securityLayer) {
                ForEach(SecurityLayer.allCases) { layer in
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
                Toggle("Allow Insecure", isOn: $draft.tlsAllowInsecure)
                if draft.tlsAllowInsecure {
                    Label("Disables TLS certificate verification. Traffic to this server can be intercepted.", systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                }
            case .reality:
                ProfileTextField("Public Key", text: $draft.realityPublicKey)
                ProfileTextField("Short ID", text: $draft.realityShortID)
                ProfileTextField("SNI", text: $draft.realityServerName, prompt: "camouflage domain")
                ProfileTextField("SpiderX (spx)", text: $draft.realitySpiderX, prompt: "/")
                ProfileTextField("ML-DSA-65 Verify", text: $draft.realityMLDSA65Verify)
                if draft.hasRealityMLDSA65Verify {
                    Label("pqv / ML-DSA-65 is preserved in this profile, but Hop's bundled sing-box/libbox engine cannot enforce it yet.", systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                }
                MultiSelectMenu("ALPN", options: ProfileEditorChoices.alpn, selection: $draft.tlsALPN)
                UTLSFingerprintPicker(selection: $draft.realityFingerprint)
            }
        }
    }

    private var transportSection: some View {
        Section("Transport") {
            Picker("Type", selection: $draft.transportType) {
                ForEach(TransportType.allCases) { type in
                    Text(type.displayName).tag(type)
                }
            }

            switch draft.transportType {
            case .tcp, .quic:
                EmptyView()
            case .websocket, .httpUpgrade:
                ProfileTextField("Path", text: $draft.transportPath, prompt: "/")
                ProfileTextField("Host Header", text: $draft.transportHost)
            case .grpc:
                ProfileTextField("Service Name", text: $draft.transportServiceName)
            }
        }
    }
}

/// Trailing-aligned labeled text field shared by the profile, group, and
/// import forms.
struct ProfileTextField: View {
    var title: String
    @Binding var text: String
    var prompt: String
    var keyboardType: UIKeyboardType
    var capitalization: TextInputAutocapitalization
    var autocorrectionDisabled: Bool
    var isSecure: Bool

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
            field
                .multilineTextAlignment(.trailing)
                .keyboardType(keyboardType)
                .textInputAutocapitalization(capitalization)
                .autocorrectionDisabled(autocorrectionDisabled)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(maxWidth: .infinity, alignment: .trailing)
        }
    }

    /// Passwords and private keys render as `SecureField` so they stay masked
    /// on screen — and out of screenshots, screen recordings, screen sharing,
    /// and the keyboard's QuickType/learned-words cache.
    @ViewBuilder
    private var field: some View {
        if isSecure {
            SecureField(prompt, text: $text)
        } else {
            TextField(prompt, text: $text)
        }
    }
}

private struct UTLSFingerprintPicker: View {
    @Binding var selection: String

    var body: some View {
        Picker("uTLS Fingerprint", selection: $selection) {
            ForEach(options, id: \.self) { option in
                Text(ProfileEditorChoices.utlsFingerprintTitle(option)).tag(option)
            }
        }
    }

    private var options: [String] {
        let current = selection.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !current.isEmpty, !ProfileEditorChoices.utlsFingerprints.contains(current) else {
            return ProfileEditorChoices.utlsFingerprints
        }
        return [current] + ProfileEditorChoices.utlsFingerprints
    }
}

private struct MultiSelectMenu: View {
    var title: String
    var options: [String]
    @Binding var selection: Set<String>

    init(_ title: String, options: [String], selection: Binding<Set<String>>) {
        self.title = title
        self.options = options
        _selection = selection
    }

    var body: some View {
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

    private var summary: String {
        let selected = options.filter { selection.contains($0) }
        return selected.isEmpty ? "None" : selected.joined(separator: ", ")
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

private struct ProfileEditorDraft {
    var id: UUID
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
    var anyTLSPassword = ""

    var securityLayer: SecurityLayer
    var tlsServerName = ""
    var tlsALPN: Set<String> = []
    var tlsFingerprint = "chrome"
    var tlsAllowInsecure = false
    var realityPublicKey = ""
    var realityShortID = ""
    var realityServerName = ""
    var realitySpiderX = ""
    var realityMLDSA65Verify = ""
    var realityFingerprint = "chrome"

    var transportType: TransportType
    var transportPath = ""
    var transportHost = ""
    var transportServiceName = ""

    init(profile: ProxyProfile) {
        id = profile.id
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
            wireGuardPrivateKey = options.privateKey
            wireGuardPeerPublicKey = options.peerPublicKey
            wireGuardPreSharedKey = options.preSharedKey ?? ""
            wireGuardLocalAddresses = options.localAddress.joined(separator: ", ")
        case let .anyTLS(options):
            anyTLSPassword = options.password
        }

        if let tls = profile.security.tls {
            tlsServerName = tls.serverName ?? ""
            tlsALPN = Set(tls.alpn)
            tlsFingerprint = tls.utlsFingerprint ?? "chrome"
            tlsAllowInsecure = tls.allowInsecure
        }

        if let reality = profile.security.reality {
            realityPublicKey = reality.publicKey
            realityShortID = reality.shortID ?? ""
            realityServerName = reality.serverName ?? ""
            realitySpiderX = reality.spiderX ?? ""
            realityMLDSA65Verify = reality.mldsa65Verify ?? ""
            realityFingerprint = reality.utlsFingerprint
        }

        transportPath = profile.transport.path ?? ""
        transportHost = profile.transport.host ?? ""
        transportServiceName = profile.transport.serviceName ?? ""
    }

    var validationMessage: String? {
        guard !trimmed(name).isEmpty else {
            return "Name is required."
        }
        guard !trimmed(host).isEmpty else {
            return "Host is required."
        }
        guard let portNumber = Int(trimmed(port)), (1 ... 65535).contains(portNumber) else {
            return "Port must be between 1 and 65535."
        }

        switch proto {
        case .vless:
            guard !trimmed(vlessUUID).isEmpty else { return "VLESS UUID is required." }
        case .trojan:
            guard !trimmed(trojanPassword).isEmpty else { return "Trojan password is required." }
        case .hysteria2:
            guard !trimmed(hysteriaPassword).isEmpty else { return "Hysteria2 password is required." }
        case .tuic:
            guard !trimmed(tuicUUID).isEmpty else { return "TUIC UUID is required." }
            guard !trimmed(tuicPassword).isEmpty else { return "TUIC password is required." }
        case .shadowsocks:
            guard !trimmed(shadowsocksMethod).isEmpty else { return "Shadowsocks method is required." }
            guard !trimmed(shadowsocksPassword).isEmpty else { return "Shadowsocks password is required." }
        case .vmess:
            guard !trimmed(vmessUUID).isEmpty else { return "VMess UUID is required." }
            guard Int(trimmed(vmessAlterID)) != nil else { return "VMess Alter ID must be a number." }
        case .http, .socks:
            break
        case .wireGuard:
            guard !trimmed(wireGuardPrivateKey).isEmpty else { return "WireGuard private key is required." }
            guard !trimmed(wireGuardPeerPublicKey).isEmpty else { return "WireGuard peer public key is required." }
            guard !list(from: wireGuardLocalAddresses).isEmpty else { return "WireGuard local address is required." }
        case .anyTLS:
            guard !trimmed(anyTLSPassword).isEmpty else { return "AnyTLS password is required." }
        }

        if securityLayer == .reality, trimmed(realityPublicKey).isEmpty {
            return "REALITY public key is required."
        }
        if securityLayer == .reality, trimmed(realityServerName).isEmpty {
            return "REALITY requires an SNI — the camouflage domain the handshake presents."
        }
        // sing-box requires TLS for QUIC-based outbounds and the QUIC
        // transport; without this guard the engine rejects the whole config at
        // connect time with no actionable message.
        if proto == .tuic || proto == .hysteria2 || proto == .anyTLS, securityLayer == .none {
            return "\(proto.displayName) requires TLS or REALITY security."
        }
        if transportType == .quic, securityLayer == .none {
            return "QUIC transport requires TLS or REALITY security."
        }
        if proto == .hysteria2, !trimmed(hysteriaObfs).isEmpty, trimmed(hysteriaObfsPassword).isEmpty {
            return "Hysteria2 obfuscation requires an obfs password."
        }

        return nil
    }

    var profile: ProxyProfile? {
        guard validationMessage == nil, let portNumber = Int(trimmed(port)) else {
            return nil
        }

        return ProxyProfile(
            id: id,
            name: trimmed(name),
            endpoint: Endpoint(host: trimmed(host), port: portNumber),
            options: protocolOptions,
            security: securityOptions,
            transport: transportOptions,
        )
    }

    private var protocolOptions: ProtocolOptions {
        switch proto {
        case .vless:
            .vless(VLESSOptions(uuid: trimmed(vlessUUID), flow: optional(vlessFlow), encryption: optional(vlessEncryption)))
        case .trojan:
            .trojan(TrojanOptions(password: trimmed(trojanPassword)))
        case .hysteria2:
            .hysteria2(Hysteria2Options(password: trimmed(hysteriaPassword), obfs: optional(hysteriaObfs), obfsPassword: optional(hysteriaObfsPassword)))
        case .tuic:
            .tuic(TUICOptions(uuid: trimmed(tuicUUID), password: trimmed(tuicPassword), congestionControl: optional(tuicCongestionControl)))
        case .shadowsocks:
            .shadowsocks(ShadowsocksOptions(method: trimmed(shadowsocksMethod), password: trimmed(shadowsocksPassword)))
        case .vmess:
            .vmess(VMessOptions(uuid: trimmed(vmessUUID), security: trimmed(vmessSecurity).isEmpty ? "auto" : trimmed(vmessSecurity), alterID: Int(trimmed(vmessAlterID)) ?? 0))
        case .http:
            .http(HTTPOptions(username: optional(httpUsername), password: optional(httpPassword)))
        case .socks:
            .socks(SOCKSOptions(username: optional(socksUsername), password: optional(socksPassword)))
        case .wireGuard:
            .wireGuard(WireGuardOptions(privateKey: trimmed(wireGuardPrivateKey), peerPublicKey: trimmed(wireGuardPeerPublicKey), preSharedKey: optional(wireGuardPreSharedKey), localAddress: list(from: wireGuardLocalAddresses)))
        case .anyTLS:
            .anyTLS(AnyTLSOptions(password: trimmed(anyTLSPassword)))
        }
    }

    private var securityOptions: ProxySecurity {
        switch securityLayer {
        case .none:
            .none
        case .tls:
            .tls(TLSOptions(serverName: optional(tlsServerName), alpn: selectedALPN, allowInsecure: tlsAllowInsecure, utlsFingerprint: optional(tlsFingerprint) ?? "chrome"))
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
        )
    }

    private var selectedALPN: [String] {
        ProfileEditorChoices.alpn.filter { tlsALPN.contains($0) }
    }

    private func optional(_ value: String) -> String? {
        let value = trimmed(value)
        return value.isEmpty ? nil : value
    }

    var hasVLESSEncryption: Bool {
        VLESSOptions(uuid: "", flow: nil, encryption: vlessEncryption).normalizedEncryption != nil
    }

    var vlessEncryptionAuthLabel: String {
        VLESSOptions(uuid: "", flow: nil, encryption: vlessEncryption).encryptionAuthLabel
    }

    var hasRealityMLDSA65Verify: Bool {
        !trimmed(realityMLDSA65Verify).isEmpty
    }

    private func list(from value: String) -> [String] {
        value
            .split(separator: ",")
            .map { trimmed(String($0)) }
            .filter { !$0.isEmpty }
    }

    private func trimmed(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
