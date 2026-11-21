import SwiftUI

struct RulesView: View {
    @Environment(HopStore.self) private var store
    @State private var editor: ConfigurationEditorState?

    var body: some View {
        List {
            Section {
                if store.ruleConfigurations.isEmpty {
                    ContentUnavailableView("No Configurations", systemImage: "arrow.triangle.branch", description: Text("Tap + to add one."))
                } else {
                    ForEach(store.ruleConfigurations) { configuration in
                        Button {
                            store.selectRuleConfiguration(id: configuration.id)
                        } label: {
                            ConfigRow(configuration: configuration, isActive: configuration.id == store.activeRuleConfigurationID)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityAddTraits(configuration.id == store.activeRuleConfigurationID ? .isSelected : [])
                        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                            Button(role: .destructive) {
                                store.deleteRuleConfiguration(id: configuration.id)
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }

                            Button {
                                editor = .edit(configuration)
                            } label: {
                                Label("Edit", systemImage: "pencil")
                            }
                            .tint(.blue)
                        }
                    }
                }
            } header: {
                Text("Configurations")
            } footer: {
                Text("Tap to activate. Swipe left to edit or delete.")
            }
        }
        .navigationTitle("Rules")
        .navigationBarTitleDisplayMode(.inline)
        .sensoryFeedback(.selection, trigger: store.activeRuleConfigurationID)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    editor = .add
                } label: {
                    Label("Add Configuration", systemImage: "plus")
                }
            }
        }
        .sheet(item: $editor) { state in
            ConfigurationEditorView(configuration: state.configuration, isNew: state.isNew) { configuration in
                if state.isNew {
                    store.addRuleConfiguration(configuration)
                    return true
                } else {
                    return store.updateRuleConfiguration(configuration, ifUnchangedSince: state.configuration)
                }
            }
        }
    }
}

private struct ConfigRow: View {
    let configuration: RuleConfiguration
    let isActive: Bool

    var body: some View {
        let count = configuration.rules.count

        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Text(configuration.name)
                    .font(.body.weight(.semibold))
                    .lineLimit(1)
                Spacer()
                if isActive {
                    ActiveBadge()
                }
            }
            Text(count == 0 ? "No rules · uses active outbound" : "\(count) rule\(count == 1 ? "" : "s")")
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
        .animation(.snappy, value: isActive)
    }
}

private struct ConfigurationEditorState: Identifiable {
    let configuration: RuleConfiguration
    let isNew: Bool

    var id: RuleConfiguration.ID {
        configuration.id
    }

    static var add: ConfigurationEditorState {
        ConfigurationEditorState(configuration: RuleConfiguration(name: "New Configuration"), isNew: true)
    }

    static func edit(_ configuration: RuleConfiguration) -> ConfigurationEditorState {
        ConfigurationEditorState(configuration: configuration, isNew: false)
    }
}

private struct ConfigurationEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(HopStore.self) private var store
    @State private var draft: RuleConfiguration
    @State private var ruleEditor: RuleEditorState?
    @State private var editMode = EditMode.inactive
    @State private var showingConflict = false

    let isNew: Bool
    let onSave: (RuleConfiguration) -> Bool

    init(configuration: RuleConfiguration, isNew: Bool, onSave: @escaping (RuleConfiguration) -> Bool) {
        _draft = State(initialValue: configuration)
        self.isNew = isNew
        self.onSave = onSave
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Name") {
                    TextField("Configuration name", text: $draft.name)
                        .autocorrectionDisabled()
                }

                Section {
                    let movable = draft.rules.prefix { $0.kind != .final }
                    ForEach(movable) { rule in editableRow(rule) }
                        .onMove { source, destination in
                            draft.moveActiveRules(fromOffsets: source, toOffset: destination)
                        }
                    ForEach(draft.rules.dropFirst(movable.count)) { rule in
                        editableRow(rule)
                    }

                    Button {
                        ruleEditor = .add
                    } label: {
                        Label("Add Rule", systemImage: "plus")
                    }
                    .controlSize(.small)
                } header: {
                    HStack {
                        Text("Rules")
                        Spacer()
                        if editMode.isEditing || draft.rules.prefix(while: { $0.kind != .final }).count > 1 {
                            Button(editMode.isEditing ? "Done" : "Reorder") {
                                withAnimation { editMode = editMode.isEditing ? .inactive : .active }
                            }
                        }
                    }
                } footer: {
                    Text("The first matching rule wins. Unmatched traffic uses the Dashboard outbound.")
                }
            }
            .environment(\.editMode, $editMode)
            .navigationTitle(isNew ? "New Configuration" : "Edit Configuration")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }

                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        draft.name = draft.name.trimmingCharacters(in: .whitespacesAndNewlines)
                        if onSave(draft) {
                            dismiss()
                        } else {
                            showingConflict = true
                        }
                    }
                    .disabled(draft.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .sheet(item: $ruleEditor) { state in
                RuleEditorView(state: state, hasOtherFinal: draft.rules.contains { $0.kind == .final && $0.id != state.id }) { rule in
                    draft.saveRule(rule)
                }
            }
            .alert("Configuration changed or removed", isPresented: $showingConflict) {
                Button("OK") {}
            } message: {
                Text("Reopen the configuration to edit its current rules.")
            }
        }
    }

    private func editableRow(_ rule: RoutingRule) -> some View {
        Button {
            ruleEditor = .edit(rule)
        } label: {
            RuleRow(rule: rule, targetName: store.displayName(for: rule.target))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
            Button(role: .destructive) {
                draft.rules.removeAll { $0.id == rule.id }
            } label: {
                Label("Delete", systemImage: "trash")
            }
        }
    }
}

extension RuleConfiguration {
    /// Rows after a legacy Final are unreachable. Moving a rule must never activate them.
    mutating func moveActiveRules(fromOffsets offsets: IndexSet, toOffset destination: Int) {
        let end = rules.firstIndex { $0.kind == .final } ?? rules.endIndex
        guard offsets.allSatisfy((0 ..< end).contains), (0 ... end).contains(destination) else { return }
        rules.move(fromOffsets: offsets, toOffset: destination)
    }
}

private struct RuleRow: View {
    let rule: RoutingRule
    let targetName: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(rule.matchDescription)
                .font(.body.weight(.semibold))
                .lineLimit(1)
                .truncationMode(.middle)

            Text("\(rule.kind.displayName) -> \(targetName)")
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }
}

private struct RuleEditorState: Identifiable {
    let rule: RoutingRule
    let isNew: Bool

    var id: RoutingRule.ID {
        rule.id
    }

    static var add: RuleEditorState {
        RuleEditorState(
            rule: RoutingRule(kind: .domainSuffix, value: "", target: .selectedProxy),
            isNew: true,
        )
    }

    static func edit(_ rule: RoutingRule) -> RuleEditorState {
        RuleEditorState(rule: rule, isNew: false)
    }
}

private struct RuleEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(HopStore.self) private var store
    @State private var draft: RuleEditorDraft
    @State private var isSaving = false
    @State private var validationError: String?

    let state: RuleEditorState
    let hasOtherFinal: Bool
    let onSave: (RoutingRule) -> Void

    init(state: RuleEditorState, hasOtherFinal: Bool, onSave: @escaping (RoutingRule) -> Void) {
        self.state = state
        self.hasOtherFinal = hasOtherFinal
        self.onSave = onSave
        _draft = State(initialValue: RuleEditorDraft(rule: state.rule))
    }

    var body: some View {
        let enabledGroups = store.groups.filter(\.isEnabled)
        let ruleKinds = RoutingRuleKind.allCases.filter { kind in
            kind == draft.kind || (kind.isAvailableInXray && (kind != .final || !hasOtherFinal))
        }

        NavigationStack {
            Form {
                Section {
                    Picker("Type", selection: $draft.kind) {
                        ForEach(ruleKinds, id: \.self) { kind in
                            Text(kind.displayName).tag(kind)
                                .disabled(!kind.isAvailableInXray || (kind == .final && hasOtherFinal))
                        }
                    }
                    .onChange(of: draft.kind) { _, newKind in
                        draft.value = newKind.defaultValue
                    }

                    if draft.kind == .final {
                        LabeledContent("Match", value: draft.rule.matchDescription)
                    } else if draft.kind.isBoolean {
                        Picker("Match", selection: $draft.value) {
                            Text("Yes").tag("true")
                            if draft.value != "true" {
                                Text("Unsupported (\(draft.value))").tag(draft.value).disabled(true)
                            }
                        }
                    } else {
                        TextField(draft.kind.valuePrompt, text: $draft.value)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }

                    Picker("Route To", selection: $draft.target) {
                        Text("Active Outbound").tag(OutboundTarget.selectedProxy)
                        Text("Direct").tag(OutboundTarget.direct)
                        Text("Reject").tag(OutboundTarget.reject)

                        if !enabledGroups.isEmpty {
                            Section("Groups") {
                                ForEach(enabledGroups) { group in
                                    Text(group.name).tag(OutboundTarget.group(group.id))
                                }
                            }
                        }

                        if !store.profiles.isEmpty {
                            Section("Nodes") {
                                ForEach(store.profiles) { profile in
                                    Text(profile.name).tag(OutboundTarget.profile(profile.id))
                                }
                            }
                        }
                    }
                } header: {
                    Text("Rule")
                } footer: {
                    Text(draft.availabilityIssue(sniffTraffic: store.settings.sniffTraffic) ?? (draft.kind == .final && hasOtherFinal ? "Edit the existing Final rule to change the fallback." : draft.kind.footerText))
                }

                if let validationError {
                    Section {
                        Label(validationError, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .disabled(isSaving)
            .navigationTitle(state.isNew ? "Add Rule" : "Edit Rule")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                    .disabled(isSaving)
                }

                ToolbarItem(placement: .confirmationAction) {
                    Button(isSaving ? "Checking…" : "Save") {
                        let draft = draft
                        isSaving = true
                        validationError = nil
                        Task { @MainActor in
                            do {
                                try await draft.validate(settings: store.settings)
                                onSave(draft.rule)
                                dismiss()
                            } catch {
                                if case let XrayCoreClientError.validationFailed(code) = error, code == "invalid_config" {
                                    validationError = "Invalid rule value. Check the format."
                                } else {
                                    validationError = error.localizedDescription
                                }
                                isSaving = false
                            }
                        }
                    }
                    .disabled(!draft.isValid || draft.availabilityIssue(sniffTraffic: store.settings.sniffTraffic) != nil || isSaving || (draft.kind == .final && hasOtherFinal))
                }
            }
            .interactiveDismissDisabled(isSaving)
        }
    }
}

struct RuleEditorDraft {
    let id: RoutingRule.ID
    var kind: RoutingRuleKind
    var value: String
    var target: OutboundTarget

    init(rule: RoutingRule) {
        id = rule.id
        kind = rule.kind
        value = rule.value
        if kind.isBoolean, ["yes", "1", "true"].contains(value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()) {
            value = "true"
        }
        target = rule.target
    }

    var rule: RoutingRule {
        RoutingRule(
            id: id,
            kind: kind,
            value: trimmedValue,
            target: target,
        )
    }

    private var trimmedValue: String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var isValid: Bool {
        !trimmedValue.isEmpty
    }

    func availabilityIssue(sniffTraffic: Bool) -> String? {
        if !kind.isAvailableInXray {
            return "This Apple-specific matcher is unavailable in Xray. Choose a different rule type."
        }
        if kind.isBoolean, value != "true" {
            return "Xray can match private IPs only with Yes. Choose Yes or a different rule type."
        }
        if !sniffTraffic {
            return kind.sniffingRequirement
        }
        return nil
    }

    func validate(sniffTraffic: Bool = true) async throws {
        var settings = AppSettings.defaults
        settings.sniffTraffic = sniffTraffic
        try await validate(settings: settings)
    }

    func validate(settings currentSettings: AppSettings) async throws {
        // Validate the matcher independently of unrelated outbound credentials.
        var candidate = rule
        candidate.target = .direct
        var settings = AppSettings.defaults
        settings.sniffTraffic = currentSettings.sniffTraffic
        if let pool = currentSettings.xrayAdvanced?.values["fakeDns"] {
            settings.xrayAdvanced = XrayAdvancedDocument(["fakeDns": pool])
        }
        let json = try XrayConfigBuilder().build(
            profiles: [], groups: [], selectedTarget: .direct,
            routingMode: .rule, rules: [candidate], settings: settings,
        )
        try await XrayCoreClient.validate(configJSON: json)
    }
}

#Preview {
    NavigationStack {
        RulesView()
    }
    .environment(HopStore.preview)
}
