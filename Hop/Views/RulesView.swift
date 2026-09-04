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
                } else {
                    store.updateRuleConfiguration(configuration)
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

    let isNew: Bool
    let onSave: (RuleConfiguration) -> Void

    init(configuration: RuleConfiguration, isNew: Bool, onSave: @escaping (RuleConfiguration) -> Void) {
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
                    ForEach(draft.rules) { rule in
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

                    Button {
                        ruleEditor = .add
                    } label: {
                        Label("Add Rule", systemImage: "plus")
                    }
                    .controlSize(.small)
                } header: {
                    Text("Rules")
                } footer: {
                    Text("Unmatched traffic uses the Dashboard outbound.")
                }
            }
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
                        onSave(draft)
                        dismiss()
                    }
                    .disabled(draft.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .sheet(item: $ruleEditor) { state in
                RuleEditorView(state: state) { rule in
                    draft.saveRule(rule)
                }
            }
        }
    }
}

private struct RuleRow: View {
    let rule: RoutingRule
    let targetName: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(rule.value)
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
    let onSave: (RoutingRule) -> Void

    init(state: RuleEditorState, onSave: @escaping (RoutingRule) -> Void) {
        self.state = state
        self.onSave = onSave
        _draft = State(initialValue: RuleEditorDraft(rule: state.rule))
    }

    var body: some View {
        let enabledGroups = store.groups.filter(\.isEnabled)

        NavigationStack {
            Form {
                Section {
                    Picker("Type", selection: $draft.kind) {
                        ForEach(RoutingRuleKind.allCases, id: \.self) { kind in
                            Text(kind.displayName).tag(kind)
                        }
                    }
                    .onChange(of: draft.kind) { _, newKind in
                        draft.value = newKind.defaultValue
                    }

                    if draft.kind.isBoolean {
                        Picker("Match", selection: $draft.value) {
                            Text("Yes").tag("true")
                            Text("No").tag("false")
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
                    Text(draft.kind.footerText)
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
                                try await draft.validate()
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
                    .disabled(!draft.isValid || isSaving)
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

    func validate() async throws {
        // Validate the matcher independently of unrelated outbound credentials.
        var candidate = rule
        candidate.target = .direct
        let json = try XrayConfigBuilder().build(
            profiles: [], groups: [], selectedTarget: .direct,
            routingMode: .rule, rules: [candidate],
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
