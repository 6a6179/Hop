import SwiftUI

struct RulesView: View {
    @Environment(HopStore.self) private var store
    @State private var editor: ConfigurationEditorState?

    var body: some View {
        List {
            Section {
                if store.ruleConfigurations.isEmpty {
                    ContentUnavailableView("No Configurations", systemImage: "arrow.triangle.branch", description: Text("Add a routing configuration with the + button."))
                } else {
                    ForEach(store.ruleConfigurations) { configuration in
                        ConfigRow(configuration: configuration, isActive: configuration.id == store.activeRuleConfigurationID)
                            .contentShape(Rectangle())
                            .onTapGesture {
                                store.selectRuleConfiguration(id: configuration.id)
                            }
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
                Text("Tap a configuration to make it active. Swipe left to edit or delete. China and Iran are generated for you. Pick Global/Direct routing on the Dashboard.")
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
                        .labelStyle(.iconOnly)
                }
                .buttonStyle(.glass)
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
            Text(count == 0 ? "No rules · proxies all matched traffic" : "\(count) rule\(count == 1 ? "" : "s")")
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
                        RuleRow(rule: rule, targetName: store.displayName(for: rule.target))
                            .contentShape(Rectangle())
                            .onTapGesture {
                                ruleEditor = .edit(rule)
                            }
                            .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                                Button(role: .destructive) {
                                    draft.rules.removeAll { $0.id == rule.id }
                                } label: {
                                    Label("Delete", systemImage: "trash")
                                }
                            }
                    }

                    Button("Add Rule") {
                        ruleEditor = .add
                    }
                } header: {
                    Text("Rules")
                } footer: {
                    Text("Unmatched traffic uses the outbound selected on the Dashboard.")
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
                    if let index = draft.rules.firstIndex(where: { $0.id == rule.id }) {
                        draft.rules[index] = rule
                    } else {
                        draft.rules.append(rule)
                    }
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
            }
            .navigationTitle(state.isNew ? "Add Rule" : "Edit Rule")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }

                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        onSave(draft.rule)
                        dismiss()
                    }
                    .disabled(!draft.isValid)
                }
            }
        }
    }
}

private struct RuleEditorDraft {
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
}

#Preview {
    NavigationStack {
        RulesView()
    }
    .environment(HopStore.preview)
}
