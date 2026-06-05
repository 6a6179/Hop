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
    var configuration: RuleConfiguration
    var isActive: Bool

    var body: some View {
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
            Text(summary)
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
        .animation(.snappy, value: isActive)
    }

    private var summary: String {
        let count = configuration.rules.count
        return count == 0 ? "No rules · proxies all matched traffic" : "\(count) rule\(count == 1 ? "" : "s")"
    }
}

private struct ConfigurationEditorState: Identifiable {
    var id: UUID
    var configuration: RuleConfiguration
    var isNew: Bool

    static var add: ConfigurationEditorState {
        ConfigurationEditorState(id: UUID(), configuration: RuleConfiguration(name: "New Configuration"), isNew: true)
    }

    static func edit(_ configuration: RuleConfiguration) -> ConfigurationEditorState {
        ConfigurationEditorState(id: configuration.id, configuration: configuration, isNew: false)
    }
}

private struct ConfigurationEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(HopStore.self) private var store
    @State private var draft: RuleConfiguration
    @State private var ruleEditor: RuleEditorState?

    let isNew: Bool
    var onSave: (RuleConfiguration) -> Void

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

                    Button {
                        ruleEditor = .add
                    } label: {
                        Label("Add Rule", systemImage: "plus")
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
    var rule: RoutingRule
    var targetName: String

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
    var id: UUID
    var rule: RoutingRule
    var isNew: Bool

    static var add: RuleEditorState {
        RuleEditorState(
            id: UUID(),
            rule: RoutingRule(kind: .domainSuffix, value: "", target: .selectedProxy),
            isNew: true,
        )
    }

    static func edit(_ rule: RoutingRule) -> RuleEditorState {
        RuleEditorState(id: rule.id, rule: rule, isNew: false)
    }
}

private struct RuleEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(HopStore.self) private var store
    @State private var draft: RuleEditorDraft

    var state: RuleEditorState
    var onSave: (RoutingRule) -> Void

    init(state: RuleEditorState, onSave: @escaping (RoutingRule) -> Void) {
        self.state = state
        self.onSave = onSave
        _draft = State(initialValue: RuleEditorDraft(rule: state.rule))
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Type", selection: $draft.kind) {
                        ForEach(RoutingRuleKind.allCases) { kind in
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

                        if !store.groups.isEmpty {
                            Section("Groups") {
                                ForEach(store.groups.filter(\.isEnabled)) { group in
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
    var id: RoutingRule.ID
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
            value: value.trimmingCharacters(in: .whitespacesAndNewlines),
            target: target,
        )
    }

    var isValid: Bool {
        !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}

#Preview {
    NavigationStack {
        RulesView()
    }
    .environment(HopStore.preview)
}
