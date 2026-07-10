import SwiftUI

/// Form for creating or editing a proxy group: membership, default target,
/// and URL-test scheduling (clamped through `ImportPolicy` on save).
struct ProxyGroupEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(HopStore.self) private var store
    @State private var draft: ProxyGroupEditorDraft

    let onSave: (ProxyGroup) -> Void

    init(group: ProxyGroup, onSave: @escaping (ProxyGroup) -> Void) {
        _draft = State(initialValue: ProxyGroupEditorDraft(group: group))
        self.onSave = onSave
    }

    var body: some View {
        let selectableGroups = store.groups.filter { $0.id != draft.id }
        let savedGroup = draft.group

        NavigationStack {
            Form {
                Section("Basics") {
                    ProfileTextField("Name", text: $draft.name, capitalization: .words, autocorrectionDisabled: false)
                    Picker("Type", selection: $draft.type) {
                        Text("Manual Select").tag(ProxyGroupType.select)
                        Text("URL Test").tag(ProxyGroupType.urlTest)
                        if draft.type == .unsupported {
                            Text("Unsupported").tag(ProxyGroupType.unsupported)
                        }
                    }
                    Toggle("Enabled", isOn: $draft.isEnabled)
                }

                Section {
                    Toggle("Direct", isOn: memberBinding(for: .direct))
                    Toggle("Reject", isOn: memberBinding(for: .reject))

                    ForEach(store.profiles) { profile in
                        Toggle(profile.name, isOn: memberBinding(for: .profile(profile.id)))
                    }

                    ForEach(selectableGroups) { group in
                        Toggle(group.name, isOn: memberBinding(for: .group(group.id)))
                    }
                } header: {
                    Text("Members")
                } footer: {
                    Text("Review Direct and Reject alongside nodes and nested groups. Avoid circular group nesting.")
                }

                Section("Default") {
                    Picker("Default", selection: $draft.defaultTarget) {
                        Text("First Member").tag(OutboundTarget?.none)
                        ForEach(draft.members, id: \.id) { target in
                            Text(store.displayName(for: target)).tag(Optional(target))
                        }
                    }
                }

                if draft.type == .urlTest {
                    Section("URL Test") {
                        ProfileTextField("URL", text: $draft.url, prompt: "https://www.gstatic.com/generate_204")
                        ProfileTextField("Interval", text: $draft.intervalSeconds, prompt: "600", keyboardType: .numberPad)
                        ProfileTextField("Tolerance", text: $draft.toleranceMilliseconds, prompt: "50", keyboardType: .numberPad)
                    }
                }

                if let warning = draft.warning {
                    Section {
                        Text(warning)
                            .foregroundStyle(.orange)
                    }
                }
            }
            .navigationTitle("Edit Group")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        guard let group = savedGroup else {
                            return
                        }
                        onSave(group)
                        dismiss()
                    }
                    .disabled(savedGroup == nil)
                }
            }
        }
    }

    private func memberBinding(for target: OutboundTarget) -> Binding<Bool> {
        Binding {
            draft.members.contains(target)
        } set: { isSelected in
            if isSelected, !draft.members.contains(target) {
                draft.members.append(target)
            } else if !isSelected {
                draft.members.removeAll { $0 == target }
                if draft.defaultTarget == target {
                    draft.defaultTarget = nil
                }
            }
        }
    }
}

struct ProxyGroupEditorDraft {
    let id: UUID
    let subscriptionID: SubscriptionSource.ID?
    var name: String
    var type: ProxyGroupType
    var members: [OutboundTarget]
    var defaultTarget: OutboundTarget?
    var url: String
    var intervalSeconds: String
    var toleranceMilliseconds: String
    var isEnabled: Bool
    var importedType: String?
    var warning: String?
    var lastLatencyMilliseconds: Int?

    init(group: ProxyGroup) {
        id = group.id
        subscriptionID = group.subscriptionID
        name = group.name
        type = group.type
        members = group.members
        defaultTarget = group.defaultTarget
        url = group.testOptions.url
        intervalSeconds = String(group.testOptions.intervalSeconds)
        toleranceMilliseconds = String(group.testOptions.toleranceMilliseconds)
        isEnabled = group.isEnabled
        importedType = group.importedType
        warning = group.warning
        lastLatencyMilliseconds = group.lastLatencyMilliseconds
    }

    var group: ProxyGroup? {
        let trimmedName = trimmed(name)
        guard !trimmedName.isEmpty,
              !members.isEmpty,
              let interval = Int(trimmed(intervalSeconds)),
              let tolerance = Int(trimmed(toleranceMilliseconds))
        else {
            return nil
        }

        let trimmedURL = trimmed(url)

        return ProxyGroup(
            id: id,
            subscriptionID: subscriptionID,
            name: trimmedName,
            type: type,
            members: members,
            defaultTarget: defaultTarget,
            testOptions: ProxyGroupTestOptions(
                // Keep the editor in agreement with the import path and config
                // builder: a disallowed/empty probe URL falls back to the default
                // so the persisted state never holds an SSRF-style probe target.
                url: ImportPolicy.isAllowedProbeURL(trimmedURL) ? trimmedURL : ProxyGroupTestOptions.defaultURL,
                intervalSeconds: ImportPolicy.clampURLTestInterval(interval),
                toleranceMilliseconds: ImportPolicy.clampURLTestTolerance(tolerance),
            ),
            isEnabled: isEnabled,
            importedType: importedType,
            warning: warning,
            lastLatencyMilliseconds: lastLatencyMilliseconds,
        )
    }

    private func trimmed(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
