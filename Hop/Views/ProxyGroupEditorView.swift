import SwiftUI

/// Form for creating or editing a proxy group: membership, default target,
/// and URL-test scheduling (clamped through `ImportPolicy` on save).
struct ProxyGroupEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(HopStore.self) private var store
    @State private var draft: ProxyGroupEditorDraft
    @State private var isSaving = false
    @State private var validationError: String?

    let onSave: (ProxyGroup) -> Void

    init(group: ProxyGroup, onSave: @escaping (ProxyGroup) -> Void) {
        _draft = State(initialValue: ProxyGroupEditorDraft(group: group))
        self.onSave = onSave
    }

    var body: some View {
        let selectableGroups = store.groups.filter { group in
            group.id != draft.id && (draft.type != .urlTest || (group.isEnabled && group.type == .select) || draft.members.contains(.group(group.id)))
        }

        NavigationStack {
            Form {
                Section("Basics") {
                    ProfileTextField("Name", text: $draft.name, capitalization: .words, autocorrectionDisabled: false)
                    Picker("Type", selection: $draft.type) {
                        Text("Manual").tag(ProxyGroupType.select)
                        Text("URL Test").tag(ProxyGroupType.urlTest)
                        if draft.type == .unsupported {
                            Text("Unsupported").tag(ProxyGroupType.unsupported)
                        }
                    }
                    Toggle("Enabled", isOn: $draft.isEnabled)
                }

                Section {
                    if draft.type != .urlTest || draft.members.contains(.direct) {
                        Toggle("Direct", isOn: memberBinding(for: .direct))
                    }
                    if draft.type != .urlTest || draft.members.contains(.reject) {
                        Toggle("Reject", isOn: memberBinding(for: .reject))
                    }

                    ForEach(store.profiles) { profile in
                        Toggle(profile.name, isOn: memberBinding(for: .profile(profile.id)))
                    }

                    ForEach(selectableGroups) { group in
                        Toggle(group.name, isOn: memberBinding(for: .group(group.id)))
                    }
                } header: {
                    Text("Members")
                } footer: {
                    Text(draft.type == .urlTest ? "Choose nodes or enabled manual groups that resolve to a node. Remove any other members." : "Review Direct/Reject targets. Avoid circular groups.")
                }

                if draft.type == .select {
                    Section("Default") {
                        Picker("Default", selection: $draft.defaultTarget) {
                            Text("First Member").tag(OutboundTarget?.none)
                            ForEach(draft.members, id: \.id) { target in
                                Text(store.displayName(for: target)).tag(Optional(target))
                            }
                        }
                    }
                }

                if draft.type == .urlTest {
                    Section("URL Test") {
                        if draft.importedType == nil {
                            ProfileTextField("URL", text: $draft.url, prompt: ProxyGroupTestOptions.defaultURL)
                        } else {
                            LabeledContent("Probe URL", value: ProxyGroupTestOptions.defaultURL)
                        }
                        ProfileTextField("Interval (s)", text: $draft.intervalSeconds, prompt: "600", keyboardType: .numberPad)
                    }
                }

                if let validationError {
                    Section {
                        Label(validationError, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    }
                }

                if let warning = draft.warning {
                    Section {
                        Text(warning)
                            .foregroundStyle(.orange)
                    }
                }
            }
            .disabled(isSaving)
            .navigationTitle(store.groups.contains(where: { $0.id == draft.id }) ? "Edit Group" : "New Group")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                    .disabled(isSaving)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(isSaving ? "Saving..." : "Save") {
                        let draft = draft
                        let profiles = store.profiles
                        let otherGroups = store.groups.filter { $0.id != draft.id }
                        validationError = nil
                        isSaving = true
                        Task { @MainActor in
                            guard let group = await draft.resolvedGroup() else {
                                isSaving = false
                                return
                            }
                            if group.isEnabled, group.type == .urlTest {
                                let issue = await Task.detached(priority: .userInitiated) {
                                    XrayConfigBuilder().validationIssues(
                                        profiles: profiles, groups: otherGroups + [group], selectedTarget: .group(group.id),
                                        routingMode: .global, rules: [],
                                    ).first
                                }.value
                                if let issue {
                                    validationError = issue.message
                                    isSaving = false
                                    return
                                }
                            }
                            onSave(group)
                            dismiss()
                        }
                    }
                    .disabled(!draft.isStructurallyValid || isSaving)
                }
            }
            .interactiveDismissDisabled(isSaving)
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
    let toleranceMilliseconds: Int
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
        toleranceMilliseconds = group.testOptions.toleranceMilliseconds
        isEnabled = group.isEnabled
        importedType = group.importedType
        warning = group.warning
        lastLatencyMilliseconds = group.lastLatencyMilliseconds
    }

    var isStructurallyValid: Bool {
        !trimmed(name).isEmpty
            && !members.isEmpty
            && Int(trimmed(intervalSeconds)) != nil
            && (!isEnabled || type != .urlTest || (!members.contains(.direct) && !members.contains(.reject)))
    }

    /// DNS resolution may block for seconds, so it must never run from a
    /// SwiftUI body. Resolve on a detached worker, then build from the same
    /// draft snapshot and the exact validation result.
    @MainActor
    func resolvedGroup(
        probeURLValidator: @escaping @Sendable (String) -> Bool = {
            ImportPolicy.isAllowedProbeURL($0)
        },
    ) async -> ProxyGroup? {
        guard isStructurallyValid else {
            return nil
        }
        if type != .urlTest || importedType != nil {
            return makeGroup(probeURLIsAllowed: type != .urlTest)
        }
        let candidateURL = url
        let probeURLIsAllowed = await Task.detached(priority: .userInitiated) {
            probeURLValidator(candidateURL)
        }.value
        return makeGroup(probeURLIsAllowed: probeURLIsAllowed)
    }

    func makeGroup(probeURLIsAllowed: Bool) -> ProxyGroup? {
        let trimmedName = trimmed(name)
        guard isStructurallyValid,
              let interval = Int(trimmed(intervalSeconds))
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
            defaultTarget: type == .urlTest ? nil : defaultTarget,
            testOptions: ProxyGroupTestOptions(
                // Keep the editor in agreement with the import path and config
                // builder: a disallowed/empty probe URL falls back to the default
                // so the persisted state never holds an SSRF-style probe target.
                url: probeURLIsAllowed ? trimmedURL : ProxyGroupTestOptions.defaultURL,
                intervalSeconds: ImportPolicy.clampURLTestInterval(interval),
                toleranceMilliseconds: toleranceMilliseconds,
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
