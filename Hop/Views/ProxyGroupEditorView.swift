import SwiftUI

/// Form for creating or editing a proxy group: membership, default target,
/// and URL-test scheduling (clamped through `ImportPolicy` on save).
struct ProxyGroupEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(HopStore.self) private var store
    @State private var draft: ProxyGroupEditorDraft
    @State private var isSaving = false
    @State private var validationError: String?

    let isNew: Bool
    let onSave: (ProxyGroup) -> Bool

    init(group: ProxyGroup, isNew: Bool, onSave: @escaping (ProxyGroup) -> Bool) {
        _draft = State(initialValue: ProxyGroupEditorDraft(group: group))
        self.isNew = isNew
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
            .navigationTitle(isNew ? "New Group" : "Edit Group")
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
                        validationError = nil
                        isSaving = true
                        Task { @MainActor in
                            let profiles = store.profiles
                            let otherGroups = store.groups.filter { $0.id != draft.id }
                            defer { isSaving = false }
                            do {
                                guard let group = try await draft.validatedGroup(profiles: profiles, otherGroups: otherGroups) else { return }
                                guard !group.isEnabled || (store.profiles == profiles && store.groups.filter { $0.id != draft.id } == otherGroups) else {
                                    validationError = "The node or group list changed. Save again to check the current members."
                                    return
                                }
                                guard onSave(group) else {
                                    validationError = "This group changed or was removed. Reopen it to edit its current settings."
                                    return
                                }
                                dismiss()
                            } catch {
                                validationError = error.localizedDescription
                            }
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

    @MainActor
    func validatedGroup(profiles: [ProxyProfile], otherGroups: [ProxyGroup]) async throws -> ProxyGroup? {
        guard let group = await resolvedGroup() else { return nil }
        if group.isEnabled {
            _ = try await Task.detached(priority: .userInitiated) {
                try XrayConfigBuilder().build(
                    profiles: profiles, groups: otherGroups + [group], selectedTarget: .group(group.id),
                    routingMode: .global, rules: [],
                )
            }.value
        }
        return group
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
