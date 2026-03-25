import SwiftUI

struct CloudBackupDetailScreen: View {
    @State private var manager = CloudBackupDetailManager()
    @State private var syncHealth: ICloudDriveHelper.SyncHealth = .noFiles
    @State private var showRecreateConfirmation = false
    @State private var showReinitializeConfirmation = false

    private var isVerifying: Bool {
        if case .verifying = manager.verification { return true }
        return false
    }

    private var isRecovering: Bool {
        if case .recovering = manager.recovery { return true }
        return false
    }

    var body: some View {
        Form {
            if isVerifying, !hasVerificationResult {
                Section {
                    VStack {
                        ProgressView("Verifying cloud backup...")
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                }
            } else if let detail = manager.detail, !isCancelled {
                DetailFormContent(
                    detail: detail,
                    syncHealth: syncHealth,
                    manager: manager
                )
            }

            VerificationSection(
                manager: manager,
                onRecreate: { showRecreateConfirmation = true },
                onReinitialize: { showReinitializeConfirmation = true }
            )
        }
        .navigationTitle("Cloud Backup")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            refreshSyncHealth()
            manager.dispatch(.refreshDetail)
        }
        .onChange(of: manager.detail) { _, _ in
            refreshSyncHealth()
        }
        .onChange(of: manager.verification) { _, _ in
            refreshSyncHealth()
        }
        .confirmationDialog(
            "Recreate Backup Index",
            isPresented: $showRecreateConfirmation,
            titleVisibility: .visible
        ) {
            Button("Recreate", role: .destructive) {
                manager.dispatch(.recreateManifest)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "This will rebuild the backup index from wallets on this device. Wallets that only exist in the cloud backup will no longer be referenced."
            )
        }
        .confirmationDialog(
            "Reinitialize Cloud Backup",
            isPresented: $showReinitializeConfirmation,
            titleVisibility: .visible
        ) {
            Button("Reinitialize", role: .destructive) {
                manager.dispatch(.reinitializeBackup)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "This will replace your entire cloud backup. Wallets that only exist in the current cloud backup will be lost."
            )
        }
    }

    private var hasVerificationResult: Bool {
        switch manager.verification {
        case .verified, .failed, .cancelled: true
        default: false
        }
    }

    private var isCancelled: Bool {
        if case .cancelled = manager.verification { return true }
        return false
    }

    private func refreshSyncHealth() {
        syncHealth = ICloudDriveHelper.shared.overallSyncHealth()
    }
}

// MARK: - Verification Section

private struct VerificationSection: View {
    let manager: CloudBackupDetailManager
    let onRecreate: () -> Void
    let onReinitialize: () -> Void

    private var isVerifying: Bool {
        if case .verifying = manager.verification { return true }
        return false
    }

    private var isRecovering: Bool {
        if case .recovering = manager.recovery { return true }
        return false
    }

    private var isBusy: Bool {
        isVerifying || isRecovering
    }

    var body: some View {
        switch manager.verification {
        case .idle:
            Section {
                Text("Run verification to confirm your cloud backup can be decrypted and restored")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Button {
                    manager.dispatch(.startVerification)
                } label: {
                    Label("Verify Now", systemImage: "checkmark.shield")
                }
                .disabled(isBusy)
            }
        case .verifying:
            Section {
                HStack {
                    ProgressView()
                        .padding(.trailing, 8)
                    Text("Verifying backup integrity...")
                }
            }
        case let .verified(report):
            verifiedSection(report)
        case let .failed(failure):
            failureSection(failure)
        case .cancelled:
            cancelledSection
        }
    }

    private var cancelledSection: some View {
        Section {
            Label(
                "Verification was cancelled",
                systemImage: "exclamationmark.shield.fill"
            )
            .foregroundStyle(.orange)

            Text(
                "If your passkey was deleted, tap \"Create New Passkey\" to restore cloud backup protection. Otherwise tap \"Verify Now\" to try again."
            )
            .font(.caption)
            .foregroundStyle(.secondary)

            Button {
                manager.dispatch(.startVerification)
            } label: {
                Label("Verify Now", systemImage: "checkmark.shield")
            }
            .disabled(isBusy)

            repairPasskeyButton
        }
    }

    @ViewBuilder
    private func verifiedSection(_ report: DeepVerificationReport) -> some View {
        Section {
            Label("Backup verified", systemImage: "checkmark.shield.fill")
                .foregroundStyle(.green)
                .alignmentGuide(.listRowSeparatorLeading) { _ in 0 }

            if report.masterKeyWrapperRepaired {
                Label(
                    "Cloud master key protection was repaired",
                    systemImage: "wrench.and.screwdriver.fill"
                )
                .foregroundStyle(.blue)
                .font(.caption)
            }

            if report.localMasterKeyRepaired {
                Label(
                    "Local backup credentials were repaired from cloud",
                    systemImage: "wrench.and.screwdriver.fill"
                )
                .foregroundStyle(.blue)
                .font(.caption)
            }

            if report.walletsFailed > 0 {
                Label(
                    "\(report.walletsFailed) wallet backup(s) could not be decrypted",
                    systemImage: "exclamationmark.triangle.fill"
                )
                .foregroundStyle(.red)
                .font(.caption)
            }

            if report.walletsUnsupported > 0 {
                Label(
                    "\(report.walletsUnsupported) wallet(s) use a newer backup format",
                    systemImage: "info.circle.fill"
                )
                .foregroundStyle(.orange)
                .font(.caption)
            }

            if report.walletsVerified > 0 {
                Text("\(report.walletsVerified) wallet(s) verified")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }

        actionButtons
    }

    @ViewBuilder
    private func failureSection(_ failure: DeepVerificationFailure) -> some View {
        Section {
            switch failure.kind {
            case .retry:
                retryFailureContent(failure.message)
            case let .recreateManifest(warning):
                recreateManifestContent(message: failure.message, warning: warning)
            case let .reinitializeBackup(warning):
                reinitializeBackupContent(message: failure.message, warning: warning)
            case .unsupportedVersion:
                unsupportedVersionContent(failure.message)
            }
        }

        if case let .failed(action: _, error) = manager.recovery {
            Section {
                Label(error, systemImage: "xmark.circle.fill")
                    .foregroundStyle(.red)
                    .font(.caption)
            }
        }
    }

    @ViewBuilder
    private func retryFailureContent(_ message: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle.fill")
            .foregroundStyle(.orange)

        retryButton
        repairPasskeyButton
    }

    @ViewBuilder
    private func recreateManifestContent(message: String, warning: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle.fill")
            .foregroundStyle(.red)

        Text(warning)
            .font(.caption)
            .foregroundStyle(.secondary)

        destructiveActionButton(
            title: "Recreate Backup Index",
            progressTitle: "Recreating...",
            systemImage: "arrow.clockwise",
            action: onRecreate
        )
    }

    @ViewBuilder
    private func reinitializeBackupContent(message: String, warning: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle.fill")
            .foregroundStyle(.red)

        Text(warning)
            .font(.caption)
            .foregroundStyle(.secondary)

        destructiveActionButton(
            title: "Reinitialize Cloud Backup",
            progressTitle: "Reinitializing...",
            systemImage: "arrow.counterclockwise",
            action: onReinitialize
        )
    }

    @ViewBuilder
    private func unsupportedVersionContent(_ message: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle.fill")
            .foregroundStyle(.orange)

        Text("Please update the app to the latest version")
            .font(.caption)
            .foregroundStyle(.secondary)
    }

    private func destructiveActionButton(
        title: String,
        progressTitle: String,
        systemImage: String,
        action: @escaping () -> Void
    ) -> some View {
        Button(role: .destructive) {
            action()
        } label: {
            if isRecovering {
                HStack {
                    ProgressView()
                        .padding(.trailing, 4)
                    Text(progressTitle)
                }
            } else {
                Label(title, systemImage: systemImage)
            }
        }
        .disabled(isBusy)
    }

    private var actionButtons: some View {
        Section {
            if manager.detail?.notBackedUp.isEmpty == false {
                syncButton
            }

            Button {
                manager.dispatch(.startVerification)
            } label: {
                Label("Verify Again", systemImage: "checkmark.shield")
            }
            .disabled(isBusy)
        }
    }

    private var syncButton: some View {
        Group {
            Button {
                manager.dispatch(.syncUnsynced)
            } label: {
                HStack {
                    if case .syncing = manager.sync {
                        ProgressView()
                            .padding(.trailing, 8)
                        Text("Syncing...")
                    } else {
                        Image(systemName: "arrow.triangle.2.circlepath")
                        Text("Sync Now")
                    }
                }
            }
            .disabled(manager.sync == .syncing)

            if case let .failed(error) = manager.sync {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
    }

    private var retryButton: some View {
        Button {
            manager.dispatch(.startVerification)
        } label: {
            Label("Try Again", systemImage: "arrow.clockwise")
        }
        .disabled(isBusy)
    }

    private var repairPasskeyButton: some View {
        Button {
            manager.dispatch(.repairPasskey)
        } label: {
            if isRecovering {
                HStack {
                    ProgressView()
                        .padding(.trailing, 4)
                    Text("Creating Passkey...")
                }
            } else {
                Label("Create New Passkey", systemImage: "person.badge.key")
            }
        }
        .disabled(isBusy)
    }
}

// MARK: - Detail Form Content

private struct DetailFormContent: View {
    let detail: CloudBackupDetail
    let syncHealth: ICloudDriveHelper.SyncHealth
    let manager: CloudBackupDetailManager

    private var showCloudOnlySection: Bool {
        switch manager.cloudOnly {
        case .notFetched: detail.cloudOnlyCount > 0
        case .loading: true
        case let .loaded(wallets): !wallets.isEmpty
        }
    }

    var body: some View {
        HeaderSection(lastSync: detail.lastSync, syncHealth: syncHealth)
        if !detail.backedUp.isEmpty { BackedUpSections(wallets: detail.backedUp) }
        if !detail.notBackedUp.isEmpty {
            NotBackedUpSections(wallets: detail.notBackedUp)
        }
        if showCloudOnlySection {
            CloudOnlySection(manager: manager)
        }
    }
}

// MARK: - Header

private struct HeaderSection: View {
    let lastSync: UInt64?
    let syncHealth: ICloudDriveHelper.SyncHealth

    var body: some View {
        Section {
            VStack(spacing: 8) {
                headerIcon
                    .font(.largeTitle)

                Text("Cloud Backup Active")
                    .fontWeight(.semibold)

                if let lastSync {
                    Text("Last synced \(formatDate(lastSync))")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    syncHealthLabel
                }
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
        }
    }

    @ViewBuilder
    private var headerIcon: some View {
        switch syncHealth {
        case .allUploaded, .noFiles:
            Image(systemName: "checkmark.icloud.fill")
                .foregroundColor(.green)
        case .uploading:
            Image(systemName: "arrow.clockwise.icloud.fill")
                .foregroundColor(.blue)
        case .failed:
            Image(systemName: "exclamationmark.icloud.fill")
                .foregroundColor(.red)
        case .unavailable:
            Image(systemName: "checkmark.icloud.fill")
                .foregroundColor(.green)
        }
    }

    @ViewBuilder
    private var syncHealthLabel: some View {
        switch syncHealth {
        case .allUploaded:
            Label("All files synced to iCloud", systemImage: "checkmark.circle.fill")
                .font(.caption)
                .foregroundStyle(.green)
        case .uploading:
            HStack(spacing: 4) {
                ProgressView()
                    .controlSize(.mini)
                Text("Syncing to iCloud...")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        case let .failed(message):
            Label("Sync error: \(message)", systemImage: "exclamationmark.triangle.fill")
                .font(.caption)
                .foregroundStyle(.red)
        case .noFiles, .unavailable:
            EmptyView()
        }
    }

    private func formatDate(_ timestamp: UInt64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(timestamp))
        return date.formatted(date: .abbreviated, time: .shortened)
    }
}

// MARK: - Cloud Only Section

private struct CloudOnlySection: View {
    let manager: CloudBackupDetailManager
    @State private var selectedWallet: CloudBackupWalletItem?
    @State private var walletToDelete: CloudBackupWalletItem?

    private var isOperating: Bool {
        if case .operating = manager.cloudOnlyOperation { return true }
        return false
    }

    private var operatingRecordId: String? {
        if case let .operating(recordId) = manager.cloudOnlyOperation { return recordId }
        return nil
    }

    var body: some View {
        Section(header: Text("Not on This Device")) {
            switch manager.cloudOnly {
            case .notFetched, .loading:
                HStack {
                    ProgressView()
                        .padding(.trailing, 8)
                    Text("Loading...")
                }
                .foregroundStyle(.secondary)
                .task {
                    manager.dispatch(.fetchCloudOnly)
                }

            case let .loaded(wallets):
                ForEach(wallets, id: \.name) { item in
                    Button {
                        selectedWallet = item
                    } label: {
                        HStack {
                            if operatingRecordId == item.recordId {
                                ProgressView()
                                    .padding(.trailing, 8)
                            }
                            WalletItemRow(item: item)
                        }
                    }
                    .foregroundStyle(.primary)
                    .disabled(isOperating)
                }

                if case let .failed(error) = manager.cloudOnlyOperation {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }
        }
        .confirmationDialog(
            selectedWallet?.name ?? "Wallet",
            isPresented: Binding(
                get: { selectedWallet != nil },
                set: { if !$0 { selectedWallet = nil } }
            ),
            titleVisibility: .visible
        ) {
            if let item = selectedWallet, let recordId = item.recordId {
                Button("Restore to This Device") {
                    manager.dispatch(.restoreCloudWallet(recordId: recordId))
                }
                Button("Delete from iCloud", role: .destructive) {
                    walletToDelete = item
                }
            }
            Button("Cancel", role: .cancel) {}
        }
        .alert(
            "Delete \(walletToDelete?.name ?? "wallet")?",
            isPresented: Binding(
                get: { walletToDelete != nil },
                set: { if !$0 { walletToDelete = nil } }
            )
        ) {
            if let item = walletToDelete, let recordId = item.recordId {
                Button("Delete", role: .destructive) {
                    manager.dispatch(.deleteCloudWallet(recordId: recordId))
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This wallet backup will be permanently removed from iCloud")
        }
    }
}

// MARK: - Backed Up Sections

private struct BackedUpSections: View {
    let wallets: [CloudBackupWalletItem]

    var body: some View {
        let grouped = Dictionary(grouping: wallets) {
            GroupKey(network: $0.network, walletMode: $0.walletMode)
        }

        ForEach(grouped.keys.sorted(), id: \.self) { key in
            Section(header: Text(key.title)) {
                ForEach(grouped[key]!, id: \.name) { item in
                    WalletItemRow(item: item)
                }
            }
        }
    }
}

// MARK: - Not Backed Up Sections

private struct NotBackedUpSections: View {
    let wallets: [CloudBackupWalletItem]

    var body: some View {
        let grouped = Dictionary(grouping: wallets) {
            GroupKey(network: $0.network, walletMode: $0.walletMode)
        }

        ForEach(grouped.keys.sorted(), id: \.self) { key in
            Section(
                header: HStack {
                    Text(key.title)
                    Text("NOT BACKED UP")
                        .font(.caption2)
                        .fontWeight(.semibold)
                        .foregroundStyle(.white)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(.red, in: Capsule())
                }
            ) {
                ForEach(grouped[key]!, id: \.name) { item in
                    WalletItemRow(item: item)
                }
            }
        }
    }
}

// MARK: - Wallet Item Row

private struct WalletItemRow: View {
    let item: CloudBackupWalletItem

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(item.name)
                    .fontWeight(.medium)
                Spacer()
                StatusBadge(status: item.status)
            }

            HStack(spacing: 12) {
                IconLabel("globe", item.network.displayName())
                IconLabel("wallet.bifold", item.walletType.displayName())
                if let fingerprint = item.fingerprint {
                    IconLabel("touchid", fingerprint)
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Status Badge

private struct StatusBadge: View {
    let status: CloudBackupWalletStatus

    private var label: String {
        switch status {
        case .backedUp: "Backed up"
        case .notBackedUp: "Not backed up"
        case .deletedFromDevice: "Not on device"
        }
    }

    private var color: Color {
        switch status {
        case .backedUp: .green
        case .notBackedUp: .red
        case .deletedFromDevice: .orange
        }
    }

    var body: some View {
        Text(label)
            .font(.caption)
            .fontWeight(.medium)
            .foregroundColor(color)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(color.opacity(0.15), in: Capsule())
    }
}

// MARK: - Group Key

private struct GroupKey: Hashable, Comparable {
    let network: Network
    let walletMode: WalletMode

    var title: String {
        switch walletMode {
        case .decoy: "\(network.displayName()) · Decoy"
        default: network.displayName()
        }
    }

    static func < (lhs: GroupKey, rhs: GroupKey) -> Bool {
        if lhs.network != rhs.network {
            return lhs.network.displayName() < rhs.network.displayName()
        }
        return lhs.walletMode == .main && rhs.walletMode != .main
    }
}
