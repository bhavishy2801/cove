import SwiftUI

struct CloudBackupDetailScreen: View {
    @State private var manager = CloudBackupManager.shared
    @State private var syncHealth: ICloudDriveHelper.SyncHealth = .noFiles
    @State private var showRecreateConfirmation = false
    @State private var showReinitializeConfirmation = false
    @State private var hasAutoVerified = false

    private var isVerifying: Bool {
        if case .verifying = manager.verification { return true }
        return false
    }

    private var hasVerificationResult: Bool {
        switch manager.verification {
        case .verified, .passkeyConfirmed, .failed, .cancelled: true
        default: false
        }
    }

    private var isCancelled: Bool {
        if case .cancelled = manager.verification { return true }
        return false
    }

    private var isPasskeyMissing: Bool {
        if case .passkeyMissing = manager.status { return true }
        return false
    }

    var body: some View {
        Form {
            if isPasskeyMissing {
                MissingPasskeyContent(manager: manager)
            } else {
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
        }
        .navigationTitle("Cloud Backup")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            guard !isPasskeyMissing else { return }

            refreshSyncHealth()
            manager.refreshDetail()

            if !hasAutoVerified {
                hasAutoVerified = true
                manager.startVerificationDiscoverable()
            }
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
                manager.recreateManifest()
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
                manager.reinitializeBackup()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "This will replace your entire cloud backup. Wallets that only exist in the current cloud backup will be lost."
            )
        }
        .alert(
            "Passkey Options",
            isPresented: $manager.showPasskeyChoiceDialog
        ) {
            Button("Use Existing Passkey") {
                manager.repairPasskey()
            }
            Button("Create New Passkey") {
                manager.repairPasskeyNoDiscovery()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Would you like to use an existing passkey or create a new one?")
        }
    }

    private func refreshSyncHealth() {
        syncHealth = ICloudDriveHelper.shared.overallSyncHealth()
    }
}
