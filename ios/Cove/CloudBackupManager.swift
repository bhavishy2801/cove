import Foundation

@_exported import CoveCore
import SwiftUI

extension WeakReconciler: CloudBackupManagerReconciler where Reconciler == CloudBackupManager {}

@Observable
final class CloudBackupManager: AnyReconciler, CloudBackupManagerReconciler, @unchecked Sendable {
    static let shared = CloudBackupManager()
    private static let passkeySheetDismissDelay: TimeInterval = 0.8

    typealias Message = CloudBackupReconcileMessage

    @ObservationIgnored let rust: RustCloudBackupManager
    @ObservationIgnored private let rustBridge = DispatchQueue(
        label: "cove.CloudBackupManager.rustbridge", qos: .userInitiated
    )

    private var revision: UInt64 = 0
    var showExistingBackupWarning = false
    var showPasskeyChoiceDialog = false

    private init() {
        let rust = RustCloudBackupManager()
        self.rust = rust
        rust.listenForUpdates(reconciler: WeakReconciler(self))
    }

    private var currentState: CloudBackupState {
        _ = revision
        return rust.state()
    }

    var state: CloudBackupState {
        currentState
    }

    var status: CloudBackupStatus {
        currentState.status
    }

    var progress: (completed: UInt32, total: UInt32)? {
        currentState.progress.map { ($0.completed, $0.total) }
    }

    var restoreProgress: CloudBackupRestoreProgress? {
        currentState.restoreProgress
    }

    var restoreReport: CloudBackupRestoreReport? {
        currentState.restoreReport
    }

    var syncError: String? {
        currentState.syncError
    }

    var hasPendingUploadVerification: Bool {
        currentState.hasPendingUploadVerification
    }

    var isUnverified: Bool {
        currentState.isUnverified
    }

    var isConfigured: Bool {
        currentState.isConfigured
    }

    var detail: CloudBackupDetail? {
        currentState.detail
    }

    var verification: VerificationState {
        currentState.verification
    }

    var sync: SyncState {
        currentState.sync
    }

    var recovery: RecoveryState {
        currentState.recovery
    }

    var cloudOnly: CloudOnlyState {
        currentState.cloudOnly
    }

    var cloudOnlyOperation: CloudOnlyOperation {
        currentState.cloudOnlyOperation
    }

    func enableCloudBackup() {
        rustBridge.async { self.rust.enableCloudBackup() }
    }

    func enableCloudBackupForceNew() {
        rustBridge.async { self.rust.enableCloudBackupForceNew() }
    }

    func enableCloudBackupNoDiscovery() {
        rustBridge.async { self.rust.enableCloudBackupNoDiscovery() }
    }

    func startVerification() {
        rustBridge.async { self.rust.startVerification() }
    }

    func startVerificationDiscoverable() {
        rustBridge.async { self.rust.startVerificationDiscoverable() }
    }

    func recreateManifest() {
        rustBridge.async { self.rust.recreateManifest() }
    }

    func reinitializeBackup() {
        rustBridge.async { self.rust.reinitializeBackup() }
    }

    func repairPasskey() {
        rustBridge.async { self.rust.repairPasskey() }
    }

    func repairPasskeyNoDiscovery() {
        rustBridge.async { self.rust.repairPasskeyNoDiscovery() }
    }

    func syncUnsynced() {
        rustBridge.async { self.rust.syncUnsynced() }
    }

    func fetchCloudOnly() {
        rustBridge.async { self.rust.fetchCloudOnly() }
    }

    func restoreCloudWallet(recordId: String) {
        rustBridge.async { self.rust.restoreCloudWallet(recordId: recordId) }
    }

    func restoreFromCloudBackup() {
        rustBridge.async { self.rust.restoreFromCloudBackup() }
    }

    func deleteCloudWallet(recordId: String) {
        rustBridge.async { self.rust.deleteCloudWallet(recordId: recordId) }
    }

    func refreshDetail() {
        rustBridge.async { self.rust.refreshDetail() }
    }

    private func apply(_ message: Message) {
        switch message {
        case .updated,
             .statusChanged,
             .progressUpdated,
             .restoreProgressUpdated,
             .enableComplete,
             .restoreComplete,
             .syncFailed,
             .pendingUploadVerificationChanged:
            revision &+= 1
        case .existingBackupFound:
            DispatchQueue.main.asyncAfter(deadline: .now() + Self.passkeySheetDismissDelay) {
                [weak self] in
                self?.showExistingBackupWarning = true
            }
        case .passkeyDiscoveryCancelled:
            DispatchQueue.main.asyncAfter(deadline: .now() + Self.passkeySheetDismissDelay) {
                [weak self] in
                self?.showPasskeyChoiceDialog = true
            }
        }
    }

    func reconcile(message: Message) {
        DispatchQueue.main.async { [weak self] in
            self?.apply(message)
        }
    }

    func reconcileMany(messages: [Message]) {
        DispatchQueue.main.async { [weak self] in
            messages.forEach { self?.apply($0) }
        }
    }
}
