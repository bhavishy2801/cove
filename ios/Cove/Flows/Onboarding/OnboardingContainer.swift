import SwiftUI

@_exported import CoveCore

@Observable
final class OnboardingManager: OnboardingManagerReconciler, @unchecked Sendable {
    let rust: RustOnboardingManager
    let app: AppManager
    var step: OnboardingStep
    var isComplete = false
    var restoreError: String?

    init(app: AppManager) {
        self.app = app
        self.step = app.isTermsAccepted ? .cloudCheck : .terms
        self.rust = RustOnboardingManager()
        self.rust.listenForUpdates(reconciler: self)
    }

    func dispatch(_ action: OnboardingAction) {
        rust.dispatch(action: action)
    }

    func reconcile(message: OnboardingReconcileMessage) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            switch message {
            case let .stepChanged(newStep):
                self.step = newStep
            case .complete:
                self.isComplete = true
            case let .restoreError(error):
                self.restoreError = error
            }
        }
    }
}

struct OnboardingContainer: View {
    @State var manager: OnboardingManager
    let onComplete: () -> Void

    var body: some View {
        stepView(for: manager.step)
            .onChange(of: manager.isComplete) { _, complete in
                if complete {
                    manager.app.reloadWallets()

                    // auto-select first restored wallet so user lands in it
                    if let wallet = manager.app.wallets.first {
                        manager.app.selectWallet(wallet.id)
                    }

                    onComplete()
                }
            }
    }

    @ViewBuilder
    func stepView(for step: OnboardingStep) -> some View {
        switch step {
        case .terms:
            TermsAndConditionsView {
                manager.app.agreeToTerms()
                manager.dispatch(.acceptTerms)
            }

        case .cloudCheck:
            CloudCheckView(manager: manager)

        case .restoreOffer:
            CloudRestoreOfferView(
                onRestore: {
                    manager.restoreError = nil
                    manager.dispatch(.startRestore)
                },
                onSkip: { manager.dispatch(.skipRestore) },
                errorMessage: manager.restoreError
            )

        case .restoring:
            DeviceRestoreView(
                onComplete: { manager.dispatch(.restoreComplete) },
                onError: { error in manager.dispatch(.restoreFailed(error: error)) }
            )
        }
    }
}

// MARK: - Cloud Check View

private struct CloudCheckView: View {
    let manager: OnboardingManager

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            ProgressView()
                .controlSize(.large)

            Text("Checking for cloud backup...")
                .foregroundStyle(.secondary)

            Spacer()
        }
        .task {
            let hasBackup = await Task.detached(priority: .userInitiated) {
                Self.checkForCloudBackup()
            }.value
            manager.dispatch(.cloudCheckComplete(hasBackup: hasBackup))
        }
    }

    private static func checkForCloudBackup() -> Bool {
        guard FileManager.default.ubiquityIdentityToken != nil else {
            Log.info("[ONBOARDING] iCloud not available")
            return false
        }

        let cloud = CloudStorage(cloudStorage: CloudStorageAccessImpl())
        for attempt in 1 ... 3 {
            Log.info("[ONBOARDING] calling hasAnyCloudBackup attempt=\(attempt)")
            let hasBackup = (try? cloud.hasAnyCloudBackup()) == true
            Log.info("[ONBOARDING] hasAnyCloudBackup returned: \(hasBackup) attempt=\(attempt)")
            if hasBackup { return true }
            Thread.sleep(forTimeInterval: attempt == 1 ? 2 : 3)
        }

        return false
    }
}
