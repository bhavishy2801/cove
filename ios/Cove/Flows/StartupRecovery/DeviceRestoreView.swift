import SwiftUI

@_exported import CoveCore

struct DeviceRestoreView: View {
    let onComplete: () -> Void
    let onError: (String) -> Void

    enum RestorePhase: Equatable {
        case restoring(progress: (completed: UInt32, total: UInt32)? = nil)
        case complete(CloudBackupRestoreReport)
        case error(String)

        static func == (lhs: RestorePhase, rhs: RestorePhase) -> Bool {
            switch (lhs, rhs) {
            case (.restoring, .restoring): true
            case (.complete, .complete): true
            case let (.error(a), .error(b)): a == b
            default: false
            }
        }
    }

    @State private var phase: RestorePhase = .restoring()
    private let backupManager = CloudBackupManager.shared

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            heroIcon

            Spacer()

            HStack {
                DotMenuView(selected: 2, size: 5, total: 3)
                Spacer()
            }

            titleContent

            Divider().overlay(Color.coveLightGray.opacity(0.50))

            bottomContent
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(
            Image(.newWalletPattern)
                .resizable()
                .aspectRatio(contentMode: .fill)
                .frame(height: screenHeight * 0.75, alignment: .topTrailing)
                .frame(maxWidth: .infinity)
                .opacity(0.75)
        )
        .background(Color.midnightBlue)
        .task {
            await runRestore()
        }
    }

    // MARK: - Hero Icon

    @ViewBuilder
    private var heroIcon: some View {
        switch phase {
        case .restoring:
            ZStack {
                Circle()
                    .fill(Color.duskBlue.opacity(0.5))
                    .frame(width: 100, height: 100)

                Circle()
                    .stroke(
                        LinearGradient(
                            colors: [.btnGradientLight, .btnGradientDark],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        lineWidth: 2
                    )
                    .frame(width: 100, height: 100)

                Image(systemName: "icloud.and.arrow.down")
                    .font(.system(size: 40))
                    .foregroundStyle(Color.btnGradientLight)
                    .symbolEffect(.pulse)
            }

        case .complete:
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: screenWidth * 0.30))
                .fontWeight(.light)
                .symbolRenderingMode(.palette)
                .foregroundStyle(.midnightBlue, Color.lightGreen)

        case .error:
            ZStack {
                Circle()
                    .fill(Color.red.opacity(0.1))
                    .frame(width: 100, height: 100)

                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 40))
                    .foregroundStyle(.red)
            }
        }
    }

    // MARK: - Title Content

    @ViewBuilder
    private var titleContent: some View {
        switch phase {
        case let .restoring(progress):
            VStack(spacing: 12) {
                HStack {
                    Text("Restoring from Cloud")
                        .font(.system(size: 38, weight: .semibold))
                        .foregroundStyle(.white)
                    Spacer()
                }

                HStack {
                    if let progress {
                        Text("Restoring wallets (\(progress.completed)/\(progress.total))")
                            .font(.footnote)
                            .foregroundStyle(.coveLightGray.opacity(0.75))
                    } else {
                        Text("Restoring wallets...")
                            .font(.footnote)
                            .foregroundStyle(.coveLightGray.opacity(0.75))
                    }
                    Spacer()
                }
            }

        case let .complete(report):
            VStack(spacing: 12) {
                HStack {
                    Text("Restore Complete")
                        .font(.system(size: 38, weight: .semibold))
                        .foregroundStyle(.white)
                    Spacer()
                }

                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Restored \(report.walletsRestored) wallet(s)")
                            .font(.footnote)
                            .foregroundStyle(.coveLightGray.opacity(0.75))

                        if report.walletsFailed > 0 {
                            Text("\(report.walletsFailed) wallet(s) could not be restored")
                                .font(.caption)
                                .foregroundStyle(.orange)
                        }
                    }
                    Spacer()
                }
            }

        case .error:
            VStack(spacing: 12) {
                HStack {
                    Text("Restore Failed")
                        .font(.system(size: 38, weight: .semibold))
                        .foregroundStyle(.white)
                    Spacer()
                }

                HStack {
                    Text("Something went wrong while restoring your wallets")
                        .font(.footnote)
                        .foregroundStyle(.coveLightGray.opacity(0.75))
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                }
            }
        }
    }

    // MARK: - Bottom Content

    @ViewBuilder
    private var bottomContent: some View {
        switch phase {
        case let .restoring(progress):
            if let progress {
                ProgressView(
                    value: Double(progress.completed),
                    total: Double(max(progress.total, 1))
                )
                .tint(.btnGradientLight)
                .animation(.easeInOut(duration: 0.3), value: progress.completed)
            } else {
                ProgressView()
                    .tint(.white)
            }

        case .complete:
            EmptyView()

        case let .error(message):
            VStack(spacing: 16) {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)

                    Text(message)
                        .font(.caption)
                        .foregroundStyle(.orange.opacity(0.9))
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(Color.orange.opacity(0.1))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .stroke(Color.orange.opacity(0.3), lineWidth: 1)
                )

                Button {
                    phase = .restoring()
                    Task { await runRestore() }
                } label: {
                    Text("Retry")
                }
                .buttonStyle(PrimaryButtonStyle())
            }
        }
    }

    // MARK: - Restore Logic

    private func runRestore() async {
        phase = .restoring()

        // run the blocking FFI call off the main thread so progress
        // updates dispatched to main can actually be processed
        let rust = backupManager.rust
        Task.detached(priority: .userInitiated) {
            rust.restoreFromCloudBackup()
        }

        await observeRestoreCompletion()
    }

    private func observeRestoreCompletion() async {
        let startTime = ContinuousClock.now

        while !Task.isCancelled {
            try? await Task.sleep(for: .milliseconds(100))

            let elapsed = ContinuousClock.now - startTime
            if elapsed >= .seconds(120) {
                phase = .error("Restore timed out. Please try again.")
                return
            }

            let currentState = backupManager.state
            let currentProgress = backupManager.progress
            let report = backupManager.restoreReport

            await MainActor.run {
                self.phase = .restoring(progress: currentProgress)
            }

            switch currentState {
            case .enabled:
                if let report {
                    // show progress at 100% before transitioning
                    if let currentProgress {
                        phase = .restoring(progress: (currentProgress.total, currentProgress.total))
                        try? await Task.sleep(for: .seconds(1))
                    }

                    phase = .complete(report)
                    try? await Task.sleep(for: .seconds(1))
                    onComplete()
                    return
                }

            case let .error(msg):
                phase = .error(msg)
                onError(msg)
                return

            case .disabled:
                if report != nil {
                    phase = .error("Restore failed — all wallets could not be recovered")
                    return
                }

            default:
                continue
            }
        }
    }
}
