import SwiftUI

@_exported import CoveCore

/// Shown after the cloud backup check finds at least one backup
struct CloudRestoreOfferView: View {
    let onRestore: () -> Void
    let onSkip: () -> Void
    var errorMessage: String? = nil

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            // decorative icon
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

                Image(systemName: "person.badge.key")
                    .font(.system(size: 40))
                    .foregroundStyle(.white)
            }

            Spacer()

            HStack {
                DotMenuView(selected: 1, size: 5, total: 3)
                Spacer()
            }

            // title + subtitle
            VStack(spacing: 12) {
                HStack {
                    Text("Cloud Backup Found")
                        .font(.system(size: 38, weight: .semibold))
                        .foregroundStyle(.white)
                    Spacer()
                }

                HStack {
                    Text("A previous iCloud backup was found. Restore your wallets securely using your passkey")
                        .font(.footnote)
                        .foregroundStyle(.coveLightGray.opacity(0.75))
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                }
            }

            Divider().overlay(Color.coveLightGray.opacity(0.50))

            // passkey option card
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: "person.badge.key")
                        .font(.title3)
                        .foregroundStyle(Color.btnGradientLight)
                        .frame(width: 28)

                    VStack(alignment: .leading, spacing: 4) {
                        Text("Passkey Restore")
                            .font(.subheadline)
                            .fontWeight(.semibold)
                            .foregroundStyle(.white)

                        Text("Secured with iCloud Keychain")
                            .font(.caption)
                            .foregroundStyle(.coveLightGray.opacity(0.75))
                    }

                    Spacer()

                    Text("Recommended")
                        .font(.caption2)
                        .fontWeight(.semibold)
                        .foregroundStyle(.white)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(
                            LinearGradient(
                                colors: [.btnGradientLight, .btnGradientDark],
                                startPoint: .leading,
                                endPoint: .trailing
                            ),
                            in: Capsule()
                        )
                }

                Text("Your wallet data is encrypted and can only be decrypted with your passkey — no one else can access it, not even Apple")
                    .font(.caption)
                    .foregroundStyle(.coveLightGray.opacity(0.60))
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Color.duskBlue.opacity(0.5))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .stroke(Color.coveLightGray.opacity(0.15), lineWidth: 1)
            )

            // error message
            if let errorMessage {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)

                    Text(errorMessage)
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
                .transition(.opacity.combined(with: .move(edge: .top)))
            }

            Button {
                onRestore()
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "arrow.down.circle")
                    Text("Restore with Passkey")
                }
            }
            .buttonStyle(PrimaryButtonStyle())

            Button {
                onSkip()
            } label: {
                Text("Skip — Start Fresh")
                    .font(.subheadline)
                    .foregroundStyle(.coveLightGray.opacity(0.75))
            }
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
        .animation(.easeInOut(duration: 0.3), value: errorMessage)
    }
}
