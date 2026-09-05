import SwiftUI

enum HushWireTheme {
  static let primary = Color(red: 40 / 255, green: 120 / 255, blue: 1)
  static let healthy = Color(red: 15 / 255, green: 159 / 255, blue: 143 / 255)
  static let warning = Color(red: 234 / 255, green: 162 / 255, blue: 26 / 255)
  static let canvas = Color(uiColor: .systemGroupedBackground)
  static let surface = Color(uiColor: .secondarySystemGroupedBackground)
  static let elevatedSurface = Color(uiColor: .systemBackground)
  static let pagePadding: CGFloat = 20
  static let sectionSpacing: CGFloat = 20
  static let cardCornerRadius: CGFloat = 18
}

struct HushWireCard<Content: View>: View {
  let content: Content

  init(@ViewBuilder content: () -> Content) {
    self.content = content()
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      content
    }
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(HushWireTheme.elevatedSurface)
    .clipShape(
      RoundedRectangle(cornerRadius: HushWireTheme.cardCornerRadius, style: .continuous)
    )
    .overlay {
      RoundedRectangle(cornerRadius: HushWireTheme.cardCornerRadius, style: .continuous)
        .stroke(Color(uiColor: .separator).opacity(0.18), lineWidth: 0.5)
    }
    .shadow(color: Color.black.opacity(0.025), radius: 8, y: 3)
  }
}

struct HushWireSectionLabel: View {
  let title: String

  var body: some View {
    Text(title)
      .font(.subheadline.weight(.bold))
      .foregroundStyle(.primary)
      .textCase(nil)
      .frame(maxWidth: .infinity, alignment: .leading)
      .padding(.horizontal, 4)
  }
}

struct HushWireValueRow: View {
  let title: String
  let value: String
  var monospaced = false
  var tint: Color? = nil
  @Environment(\.dynamicTypeSize) private var dynamicTypeSize

  var body: some View {
    Group {
      if dynamicTypeSize.isAccessibilitySize {
        verticalLayout
      } else {
        ViewThatFits(in: .horizontal) {
          HStack(alignment: .firstTextBaseline, spacing: 16) {
            titleText
            Spacer(minLength: 12)
            valueText
              .lineLimit(1)
              .fixedSize(horizontal: true, vertical: false)
              .multilineTextAlignment(.trailing)
          }
          verticalLayout
        }
      }
    }
    .padding(.horizontal, 16)
    .padding(.vertical, 14)
    .accessibilityElement(children: .combine)
  }

  private var titleText: some View {
    Text(title)
      .font(.subheadline)
      .foregroundStyle(.secondary)
  }

  private var valueText: some View {
    Text(value)
      .font(monospaced ? .subheadline.monospaced() : .subheadline)
      .fontWeight(.medium)
      .foregroundStyle(tint ?? Color.primary)
      .textSelection(.enabled)
  }

  private var verticalLayout: some View {
    VStack(alignment: .leading, spacing: 5) {
      titleText
      valueText
        .multilineTextAlignment(.leading)
        .fixedSize(horizontal: false, vertical: true)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}

struct HushWireDivider: View {
  var body: some View {
    Divider().padding(.leading, 16)
  }
}

struct HushWireProfileButton: View {
  let profile: HushWireProfile
  let enabled: Bool
  let action: () -> Void

  var body: some View {
    Button(action: action) {
      HStack(spacing: 13) {
        Image(systemName: "network")
          .font(.body.weight(.semibold))
          .foregroundStyle(HushWireTheme.primary)
          .frame(width: 40, height: 40)
          .background(HushWireTheme.primary.opacity(0.1), in: Circle())
        VStack(alignment: .leading, spacing: 2) {
          Text(profile.name)
            .font(.headline)
            .foregroundStyle(.primary)
            .lineLimit(2)
          Text(enabled ? profile.routePolicy.title : "连接期间不可切换")
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        Spacer()
        Image(systemName: enabled ? "chevron.up.chevron.down" : "lock.fill")
          .font(.caption.weight(.bold))
          .foregroundStyle(.tertiary)
      }
      .padding(.horizontal, 14)
      .padding(.vertical, 11)
      .background(HushWireTheme.elevatedSurface)
      .clipShape(RoundedRectangle(cornerRadius: 17, style: .continuous))
      .overlay {
        RoundedRectangle(cornerRadius: 17, style: .continuous)
          .stroke(Color(uiColor: .separator).opacity(0.18), lineWidth: 0.5)
      }
    }
    .buttonStyle(.plain)
    .accessibilityLabel("当前配置，\(profile.name)")
    .accessibilityHint(enabled ? "打开配置选择器" : "请先断开连接")
  }
}

struct HushWireCallout: View {
  let symbol: String
  let title: String
  let detail: String
  var tint = HushWireTheme.primary

  var body: some View {
    HStack(alignment: .top, spacing: 13) {
      Image(systemName: symbol)
        .font(.subheadline.weight(.semibold))
        .foregroundStyle(tint)
        .frame(width: 32, height: 32)
        .background(tint.opacity(0.1), in: Circle())
      VStack(alignment: .leading, spacing: 3) {
        Text(title)
          .font(.subheadline.weight(.semibold))
        Text(detail)
          .font(.footnote)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
      }
      Spacer(minLength: 0)
    }
    .padding(14)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(tint.opacity(0.07))
    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
    .accessibilityElement(children: .combine)
  }
}

struct HushWireProfileSelectorSheet: View {
  @ObservedObject var controller: HushWireIOSController
  let importAction: () -> Void
  @Environment(\.dismiss) private var dismiss

  var body: some View {
    NavigationStack {
      List {
        Section {
          ForEach(controller.profiles) { profile in
            Button {
              controller.selectProfile(profile)
              dismiss()
            } label: {
              HStack(spacing: 12) {
                Image(systemName: "network")
                  .foregroundStyle(HushWireTheme.primary)
                VStack(alignment: .leading, spacing: 3) {
                  Text(profile.name)
                    .foregroundStyle(.primary)
                  Text(profile.routePolicy.title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                Spacer()
                if profile.id == controller.selectedProfileID {
                  Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(HushWireTheme.primary)
                }
              }
            }
            .disabled(!controller.canEditProfiles && profile.id != controller.selectedProfileID)
          }
        } footer: {
          if !controller.canEditProfiles {
            Text("一个设备同一时间只有一个活动隧道。请断开后再切换配置。")
          }
        }

        Section {
          Button {
            dismiss()
            DispatchQueue.main.async { importAction() }
          } label: {
            Label("导入另一份 TOML", systemImage: "square.and.arrow.down")
          }
          .disabled(!controller.canEditProfiles)
        }
      }
      .navigationTitle("选择配置")
      .navigationBarTitleDisplayMode(.inline)
      .toolbar {
        ToolbarItem(placement: .confirmationAction) {
          Button("完成") { dismiss() }
        }
      }
    }
    .presentationDetents([.medium, .large])
  }
}
