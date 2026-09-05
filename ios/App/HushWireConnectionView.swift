import SwiftUI

struct HushWireConnectionView: View {
  @ObservedObject var controller: HushWireIOSController
  @Binding var selectedTab: HushWireTab
  let importAction: () -> Void
  @Environment(\.dynamicTypeSize) private var dynamicTypeSize

  @State private var showingProfileSelector = false
  @State private var showingFullTunnelConfirmation = false

  var body: some View {
    NavigationStack {
      ScrollView {
        VStack(spacing: HushWireTheme.sectionSpacing) {
          if let profile = controller.selectedProfile {
            HushWireProfileButton(
              profile: profile,
              enabled: controller.canEditProfiles,
              action: { showingProfileSelector = true }
            )

            connectionStatus
            primaryAction

            if controller.providerReady {
              trafficCard
            }

            routeImpact
            profileSummary
            activityMessage
            lastSessionSummary
          } else {
            firstLaunch
          }
        }
        .padding(.horizontal, HushWireTheme.pagePadding)
        .padding(.top, 12)
        .padding(.bottom, 112)
      }
      .background(HushWireTheme.canvas)
      .scrollIndicators(.hidden)
      .navigationTitle("HushWire")
      .navigationBarTitleDisplayMode(.inline)
      .toolbar {
        ToolbarItem(placement: .topBarTrailing) {
          Button {
            selectedTab = .configuration
          } label: {
            Image(systemName: "gearshape")
          }
          .accessibilityLabel("打开配置")
        }
      }
    }
    .sheet(isPresented: $showingProfileSelector) {
      HushWireProfileSelectorSheet(controller: controller, importAction: importAction)
    }
    .sheet(isPresented: $showingFullTunnelConfirmation) {
      HushWireFullTunnelConfirmationView(controller: controller) {
        showingFullTunnelConfirmation = false
        controller.connect(fullTunnelConfirmed: true)
      }
    }
  }

  private var connectionStatus: some View {
    VStack(spacing: 14) {
      ZStack {
        Circle()
          .fill(statusColor.opacity(0.1))
        Circle()
          .stroke(statusColor.opacity(0.2), lineWidth: 1.5)
        if controller.connectionPhase == .connecting || controller.connectionPhase == .disconnecting
        {
          ProgressView()
            .controlSize(.large)
            .tint(statusColor)
            .accessibilityHidden(true)
        } else {
          Image(systemName: statusSymbol)
            .font(.system(size: 44, weight: .medium))
            .foregroundStyle(statusColor)
            .accessibilityHidden(true)
        }
      }
      .frame(width: 116, height: 116)

      VStack(spacing: 5) {
        Text(controller.connectionPhase.title)
          .font(.title.bold())
        Text(statusSubtitle)
          .font(.subheadline)
          .foregroundStyle(.secondary)
          .multilineTextAlignment(.center)
          .monospacedDigit()
      }
    }
    .frame(maxWidth: .infinity)
    .accessibilityElement(children: .combine)
    .accessibilityLabel("连接状态，\(controller.connectionPhase.title)，\(statusSubtitle)")
    .accessibilityIdentifier("hushwire.connection.status")
  }

  @ViewBuilder
  private var primaryAction: some View {
    switch controller.connectionPhase {
    case .connected, .recovering:
      Button(role: .destructive) {
        controller.disconnect()
      } label: {
        Label("断开连接", systemImage: "power")
          .font(.headline)
          .frame(maxWidth: .infinity, minHeight: 50)
      }
      .buttonStyle(.bordered)
      .buttonBorderShape(.capsule)
      .tint(.red)
      .disabled(!controller.canDisconnect)
      .accessibilityIdentifier("hushwire.disconnect")

    case .connecting:
      Button(role: .destructive) {
        controller.disconnect()
      } label: {
        Label("取消连接", systemImage: "xmark")
          .font(.headline)
          .frame(maxWidth: .infinity, minHeight: 50)
      }
      .buttonStyle(.bordered)
      .buttonBorderShape(.capsule)
      .disabled(!controller.canDisconnect)

    case .disconnecting:
      Button {
      } label: {
        Label("正在断开", systemImage: "hourglass")
          .font(.headline)
          .frame(maxWidth: .infinity, minHeight: 50)
      }
      .buttonStyle(.bordered)
      .buttonBorderShape(.capsule)
      .disabled(true)

    case .disconnected, .failed:
      Button {
        if controller.selectedProfile?.routePolicy == .fullTunnel {
          showingFullTunnelConfirmation = true
        } else {
          controller.connect()
        }
      } label: {
        Label("连接", systemImage: "power")
          .font(.headline)
          .frame(maxWidth: .infinity, minHeight: 50)
      }
      .buttonStyle(.borderedProminent)
      .buttonBorderShape(.capsule)
      .disabled(!controller.canConnect)
      .accessibilityIdentifier("hushwire.connect")

    case .noConfiguration:
      EmptyView()
    }
  }

  private var routeImpact: some View {
    HushWireCallout(
      symbol: routeImpactSymbol,
      title: controller.routeImpactTitle,
      detail: controller.routeImpactDetail,
      tint: routeImpactTint
    )
    .accessibilityElement(children: .combine)
    .accessibilityLabel("网络影响，\(controller.routeImpactTitle)，\(controller.routeImpactDetail)")
  }

  @ViewBuilder
  private var profileSummary: some View {
    if let summary = controller.profileInspection?.summary {
      VStack(spacing: 9) {
        HushWireSectionLabel(title: "连接详情")
        HushWireCard {
          HushWireValueRow(
            title: "Endpoint",
            value: controller.peerSessions.first?.endpoint ?? summary.endpointDescription,
            monospaced: true
          )
          HushWireDivider()
          HushWireValueRow(
            title: "传输 / MTU",
            value: "\(summary.transport) · \(summary.mtu)",
            monospaced: true
          )
          HushWireDivider()
          HushWireValueRow(title: "隧道地址", value: summary.interface, monospaced: true)
          HushWireDivider()
          Button {
            selectedTab = .configuration
          } label: {
            HStack(spacing: 7) {
              Text("查看完整配置")
              Image(systemName: "chevron.right")
                .font(.caption.bold())
            }
            .font(.subheadline.weight(.semibold))
            .frame(maxWidth: .infinity, minHeight: 46)
          }
        }
      }
    }
  }

  private var trafficCard: some View {
    VStack(spacing: 9) {
      HushWireSectionLabel(title: "实时流量")
      HushWireCard {
        trafficSummary
          .padding(.vertical, 14)
        HushWireDivider()
        Text("仅统计当前 HushWire 会话；速度每秒更新。")
          .font(.caption2)
          .foregroundStyle(.secondary)
          .padding(.horizontal, 16)
          .padding(.vertical, 11)
      }
    }
  }

  @ViewBuilder
  private var trafficSummary: some View {
    if dynamicTypeSize.isAccessibilitySize {
      VStack(alignment: .leading, spacing: 12) {
        trafficMetric(
          title: "上传",
          rate: controller.uploadRate,
          total: controller.totalUploadBytes,
          symbol: "arrow.up",
          color: HushWireTheme.primary
        )
        Divider()
        trafficMetric(
          title: "下载",
          rate: controller.downloadRate,
          total: controller.totalDownloadBytes,
          symbol: "arrow.down",
          color: HushWireTheme.healthy
        )
      }
    } else {
      HStack(spacing: 0) {
        trafficMetric(
          title: "上传",
          rate: controller.uploadRate,
          total: controller.totalUploadBytes,
          symbol: "arrow.up",
          color: HushWireTheme.primary
        )
        Divider().frame(height: 64)
        trafficMetric(
          title: "下载",
          rate: controller.downloadRate,
          total: controller.totalDownloadBytes,
          symbol: "arrow.down",
          color: HushWireTheme.healthy
        )
      }
    }
  }

  private var activityMessage: some View {
    HStack(alignment: .top, spacing: 8) {
      Image(systemName: activitySymbol)
        .foregroundStyle(activityColor)
      Text(controller.activity)
        .font(.footnote)
        .foregroundStyle(controller.lastError == nil ? Color.secondary : Color.red)
        .fixedSize(horizontal: false, vertical: true)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
    .padding(.horizontal, 2)
    .accessibilityElement(children: .combine)
    .accessibilityIdentifier("hushwire.connection.activity")
  }

  @ViewBuilder
  private var lastSessionSummary: some View {
    if controller.connectionPhase == .disconnected,
      let session = controller.lastSession,
      session.profileID == controller.selectedProfileID
    {
      HStack {
        Label(
          "上次 \(HushWireFormatters.duration(session.duration))",
          systemImage: "clock.arrow.circlepath")
        Spacer()
        Label(HushWireFormatters.bytes(session.rxBytes), systemImage: "arrow.down.to.line")
      }
      .font(.caption)
      .foregroundStyle(.tertiary)
      .monospacedDigit()
      .padding(.horizontal, 2)
    }
  }

  private var firstLaunch: some View {
    VStack(spacing: 22) {
      Spacer(minLength: 18)
      Image(systemName: "network.badge.shield.half.filled")
        .font(.system(size: 48, weight: .medium))
        .foregroundStyle(HushWireTheme.primary)
        .frame(width: 108, height: 108)
        .background(HushWireTheme.primary.opacity(0.08), in: Circle())
      VStack(spacing: 8) {
        Text("从本地配置开始")
          .font(.title.bold())
        Text("HushWire 会先验证 TOML 与网络影响，再把密钥保存在本机 Keychain。首次连接时，iOS 会显示真正的 VPN 授权。")
          .font(.subheadline)
          .foregroundStyle(.secondary)
          .multilineTextAlignment(.center)
          .fixedSize(horizontal: false, vertical: true)
      }
      Button(action: importAction) {
        Label("导入 TOML 配置", systemImage: "square.and.arrow.down")
          .font(.headline)
          .frame(maxWidth: .infinity, minHeight: 50)
      }
      .buttonStyle(.borderedProminent)
      .buttonBorderShape(.capsule)
      HushWireCard {
        VStack(alignment: .leading, spacing: 12) {
          Label("支持保存多份本地配置", systemImage: "checkmark.circle")
          Label("同一时间只启用一个隧道", systemImage: "checkmark.circle")
          Label("私钥与 PSK 不在界面中显示", systemImage: "lock")
        }
        .padding(16)
      }
      .font(.subheadline)
      .foregroundStyle(.secondary)
    }
  }

  private func trafficMetric(
    title: String,
    rate: Double,
    total: UInt64,
    symbol: String,
    color: Color
  ) -> some View {
    VStack(alignment: .leading, spacing: 5) {
      Label(title, systemImage: symbol)
        .font(.caption)
        .foregroundStyle(color)
      Text(HushWireFormatters.rate(rate))
        .font(.headline.monospacedDigit())
      Text("累计 \(HushWireFormatters.bytes(total))")
        .font(.caption2.monospacedDigit())
        .foregroundStyle(.secondary)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
    .padding(.horizontal, 16)
    .accessibilityElement(children: .combine)
    .accessibilityLabel(
      "\(title)，\(HushWireFormatters.rate(rate))，累计 \(HushWireFormatters.bytes(total))"
    )
    .accessibilityIdentifier(
      title == "上传" ? "hushwire.traffic.upload" : "hushwire.traffic.download"
    )
  }

  private var statusColor: Color {
    switch controller.connectionPhase {
    case .connected: HushWireTheme.healthy
    case .recovering: HushWireTheme.warning
    case .failed: .red
    case .connecting: HushWireTheme.primary
    default: .secondary
    }
  }

  private var statusSymbol: String {
    switch controller.connectionPhase {
    case .connected: "checkmark.shield.fill"
    case .recovering: "arrow.triangle.2.circlepath"
    case .failed: "exclamationmark.shield.fill"
    default: "shield"
    }
  }

  private var statusSubtitle: String {
    switch controller.connectionPhase {
    case .connected:
      "已认证 · \(HushWireFormatters.duration(controller.connectionDuration))"
    case .recovering:
      controller.peerSessions.first?.healthDescription ?? "网络路径正在恢复"
    case .connecting:
      "认证成功前不会接管受保护流量"
    case .disconnecting:
      "路由与 DNS 仍由 iOS 收尾"
    case .failed:
      "设备网络未被继续接管"
    case .disconnected:
      "流量未经过 HushWire"
    case .noConfiguration:
      ""
    }
  }

  private var activityColor: Color {
    if controller.lastError != nil { return .red }
    return switch controller.connectionPhase {
    case .connected: HushWireTheme.healthy
    case .recovering: HushWireTheme.warning
    default: .secondary
    }
  }

  private var activitySymbol: String {
    controller.lastError == nil ? "info.circle" : "exclamationmark.circle.fill"
  }

  private var routeImpactTint: Color {
    controller.profileInspection?.summary.routePolicy == .fullTunnel
      ? HushWireTheme.warning
      : HushWireTheme.primary
  }

  private var routeImpactSymbol: String {
    controller.profileInspection?.summary.routePolicy == .fullTunnel
      ? "globe.americas.fill"
      : "point.3.connected.trianglepath.dotted"
  }
}

private struct HushWireFullTunnelConfirmationView: View {
  @ObservedObject var controller: HushWireIOSController
  let confirm: () -> Void
  @Environment(\.dismiss) private var dismiss

  var body: some View {
    NavigationStack {
      ScrollView {
        VStack(alignment: .leading, spacing: 20) {
          Image(systemName: "globe.americas.fill")
            .font(.system(size: 42))
            .foregroundStyle(HushWireTheme.warning)
            .frame(maxWidth: .infinity)
          Text("本次连接会接管默认 IPv4 流量")
            .font(.title2.bold())
            .frame(maxWidth: .infinity)
            .multilineTextAlignment(.center)
          Text("HushWire 只会在认证预握手成功后应用这些设置。断开后，路由与 DNS 由 iOS 恢复。")
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)

          HushWireCard {
            HushWireValueRow(title: "默认路由", value: "经 HushWire")
            HushWireDivider()
            HushWireValueRow(
              title: "DNS",
              value: controller.profileInspection?.summary.dnsDescription ?? "保持系统 DNS"
            )
            HushWireDivider()
            HushWireValueRow(
              title: "Endpoint 保护",
              value: controller.profileInspection?.summary.resolvedEndpoints.first ?? "自动"
            )
            HushWireDivider()
            HushWireValueRow(
              title: "直连例外",
              value: controller.profileInspection?.summary.directRouteDescription ?? "无"
            )
          }

          Button(action: confirm) {
            Text("确认并连接")
              .font(.headline)
              .frame(maxWidth: .infinity, minHeight: 52)
          }
          .buttonStyle(.borderedProminent)
          .buttonBorderShape(.capsule)
          .accessibilityIdentifier("hushwire.full-tunnel.confirm")
          Button("取消", role: .cancel) { dismiss() }
            .frame(maxWidth: .infinity)
        }
        .padding(20)
      }
      .background(HushWireTheme.canvas)
      .navigationTitle("确认网络影响")
      .navigationBarTitleDisplayMode(.inline)
    }
    .presentationDetents([.large])
  }
}
