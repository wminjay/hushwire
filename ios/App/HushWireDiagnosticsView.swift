import SwiftUI
import UIKit

struct HushWireDiagnosticsView: View {
  @ObservedObject var controller: HushWireIOSController
  @State private var copied = false
  @Environment(\.dynamicTypeSize) private var dynamicTypeSize

  var body: some View {
    NavigationStack {
      ScrollView {
        VStack(spacing: HushWireTheme.sectionSpacing) {
          healthCard

          if controller.selectedProfile != nil {
            if controller.providerReady {
              liveTrafficSection
            }
            liveSessionSection
            networkImpactSection
            recentActivitySection

            Button {
              controller.runConnectionCheck()
            } label: {
              Label("运行连接检查", systemImage: "point.topleft.down.to.point.bottomright.curvepath")
                .font(.headline)
                .frame(maxWidth: .infinity, minHeight: 48)
            }
            .buttonStyle(.bordered)
            .buttonBorderShape(.capsule)

            HushWireCallout(
              symbol: "lock.doc.fill",
              title: "诊断信息已脱敏",
              detail: "复制或分享的报告不包含私钥、PSK、TOML 正文和可信 Wi-Fi 名称。",
              tint: HushWireTheme.healthy
            )
          }
        }
        .padding(.horizontal, HushWireTheme.pagePadding)
        .padding(.top, 12)
        .padding(.bottom, 112)
      }
      .background(HushWireTheme.canvas)
      .scrollIndicators(.hidden)
      .navigationTitle("诊断")
      .toolbar {
        ToolbarItemGroup(placement: .topBarTrailing) {
          Button {
            UIPasteboard.general.string = controller.redactedDiagnostics()
            copied = true
          } label: {
            Image(systemName: copied ? "checkmark" : "doc.on.doc")
          }
          .accessibilityLabel(copied ? "已复制诊断报告" : "复制诊断报告")
          .disabled(controller.selectedProfile == nil)

          ShareLink(item: controller.redactedDiagnostics()) {
            Image(systemName: "square.and.arrow.up")
          }
          .accessibilityLabel("分享脱敏诊断报告")
          .disabled(controller.selectedProfile == nil)
        }
      }
    }
    .onChange(of: controller.events.count) { _, _ in
      copied = false
    }
  }

  private var healthCard: some View {
    HushWireCard {
      HStack(spacing: 15) {
        Image(systemName: healthSymbol)
          .font(.system(size: 26, weight: .semibold))
          .foregroundStyle(healthColor)
          .frame(width: 52, height: 52)
          .background(healthColor.opacity(0.12), in: Circle())
        VStack(alignment: .leading, spacing: 5) {
          Text(healthTitle)
            .font(.title3.bold())
          Text(healthDetail)
            .font(.subheadline)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
          if controller.providerReady {
            Text("会话时长 \(HushWireFormatters.duration(controller.connectionDuration))")
              .font(.subheadline.monospacedDigit())
              .foregroundStyle(.secondary)
          }
        }
      }
      .padding(16)
    }
    .accessibilityElement(children: .combine)
  }

  private var liveTrafficSection: some View {
    VStack(spacing: 9) {
      HushWireSectionLabel(title: "实时流量")
      HushWireCard {
        trafficSummary
          .padding(.vertical, 15)
      }
    }
  }

  @ViewBuilder
  private var liveSessionSection: some View {
    VStack(spacing: 9) {
      HushWireSectionLabel(title: "会话详情")
      HushWireCard {
        HushWireValueRow(
          title: "Peer",
          value: controller.peerSessions.first?.name
            ?? controller.profileInspection?.peers.first?.name
            ?? "未知"
        )
        HushWireDivider()
        HushWireValueRow(
          title: "当前 Endpoint",
          value: controller.peerSessions.first?.endpoint
            ?? controller.profileInspection?.summary.endpointDescription
            ?? "未知",
          monospaced: true
        )
        if let configuredEndpoint = controller.profileInspection?.peers.first?.configuredEndpoint {
          HushWireDivider()
          HushWireValueRow(
            title: "配置 Endpoint",
            value: configuredEndpoint,
            monospaced: true
          )
        }
        HushWireDivider()
        HushWireValueRow(
          title: "传输",
          value: controller.providerTransport.isEmpty
            ? controller.profileInspection?.summary.transport ?? "未知"
            : controller.providerTransport,
          monospaced: true
        )
        HushWireDivider()
        HushWireValueRow(
          title: "隧道地址",
          value: controller.providerInterface.isEmpty
            ? controller.profileInspection?.summary.interface ?? "未知"
            : controller.providerInterface,
          monospaced: true
        )
        HushWireDivider()
        HushWireValueRow(
          title: "最近握手",
          value: controller.peerSessions.first?.healthDescription
            ?? (controller.lastHandshake.isEmpty ? "当前无会话" : controller.lastHandshake)
        )
        HushWireDivider()
        HushWireValueRow(
          title: "Core",
          value: controller.providerCoreVersion.isEmpty
            ? controller.profileInspection?.coreVersion ?? "未知"
            : controller.providerCoreVersion,
          monospaced: true
        )
      }
    }
  }

  private var networkImpactSection: some View {
    VStack(spacing: 9) {
      HushWireSectionLabel(title: "网络影响")
      HushWireCard {
        HushWireValueRow(title: "路由模式", value: controller.routeImpactTitle)
        HushWireDivider()
        HushWireValueRow(
          title: "隧道路由",
          value: "\(controller.profileInspection?.summary.routes.count ?? 0) 条"
        )
        HushWireDivider()
        HushWireValueRow(
          title: "直连例外",
          value: directRouteSummary
        )
        HushWireDivider()
        HushWireValueRow(
          title: "DNS",
          value: controller.profileInspection?.summary.dnsDescription ?? "未知"
        )
        HushWireDivider()
        HushWireValueRow(
          title: "自动连接",
          value: controller.selectedProfile?.autoConnectOutsideTrustedWiFi == true
            ? "已开启"
            : "关闭",
          tint: controller.selectedProfile?.autoConnectOutsideTrustedWiFi == true
            ? HushWireTheme.healthy
            : nil
        )
      }
    }
  }

  @ViewBuilder
  private var trafficSummary: some View {
    if dynamicTypeSize.isAccessibilitySize {
      VStack(alignment: .leading, spacing: 12) {
        uploadTraffic
        Divider()
        downloadTraffic
      }
    } else {
      HStack(spacing: 0) {
        uploadTraffic
        Divider().frame(height: 58)
        downloadTraffic
      }
    }
  }

  private var uploadTraffic: some View {
    trafficValue(
      title: "上传",
      symbol: "arrow.up",
      color: HushWireTheme.primary,
      rate: controller.uploadRate,
      total: controller.totalUploadBytes
    )
  }

  private var downloadTraffic: some View {
    trafficValue(
      title: "下载",
      symbol: "arrow.down",
      color: HushWireTheme.healthy,
      rate: controller.downloadRate,
      total: controller.totalDownloadBytes
    )
  }

  private var recentActivitySection: some View {
    VStack(spacing: 9) {
      HushWireSectionLabel(title: "最近活动")
      HushWireCard {
        if controller.events.isEmpty {
          Text("还没有会话活动")
            .foregroundStyle(.secondary)
            .padding(16)
        } else {
          ForEach(Array(controller.events.prefix(8).enumerated()), id: \.element.id) {
            index, event in
            if index > 0 { HushWireDivider() }
            HStack(alignment: .top, spacing: 12) {
              Circle()
                .fill(eventColor(event.kind))
                .frame(width: 8, height: 8)
                .padding(.top, 6)
              Text(event.message)
                .font(.subheadline)
                .fixedSize(horizontal: false, vertical: true)
              Spacer(minLength: 8)
              Text(event.date, style: .time)
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
          }
        }
      }
    }
  }

  private func trafficValue(
    title: String,
    symbol: String,
    color: Color,
    rate: Double,
    total: UInt64
  ) -> some View {
    VStack(alignment: .leading, spacing: 4) {
      Label(title, systemImage: symbol)
        .font(.caption)
        .foregroundStyle(color)
      Text(HushWireFormatters.rate(rate))
        .font(.title3.monospacedDigit().weight(.semibold))
      Text(HushWireFormatters.bytes(total))
        .font(.caption.monospacedDigit())
        .foregroundStyle(.secondary)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
    .padding(.horizontal, 16)
    .accessibilityElement(children: .combine)
  }

  private var healthTitle: String {
    switch controller.connectionPhase {
    case .connected: "隧道健康"
    case .recovering: "正在自动恢复"
    case .connecting: "正在认证"
    case .disconnecting: "正在安全断开"
    case .failed: "需要检查"
    case .disconnected: "当前未连接"
    case .noConfiguration: "等待配置"
    }
  }

  private var healthDetail: String {
    if let peer = controller.peerSessions.first {
      return "最近认证流量：\(peer.healthDescription)"
    }
    return controller.activity
  }

  private var healthSymbol: String {
    switch controller.connectionPhase {
    case .connected: "checkmark.circle.fill"
    case .recovering: "arrow.triangle.2.circlepath.circle.fill"
    case .failed: "exclamationmark.circle.fill"
    case .connecting, .disconnecting: "clock.fill"
    default: "minus.circle.fill"
    }
  }

  private var healthColor: Color {
    switch controller.connectionPhase {
    case .connected: HushWireTheme.healthy
    case .recovering: HushWireTheme.warning
    case .failed: .red
    case .connecting: HushWireTheme.primary
    default: .secondary
    }
  }

  private var directRouteSummary: String {
    guard let routes = controller.profileInspection?.summary.directRoutes else { return "未知" }
    return routes.isEmpty ? "无" : "\(routes.count) 条"
  }

  private func eventColor(_ kind: HushWireActivityEvent.Kind) -> Color {
    switch kind {
    case .info: HushWireTheme.primary
    case .success: HushWireTheme.healthy
    case .warning: HushWireTheme.warning
    case .failure: .red
    }
  }
}
