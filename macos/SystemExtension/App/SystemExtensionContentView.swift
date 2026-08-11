import NetworkExtension
import SwiftUI
import UniformTypeIdentifiers

struct SystemExtensionContentView: View {
  @ObservedObject var controller: SystemExtensionController
  @State private var isImportingConfiguration = false
  @State private var isConfirmingFullTunnelConnection = false
  @State private var isShowingAllRoutes = false
  @State private var isShowingAllDirectRoutes = false

  var body: some View {
    ScrollView(.vertical) {
      VStack(alignment: .leading, spacing: 16) {
        HStack(spacing: 12) {
          Image(systemName: "network.badge.shield.half.filled")
            .font(.system(size: 30))
            .foregroundStyle(.blue)
          VStack(alignment: .leading, spacing: 2) {
            Text("HushWire System Extension")
              .font(.title2.weight(.semibold))
            Text("开发预览 · 自定义分流阶段")
              .foregroundStyle(.secondary)
          }
          Spacer()
          if controller.isBusy {
            ProgressView()
              .controlSize(.small)
          }
        }

        GroupBox("系统状态") {
          Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
            GridRow {
              Text("System Extension").foregroundStyle(.secondary)
              Text(controller.installationState.title)
            }
            GridRow {
              Text("VPN 状态").foregroundStyle(.secondary)
              Text(controller.vpnStatusTitle)
            }
            GridRow {
              Text("扩展标识").foregroundStyle(.secondary)
              Text(SystemExtensionConstants.extensionBundleIdentifier)
                .font(.system(.body, design: .monospaced))
            }
          }
          .frame(maxWidth: .infinity, alignment: .leading)
          .padding(.top, 3)
        }

        GroupBox("网络策略") {
          VStack(alignment: .leading, spacing: 10) {
            Picker(
              "路由模式",
              selection: Binding(
                get: { controller.selectedRoutePolicy },
                set: { controller.selectRoutePolicy($0) }
              )
            ) {
              ForEach(HushWireRoutePolicy.allCases) { policy in
                Text(policy.title).tag(policy)
              }
            }
            .pickerStyle(.segmented)
            .disabled(!controller.canEditNetworkPolicy)

            Text(controller.selectedRoutePolicy.detail)
              .font(.caption)
              .foregroundStyle(.secondary)

            LabeledContent("DNS 服务器") {
              TextField("留空则保持系统 DNS；例如 1.1.1.1, 1.0.0.1", text: $controller.dnsServersText)
                .textFieldStyle(.roundedBorder)
                .disabled(
                  !controller.canEditNetworkPolicy || !controller.canConfigureDNS
                )
            }
          }
          .frame(maxWidth: .infinity, alignment: .leading)
          .padding(.top, 3)
        }

        GroupBox("隧道配置（不显示密钥）") {
          if let summary = controller.configurationSummary {
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
              GridRow {
                Text("模式").foregroundStyle(.secondary)
                Text(summary.routePolicy.title)
              }
              GridRow {
                Text("接口").foregroundStyle(.secondary)
                Text(summary.interface).font(.system(.body, design: .monospaced))
              }
              GridRow {
                Text("传输 / MTU").foregroundStyle(.secondary)
                Text("\(summary.transport) / \(summary.mtu)")
              }
              GridRow {
                Text("Peer / Endpoint").foregroundStyle(.secondary)
                Text("\(summary.peerCount) / \(summary.endpointDescription)")
                  .font(.system(.body, design: .monospaced))
                  .lineLimit(2)
                  .truncationMode(.middle)
                  .textSelection(.enabled)
              }
              GridRow {
                Text("允许路由").foregroundStyle(.secondary)
                Text(summary.routeDescription)
                  .font(.system(.body, design: .monospaced))
                  .lineLimit(3)
                  .truncationMode(.middle)
                  .textSelection(.enabled)
              }
              GridRow {
                Text("直连例外").foregroundStyle(.secondary)
                Text(summary.directRouteDescription)
                  .font(.system(.body, design: .monospaced))
                  .lineLimit(3)
                  .truncationMode(.middle)
                  .textSelection(.enabled)
              }
              GridRow {
                Text("DNS").foregroundStyle(.secondary)
                Text(summary.dnsDescription)
                  .font(.system(.body, design: .monospaced))
              }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if summary.routes.count > 6 {
              DisclosureGroup(
                "查看全部 \(summary.routes.count) 条路由",
                isExpanded: $isShowingAllRoutes
              ) {
                ScrollView([.horizontal, .vertical]) {
                  Text(summary.routes.joined(separator: "\n"))
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 4)
                }
                .frame(maxHeight: 180)
              }
              .font(.caption)
              .padding(.top, 8)
            }
            if summary.directRoutes.count > 6 {
              DisclosureGroup(
                "查看全部 \(summary.directRoutes.count) 条直连例外",
                isExpanded: $isShowingAllDirectRoutes
              ) {
                ScrollView([.horizontal, .vertical]) {
                  Text(summary.directRoutes.joined(separator: "\n"))
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 4)
                }
                .frame(maxHeight: 180)
              }
              .font(.caption)
              .padding(.top, 8)
            }
          } else {
            Text("尚未导入与当前网络策略匹配的配置；本地监听端口必须为 0。")
              .foregroundStyle(.secondary)
              .frame(maxWidth: .infinity, alignment: .leading)
          }
        }

        if controller.vpnStatus == .connected || !controller.peerStatuses.isEmpty {
          GroupBox("实时会话") {
            VStack(alignment: .leading, spacing: 8) {
              if !controller.lastHandshake.isEmpty {
                LabeledContent("最近握手", value: controller.lastHandshake)
              }
              if controller.peerStatuses.isEmpty {
                Text("等待握手或认证流量…")
                  .foregroundStyle(.secondary)
              } else {
                ForEach(controller.peerStatuses) { peer in
                  Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 4) {
                    GridRow {
                      Text(peer.name).fontWeight(.medium)
                      Text(peer.endpoint ?? "endpoint 未确认")
                        .font(.system(.body, design: .monospaced))
                    }
                    GridRow {
                      Text(peer.lastSeenDescription).foregroundStyle(.secondary)
                      Text(peer.trafficDescription).foregroundStyle(.secondary)
                    }
                  }
                }
              }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
          }
        }

        HStack(spacing: 10) {
          Button("激活扩展") {
            controller.requestSystemExtensionActivation()
          }
          .disabled(controller.isBusy)

          Button("导入 TOML…") {
            isImportingConfiguration = true
          }
          .disabled(controller.isBusy)

          Button("保存 VPN 配置") {
            controller.saveVPNConfiguration()
          }
          .disabled(controller.isBusy || controller.configurationSummary == nil)

          Spacer()

          Button(connectButtonTitle) {
            if controller.isFullTunnelSelected {
              isConfirmingFullTunnelConnection = true
            } else {
              controller.startTunnel()
            }
          }
          .buttonStyle(.borderedProminent)
          .disabled(
            controller.isBusy
              || controller.configurationSummary == nil
              || controller.vpnStatus == .connecting
              || controller.vpnStatus == .connected
          )

          Button("断开") {
            controller.stopTunnel()
          }
          .disabled(
            controller.vpnStatus == .invalid || controller.vpnStatus == .disconnected
          )
        }

        GroupBox("活动记录") {
          Text(controller.activity)
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, minHeight: 44, alignment: .topLeading)
            .padding(.top, 3)
        }

        Label(
          safetyBoundaryText,
          systemImage: "checkmark.shield"
        )
        .font(.caption)
        .foregroundStyle(.secondary)
      }
      .frame(maxWidth: .infinity, alignment: .topLeading)
      .padding(22)
    }
    .scrollBounceBehavior(.basedOnSize)
    .fileImporter(
      isPresented: $isImportingConfiguration,
      allowedContentTypes: [UTType(filenameExtension: "toml") ?? .plainText],
      allowsMultipleSelection: false
    ) { result in
      switch result {
      case .success(let urls):
        if let url = urls.first {
          controller.importConfiguration(from: url)
        }
      case .failure(let error):
        // A cancelled picker needs no status mutation; genuine picker errors
        // are surfaced through the system dialog.
        _ = error
      }
    }
    .alert("确认启用 IPv4 默认隧道？", isPresented: $isConfirmingFullTunnelConnection) {
      Button("取消", role: .cancel) {}
      Button("连接并接管 IPv4 流量", role: .destructive) {
        controller.startTunnel()
      }
    } message: {
      Text(
        "此操作会把 IPv4 默认路由交给 HushWire；TOML 的 excluded_ips 与 Peer endpoint 保持直连。DNS 是否修改取决于上方设置。请仅在已验证的服务端和可恢复网络环境中使用。"
      )
    }
  }

  private var connectButtonTitle: String {
    switch controller.vpnStatus {
    case .connecting:
      return "正在启动…"
    case .connected:
      return controller.providerReady ? "已连接" : "正在配置…"
    case .reasserting:
      return "正在恢复…"
    default:
      return "连接"
    }
  }

  private var safetyBoundaryText: String {
    switch controller.selectedRoutePolicy {
    case .hostRoutesOnly:
      return "主机路由边界：仅安装 TOML 中的 /32 路由；不设置默认路由、不修改 DNS，也不运行提权脚本。"
    case .splitRoutes:
      return "分流边界：单 Peer、最多 256 条非默认 IPv4 CIDR；认证后才安装路由与可选 DNS；自动排除被路由覆盖的 endpoint。"
    case .fullTunnel:
      return "默认隧道边界：单 Peer、恰好一条 0.0.0.0/0；可用更具体规则覆盖 excluded_ips；认证后才接管流量。"
    }
  }
}
