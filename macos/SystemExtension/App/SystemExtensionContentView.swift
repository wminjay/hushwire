import NetworkExtension
import SwiftUI
import UniformTypeIdentifiers

struct SystemExtensionContentView: View {
  @ObservedObject var controller: SystemExtensionController
  @State private var isImportingConfiguration = false

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
            Text("0.7.0 开发预览 · /32 Packet Flow 阶段")
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

        GroupBox("隧道配置（不显示密钥）") {
          if let summary = controller.configurationSummary {
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
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
              }
              GridRow {
                Text("允许路由").foregroundStyle(.secondary)
                Text(summary.routeDescription)
                  .font(.system(.body, design: .monospaced))
              }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
          } else {
            Text("尚未导入配置。当前阶段只接受 /32 主机路由和本地端口 0。")
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
            controller.startTunnel()
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
          "安全边界：仅安装 TOML 中的 /32 路由；不设置 0.0.0.0/0、不修改 DNS，也不运行提权脚本。",
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
}
