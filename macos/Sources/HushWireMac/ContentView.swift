import AppKit
import SwiftUI

struct ContentView: View {
  @ObservedObject var controller: TunnelController

  var body: some View {
    VStack(spacing: 16) {
      header
      configuration
      actions
      activity
    }
    .padding(20)
    .background(Color(nsColor: .windowBackgroundColor))
  }

  private var header: some View {
    HStack(spacing: 12) {
      ZStack {
        Circle()
          .fill(statusColor.opacity(0.16))
          .frame(width: 42, height: 42)
        Image(systemName: controller.state.isConnected ? "lock.shield.fill" : "lock.shield")
          .font(.system(size: 20, weight: .semibold))
          .foregroundStyle(statusColor)
      }

      VStack(alignment: .leading, spacing: 2) {
        Text("HushWire")
          .font(.title2.weight(.semibold))
        Text(controller.state.title)
          .font(.subheadline)
          .foregroundStyle(statusColor)
      }

      Spacer()

      if controller.isBusy {
        ProgressView()
          .controlSize(.small)
      }

      Text("个人版")
        .font(.caption.weight(.medium))
        .padding(.horizontal, 9)
        .padding(.vertical, 5)
        .background(.quaternary, in: Capsule())
    }
  }

  private var configuration: some View {
    GroupBox("连接配置") {
      VStack(alignment: .leading, spacing: 10) {
        HStack(spacing: 10) {
          Image(systemName: "doc.text")
            .foregroundStyle(.secondary)

          Text(controller.configDisplayPath)
            .font(.system(.body, design: .monospaced))
            .lineLimit(1)
            .truncationMode(.middle)
            .foregroundStyle(controller.configURL == nil ? .secondary : .primary)

          Spacer(minLength: 8)

          Button("显示") {
            controller.revealConfiguration()
          }
          .disabled(controller.configURL == nil)

          Button("选择…") {
            controller.chooseConfiguration()
          }
        }

        Text("配置文件包含私钥和预共享密钥，请只保存在你信任的位置。")
          .font(.caption)
          .foregroundStyle(.secondary)
      }
      .padding(.top, 4)
    }
  }

  private var actions: some View {
    HStack(spacing: 10) {
      Button {
        controller.validateConfiguration()
      } label: {
        Label("检查配置", systemImage: "checkmark.circle")
      }
      .disabled(controller.configURL == nil || controller.isBusy)

      Button {
        controller.generateKeyPair()
      } label: {
        Label("生成密钥", systemImage: "key")
      }
      .disabled(controller.isBusy)

      Spacer()

      if controller.state.isConnected {
        Button(role: .destructive) {
          controller.disconnect()
        } label: {
          Label("断开", systemImage: "stop.fill")
        }
        .keyboardShortcut(".", modifiers: [.command])
        .disabled(controller.isBusy)
      } else {
        Button {
          controller.connect()
        } label: {
          Label("连接", systemImage: "play.fill")
        }
        .keyboardShortcut(.defaultAction)
        .buttonStyle(.borderedProminent)
        .disabled(controller.configURL == nil || controller.isBusy)
      }
    }
  }

  private var activity: some View {
    GroupBox {
      VStack(alignment: .leading, spacing: 8) {
        HStack {
          Label("运行记录", systemImage: "waveform.path.ecg")
            .font(.headline)
          Spacer()
          if let pid = controller.runningPID {
            Text("PID \(pid)")
              .font(.caption.monospacedDigit())
              .foregroundStyle(.secondary)
          }
          Button("清空显示") {
            controller.clearDisplay()
          }
          .controlSize(.small)
        }

        ScrollView {
          Text(controller.displayText)
            .font(.system(size: 11, design: .monospaced))
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .topLeading)
            .padding(10)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
        .overlay {
          RoundedRectangle(cornerRadius: 6)
            .stroke(.separator.opacity(0.6), lineWidth: 1)
        }

        HStack {
          Text(controller.statusMessage)
            .font(.caption)
            .foregroundStyle(controller.lastOperationFailed ? Color.red : Color.secondary)
            .lineLimit(1)
          Spacer()
          Button("打开日志目录") {
            controller.openLogDirectory()
          }
          .font(.caption)
          .buttonStyle(.link)
        }
      }
      .padding(.top, 2)
    }
  }

  private var statusColor: Color {
    switch controller.state {
    case .disconnected:
      return .secondary
    case .connecting, .stopping:
      return .orange
    case .connected:
      return .green
    }
  }
}
