import SwiftUI

@main
struct HushWireMacApp: App {
  @StateObject private var controller = TunnelController()

  var body: some Scene {
    WindowGroup {
      ContentView(controller: controller)
        .frame(minWidth: 680, minHeight: 520)
    }
    .windowResizability(.contentMinSize)

    Settings {
      SettingsView(controller: controller)
    }
  }
}

private struct SettingsView: View {
  @ObservedObject var controller: TunnelController

  var body: some View {
    Form {
      Toggle("连接成功后隐藏窗口", isOn: $controller.hideAfterConnecting)
      Text("退出客户端不会强制断开正在运行的隧道。重新打开客户端后仍可查看并断开它。")
        .font(.caption)
        .foregroundStyle(.secondary)
    }
    .padding(20)
    .frame(width: 440)
  }
}
