import SwiftUI

@main
struct HushWireSystemApp: App {
  @StateObject private var controller = SystemExtensionController()

  var body: some Scene {
    WindowGroup {
      SystemExtensionContentView(controller: controller)
        .frame(minWidth: 760, minHeight: 600)
    }
    .defaultSize(width: 900, height: 760)
    .windowResizability(.contentMinSize)
  }
}
