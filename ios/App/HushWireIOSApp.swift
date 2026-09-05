import SwiftUI
import UniformTypeIdentifiers

enum HushWireTab: Hashable {
  case connection
  case configuration
  case diagnostics
}

@main
struct HushWireIOSApp: App {
  @StateObject private var controller = HushWireIOSController()
  @State private var selectedTab = HushWireTab.connection
  @State private var showingImporter = false

  var body: some Scene {
    WindowGroup {
      TabView(selection: $selectedTab) {
        HushWireConnectionView(
          controller: controller,
          selectedTab: $selectedTab,
          importAction: { showingImporter = true }
        )
        .tag(HushWireTab.connection)
        .tabItem {
          Label("连接", systemImage: "shield.lefthalf.filled")
        }

        HushWireConfigurationView(
          controller: controller,
          importAction: { showingImporter = true }
        )
        .tag(HushWireTab.configuration)
        .tabItem {
          Label("配置", systemImage: "slider.horizontal.3")
        }

        HushWireDiagnosticsView(controller: controller)
          .tag(HushWireTab.diagnostics)
          .tabItem {
            Label("诊断", systemImage: "waveform.path.ecg")
          }
      }
      .tint(HushWireTheme.primary)
      .fileImporter(
        isPresented: $showingImporter,
        allowedContentTypes: [.hushWireTOML, .plainText],
        allowsMultipleSelection: false
      ) { result in
        switch result {
        case .success(let urls):
          if let url = urls.first {
            controller.importConfiguration(from: url)
          }
        case .failure(let error):
          controller.reportImportFailure(error)
        }
      }
      .onOpenURL { url in
        controller.importConfiguration(from: url)
      }
    }
  }
}

extension UTType {
  fileprivate static var hushWireTOML: UTType {
    UTType(filenameExtension: "toml") ?? .plainText
  }
}
