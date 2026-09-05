import XCTest

final class HushWireIOSVisualUITests: XCTestCase {
  override func setUp() {
    continueAfterFailure = false
  }

  /// Visits every primary tab without changing the saved VPN configuration.
  ///
  /// The screenshots make layout regressions easy to inspect in the result
  /// bundle, while the assertions catch tabs that become inaccessible.
  @MainActor
  func testPrimaryScreensAreReachable() {
    let app = XCUIApplication()
    app.launch()

    captureScreen(named: "Connection")

    let configurationTab = app.tabBars.buttons["配置"]
    XCTAssertTrue(configurationTab.waitForExistence(timeout: 8))
    configurationTab.tap()
    captureScreen(named: "Configuration")

    let diagnosticsTab = app.tabBars.buttons["诊断"]
    XCTAssertTrue(diagnosticsTab.waitForExistence(timeout: 8))
    diagnosticsTab.tap()
    captureScreen(named: "Diagnostics")
  }

  private func captureScreen(named name: String) {
    let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
    attachment.name = name
    attachment.lifetime = .keepAlways
    add(attachment)
  }
}
