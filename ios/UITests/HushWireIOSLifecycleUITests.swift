import XCTest

final class HushWireIOSLifecycleUITests: XCTestCase {
  override func setUp() {
    continueAfterFailure = false
  }

  /// Exercises the real NetworkExtension controls on a provisioned device.
  ///
  /// The test intentionally accepts either an already-connected or a
  /// disconnected starting state. It always leaves the tunnel disconnected.
  @MainActor
  func testConnectAndDisconnectProvisionedTunnel() {
    let app = XCUIApplication()
    app.launch()

    let connectButton = app.buttons["hushwire.connect"]
    let disconnectButton = app.buttons["hushwire.disconnect"]

    if disconnectButton.waitForExistence(timeout: 8) {
      XCTAssertTrue(disconnectButton.isHittable)
      disconnectButton.tap()
      XCTAssertTrue(
        connectButton.waitForExistence(timeout: 30),
        "The app did not return to its disconnected state."
      )
    } else {
      XCTAssertTrue(
        connectButton.waitForExistence(timeout: 8),
        "Neither the connect nor disconnect control became available."
      )
    }

    XCTAssertTrue(connectButton.isEnabled)
    XCTAssertTrue(connectButton.isHittable)
    connectButton.tap()
    confirmFullTunnelIfPresented(in: app)

    XCTAssertTrue(
      disconnectButton.waitForExistence(timeout: 30),
      "The provisioned tunnel did not reach its connected state."
    )
    XCTAssertTrue(disconnectButton.isHittable)
    disconnectButton.tap()

    XCTAssertTrue(
      connectButton.waitForExistence(timeout: 30),
      "The tunnel did not finish its final disconnect."
    )
    XCTAssertTrue(connectButton.isEnabled)
  }

  /// Waits for externally generated tunnel packets and verifies that the
  /// provider's receive counter is reflected by the real app UI.
  ///
  /// The paired integration harness sends packets from the configured peer
  /// after this test reaches the connected state.
  @MainActor
  func testDownloadCounterReflectsTunnelTraffic() {
    let app = XCUIApplication()
    app.launch()

    let connectButton = app.buttons["hushwire.connect"]
    let disconnectButton = app.buttons["hushwire.disconnect"]
    if disconnectButton.waitForExistence(timeout: 8) {
      disconnectButton.tap()
      XCTAssertTrue(connectButton.waitForExistence(timeout: 30))
    } else {
      XCTAssertTrue(connectButton.waitForExistence(timeout: 8))
    }

    connectButton.tap()
    confirmFullTunnelIfPresented(in: app)
    XCTAssertTrue(
      disconnectButton.waitForExistence(timeout: 30),
      "The provisioned tunnel did not reach its connected state."
    )

    let uploadMetric = app.descendants(matching: .any)["hushwire.traffic.upload"]
    let downloadMetric = app.descendants(matching: .any)["hushwire.traffic.download"]
    XCTAssertTrue(uploadMetric.waitForExistence(timeout: 8))
    XCTAssertTrue(downloadMetric.waitForExistence(timeout: 8))

    let initialUpload = uploadMetric.label
    let initialDownload = downloadMetric.label
    let deadline = Date().addingTimeInterval(45)
    while Date() < deadline, downloadMetric.label.contains("累计 0 B") {
      Thread.sleep(forTimeInterval: 1)
    }

    // Keep the tunnel alive briefly after the first observed packet so the
    // external sender can finish its deterministic burst before teardown.
    if !downloadMetric.label.contains("累计 0 B") {
      Thread.sleep(forTimeInterval: 3)
    }

    let finalUpload = uploadMetric.label
    let finalDownload = downloadMetric.label
    print("HUSHWIRE_TRAFFIC_INITIAL upload=\(initialUpload) download=\(initialDownload)")
    print("HUSHWIRE_TRAFFIC_FINAL upload=\(finalUpload) download=\(finalDownload)")
    XCTAssertFalse(
      finalDownload.contains("累计 0 B"),
      "The UI download total stayed at zero after authenticated tunnel packets arrived."
    )

    disconnectButton.tap()
    XCTAssertTrue(
      connectButton.waitForExistence(timeout: 30),
      "The tunnel did not finish disconnecting after the traffic test."
    )
  }

  /// Establishes the selected provisioned profile and deliberately leaves the
  /// Packet Tunnel running for external route and egress verification.
  @MainActor
  func testConnectProvisionedTunnelAndLeaveRunning() {
    let app = XCUIApplication()
    app.launch()

    let connectButton = app.buttons["hushwire.connect"]
    let disconnectButton = app.buttons["hushwire.disconnect"]
    if disconnectButton.waitForExistence(timeout: 8) {
      disconnectButton.tap()
      XCTAssertTrue(connectButton.waitForExistence(timeout: 30))
    } else {
      XCTAssertTrue(connectButton.waitForExistence(timeout: 8))
    }

    connectButton.tap()
    confirmFullTunnelIfPresented(in: app)
    XCTAssertTrue(
      disconnectButton.waitForExistence(timeout: 30),
      "The provisioned tunnel did not reach its connected state."
    )
  }

  @MainActor
  private func confirmFullTunnelIfPresented(in app: XCUIApplication) {
    let confirmation = app.buttons["hushwire.full-tunnel.confirm"]
    if confirmation.waitForExistence(timeout: 2) {
      XCTAssertTrue(confirmation.isHittable)
      confirmation.tap()
    }
  }
}
