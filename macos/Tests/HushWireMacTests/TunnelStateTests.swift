import XCTest

@testable import HushWireMac

final class TunnelStateTests: XCTestCase {
  func testConnectedStateExposesConnectionAndLocalizedTitle() {
    let state = TunnelState.connected(pid: 42)

    XCTAssertTrue(state.isConnected)
    XCTAssertEqual(state.title, "已连接")
  }

  func testNonConnectedStatesExposeExpectedTitles() {
    XCTAssertFalse(TunnelState.disconnected.isConnected)
    XCTAssertEqual(TunnelState.disconnected.title, "未连接")
    XCTAssertEqual(TunnelState.connecting.title, "正在连接")
    XCTAssertEqual(TunnelState.stopping.title, "正在断开")
  }
}
