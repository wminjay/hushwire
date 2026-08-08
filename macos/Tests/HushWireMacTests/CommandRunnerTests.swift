import Foundation
import XCTest

@testable import HushWireMac

final class CommandRunnerTests: XCTestCase {
  func testArgumentsArePassedLiterallyWithoutShellInterpretation() {
    let literal = "value with spaces; $(not-a-command) 'quoted'"
    let result = CommandRunner.run(
      executable: URL(fileURLWithPath: "/usr/bin/printf"),
      arguments: ["%s", literal]
    )

    XCTAssertTrue(result.succeeded)
    XCTAssertEqual(result.output, literal)
  }

  func testMissingExecutableReturnsACommandNotFoundStatus() {
    let result = CommandRunner.run(
      executable: URL(fileURLWithPath: "/path/that/does/not/exist"),
      arguments: []
    )

    XCTAssertEqual(result.exitCode, 127)
    XCTAssertFalse(result.output.isEmpty)
  }
}
