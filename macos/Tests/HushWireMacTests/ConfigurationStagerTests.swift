import Foundation
import XCTest

@testable import HushWireMac

final class ConfigurationStagerTests: XCTestCase {
  func testStagesPrivateCopyAndRemovesItAfterUse() throws {
    let fileManager = FileManager.default
    let testDirectory = fileManager.temporaryDirectory.appendingPathComponent(
      "hushwire-stager-test-\(UUID().uuidString)",
      isDirectory: true
    )
    try fileManager.createDirectory(at: testDirectory, withIntermediateDirectories: false)
    defer { try? fileManager.removeItem(at: testDirectory) }

    let sourceURL = testDirectory.appendingPathComponent("source.toml")
    let expected = Data("private_key = \"test-secret\"\n".utf8)
    try expected.write(to: sourceURL)

    let staged = try ConfigurationStager.stage(
      sourceURL: sourceURL,
      userID: 501,
      baseDirectory: testDirectory
    )
    XCTAssertNotEqual(staged.fileURL, sourceURL)
    XCTAssertEqual(try Data(contentsOf: staged.fileURL), expected)

    let directoryAttributes = try fileManager.attributesOfItem(atPath: staged.directoryURL.path)
    let fileAttributes = try fileManager.attributesOfItem(atPath: staged.fileURL.path)
    let directoryMode = (directoryAttributes[.posixPermissions] as? NSNumber)?.intValue
    let fileMode = (fileAttributes[.posixPermissions] as? NSNumber)?.intValue
    XCTAssertEqual(directoryMode, 0o700)
    XCTAssertEqual(fileMode, 0o600)

    staged.remove()
    XCTAssertFalse(fileManager.fileExists(atPath: staged.directoryURL.path))
    XCTAssertTrue(fileManager.fileExists(atPath: sourceURL.path))
  }

  func testFailedReadDoesNotLeaveAStagingDirectory() throws {
    let fileManager = FileManager.default
    let testDirectory = fileManager.temporaryDirectory.appendingPathComponent(
      "hushwire-stager-test-\(UUID().uuidString)",
      isDirectory: true
    )
    try fileManager.createDirectory(at: testDirectory, withIntermediateDirectories: false)
    defer { try? fileManager.removeItem(at: testDirectory) }

    let missingSource = testDirectory.appendingPathComponent("missing.toml")
    XCTAssertThrowsError(
      try ConfigurationStager.stage(
        sourceURL: missingSource,
        userID: 501,
        baseDirectory: testDirectory
      )
    )
    XCTAssertTrue(try fileManager.contentsOfDirectory(atPath: testDirectory.path).isEmpty)
  }
}
