import Foundation

struct StagedConfiguration {
  let fileURL: URL
  let directoryURL: URL

  func remove() {
    try? FileManager.default.removeItem(at: directoryURL)
  }
}

enum ConfigurationStager {
  static func stage(
    sourceURL: URL,
    userID: uid_t,
    baseDirectory: URL = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
  ) throws -> StagedConfiguration {
    let fileManager = FileManager.default
    let directoryURL = baseDirectory.appendingPathComponent(
      "hushwire-\(userID)-\(UUID().uuidString)",
      isDirectory: true
    )

    try fileManager.createDirectory(
      at: directoryURL,
      withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700]
    )

    do {
      // Read while the GUI still has the user's normal file access. The
      // privileged child may be denied access to external volumes, Desktop,
      // or Documents by macOS privacy controls even after authorization.
      let contents = try Data(contentsOf: sourceURL)
      let fileURL = directoryURL.appendingPathComponent("config.toml", isDirectory: false)
      try contents.write(to: fileURL, options: .atomic)
      try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
      return StagedConfiguration(fileURL: fileURL, directoryURL: directoryURL)
    } catch {
      try? fileManager.removeItem(at: directoryURL)
      throw error
    }
  }
}
