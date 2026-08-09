import Foundation

enum HushWireConfigurationStore {
  static let appGroupIdentifier = "95Q852BXKJ.com.jamie.HushWire.shared"
  static let providerStorageKind = "app-group-v1"
  static let routePolicy = "host-routes-only"

  private static let directoryComponents = ["Library", "Application Support", "HushWire"]
  private static let configurationFileName = "active.toml"

  static func load() throws -> Data {
    try Data(contentsOf: configurationURL())
  }

  @discardableResult
  static func install(_ data: Data) throws -> URL {
    let fileManager = FileManager.default
    let directory = try configurationDirectoryURL()
    try fileManager.createDirectory(
      at: directory,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)

    let destination = directory.appendingPathComponent(configurationFileName, isDirectory: false)
    try data.write(to: destination, options: [.atomic])
    try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
    return destination
  }

  static func exists() -> Bool {
    (try? configurationURL()).map { FileManager.default.fileExists(atPath: $0.path) } ?? false
  }

  private static func configurationURL() throws -> URL {
    try configurationDirectoryURL()
      .appendingPathComponent(configurationFileName, isDirectory: false)
  }

  private static func configurationDirectoryURL() throws -> URL {
    guard
      var url = FileManager.default.containerURL(
        forSecurityApplicationGroupIdentifier: appGroupIdentifier
      )
    else {
      throw NSError(
        domain: "com.jamie.HushWire.ConfigurationStore",
        code: 1,
        userInfo: [NSLocalizedDescriptionKey: "无法访问 HushWire App Group 配置容器。"]
      )
    }
    for component in directoryComponents {
      url.appendPathComponent(component, isDirectory: true)
    }
    return url
  }
}
