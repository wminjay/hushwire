import Foundation
import Security

enum HushWireConfigurationStoreError: LocalizedError, Equatable {
  case notFound
  case keychain(OSStatus)

  var errorDescription: String? {
    switch self {
    case .notFound:
      "找不到安全保存的隧道配置。"
    case .keychain(let status):
      SecCopyErrorMessageString(status, nil) as String?
        ?? "Keychain 操作失败（\(status)）。"
    }
  }
}

/// The app and Packet Tunnel extension share only the selected TOML through a
/// code-signing-protected Keychain access group. Nothing secret is copied into
/// `NETunnelProviderProtocol` preferences or tunnel start options.
enum HushWireConfigurationStore {
  static let providerStorageKind = "shared-keychain-v1"
  static let legacyProviderStorageKind = "app-message-v1"
  static let keychainAccessGroup = "95Q852BXKJ.com.jamie.HushWire.shared"
  static let activeProfileIDKey = "activeProfileID"
  static let onDemandStartAuthorizedKey = "onDemandStartAuthorized"

  private static let keychainService = "com.jamie.HushWire.iOS.configuration"

  static func load(for profileID: UUID) throws -> Data {
    var query = keychainQuery(for: profileID)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status != errSecItemNotFound else {
      throw HushWireConfigurationStoreError.notFound
    }
    guard status == errSecSuccess, let data = result as? Data else {
      throw HushWireConfigurationStoreError.keychain(status)
    }
    return data
  }

  static func store(_ configuration: Data, for profileID: UUID) throws {
    let query = keychainQuery(for: profileID)
    let attributes: [String: Any] = [
      kSecValueData as String: configuration,
      // On Demand may launch the extension while the device is locked. This
      // remains device-only and becomes available only after the first unlock.
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    if updateStatus == errSecSuccess { return }
    guard updateStatus == errSecItemNotFound else {
      throw HushWireConfigurationStoreError.keychain(updateStatus)
    }

    var newItem = query
    for (key, value) in attributes {
      newItem[key] = value
    }
    let addStatus = SecItemAdd(newItem as CFDictionary, nil)
    guard addStatus == errSecSuccess else {
      throw HushWireConfigurationStoreError.keychain(addStatus)
    }
  }

  static func delete(for profileID: UUID) throws {
    let status = SecItemDelete(keychainQuery(for: profileID) as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw HushWireConfigurationStoreError.keychain(status)
    }
  }

  private static func keychainQuery(for profileID: UUID) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: keychainService,
      kSecAttrAccount as String: profileID.uuidString,
      kSecAttrAccessGroup as String: keychainAccessGroup,
      kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
    ]
  }
}
