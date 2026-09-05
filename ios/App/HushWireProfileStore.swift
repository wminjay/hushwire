import Foundation
import Security

enum HushWireProfileStoreError: LocalizedError {
  case metadataUnreadable
  case profileNotFound
  case keychain(OSStatus)

  var errorDescription: String? {
    switch self {
    case .metadataUnreadable:
      "配置索引无法读取。"
    case .profileNotFound:
      "找不到所选配置，可能已被删除。"
    case .keychain(let status):
      SecCopyErrorMessageString(status, nil) as String?
        ?? "Keychain 操作失败（\(status)）。"
    }
  }
}

enum HushWireProfileStore {
  private struct MetadataEnvelope: Codable {
    let schemaVersion: Int
    var profiles: [HushWireProfile]
  }

  private static let metadataKey = "hushwire.ios.profile-metadata-v1"
  private static let selectedProfileKey = "hushwire.ios.selected-profile-v1"
  private static let legacyKeychainService = "com.jamie.HushWire.iOS.configuration"
  private static let legacyKeychainAccessGroup =
    "95Q852BXKJ.com.jamie.HushWire.iOS"

  static func loadProfiles() throws -> [HushWireProfile] {
    guard let data = UserDefaults.standard.data(forKey: metadataKey) else { return [] }
    guard
      let envelope = try? JSONDecoder().decode(MetadataEnvelope.self, from: data),
      (1...3).contains(envelope.schemaVersion)
    else {
      throw HushWireProfileStoreError.metadataUnreadable
    }
    return envelope.profiles.sorted {
      if $0.updatedAt != $1.updatedAt { return $0.updatedAt > $1.updatedAt }
      return $0.name.localizedStandardCompare($1.name) == .orderedAscending
    }
  }

  static func configuration(for profileID: UUID) throws -> Data {
    do {
      return try HushWireConfigurationStore.load(for: profileID)
    } catch HushWireConfigurationStoreError.notFound {
      // Profiles imported before On Demand auto-connect lived in the app's
      // private Keychain group. Migrate only after the shared write succeeds.
      let configuration = try legacyConfiguration(for: profileID)
      do {
        try HushWireConfigurationStore.store(configuration, for: profileID)
      } catch let error as HushWireConfigurationStoreError {
        throw mapSharedStoreError(error)
      }
      let deleteStatus = SecItemDelete(legacyKeychainQuery(for: profileID) as CFDictionary)
      guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
        throw HushWireProfileStoreError.keychain(deleteStatus)
      }
      return configuration
    } catch let error as HushWireConfigurationStoreError {
      throw mapSharedStoreError(error)
    }
  }

  private static func legacyConfiguration(for profileID: UUID) throws -> Data {
    var query = legacyKeychainQuery(for: profileID)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status != errSecItemNotFound else {
      throw HushWireProfileStoreError.profileNotFound
    }
    guard status == errSecSuccess, let data = result as? Data else {
      throw HushWireProfileStoreError.keychain(status)
    }
    return data
  }

  static func add(
    configuration: Data,
    name: String,
    inspection: HushWireProfileInspection
  ) throws -> HushWireProfile {
    let now = Date()
    let profile = HushWireProfile(
      name: uniqueName(HushWireProfileInspector.normalizedProfileName(name)),
      routePolicy: inspection.summary.routePolicy,
      dnsServers: inspection.summary.dnsServers,
      configurationFingerprint: HushWireProfileInspector.fingerprint(configuration),
      createdAt: now,
      updatedAt: now
    )
    do {
      try HushWireConfigurationStore.store(configuration, for: profile.id)
    } catch let error as HushWireConfigurationStoreError {
      throw mapSharedStoreError(error)
    }
    var profiles = try loadProfiles()
    profiles.append(profile)
    saveProfiles(profiles)
    selectedProfileID = profile.id
    return profile
  }

  static func update(_ profile: HushWireProfile) throws {
    var profiles = try loadProfiles()
    guard let index = profiles.firstIndex(where: { $0.id == profile.id }) else {
      throw HushWireProfileStoreError.profileNotFound
    }
    profiles[index] = profile
    saveProfiles(profiles)
  }

  static func delete(_ profile: HushWireProfile) throws {
    do {
      try HushWireConfigurationStore.delete(for: profile.id)
    } catch let error as HushWireConfigurationStoreError {
      throw mapSharedStoreError(error)
    }
    let legacyStatus = SecItemDelete(legacyKeychainQuery(for: profile.id) as CFDictionary)
    guard legacyStatus == errSecSuccess || legacyStatus == errSecItemNotFound else {
      throw HushWireProfileStoreError.keychain(legacyStatus)
    }
    var profiles = try loadProfiles()
    profiles.removeAll { $0.id == profile.id }
    saveProfiles(profiles)
    if selectedProfileID == profile.id {
      selectedProfileID = profiles.sorted { $0.updatedAt > $1.updatedAt }.first?.id
    }
  }

  static var selectedProfileID: UUID? {
    get {
      guard let value = UserDefaults.standard.string(forKey: selectedProfileKey) else { return nil }
      return UUID(uuidString: value)
    }
    set {
      UserDefaults.standard.set(newValue?.uuidString, forKey: selectedProfileKey)
    }
  }

  private static func legacyKeychainQuery(for profileID: UUID) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: legacyKeychainService,
      kSecAttrAccount as String: profileID.uuidString,
      kSecAttrAccessGroup as String: legacyKeychainAccessGroup,
      kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
    ]
  }

  private static func mapSharedStoreError(
    _ error: HushWireConfigurationStoreError
  ) -> HushWireProfileStoreError {
    switch error {
    case .notFound:
      .profileNotFound
    case .keychain(let status):
      .keychain(status)
    }
  }

  private static func saveProfiles(_ profiles: [HushWireProfile]) {
    let envelope = MetadataEnvelope(schemaVersion: 3, profiles: profiles)
    let data = try? JSONEncoder().encode(envelope)
    UserDefaults.standard.set(data, forKey: metadataKey)
  }

  private static func uniqueName(_ baseName: String) -> String {
    let existingNames = Set((try? loadProfiles().map(\.name)) ?? [])
    guard existingNames.contains(baseName) else { return baseName }
    for suffix in 2...9_999 {
      let candidate = "\(baseName) \(suffix)"
      if !existingNames.contains(candidate) { return candidate }
    }
    return "\(baseName) \(UUID().uuidString.prefix(6))"
  }
}
