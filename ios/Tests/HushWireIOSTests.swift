import NetworkExtension
import Security
import XCTest

@testable import HushWireIOS

final class HushWireIOSTests: XCTestCase {
  private let hostRouteConfiguration =
    """
    [interface]
    name = "hushwire-ios-test"
    address = "10.77.99.2/30"
    listen = "0.0.0.0:0"
    transport = "tcp"
    mtu = 1280
    private_key = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="

    [[peer]]
    name = "test-peer"
    endpoint = "192.0.2.10:27777"
    allowed_ips = ["10.77.99.1/32"]
    psk = "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M="
    public_key = "REREREREREREREREREREREREREREREREREREREREREQ="
    persistent_keepalive = 5
    """

  func testBundleIdentifiersAreDistinct() {
    XCTAssertNotEqual(
      HushWireIOSConstants.appBundleIdentifier,
      HushWireIOSConstants.extensionBundleIdentifier
    )
  }

  func testInfersSafeHostRoutePolicyAndMetadata() throws {
    let inspection = try HushWireProfileInspector.inspectWithInferredPolicy(
      Data(hostRouteConfiguration.utf8)
    )

    XCTAssertEqual(inspection.summary.routePolicy, .hostRoutesOnly)
    XCTAssertEqual(inspection.summary.interface, "10.77.99.2/30")
    XCTAssertEqual(inspection.summary.transport, "TCP")
    XCTAssertEqual(inspection.summary.routes, ["10.77.99.1/32"])
    XCTAssertEqual(inspection.peers.first?.persistentKeepalive, 5)
    XCTAssertEqual(inspection.peers.first?.sessionTimeout, 15)
  }

  func testDiagnosticsRedactsCredentials() {
    let input =
      #"""
      private_key = "sensitive-private"
      9 |   psk = "sensitive-psk"
      {"private_key":"json-private"}
      private_key = """triple-private"""
      endpoint = "192.0.2.10:27777"
      """#
    let output = HushWireRedactor.redact(input)

    XCTAssertFalse(output.contains("sensitive-private"))
    XCTAssertFalse(output.contains("sensitive-psk"))
    XCTAssertFalse(output.contains("json-private"))
    XCTAssertFalse(output.contains("triple-private"))
    XCTAssertTrue(output.contains("private_key = \"<redacted>\""))
    XCTAssertTrue(output.contains("psk = \"<redacted>\""))
    XCTAssertTrue(output.contains("192.0.2.10:27777"))
  }

  func testCoreParseErrorCannotExposeMalformedCredentialLine() {
    let malformedConfiguration =
      """
      [interface]
      private_key = "malformed-secret-that-must-not-escape
      """

    XCTAssertThrowsError(
      try HushWireCoreRuntime(configuration: Data(malformedConfiguration.utf8))
    ) { error in
      XCTAssertFalse(error.localizedDescription.contains("malformed-secret-that-must-not-escape"))
    }
  }

  func testFingerprintIsStableAndSensitiveToContent() {
    let first = HushWireProfileInspector.fingerprint(Data("one".utf8))
    let again = HushWireProfileInspector.fingerprint(Data("one".utf8))
    let second = HushWireProfileInspector.fingerprint(Data("two".utf8))

    XCTAssertEqual(first, again)
    XCTAssertNotEqual(first, second)
    XCTAssertEqual(first.count, 64)
  }

  func testTrustedWiFiPolicyTrimsAndDeduplicatesExactNames() throws {
    let result = try HushWireTrustedWiFiPolicy.parse(
      "  Home Wi-Fi  \nGuest\nHome Wi-Fi\n"
    )

    XCTAssertEqual(result, ["Home Wi-Fi", "Guest"])
  }

  func testTrustedWiFiPolicyRejectsNamesLongerThanSSIDLimit() {
    XCTAssertThrowsError(try HushWireTrustedWiFiPolicy.parse(String(repeating: "a", count: 33)))
  }

  func testLegacyProfileDecodesWithoutTrustedWiFiField() throws {
    let id = UUID()
    let createdAt = Date(timeIntervalSince1970: 1_700_000_000)
    let legacyObject: [String: Any] = [
      "id": id.uuidString,
      "name": "Legacy",
      "routePolicyRawValue": HushWireRoutePolicy.hostRoutesOnly.rawValue,
      "dnsServers": [],
      "configurationFingerprint": String(repeating: "a", count: 64),
      "createdAt": createdAt.timeIntervalSinceReferenceDate,
      "updatedAt": createdAt.timeIntervalSinceReferenceDate,
    ]
    let data = try JSONSerialization.data(withJSONObject: legacyObject)
    let profile = try JSONDecoder().decode(HushWireProfile.self, from: data)

    XCTAssertEqual(profile.id, id)
    XCTAssertTrue(profile.trustedWiFiSSIDs.isEmpty)
    XCTAssertFalse(profile.autoConnectOutsideTrustedWiFi)
  }

  func testProfileRoundTripsAutoConnectPolicy() throws {
    let original = HushWireProfile(
      name: "Auto Connect",
      routePolicy: .fullTunnel,
      dnsServers: ["1.1.1.1"],
      trustedWiFiSSIDs: ["Home Wi-Fi"],
      autoConnectOutsideTrustedWiFi: true,
      configurationFingerprint: String(repeating: "b", count: 64)
    )

    let data = try JSONEncoder().encode(original)
    let decoded = try JSONDecoder().decode(HushWireProfile.self, from: data)

    XCTAssertEqual(decoded, original)
    XCTAssertTrue(decoded.autoConnectOutsideTrustedWiFi)
  }

  @MainActor
  func testAutoConnectRulesDisconnectTrustedWiFiBeforeConnectingElsewhere() {
    let profile = HushWireProfile(
      name: "Auto Connect",
      routePolicy: .fullTunnel,
      dnsServers: ["1.1.1.1"],
      trustedWiFiSSIDs: ["Home Wi-Fi"],
      autoConnectOutsideTrustedWiFi: true,
      configurationFingerprint: String(repeating: "c", count: 64)
    )

    let rules = HushWireIOSController.makeOnDemandRules(for: profile)

    XCTAssertEqual(rules.count, 2)
    let disconnect = rules[0] as? NEOnDemandRuleDisconnect
    XCTAssertEqual(disconnect?.interfaceTypeMatch, .wiFi)
    XCTAssertEqual(disconnect?.ssidMatch, ["Home Wi-Fi"])
    XCTAssertTrue(rules[1] is NEOnDemandRuleConnect)
  }

  @MainActor
  func testTrustedWiFiWithoutAutoConnectFallsBackToIgnore() {
    let profile = HushWireProfile(
      name: "Disconnect Only",
      routePolicy: .hostRoutesOnly,
      dnsServers: [],
      trustedWiFiSSIDs: ["Office"],
      configurationFingerprint: String(repeating: "d", count: 64)
    )

    let rules = HushWireIOSController.makeOnDemandRules(for: profile)

    XCTAssertEqual(rules.count, 2)
    XCTAssertTrue(rules[0] is NEOnDemandRuleDisconnect)
    XCTAssertTrue(rules[1] is NEOnDemandRuleIgnore)
  }

  func testSharedKeychainGroupMatchesSigningTeam() {
    XCTAssertEqual(
      HushWireConfigurationStore.keychainAccessGroup,
      "95Q852BXKJ.com.jamie.HushWire.shared"
    )
  }

  func testLegacyPrivateKeychainItemMigratesToSharedGroup() throws {
    let profileID = UUID()
    let configuration = Data(hostRouteConfiguration.utf8)
    let legacyQuery = Self.legacyKeychainQuery(for: profileID)
    SecItemDelete(legacyQuery as CFDictionary)
    try? HushWireConfigurationStore.delete(for: profileID)
    addTeardownBlock {
      SecItemDelete(Self.legacyKeychainQuery(for: profileID) as CFDictionary)
      try? HushWireConfigurationStore.delete(for: profileID)
    }

    var legacyItem = legacyQuery
    legacyItem[kSecValueData as String] = configuration
    legacyItem[kSecAttrAccessible as String] =
      kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    XCTAssertEqual(SecItemAdd(legacyItem as CFDictionary, nil), errSecSuccess)

    XCTAssertEqual(try HushWireProfileStore.configuration(for: profileID), configuration)
    XCTAssertEqual(try HushWireConfigurationStore.load(for: profileID), configuration)
    XCTAssertEqual(SecItemCopyMatching(legacyQuery as CFDictionary, nil), errSecItemNotFound)
  }

  func testProfileStoreRoundTripsConfigurationThroughKeychain() throws {
    let originalSelection = HushWireProfileStore.selectedProfileID
    addTeardownBlock {
      HushWireProfileStore.selectedProfileID = originalSelection
    }
    let configuration = Data(hostRouteConfiguration.utf8)
    let inspection = try HushWireProfileInspector.inspectWithInferredPolicy(configuration)
    let profile = try HushWireProfileStore.add(
      configuration: configuration,
      name: "Keychain round trip \(UUID().uuidString)",
      inspection: inspection
    )
    addTeardownBlock {
      try? HushWireProfileStore.delete(profile)
    }

    XCTAssertEqual(try HushWireProfileStore.configuration(for: profile.id), configuration)
    XCTAssertTrue(try HushWireProfileStore.loadProfiles().contains(where: { $0.id == profile.id }))

    try HushWireProfileStore.delete(profile)
    XCTAssertThrowsError(try HushWireProfileStore.configuration(for: profile.id))
  }

  func testProfileStoreKeepsMultipleConfigurationsIndependent() throws {
    let originalSelection = HushWireProfileStore.selectedProfileID
    addTeardownBlock {
      HushWireProfileStore.selectedProfileID = originalSelection
    }
    let firstConfiguration = Data(hostRouteConfiguration.utf8)
    let secondConfiguration = Data(
      hostRouteConfiguration.replacingOccurrences(of: "test-peer", with: "test-peer-two").utf8
    )
    let firstInspection = try HushWireProfileInspector.inspectWithInferredPolicy(
      firstConfiguration)
    let secondInspection = try HushWireProfileInspector.inspectWithInferredPolicy(
      secondConfiguration)
    let testID = UUID().uuidString
    let first = try HushWireProfileStore.add(
      configuration: firstConfiguration,
      name: "First \(testID)",
      inspection: firstInspection
    )
    let second = try HushWireProfileStore.add(
      configuration: secondConfiguration,
      name: "Second \(testID)",
      inspection: secondInspection
    )
    addTeardownBlock {
      try? HushWireProfileStore.delete(first)
      try? HushWireProfileStore.delete(second)
    }

    let storedIDs = Set(try HushWireProfileStore.loadProfiles().map(\.id))
    XCTAssertTrue(storedIDs.isSuperset(of: [first.id, second.id]))
    XCTAssertEqual(HushWireProfileStore.selectedProfileID, second.id)
    XCTAssertEqual(try HushWireProfileStore.configuration(for: first.id), firstConfiguration)
    XCTAssertEqual(try HushWireProfileStore.configuration(for: second.id), secondConfiguration)

    try HushWireProfileStore.delete(first)
    XCTAssertEqual(try HushWireProfileStore.configuration(for: second.id), secondConfiguration)
  }

  func testTrafficFormattingIsStableAcrossLocales() {
    XCTAssertEqual(HushWireFormatters.bytes(0), "0 B")
    XCTAssertEqual(HushWireFormatters.bytes(1_024), "1.0 KB")
    XCTAssertEqual(HushWireFormatters.rate(0), "0 B/s")
  }

  private static func legacyKeychainQuery(for profileID: UUID) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: "com.jamie.HushWire.iOS.configuration",
      kSecAttrAccount as String: profileID.uuidString,
      kSecAttrAccessGroup as String: "95Q852BXKJ.com.jamie.HushWire.iOS",
      kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
    ]
  }
}
