import CryptoKit
import Foundation

struct HushWireProfile: Codable, Identifiable, Equatable, Sendable {
  let id: UUID
  var name: String
  var routePolicyRawValue: String
  var dnsServers: [String]
  var trustedWiFiSSIDs: [String]
  var autoConnectOutsideTrustedWiFi: Bool
  let configurationFingerprint: String
  let createdAt: Date
  var updatedAt: Date

  private enum CodingKeys: String, CodingKey {
    case id
    case name
    case routePolicyRawValue
    case dnsServers
    case trustedWiFiSSIDs
    case autoConnectOutsideTrustedWiFi
    case configurationFingerprint
    case createdAt
    case updatedAt
  }

  var routePolicy: HushWireRoutePolicy {
    HushWireRoutePolicy(rawValue: routePolicyRawValue) ?? .hostRoutesOnly
  }

  init(
    id: UUID = UUID(),
    name: String,
    routePolicy: HushWireRoutePolicy,
    dnsServers: [String],
    trustedWiFiSSIDs: [String] = [],
    autoConnectOutsideTrustedWiFi: Bool = false,
    configurationFingerprint: String,
    createdAt: Date = Date(),
    updatedAt: Date = Date()
  ) {
    self.id = id
    self.name = name
    routePolicyRawValue = routePolicy.rawValue
    self.dnsServers = dnsServers
    self.trustedWiFiSSIDs = trustedWiFiSSIDs
    self.autoConnectOutsideTrustedWiFi = autoConnectOutsideTrustedWiFi
    self.configurationFingerprint = configurationFingerprint
    self.createdAt = createdAt
    self.updatedAt = updatedAt
  }

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    id = try container.decode(UUID.self, forKey: .id)
    name = try container.decode(String.self, forKey: .name)
    routePolicyRawValue = try container.decode(String.self, forKey: .routePolicyRawValue)
    dnsServers = try container.decode([String].self, forKey: .dnsServers)
    trustedWiFiSSIDs =
      try container.decodeIfPresent(
        [String].self,
        forKey: .trustedWiFiSSIDs
      ) ?? []
    autoConnectOutsideTrustedWiFi =
      try container.decodeIfPresent(
        Bool.self,
        forKey: .autoConnectOutsideTrustedWiFi
      ) ?? false
    configurationFingerprint = try container.decode(
      String.self,
      forKey: .configurationFingerprint
    )
    createdAt = try container.decode(Date.self, forKey: .createdAt)
    updatedAt = try container.decode(Date.self, forKey: .updatedAt)
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(id, forKey: .id)
    try container.encode(name, forKey: .name)
    try container.encode(routePolicyRawValue, forKey: .routePolicyRawValue)
    try container.encode(dnsServers, forKey: .dnsServers)
    try container.encode(trustedWiFiSSIDs, forKey: .trustedWiFiSSIDs)
    try container.encode(
      autoConnectOutsideTrustedWiFi,
      forKey: .autoConnectOutsideTrustedWiFi
    )
    try container.encode(configurationFingerprint, forKey: .configurationFingerprint)
    try container.encode(createdAt, forKey: .createdAt)
    try container.encode(updatedAt, forKey: .updatedAt)
  }
}

enum HushWireTrustedWiFiPolicy {
  static let maximumSSIDCount = 16
  static let maximumSSIDByteCount = 32

  static func parse(_ text: String) throws -> [String] {
    try normalize(text.components(separatedBy: .newlines))
  }

  static func normalize(_ values: [String]) throws -> [String] {
    var normalized: [String] = []
    var seen = Set<String>()

    for rawValue in values {
      let value = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !value.isEmpty else { continue }
      guard !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
        throw HushWireCoreError.operation("Wi-Fi 名称不能包含控制字符。")
      }
      guard value.lengthOfBytes(using: .utf8) <= maximumSSIDByteCount else {
        throw HushWireCoreError.operation("Wi-Fi 名称不能超过 32 个 UTF-8 字节。")
      }
      if seen.insert(value).inserted {
        normalized.append(value)
      }
    }

    guard normalized.count <= maximumSSIDCount else {
      throw HushWireCoreError.operation("可信 Wi-Fi 最多可配置 16 个。")
    }
    return normalized
  }
}

struct HushWirePeerConfiguration: Identifiable, Equatable, Sendable {
  var id: String { name }
  let name: String
  let configuredEndpoint: String
  let resolvedEndpoint: String
  let persistentKeepalive: UInt16
  let udpRebindAfter: UInt16
  let sessionTimeout: UInt64
}

struct HushWireProfileInspection: Equatable {
  let summary: HushWireConfigurationSummary
  let peers: [HushWirePeerConfiguration]
  let coreVersion: String
}

enum HushWireProfileInspector {
  static let maximumConfigurationSize = 1_048_576

  static func inspect(
    _ configuration: Data,
    routePolicy: HushWireRoutePolicy,
    dnsServers: [String]
  ) throws -> HushWireProfileInspection {
    guard !configuration.isEmpty else {
      throw HushWireCoreError.operation("配置文件为空。")
    }
    guard configuration.count <= maximumConfigurationSize else {
      throw HushWireCoreError.operation("配置文件超过 1 MiB，已拒绝导入。")
    }

    let networkPolicy = try HushWireNetworkPolicy(
      routePolicy: routePolicy,
      dnsServers: dnsServers
    )
    let runtime = try HushWireCoreRuntime(configuration: configuration)
    let interface = try runtime.interfaceMetadata()
    let routes = try runtime.routes()
    let plan = try HushWireConfigurationPolicy.plan(
      interface: interface,
      routes: routes,
      networkPolicy: networkPolicy
    )

    var seenPeers = Set<String>()
    let peers = routes.compactMap { route -> HushWirePeerConfiguration? in
      guard seenPeers.insert(route.peerName).inserted else { return nil }
      return HushWirePeerConfiguration(
        name: route.peerName,
        configuredEndpoint: route.configuredEndpoint,
        resolvedEndpoint: route.endpoint.displayString,
        persistentKeepalive: route.persistentKeepalive,
        udpRebindAfter: route.udpRebindAfter,
        sessionTimeout: route.sessionTimeout
      )
    }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }

    return HushWireProfileInspection(
      summary: plan.summary,
      peers: peers,
      coreVersion: runtime.coreVersion
    )
  }

  static func inspectWithInferredPolicy(
    _ configuration: Data
  ) throws -> HushWireProfileInspection {
    guard !configuration.isEmpty else {
      throw HushWireCoreError.operation("配置文件为空。")
    }
    guard configuration.count <= maximumConfigurationSize else {
      throw HushWireCoreError.operation("配置文件超过 1 MiB，已拒绝导入。")
    }

    let runtime = try HushWireCoreRuntime(configuration: configuration)
    let routes = try runtime.routes()
    let included = routes.filter { $0.routeKind == .included }
    let hasDefaultRoute = included.contains {
      $0.network == "0.0.0.0" && $0.prefixLength == 0
    }
    let hasExcludedRoutes = routes.contains { $0.routeKind == .excluded }
    let inferredPolicy: HushWireRoutePolicy
    if hasDefaultRoute {
      inferredPolicy = .fullTunnel
    } else if !hasExcludedRoutes && included.allSatisfy({ $0.prefixLength == 32 }) {
      inferredPolicy = .hostRoutesOnly
    } else {
      inferredPolicy = .splitRoutes
    }
    return try inspect(configuration, routePolicy: inferredPolicy, dnsServers: [])
  }

  static func fingerprint(_ configuration: Data) -> String {
    SHA256.hash(data: configuration).map { String(format: "%02x", $0) }.joined()
  }

  static func normalizedProfileName(_ proposedName: String) -> String {
    let value = proposedName.trimmingCharacters(in: .whitespacesAndNewlines)
    return value.isEmpty ? "未命名配置" : String(value.prefix(80))
  }
}
