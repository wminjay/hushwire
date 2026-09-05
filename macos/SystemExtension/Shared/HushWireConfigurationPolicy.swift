import Foundation
import Network

enum HushWireRoutePolicy: String, CaseIterable, Identifiable, Sendable {
  case hostRoutesOnly = "host-routes-only"
  case splitRoutes = "split-routes-v1"
  case fullTunnel = "full-tunnel-v1"

  var id: String { rawValue }

  var title: String {
    switch self {
    case .hostRoutesOnly: "主机路由（/32）"
    case .splitRoutes: "自定义分流"
    case .fullTunnel: "默认走隧道"
    }
  }

  var detail: String {
    switch self {
    case .hostRoutesOnly:
      "只把 TOML 中明确列出的 /32 地址交给 HushWire。"
    case .splitRoutes:
      "按 TOML 中的 IPv4 CIDR 精确分流；不接受默认路由，并自动保护 Peer endpoint。"
    case .fullTunnel:
      "默认把 IPv4 交给 HushWire；TOML 的 excluded_ips 与真实 endpoint 保持直连。"
    }
  }

  var allowsDNS: Bool { self != .hostRoutesOnly }

  var requiresAuthenticatedPreflight: Bool { self != .hostRoutesOnly }
}

struct HushWireNetworkPolicy: Equatable, Sendable {
  static let routePolicyKey = "routePolicy"
  static let dnsServersKey = "dnsServers"
  static let fullTunnelApprovalOptionKey = "fullTunnelApproved"
  static let hostRoutesOnly = try! HushWireNetworkPolicy(
    routePolicy: .hostRoutesOnly,
    dnsServers: []
  )

  let routePolicy: HushWireRoutePolicy
  let dnsServers: [String]

  init(routePolicy: HushWireRoutePolicy, dnsServers: [String]) throws {
    var normalizedServers: [String] = []
    var seenServers = Set<String>()
    for rawServer in dnsServers {
      let server = rawServer.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !server.isEmpty else { continue }
      guard seenServers.insert(server).inserted else { continue }
      normalizedServers.append(server)
    }

    guard normalizedServers.count <= 4 else {
      throw HushWireCoreError.operation("DNS 服务器最多允许 4 个。")
    }
    if routePolicy == .hostRoutesOnly, !normalizedServers.isEmpty {
      throw HushWireCoreError.operation("/32 主机路由模式不会修改 DNS；请清空 DNS 服务器。")
    }
    for server in normalizedServers {
      guard let address = IPv4Address(server) else {
        throw HushWireCoreError.operation("DNS 服务器必须是 IPv4 地址：\(server)")
      }
      let bytes = Array(address.rawValue)
      guard
        bytes.count == 4,
        bytes[0] != 0,
        bytes[0] < 224,
        bytes != [255, 255, 255, 255]
      else {
        throw HushWireCoreError.operation("DNS 服务器地址不可用：\(server)")
      }
    }

    self.routePolicy = routePolicy
    self.dnsServers = normalizedServers
  }

  init(providerConfiguration: [String: Any]) throws {
    guard
      let rawPolicy = providerConfiguration[Self.routePolicyKey] as? String,
      let routePolicy = HushWireRoutePolicy(rawValue: rawPolicy)
    else {
      throw HushWireCoreError.operation("VPN 配置缺少受支持的路由策略。")
    }
    let dnsServers: [String]
    if let rawDNSServers = providerConfiguration[Self.dnsServersKey] {
      guard let configuredServers = rawDNSServers as? [String] else {
        throw HushWireCoreError.operation("VPN 配置中的 DNS 服务器格式无效。")
      }
      dnsServers = configuredServers
    } else {
      dnsServers = []
    }
    try self.init(routePolicy: routePolicy, dnsServers: dnsServers)
  }

  static func parseDNSServers(_ text: String) -> [String] {
    text.split { character in
      character == "," || character == ";" || character.isWhitespace
    }.map(String.init)
  }

  func addingProviderConfiguration(to configuration: [String: Any]) -> [String: Any] {
    var value = configuration
    value[Self.routePolicyKey] = routePolicy.rawValue
    value[Self.dnsServersKey] = dnsServers
    return value
  }

  var dnsDescription: String {
    dnsServers.isEmpty ? "保持系统 DNS" : dnsServers.joined(separator: ", ")
  }
}

struct HushWireIPv4RouteSpec: Equatable, Hashable, Sendable {
  let network: String
  let prefixLength: UInt8

  var cidr: String { "\(network)/\(prefixLength)" }

  var subnetMask: String {
    switch prefixLength {
    case 0: return "0.0.0.0"
    case 32: return "255.255.255.255"
    default:
      let mask = prefixLength == 0 ? UInt32(0) : UInt32.max << (32 - UInt32(prefixLength))
      return [24, 16, 8, 0].map { String((mask >> UInt32($0)) & 0xff) }
        .joined(separator: ".")
    }
  }

  func contains(_ address: String) -> Bool {
    guard
      prefixLength <= 32,
      let routeAddress = IPv4Address(network),
      let targetAddress = IPv4Address(address)
    else { return false }
    let routeValue = Self.integerValue(routeAddress)
    let targetValue = Self.integerValue(targetAddress)
    let mask = prefixLength == 0 ? UInt32(0) : UInt32.max << (32 - UInt32(prefixLength))
    return routeValue & mask == targetValue & mask
  }

  func contains(_ route: HushWireIPv4RouteSpec) -> Bool {
    prefixLength <= route.prefixLength && contains(route.network)
  }

  private static func integerValue(_ address: IPv4Address) -> UInt32 {
    address.rawValue.reduce(UInt32(0)) { value, byte in
      (value << 8) | UInt32(byte)
    }
  }
}

struct HushWireConfigurationSummary: Equatable {
  let interface: String
  let transport: String
  let mtu: UInt16
  let peerCount: Int
  let routes: [String]
  let directRoutes: [String]
  let endpoints: [String]
  let resolvedEndpoints: [String]
  let routePolicy: HushWireRoutePolicy
  let dnsServers: [String]

  var routeDescription: String {
    guard routes.count > 6 else { return routes.joined(separator: ", ") }
    return "共 \(routes.count) 条 · "
      + routes.prefix(5).joined(separator: ", ")
      + " …"
  }

  var endpointDescription: String {
    endpoints.joined(separator: ", ")
  }

  var directRouteDescription: String {
    guard !directRoutes.isEmpty else { return "无" }
    guard directRoutes.count > 6 else { return directRoutes.joined(separator: ", ") }
    return "共 \(directRoutes.count) 条 · "
      + directRoutes.prefix(5).joined(separator: ", ")
      + " …"
  }

  var dnsDescription: String {
    dnsServers.isEmpty ? "保持系统 DNS" : dnsServers.joined(separator: ", ")
  }
}

struct HushWireConfigurationPlan: Equatable {
  let summary: HushWireConfigurationSummary
  let includedRoutes: [HushWireIPv4RouteSpec]
  let excludedRoutes: [HushWireIPv4RouteSpec]
  let dnsServers: [String]

  /// Routes rendered into `NEIPv4Settings`.
  ///
  /// Keep `0.0.0.0/0` in the semantic plan and in the HushWire core, but
  /// express it to Apple Packet Tunnel platforms as the equivalent pair of /1
  /// routes. A directly installed default route can appear in the routing table while
  /// sends through a /32-addressed packet tunnel still fail with
  /// `EHOSTUNREACH`. The two /1 routes avoid that special default-route path
  /// without changing configured allowed/excluded-prefix precedence.
  var packetTunnelIncludedRoutes: [HushWireIPv4RouteSpec] {
    includedRoutes.flatMap { route in
      guard route.network == "0.0.0.0", route.prefixLength == 0 else {
        return [route]
      }
      return [
        HushWireIPv4RouteSpec(network: "0.0.0.0", prefixLength: 1),
        HushWireIPv4RouteSpec(network: "128.0.0.0", prefixLength: 1),
      ]
    }
  }
}

enum HushWireConfigurationPolicy {
  static let maximumSplitRouteCount = 256
  static let maximumExcludedRouteCount = 256

  static func inspect(
    _ data: Data,
    networkPolicy: HushWireNetworkPolicy = .hostRoutesOnly
  ) throws -> HushWireConfigurationSummary {
    try plan(data, networkPolicy: networkPolicy).summary
  }

  static func plan(
    _ data: Data,
    networkPolicy: HushWireNetworkPolicy = .hostRoutesOnly
  ) throws -> HushWireConfigurationPlan {
    let runtime = try HushWireCoreRuntime(configuration: data)
    return try plan(
      interface: runtime.interfaceMetadata(),
      routes: runtime.routes(),
      networkPolicy: networkPolicy
    )
  }

  static func plan(
    interface: HushWireInterfaceMetadata,
    routes: [HushWireRouteMetadata],
    networkPolicy: HushWireNetworkPolicy
  ) throws -> HushWireConfigurationPlan {
    let tunnelRouteMetadata = routes.filter { $0.routeKind == .included }
    let configuredExclusionMetadata = routes.filter { $0.routeKind == .excluded }
    guard !tunnelRouteMetadata.isEmpty else {
      throw HushWireCoreError.operation("配置没有 Peer 路由。")
    }
    guard interface.listen.port == 0 else {
      throw HushWireCoreError.operation("当前 Packet Tunnel 客户端要求 interface.listen 使用端口 0。")
    }
    guard routes.allSatisfy({ $0.endpoint.port != 0 && !$0.endpoint.host.isEmpty }) else {
      throw HushWireCoreError.operation("Peer endpoint 无效。")
    }
    guard configuredExclusionMetadata.count <= maximumExcludedRouteCount else {
      throw HushWireCoreError.operation(
        "直连例外最多接受 \(maximumExcludedRouteCount) 条 excluded_ips。"
      )
    }
    let configuredExclusions = configuredExclusionMetadata.map {
      HushWireIPv4RouteSpec(network: $0.network, prefixLength: $0.prefixLength)
    }

    let includedRoutes: [HushWireIPv4RouteSpec]
    let excludedRoutes: [HushWireIPv4RouteSpec]
    switch networkPolicy.routePolicy {
    case .hostRoutesOnly:
      guard configuredExclusions.isEmpty else {
        throw HushWireCoreError.operation("主机路由模式不接受 excluded_ips。")
      }
      guard tunnelRouteMetadata.allSatisfy({ $0.prefixLength == 32 }) else {
        throw HushWireCoreError.operation(
          "主机路由模式只接受 /32，不接受子网或默认路由。"
        )
      }
      includedRoutes = tunnelRouteMetadata.map {
        HushWireIPv4RouteSpec(network: $0.network, prefixLength: $0.prefixLength)
      }
      let endpointHosts = Set(
        tunnelRouteMetadata.filter { $0.endpoint.family == 4 }.map { $0.endpoint.host }
      )
      guard !tunnelRouteMetadata.contains(where: { endpointHosts.contains($0.network) }) else {
        throw HushWireCoreError.operation("主机路由不能与 Peer endpoint 相同，否则会形成路由环路。")
      }
      excludedRoutes = []

    case .splitRoutes:
      guard tunnelRouteMetadata.count <= maximumSplitRouteCount else {
        throw HushWireCoreError.operation(
          "自定义分流最多接受 \(maximumSplitRouteCount) 条 allowed_ips。"
        )
      }
      guard tunnelRouteMetadata.allSatisfy({ $0.prefixLength > 0 }) else {
        throw HushWireCoreError.operation(
          "自定义分流不接受 0.0.0.0/0；如需默认路由请选择默认走隧道。"
        )
      }
      let route = try validateProtectedPolicy(
        interface: interface,
        routes: routes,
        policyName: "自定义分流"
      )
      includedRoutes = tunnelRouteMetadata.map {
        HushWireIPv4RouteSpec(network: $0.network, prefixLength: $0.prefixLength)
      }
      excludedRoutes = try protectedExclusions(
        configuredExclusions,
        endpoint: route.endpoint.host,
        coveredBy: includedRoutes
      )
      try validateDNS(
        networkPolicy.dnsServers,
        endpoint: route.endpoint.host,
        coveredBy: includedRoutes,
        excludedBy: excludedRoutes
      )

    case .fullTunnel:
      guard tunnelRouteMetadata.count <= maximumSplitRouteCount else {
        throw HushWireCoreError.operation(
          "默认隧道最多接受 \(maximumSplitRouteCount) 条 allowed_ips。"
        )
      }
      let defaultRoutes = tunnelRouteMetadata.filter {
        $0.network == "0.0.0.0" && $0.prefixLength == 0
      }
      guard defaultRoutes.count == 1 else {
        throw HushWireCoreError.operation(
          "默认隧道 v1 要求恰好一条 0.0.0.0/0；更具体的 allowed_ips 可覆盖较宽的 excluded_ips。"
        )
      }
      let route = defaultRoutes[0]
      _ = try validateProtectedPolicy(
        interface: interface,
        routes: routes,
        policyName: "默认隧道"
      )
      includedRoutes = tunnelRouteMetadata.map {
        HushWireIPv4RouteSpec(network: $0.network, prefixLength: $0.prefixLength)
      }
      excludedRoutes = try protectedExclusions(
        configuredExclusions,
        endpoint: route.endpoint.host,
        coveredBy: includedRoutes
      )
      try validateDNS(
        networkPolicy.dnsServers,
        endpoint: route.endpoint.host,
        coveredBy: includedRoutes,
        excludedBy: excludedRoutes
      )
    }

    let peerNames = Set(routes.map(\.peerName))
    let endpoints = Array(Set(routes.map(\.endpointDescription))).sorted()
    let resolvedEndpoints = Array(Set(routes.map { $0.endpoint.displayString })).sorted()
    let summary = HushWireConfigurationSummary(
      interface: interface.cidr,
      transport: interface.transport.title,
      mtu: interface.mtu,
      peerCount: peerNames.count,
      routes: tunnelRouteMetadata.map(\.cidr),
      directRoutes: excludedRoutes.map(\.cidr),
      endpoints: endpoints,
      resolvedEndpoints: resolvedEndpoints,
      routePolicy: networkPolicy.routePolicy,
      dnsServers: networkPolicy.dnsServers
    )
    return HushWireConfigurationPlan(
      summary: summary,
      includedRoutes: includedRoutes,
      excludedRoutes: excludedRoutes,
      dnsServers: networkPolicy.dnsServers
    )
  }

  private static func validateProtectedPolicy(
    interface: HushWireInterfaceMetadata,
    routes: [HushWireRouteMetadata],
    policyName: String
  ) throws -> HushWireRouteMetadata {
    guard Set(routes.map(\.peerName)).count == 1 else {
      throw HushWireCoreError.operation("\(policyName) v1 只接受单 Peer 配置。")
    }
    let route = routes[0]
    guard
      routes.allSatisfy({
        $0.endpoint == route.endpoint
          && $0.configuredEndpoint == route.configuredEndpoint
      }),
      route.endpoint.family == 4,
      route.endpoint.host != "0.0.0.0",
      route.endpoint.port != 0
    else {
      throw HushWireCoreError.operation("\(policyName) v1 要求单个有效的 IPv4 Peer endpoint。")
    }
    guard route.persistentKeepalive > 0 else {
      throw HushWireCoreError.operation("\(policyName)必须启用 persistent_keepalive。")
    }
    switch interface.transport {
    case .udp:
      guard route.udpRebindAfter > route.persistentKeepalive else {
        throw HushWireCoreError.operation(
          "UDP \(policyName)必须设置大于 persistent_keepalive 的 udp_rebind_after。"
        )
      }
    case .tcp:
      guard route.sessionTimeout > UInt64(route.persistentKeepalive) else {
        throw HushWireCoreError.operation(
          "TCP \(policyName)必须启用大于 persistent_keepalive 的 session_timeout。"
        )
      }
    }
    return route
  }

  private static func validateDNS(
    _ dnsServers: [String],
    endpoint: String,
    coveredBy includedRoutes: [HushWireIPv4RouteSpec],
    excludedBy excludedRoutes: [HushWireIPv4RouteSpec]
  ) throws {
    guard !dnsServers.contains(endpoint) else {
      throw HushWireCoreError.operation("DNS 服务器不能与被排除的 Peer endpoint 相同。")
    }
    for server in dnsServers where !includedRoutes.contains(where: { $0.contains(server) }) {
      throw HushWireCoreError.operation(
        "DNS 服务器 \(server) 不在 allowed_ips 内；为避免 DNS 中断，已拒绝配置。"
      )
    }
    for server in dnsServers
    where !isRoutedToTunnel(server, includedRoutes: includedRoutes, excludedRoutes: excludedRoutes)
    {
      throw HushWireCoreError.operation(
        "DNS 服务器 \(server) 位于 excluded_ips 直连例外内；为避免 DNS 走错路径，已拒绝配置。"
      )
    }
  }

  private static func protectedExclusions(
    _ configuredExclusions: [HushWireIPv4RouteSpec],
    endpoint: String,
    coveredBy includedRoutes: [HushWireIPv4RouteSpec]
  ) throws -> [HushWireIPv4RouteSpec] {
    for exclusion in configuredExclusions
    where !includedRoutes.contains(where: { $0.contains(exclusion) }) {
      throw HushWireCoreError.operation(
        "直连例外 \(exclusion.cidr) 不在 allowed_ips 内。"
      )
    }

    var exclusions = configuredExclusions
    if isRoutedToTunnel(
      endpoint,
      includedRoutes: includedRoutes,
      excludedRoutes: exclusions
    ) {
      exclusions.append(HushWireIPv4RouteSpec(network: endpoint, prefixLength: 32))
    }
    exclusions.sort { left, right in
      if left.prefixLength != right.prefixLength {
        return left.prefixLength > right.prefixLength
      }
      return left.network < right.network
    }
    return exclusions
  }

  private static func isRoutedToTunnel(
    _ address: String,
    includedRoutes: [HushWireIPv4RouteSpec],
    excludedRoutes: [HushWireIPv4RouteSpec]
  ) -> Bool {
    guard
      let includedPrefixLength =
        includedRoutes
        .filter({ $0.contains(address) })
        .map(\.prefixLength)
        .max()
    else { return false }
    let excludedPrefixLength =
      excludedRoutes
      .filter { $0.contains(address) }
      .map(\.prefixLength)
      .max()
    return
      excludedPrefixLength
      .map { includedPrefixLength > $0 }
      ?? true
  }
}
