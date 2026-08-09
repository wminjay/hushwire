import Foundation
import Network

enum HushWireRoutePolicy: String, CaseIterable, Identifiable, Sendable {
  case hostRoutesOnly = "host-routes-only"
  case fullTunnel = "full-tunnel-v1"

  var id: String { rawValue }

  var title: String {
    switch self {
    case .hostRoutesOnly: "主机路由（/32）"
    case .fullTunnel: "全隧道（IPv4）"
    }
  }

  var detail: String {
    switch self {
    case .hostRoutesOnly:
      "只把 TOML 中明确列出的 /32 地址交给 HushWire。"
    case .fullTunnel:
      "把 IPv4 默认路由交给 HushWire，并为真实 endpoint 保留直连例外。"
    }
  }
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

struct HushWireIPv4RouteSpec: Equatable, Sendable {
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
}

struct HushWireConfigurationSummary: Equatable {
  let interface: String
  let transport: String
  let mtu: UInt16
  let peerCount: Int
  let routes: [String]
  let endpoints: [String]
  let routePolicy: HushWireRoutePolicy
  let dnsServers: [String]

  var routeDescription: String {
    routes.joined(separator: ", ")
  }

  var endpointDescription: String {
    endpoints.joined(separator: ", ")
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
}

enum HushWireConfigurationPolicy {
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
    guard !routes.isEmpty else {
      throw HushWireCoreError.operation("配置没有 Peer 路由。")
    }
    guard interface.listen.port == 0 else {
      throw HushWireCoreError.operation("当前 macOS 客户端要求 interface.listen 使用端口 0。")
    }
    guard routes.allSatisfy({ $0.endpoint.port != 0 && !$0.endpoint.host.isEmpty }) else {
      throw HushWireCoreError.operation("Peer endpoint 无效。")
    }

    let includedRoutes: [HushWireIPv4RouteSpec]
    let excludedRoutes: [HushWireIPv4RouteSpec]
    switch networkPolicy.routePolicy {
    case .hostRoutesOnly:
      guard routes.allSatisfy({ $0.prefixLength == 32 }) else {
        throw HushWireCoreError.operation(
          "主机路由模式只接受 /32，不接受子网或默认路由。"
        )
      }
      includedRoutes = routes.map {
        HushWireIPv4RouteSpec(network: $0.network, prefixLength: $0.prefixLength)
      }
      excludedRoutes = []

    case .fullTunnel:
      guard
        routes.count == 1,
        routes[0].network == "0.0.0.0",
        routes[0].prefixLength == 0
      else {
        throw HushWireCoreError.operation(
          "全隧道 v1 只接受单 Peer、单条 0.0.0.0/0 路由。"
        )
      }
      let route = routes[0]
      guard route.endpoint.family == 4, route.endpoint.host != "0.0.0.0" else {
        throw HushWireCoreError.operation("全隧道 v1 要求有效的 IPv4 Peer endpoint。")
      }
      guard route.persistentKeepalive > 0 else {
        throw HushWireCoreError.operation("全隧道必须启用 persistent_keepalive。")
      }
      switch interface.transport {
      case .udp:
        guard route.udpRebindAfter > route.persistentKeepalive else {
          throw HushWireCoreError.operation(
            "UDP 全隧道必须设置大于 persistent_keepalive 的 udp_rebind_after。"
          )
        }
      case .tcp:
        guard route.sessionTimeout > UInt64(route.persistentKeepalive) else {
          throw HushWireCoreError.operation(
            "TCP 全隧道必须启用大于 persistent_keepalive 的 session_timeout。"
          )
        }
      }
      guard !networkPolicy.dnsServers.contains(route.endpoint.host) else {
        throw HushWireCoreError.operation("DNS 服务器不能与被排除的 Peer endpoint 相同。")
      }
      includedRoutes = [HushWireIPv4RouteSpec(network: "0.0.0.0", prefixLength: 0)]
      excludedRoutes = [
        HushWireIPv4RouteSpec(network: route.endpoint.host, prefixLength: 32)
      ]
    }

    let peerNames = Set(routes.map(\.peerName))
    let endpoints = Array(Set(routes.map { $0.endpoint.displayString })).sorted()
    let summary = HushWireConfigurationSummary(
      interface: interface.cidr,
      transport: interface.transport.title,
      mtu: interface.mtu,
      peerCount: peerNames.count,
      routes: routes.map(\.cidr),
      endpoints: endpoints,
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
}
