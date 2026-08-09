import Foundation

struct HushWireConfigurationSummary: Equatable {
  let interface: String
  let transport: String
  let mtu: UInt16
  let peerCount: Int
  let routes: [String]
  let endpoints: [String]

  var routeDescription: String {
    routes.joined(separator: ", ")
  }

  var endpointDescription: String {
    endpoints.joined(separator: ", ")
  }
}

enum HushWireHostRouteConfigurationPolicy {
  static func inspect(_ data: Data) throws -> HushWireConfigurationSummary {
    let runtime = try HushWireCoreRuntime(configuration: data)
    let interface = try runtime.interfaceMetadata()
    let routes = try runtime.routes()
    guard !routes.isEmpty else {
      throw HushWireCoreError.operation("配置没有 Peer 路由。")
    }
    guard routes.allSatisfy({ $0.prefixLength == 32 }) else {
      throw HushWireCoreError.operation(
        "当前安全测试阶段只接受 /32 主机路由，不接受子网或默认路由。"
      )
    }
    guard interface.listen.port == 0 else {
      throw HushWireCoreError.operation(
        "当前 macOS 客户端要求 interface.listen 使用端口 0。"
      )
    }
    let peerNames = Set(routes.map(\.peerName))
    let endpoints = Array(Set(routes.map { $0.endpoint.displayString })).sorted()
    return HushWireConfigurationSummary(
      interface: interface.cidr,
      transport: interface.transport.title,
      mtu: interface.mtu,
      peerCount: peerNames.count,
      routes: routes.map(\.cidr),
      endpoints: endpoints
    )
  }
}
