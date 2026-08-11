import Foundation

@main
enum SystemExtensionCoreSmoke {
  static func main() throws {
    let configurationText =
      """
      [interface]
      name = "utun-test"
      address = "10.77.99.2/30"
      listen = "0.0.0.0:0"
      transport = "tcp"
      mtu = 1280
      private_key = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="

      [[peer]]
      name = "smoke-peer"
      endpoint = "192.0.2.10:27777"
      allowed_ips = ["10.77.99.1/32"]
      psk = "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M="
      public_key = "REREREREREREREREREREREREREREREREREREREREREQ="
      persistent_keepalive = 5
      """
    let configuration = Data(configurationText.utf8)

    let runtime = try HushWireCoreRuntime(configuration: configuration)
    let interface = try runtime.interfaceMetadata()
    let routes = try runtime.routes()

    precondition(interface.cidr == "10.77.99.2/30")
    precondition(interface.transport == .tcp)
    precondition(interface.mtu == 1280)
    precondition(interface.listen.port == 0)
    precondition(routes.count == 1)
    precondition(routes[0].peerName == "smoke-peer")
    precondition(routes[0].cidr == "10.77.99.1/32")
    precondition(routes[0].routeKind == .included)
    precondition(routes[0].configuredEndpoint == "192.0.2.10:27777")
    precondition(routes[0].endpoint.displayString == "192.0.2.10:27777")
    precondition(routes[0].endpointDescription == "192.0.2.10:27777")
    precondition(routes[0].sessionTimeout == 15)

    let hostPolicy = HushWireNetworkPolicy.hostRoutesOnly
    let summary = try HushWireConfigurationPolicy.inspect(
      configuration,
      networkPolicy: hostPolicy
    )
    precondition(summary.interface == "10.77.99.2/30")
    precondition(summary.transport == "TCP")
    precondition(summary.mtu == 1280)
    precondition(summary.peerCount == 1)
    precondition(summary.routes == ["10.77.99.1/32"])
    precondition(summary.directRoutes.isEmpty)
    precondition(summary.endpoints == ["192.0.2.10:27777"])
    precondition(summary.resolvedEndpoints == ["192.0.2.10:27777"])
    precondition(summary.routePolicy == .hostRoutesOnly)
    precondition(summary.dnsServers.isEmpty)

    let hostPlan = try HushWireConfigurationPolicy.plan(
      configuration,
      networkPolicy: hostPolicy
    )
    precondition(
      hostPlan.includedRoutes == [
        HushWireIPv4RouteSpec(network: "10.77.99.1", prefixLength: 32)
      ]
    )
    precondition(hostPlan.excludedRoutes.isEmpty)
    precondition(hostPlan.dnsServers.isEmpty)

    let splitRoutesText = configurationText.replacingOccurrences(
      of: "allowed_ips = [\"10.77.99.1/32\"]",
      with:
        "allowed_ips = [\"172.16.1.8/32\", \"10.0.0.0/8\", \"192.0.0.0/4\"]"
    )
    let splitRoutesPolicy = try HushWireNetworkPolicy(
      routePolicy: .splitRoutes,
      dnsServers: ["192.168.100.1"]
    )
    let splitRoutesPlan = try HushWireConfigurationPolicy.plan(
      Data(splitRoutesText.utf8),
      networkPolicy: splitRoutesPolicy
    )
    precondition(splitRoutesPlan.summary.routePolicy == .splitRoutes)
    precondition(splitRoutesPlan.summary.routes.count == 3)
    precondition(
      splitRoutesPlan.includedRoutes == [
        HushWireIPv4RouteSpec(network: "172.16.1.8", prefixLength: 32),
        HushWireIPv4RouteSpec(network: "10.0.0.0", prefixLength: 8),
        HushWireIPv4RouteSpec(network: "192.0.0.0", prefixLength: 4),
      ]
    )
    precondition(
      splitRoutesPlan.excludedRoutes == [
        HushWireIPv4RouteSpec(network: "192.0.2.10", prefixLength: 32)
      ]
    )
    precondition(splitRoutesPlan.dnsServers == ["192.168.100.1"])
    precondition(
      HushWireIPv4RouteSpec(network: "192.0.0.0", prefixLength: 4)
        .contains("192.168.100.1")
    )

    let hostnameText = configurationText.replacingOccurrences(
      of: "endpoint = \"192.0.2.10:27777\"",
      with: "endpoint = \"localhost:27777\""
    )
    let hostnameSummary = try HushWireConfigurationPolicy.inspect(Data(hostnameText.utf8))
    precondition(hostnameSummary.endpoints.count == 1)
    precondition(hostnameSummary.endpoints[0].hasPrefix("localhost:27777 → 127.0.0.1:27777"))

    let fullTunnelText = configurationText.replacingOccurrences(
      of: "allowed_ips = [\"10.77.99.1/32\"]",
      with: "allowed_ips = [\"0.0.0.0/0\"]"
    )
    let fullTunnelPolicy = try HushWireNetworkPolicy(
      routePolicy: .fullTunnel,
      dnsServers: ["1.1.1.1", "1.0.0.1", "1.1.1.1"]
    )
    let fullTunnelPlan = try HushWireConfigurationPolicy.plan(
      Data(fullTunnelText.utf8),
      networkPolicy: fullTunnelPolicy
    )
    precondition(fullTunnelPlan.summary.routePolicy == .fullTunnel)
    precondition(fullTunnelPlan.summary.routes == ["0.0.0.0/0"])
    precondition(fullTunnelPlan.summary.directRoutes == ["192.0.2.10/32"])
    precondition(fullTunnelPlan.summary.dnsServers == ["1.1.1.1", "1.0.0.1"])
    precondition(
      fullTunnelPlan.includedRoutes == [
        HushWireIPv4RouteSpec(network: "0.0.0.0", prefixLength: 0)
      ]
    )
    precondition(
      fullTunnelPlan.packetTunnelIncludedRoutes == [
        HushWireIPv4RouteSpec(network: "0.0.0.0", prefixLength: 1),
        HushWireIPv4RouteSpec(network: "128.0.0.0", prefixLength: 1),
      ]
    )
    precondition(
      fullTunnelPlan.excludedRoutes == [
        HushWireIPv4RouteSpec(network: "192.0.2.10", prefixLength: 32)
      ]
    )
    precondition(fullTunnelPlan.dnsServers == ["1.1.1.1", "1.0.0.1"])

    let defaultTunnelWithExclusionsText = fullTunnelText.replacingOccurrences(
      of: "allowed_ips = [\"0.0.0.0/0\"]",
      with:
        "allowed_ips = [\"0.0.0.0/0\"]\nexcluded_ips = [\"10.0.0.0/8\", \"192.0.2.0/24\"]"
    )
    let defaultTunnelWithExclusionsPlan = try HushWireConfigurationPolicy.plan(
      Data(defaultTunnelWithExclusionsText.utf8),
      networkPolicy: fullTunnelPolicy
    )
    precondition(
      defaultTunnelWithExclusionsPlan.excludedRoutes == [
        HushWireIPv4RouteSpec(network: "192.0.2.0", prefixLength: 24),
        HushWireIPv4RouteSpec(network: "10.0.0.0", prefixLength: 8),
      ]
    )
    precondition(
      defaultTunnelWithExclusionsPlan.summary.directRoutes
        == ["192.0.2.0/24", "10.0.0.0/8"]
    )

    let migratedWireGuardPolicyText = fullTunnelText.replacingOccurrences(
      of: "allowed_ips = [\"0.0.0.0/0\"]",
      with:
        """
        allowed_ips = ["10.0.0.1/32", "172.16.1.8/32", "0.0.0.0/0"]
        excluded_ips = ["10.0.0.0/8", "42.187.128.0/17", "58.32.0.0/16", "58.41.0.0/16", "109.244.0.0/19", "218.80.0.0/16"]
        """
    )
    let migratedWireGuardPolicy = try HushWireNetworkPolicy(
      routePolicy: .fullTunnel,
      dnsServers: ["192.168.100.1"]
    )
    let migratedWireGuardPlan = try HushWireConfigurationPolicy.plan(
      Data(migratedWireGuardPolicyText.utf8),
      networkPolicy: migratedWireGuardPolicy
    )
    precondition(
      migratedWireGuardPlan.includedRoutes == [
        HushWireIPv4RouteSpec(network: "10.0.0.1", prefixLength: 32),
        HushWireIPv4RouteSpec(network: "172.16.1.8", prefixLength: 32),
        HushWireIPv4RouteSpec(network: "0.0.0.0", prefixLength: 0),
      ]
    )
    precondition(
      migratedWireGuardPlan.packetTunnelIncludedRoutes == [
        HushWireIPv4RouteSpec(network: "10.0.0.1", prefixLength: 32),
        HushWireIPv4RouteSpec(network: "172.16.1.8", prefixLength: 32),
        HushWireIPv4RouteSpec(network: "0.0.0.0", prefixLength: 1),
        HushWireIPv4RouteSpec(network: "128.0.0.0", prefixLength: 1),
      ]
    )
    precondition(
      migratedWireGuardPlan.excludedRoutes == [
        HushWireIPv4RouteSpec(network: "192.0.2.10", prefixLength: 32),
        HushWireIPv4RouteSpec(network: "109.244.0.0", prefixLength: 19),
        HushWireIPv4RouteSpec(network: "42.187.128.0", prefixLength: 17),
        HushWireIPv4RouteSpec(network: "218.80.0.0", prefixLength: 16),
        HushWireIPv4RouteSpec(network: "58.32.0.0", prefixLength: 16),
        HushWireIPv4RouteSpec(network: "58.41.0.0", prefixLength: 16),
        HushWireIPv4RouteSpec(network: "10.0.0.0", prefixLength: 8),
      ]
    )
    precondition(migratedWireGuardPlan.dnsServers == ["192.168.100.1"])

    let providerConfiguration = fullTunnelPolicy.addingProviderConfiguration(to: [
      "schemaVersion": 4,
      "configurationStorage": "app-group-v1",
    ])
    let restoredFullTunnelPolicy = try HushWireNetworkPolicy(
      providerConfiguration: providerConfiguration
    )
    precondition(restoredFullTunnelPolicy == fullTunnelPolicy)
    precondition(
      HushWireNetworkPolicy.parseDNSServers("1.1.1.1, 1.0.0.1;9.9.9.9")
        == ["1.1.1.1", "1.0.0.1", "9.9.9.9"]
    )

    try expectPolicyRejection(
      fullTunnelText,
      networkPolicy: hostPolicy,
      containing: "主机路由模式"
    )
    try expectPolicyRejection(
      configurationText,
      networkPolicy: fullTunnelPolicy,
      containing: "默认隧道 v1"
    )
    try expectPolicyRejection(
      fullTunnelText,
      networkPolicy: splitRoutesPolicy,
      containing: "不接受 0.0.0.0/0"
    )
    try expectPolicyRejection(
      splitRoutesText,
      networkPolicy: try HushWireNetworkPolicy(
        routePolicy: .splitRoutes,
        dnsServers: ["8.8.8.8"]
      ),
      containing: "不在 allowed_ips 内"
    )
    let tooManyRoutes = (0...HushWireConfigurationPolicy.maximumSplitRouteCount)
      .map { index in
        "\"10.\(index / 256).\(index % 256).1/32\""
      }
      .joined(separator: ", ")
    try expectPolicyRejection(
      configurationText.replacingOccurrences(
        of: "allowed_ips = [\"10.77.99.1/32\"]",
        with: "allowed_ips = [\(tooManyRoutes)]"
      ),
      networkPolicy: try HushWireNetworkPolicy(routePolicy: .splitRoutes, dnsServers: []),
      containing: "最多接受 256 条"
    )
    let nestedOverrideText = fullTunnelText.replacingOccurrences(
      of: "allowed_ips = [\"0.0.0.0/0\"]",
      with:
        "allowed_ips = [\"10.0.0.1/32\", \"0.0.0.0/0\"]\nexcluded_ips = [\"10.0.0.0/8\"]"
    )
    let nestedOverridePolicy = try HushWireNetworkPolicy(
      routePolicy: .fullTunnel,
      dnsServers: ["10.0.0.1"]
    )
    let nestedOverridePlan = try HushWireConfigurationPolicy.plan(
      Data(nestedOverrideText.utf8),
      networkPolicy: nestedOverridePolicy
    )
    precondition(
      nestedOverridePlan.includedRoutes == [
        HushWireIPv4RouteSpec(network: "10.0.0.1", prefixLength: 32),
        HushWireIPv4RouteSpec(network: "0.0.0.0", prefixLength: 0),
      ]
    )
    precondition(
      nestedOverridePlan.excludedRoutes == [
        HushWireIPv4RouteSpec(network: "192.0.2.10", prefixLength: 32),
        HushWireIPv4RouteSpec(network: "10.0.0.0", prefixLength: 8),
      ]
    )
    precondition(nestedOverridePlan.dnsServers == ["10.0.0.1"])
    try expectPolicyRejection(
      fullTunnelText,
      networkPolicy: try HushWireNetworkPolicy(
        routePolicy: .fullTunnel,
        dnsServers: ["192.0.2.10"]
      ),
      containing: "不能与被排除"
    )
    try expectPolicyRejection(
      defaultTunnelWithExclusionsText,
      networkPolicy: try HushWireNetworkPolicy(
        routePolicy: .fullTunnel,
        dnsServers: ["10.0.0.1"]
      ),
      containing: "excluded_ips"
    )
    try expectPolicyRejection(
      fullTunnelText.replacingOccurrences(
        of: "persistent_keepalive = 5",
        with: "persistent_keepalive = 0"
      ),
      networkPolicy: fullTunnelPolicy,
      containing: "persistent_keepalive"
    )
    try expectPolicyRejection(
      fullTunnelText.replacingOccurrences(
        of: "transport = \"tcp\"",
        with: "transport = \"udp\""
      ),
      networkPolicy: fullTunnelPolicy,
      containing: "udp_rebind_after"
    )
    let udpFullTunnelText =
      fullTunnelText
      .replacingOccurrences(of: "transport = \"tcp\"", with: "transport = \"udp\"")
      .replacingOccurrences(
        of: "persistent_keepalive = 5",
        with: "persistent_keepalive = 5\nudp_rebind_after = 20"
      )
    let udpFullTunnelSummary = try HushWireConfigurationPolicy.inspect(
      Data(udpFullTunnelText.utf8),
      networkPolicy: fullTunnelPolicy
    )
    precondition(udpFullTunnelSummary.transport == "UDP")
    try expectNetworkPolicyRejection(
      routePolicy: .hostRoutesOnly,
      dnsServers: ["1.1.1.1"],
      containing: "不会修改 DNS"
    )
    try expectNetworkPolicyRejection(
      routePolicy: .fullTunnel,
      dnsServers: ["not-an-ip"],
      containing: "必须是 IPv4"
    )
    try expectProviderPolicyRejection(
      [
        HushWireNetworkPolicy.routePolicyKey: HushWireRoutePolicy.fullTunnel.rawValue,
        HushWireNetworkPolicy.dnsServersKey: [NSNumber(value: 1)],
      ],
      containing: "格式无效"
    )

    try expectPolicyRejection(
      configurationText.replacingOccurrences(
        of: "allowed_ips = [\"10.77.99.1/32\"]",
        with: "allowed_ips = [\"10.77.99.0/24\"]"
      ),
      containing: "主机路由模式"
    )
    try expectPolicyRejection(
      configurationText.replacingOccurrences(
        of: "listen = \"0.0.0.0:0\"",
        with: "listen = \"0.0.0.0:27783\""
      ),
      containing: "端口 0"
    )
    try expectPolicyRejection(
      """
      [interface]
      name = "utun-test"
      address = "10.77.99.2/30"
      listen = "0.0.0.0:0"
      transport = "udp"
      mtu = 1280
      private_key = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
      """,
      containing: "没有 Peer 路由"
    )

    try runtime.start()
    try runtime.initiateHandshake(peerName: "smoke-peer")
    try runtime.tick()
    try runtime.stop()

    print("HushWire System Extension core wrapper smoke test passed")
  }

  private static func expectPolicyRejection(
    _ configuration: String,
    networkPolicy: HushWireNetworkPolicy = .hostRoutesOnly,
    containing expectedMessage: String
  ) throws {
    do {
      _ = try HushWireConfigurationPolicy.inspect(
        Data(configuration.utf8),
        networkPolicy: networkPolicy
      )
      preconditionFailure("configuration policy unexpectedly accepted invalid input")
    } catch {
      precondition(error.localizedDescription.contains(expectedMessage))
    }
  }

  private static func expectNetworkPolicyRejection(
    routePolicy: HushWireRoutePolicy,
    dnsServers: [String],
    containing expectedMessage: String
  ) throws {
    do {
      _ = try HushWireNetworkPolicy(routePolicy: routePolicy, dnsServers: dnsServers)
      preconditionFailure("network policy unexpectedly accepted invalid input")
    } catch {
      precondition(error.localizedDescription.contains(expectedMessage))
    }
  }

  private static func expectProviderPolicyRejection(
    _ providerConfiguration: [String: Any],
    containing expectedMessage: String
  ) throws {
    do {
      _ = try HushWireNetworkPolicy(providerConfiguration: providerConfiguration)
      preconditionFailure("provider policy unexpectedly accepted invalid input")
    } catch {
      precondition(error.localizedDescription.contains(expectedMessage))
    }
  }
}
