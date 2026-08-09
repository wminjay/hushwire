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
    precondition(routes[0].endpoint.displayString == "192.0.2.10:27777")
    precondition(routes[0].sessionTimeout == 15)

    let summary = try HushWireHostRouteConfigurationPolicy.inspect(configuration)
    precondition(summary.interface == "10.77.99.2/30")
    precondition(summary.transport == "TCP")
    precondition(summary.mtu == 1280)
    precondition(summary.peerCount == 1)
    precondition(summary.routes == ["10.77.99.1/32"])
    precondition(summary.endpoints == ["192.0.2.10:27777"])

    try expectPolicyRejection(
      configurationText.replacingOccurrences(
        of: "allowed_ips = [\"10.77.99.1/32\"]",
        with: "allowed_ips = [\"10.77.99.0/24\"]"
      ),
      containing: "/32"
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
    containing expectedMessage: String
  ) throws {
    do {
      _ = try HushWireHostRouteConfigurationPolicy.inspect(Data(configuration.utf8))
      preconditionFailure("configuration policy unexpectedly accepted invalid input")
    } catch {
      precondition(error.localizedDescription.contains(expectedMessage))
    }
  }
}
