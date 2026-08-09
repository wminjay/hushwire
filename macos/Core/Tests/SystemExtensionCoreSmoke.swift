import Foundation

@main
enum SystemExtensionCoreSmoke {
  static func main() throws {
    let configuration = Data(
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
      """.utf8
    )

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

    try runtime.start()
    try runtime.initiateHandshake(peerName: "smoke-peer")
    try runtime.tick()
    try runtime.stop()

    print("HushWire System Extension core wrapper smoke test passed")
  }
}
