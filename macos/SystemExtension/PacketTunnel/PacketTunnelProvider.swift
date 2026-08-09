import Darwin
import Foundation
import HushWireCore
import NetworkExtension
import os

final class PacketTunnelProvider: NEPacketTunnelProvider, HushWireCoreRuntimeDelegate {
  private enum ProviderFailure {
    static func error(code: Int, description: String) -> Error {
      NSError(
        domain: "com.jamie.HushWire.PacketTunnel",
        code: code,
        userInfo: [NSLocalizedDescriptionKey: description]
      )
    }
  }

  private let workQueue = DispatchQueue(label: "com.jamie.HushWire.PacketTunnel.provider")
  private let logger = Logger(subsystem: "com.jamie.HushWire", category: "PacketTunnel")
  private var core: HushWireCoreRuntime?
  private var transport: HushWireNetworkTransport?
  private var maintenanceTimer: DispatchSourceTimer?
  private var peerNames: [String] = []
  private var interfaceMetadata: HushWireInterfaceMetadata?
  private var routeMetadata: [HushWireRouteMetadata] = []
  private var lastHandshakeDescription: String?
  private var awaitingConfiguration = false
  private var running = false

  override func startTunnel(
    options: [String: NSObject]?,
    completionHandler: @escaping (Error?) -> Void
  ) {
    workQueue.async { [weak self] in
      guard let self else { return }
      do {
        guard !running, core == nil else {
          throw ProviderFailure.error(code: 1, description: "HushWire Packet Tunnel 已经在运行。")
        }
        let providerConfiguration = try validatedProviderConfiguration()
        guard
          providerConfiguration["configurationStorage"] as? String
            == HushWireConfigurationStore.providerStorageKind
        else {
          throw ProviderFailure.error(
            code: 2,
            description: "VPN 配置尚未引用安全的 App Group 配置。请先在 HushWire 中导入 TOML。"
          )
        }
        guard
          providerConfiguration["routePolicy"] as? String
            == HushWireConfigurationStore.routePolicy
        else {
          throw ProviderFailure.error(code: 3, description: "VPN 配置缺少安全路由策略。")
        }
        // Secrets are intentionally not accepted in start options because
        // macOS retains those options in diagnostic session state. Mark the
        // provider connected without routes, then receive the configuration
        // over the private provider-message channel.
        awaitingConfiguration = true
        logger.info("Packet Tunnel is waiting for private configuration delivery")
        completionHandler(nil)
      } catch {
        finishFailedStart(error, completionHandler: completionHandler)
      }
    }
  }

  override func stopTunnel(
    with reason: NEProviderStopReason,
    completionHandler: @escaping () -> Void
  ) {
    workQueue.async { [weak self] in
      guard let self else {
        completionHandler()
        return
      }
      self.logger.info("Packet Tunnel stopping; reason=\(reason.rawValue)")
      self.tearDownRuntime()
      self.setTunnelNetworkSettings(nil) { error in
        if let error {
          self.logger.error("Failed to clear tunnel settings: \(error.localizedDescription)")
        }
        completionHandler()
      }
    }
  }

  override func handleAppMessage(
    _ messageData: Data,
    completionHandler: ((Data?) -> Void)?
  ) {
    workQueue.async { [weak self] in
      guard let self else {
        completionHandler?(nil)
        return
      }
      guard let command = messageData.first else {
        completionHandler?(self.response(ok: false, error: "空的 provider message。"))
        return
      }
      switch command {
      case 0x01:
        completionHandler?(self.statusResponse())
      case 0x02:
        self.installConfiguration(
          Data(messageData.dropFirst()),
          completionHandler: completionHandler
        )
      default:
        completionHandler?(self.response(ok: false, error: "未知的 provider message。"))
      }
    }
  }

  func coreRuntime(
    _ runtime: HushWireCoreRuntime,
    sendTransport frame: Data,
    to endpoint: HushWireEndpoint,
    peerName: String
  ) {
    guard runtime === core, let transport else { return }
    transport.send(frame, to: endpoint) { [weak runtime] succeeded in
      guard succeeded, let runtime else { return }
      do {
        try runtime.recordTransportSent(peerName: peerName, byteCount: frame.count)
      } catch {
        // A completion racing with stop is expected to see a stopped runtime.
      }
    }
  }

  func coreRuntime(
    _ runtime: HushWireCoreRuntime,
    writeIPPacket packet: Data,
    from endpoint: HushWireEndpoint,
    peerName: String
  ) {
    guard runtime === core else { return }
    packetFlow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
  }

  func coreRuntime(
    _ runtime: HushWireCoreRuntime,
    handshakeCompletedFor peerName: String,
    endpoint: HushWireEndpoint,
    role: UInt8
  ) {
    guard runtime === core else { return }
    let roleName = role == 1 ? "initiator" : "responder"
    logger.info(
      "Handshake completed for \(peerName, privacy: .public) as \(roleName, privacy: .public)"
    )
    workQueue.async { [weak self] in
      self?.lastHandshakeDescription = "\(peerName) · \(roleName) · \(endpoint.displayString)"
    }
  }

  func coreRuntimeRebindUDP(
    _ runtime: HushWireCoreRuntime,
    peerName: String,
    silenceMilliseconds: UInt64
  ) -> Bool {
    guard runtime === core, let transport else { return false }
    logger.notice(
      "Rebinding UDP after \(silenceMilliseconds) ms without authenticated traffic from \(peerName, privacy: .public)"
    )
    return transport.rebindUDP()
  }

  private func validatedProviderConfiguration() throws -> [String: Any] {
    guard
      let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol,
      let configuration = tunnelProtocol.providerConfiguration
    else {
      throw ProviderFailure.error(code: 4, description: "HushWire VPN 配置不存在。")
    }
    return configuration
  }

  private func installConfiguration(
    _ configuration: Data,
    completionHandler: ((Data?) -> Void)?
  ) {
    do {
      guard awaitingConfiguration, !running, core == nil else {
        throw ProviderFailure.error(code: 9, description: "隧道配置已经安装。")
      }
      guard !configuration.isEmpty, configuration.count <= 1_048_576 else {
        throw ProviderFailure.error(code: 10, description: "临时配置为空或超过 1 MiB。")
      }

      let runtime = try HushWireCoreRuntime(configuration: configuration)
      let interface = try runtime.interfaceMetadata()
      let routes = try runtime.routes()
      try validateHostRoutePreview(interface: interface, routes: routes)

      let networkTransport = HushWireNetworkTransport(
        mode: interface.transport,
        frameHandler: { [weak self] frame, endpoint in
          self?.receiveTransport(frame, source: endpoint)
        },
        eventHandler: { [weak self] message in
          self?.logger.info("\(message, privacy: .public)")
        }
      )
      runtime.delegate = self
      try runtime.start()

      core = runtime
      transport = networkTransport
      interfaceMetadata = interface
      routeMetadata = routes
      peerNames = Array(Set(routes.map(\.peerName))).sorted()

      let settings = makeNetworkSettings(interface: interface, routes: routes)
      setTunnelNetworkSettings(settings) { [weak self] error in
        guard let self else { return }
        self.workQueue.async {
          if let error {
            self.finishFailedConfiguration(error, completionHandler: completionHandler)
            return
          }
          self.awaitingConfiguration = false
          self.running = true
          self.beginPacketRead()
          self.startMaintenanceTimer()
          self.startInitialHandshakes()
          self.logger.info(
            "Packet Tunnel configured with \(routes.count) host route(s), no DNS and no default route"
          )
          completionHandler?(self.response(ok: true))
        }
      }
    } catch {
      finishFailedConfiguration(error, completionHandler: completionHandler)
    }
  }

  private func statusResponse() -> Data? {
    let statistics = (try? core?.peerStatistics()) ?? []
    let peers: [[String: Any]] = statistics.map { stats in
      var value: [String: Any] = [
        "name": stats.peerName,
        "txBytes": stats.txBytes,
        "rxBytes": stats.rxBytes,
      ]
      if let lastSeen = stats.lastSeenMillisecondsAgo {
        value["lastSeenMillisecondsAgo"] = lastSeen
      }
      if let endpoint = stats.endpoint {
        value["endpoint"] = endpoint.displayString
      }
      return value
    }
    let value: [String: Any] = [
      "ok": true,
      "abiVersion": hw_core_abi_version(),
      "coreVersion": String(cString: hw_core_version_string()),
      "packetFlowEnabled": true,
      "awaitingConfiguration": awaitingConfiguration,
      "running": running,
      "routePolicy": HushWireConfigurationStore.routePolicy,
      "interface": interfaceMetadata?.cidr ?? "",
      "transport": interfaceMetadata?.transport.title ?? "",
      "routes": routeMetadata.map(\.cidr),
      "lastHandshake": lastHandshakeDescription ?? "",
      "peers": peers,
    ]
    return try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
  }

  private func response(ok: Bool, error: String? = nil) -> Data? {
    var value: [String: Any] = ["ok": ok]
    if let error { value["error"] = error }
    return try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
  }

  private func validateHostRoutePreview(
    interface: HushWireInterfaceMetadata,
    routes: [HushWireRouteMetadata]
  ) throws {
    guard !routes.isEmpty else {
      throw ProviderFailure.error(code: 5, description: "配置没有 Peer 路由。")
    }
    guard routes.allSatisfy({ $0.prefixLength == 32 }) else {
      throw ProviderFailure.error(
        code: 6,
        description: "当前安全阶段只允许 /32 主机路由；未启用子网、默认路由或 DNS。"
      )
    }
    guard interface.listen.port == 0 else {
      throw ProviderFailure.error(
        code: 7,
        description: "当前 macOS 客户端要求 interface.listen 使用端口 0（系统分配本地端口）。"
      )
    }
    guard routes.allSatisfy({ $0.endpoint.port != 0 && !$0.endpoint.host.isEmpty }) else {
      throw ProviderFailure.error(code: 8, description: "Peer endpoint 无效。")
    }
  }

  private func makeNetworkSettings(
    interface: HushWireInterfaceMetadata,
    routes: [HushWireRouteMetadata]
  ) -> NEPacketTunnelNetworkSettings {
    let settings = NEPacketTunnelNetworkSettings(
      tunnelRemoteAddress: routes[0].endpoint.host
    )
    // Use a /32 interface mask during the host-route-only phase. This avoids
    // macOS implicitly adding the wider address subnet as a connected route.
    let ipv4 = NEIPv4Settings(
      addresses: [interface.address],
      subnetMasks: ["255.255.255.255"]
    )
    ipv4.includedRoutes = routes.map {
      NEIPv4Route(destinationAddress: $0.network, subnetMask: "255.255.255.255")
    }
    ipv4.excludedRoutes = []
    settings.ipv4Settings = ipv4
    settings.mtu = NSNumber(value: interface.mtu)
    return settings
  }

  private func beginPacketRead() {
    guard running else { return }
    packetFlow.readPackets { [weak self] packets, protocols in
      guard let self else { return }
      self.workQueue.async {
        guard self.running else { return }
        for (packet, protocolNumber) in zip(packets, protocols)
        where protocolNumber.int32Value == AF_INET {
          do {
            try self.core?.submitOutboundIP(packet)
          } catch {
            self.logger.error("Core rejected outbound IP packet: \(error.localizedDescription)")
          }
        }
        self.beginPacketRead()
      }
    }
  }

  private func receiveTransport(_ frame: Data, source: HushWireEndpoint) {
    do {
      try core?.submitInboundTransport(frame, source: source)
    } catch {
      logger.error("Core rejected inbound transport frame: \(error.localizedDescription)")
    }
  }

  private func startInitialHandshakes() {
    guard let core else { return }
    for peerName in peerNames {
      do {
        try core.initiateHandshake(peerName: peerName)
      } catch {
        logger.error(
          "Could not initiate handshake for \(peerName, privacy: .public): \(error.localizedDescription)"
        )
      }
    }
  }

  private func startMaintenanceTimer() {
    let timer = DispatchSource.makeTimerSource(queue: workQueue)
    timer.schedule(deadline: .now() + 1, repeating: 1, leeway: .milliseconds(100))
    timer.setEventHandler { [weak self] in
      guard let self, self.running, let core = self.core else { return }
      do {
        try core.tick()
      } catch {
        self.logger.error("Session maintenance failed: \(error.localizedDescription)")
      }
    }
    maintenanceTimer = timer
    timer.resume()
  }

  private func finishFailedStart(
    _ error: Error,
    completionHandler: @escaping (Error?) -> Void
  ) {
    logger.error("Packet Tunnel failed to start: \(error.localizedDescription)")
    tearDownRuntime()
    completionHandler(error)
  }

  private func finishFailedConfiguration(
    _ error: Error,
    completionHandler: ((Data?) -> Void)?
  ) {
    logger.error("Packet Tunnel configuration failed: \(error.localizedDescription)")
    tearDownRuntime()
    completionHandler?(response(ok: false, error: error.localizedDescription))
  }

  private func tearDownRuntime() {
    awaitingConfiguration = false
    running = false
    maintenanceTimer?.setEventHandler {}
    maintenanceTimer?.cancel()
    maintenanceTimer = nil
    transport?.stop()
    transport = nil
    core?.delegate = nil
    do {
      try core?.stop()
    } catch {
      logger.error("Rust Core stop failed: \(error.localizedDescription)")
    }
    core = nil
    peerNames = []
    interfaceMetadata = nil
    routeMetadata = []
    lastHandshakeDescription = nil
  }
}
