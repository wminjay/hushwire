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

  private struct PendingFullTunnelActivation {
    let settings: NEPacketTunnelNetworkSettings
    let plan: HushWireConfigurationPlan
    let completionHandler: ((Data?) -> Void)?
  }

  private let workQueue = DispatchQueue(label: "com.jamie.HushWire.PacketTunnel.provider")
  private let logger = Logger(subsystem: "com.jamie.HushWire", category: "PacketTunnel")
  private var core: HushWireCoreRuntime?
  private var transport: HushWireNetworkTransport?
  private var maintenanceTimer: DispatchSourceTimer?
  private var fullTunnelHandshakeTimeout: DispatchWorkItem?
  private var pendingFullTunnelActivation: PendingFullTunnelActivation?
  private var peerNames: [String] = []
  private var interfaceMetadata: HushWireInterfaceMetadata?
  private var routeMetadata: [HushWireRouteMetadata] = []
  private var networkPolicy = HushWireNetworkPolicy.hostRoutesOnly
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
        let networkPolicy = try HushWireNetworkPolicy(
          providerConfiguration: providerConfiguration
        )
        let schemaVersion =
          (providerConfiguration["schemaVersion"] as? NSNumber)?.intValue
          ?? providerConfiguration["schemaVersion"] as? Int
        guard schemaVersion == 2 || schemaVersion == 3 else {
          throw ProviderFailure.error(code: 3, description: "VPN 配置 schemaVersion 不受支持。")
        }
        if networkPolicy.routePolicy == .fullTunnel {
          guard schemaVersion == 3 else {
            throw ProviderFailure.error(
              code: 3,
              description: "全隧道要求 schemaVersion 3，请重新保存 VPN 配置。"
            )
          }
          guard
            (options?[HushWireNetworkPolicy.fullTunnelApprovalOptionKey] as? NSNumber)?
              .boolValue == true
          else {
            throw ProviderFailure.error(
              code: 3,
              description: "全隧道启动缺少本次明确确认；请从 HushWire App 点击连接。"
            )
          }
        }
        // Secrets are intentionally not accepted in start options because
        // macOS retains those options in diagnostic session state. Mark the
        // provider connected without routes, then receive the configuration
        // over the private provider-message channel.
        self.networkPolicy = networkPolicy
        awaitingConfiguration = true
        logger.info(
          "Packet Tunnel is waiting for private configuration delivery; routePolicy=\(networkPolicy.routePolicy.rawValue, privacy: .public)"
        )
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
      // The system tears down the virtual interface and its routes when the
      // provider finishes stopTunnel. Trying to replace the network settings
      // with nil while that teardown is already under way races the system on
      // macOS and can report a spurious "Device not configured" error even
      // though the routes and DNS have been removed successfully.
      completionHandler()
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
    guard runtime === core, running else { return }
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
      guard let self, runtime === self.core else { return }
      self.lastHandshakeDescription = "\(peerName) · \(roleName) · \(endpoint.displayString)"
      self.activatePendingFullTunnelIfNeeded(peerName: peerName)
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
      let configurationPlan = try HushWireConfigurationPolicy.plan(
        interface: interface,
        routes: routes,
        networkPolicy: networkPolicy
      )

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

      let settings = makeNetworkSettings(
        interface: interface,
        routes: routes,
        plan: configurationPlan
      )
      if networkPolicy.routePolicy == .fullTunnel {
        pendingFullTunnelActivation = PendingFullTunnelActivation(
          settings: settings,
          plan: configurationPlan,
          completionHandler: completionHandler
        )
        startMaintenanceTimer()
        scheduleFullTunnelHandshakeTimeout()
        logger.info(
          "Full tunnel is waiting for an authenticated preflight handshake before routes or DNS are installed"
        )
        startInitialHandshakes()
      } else {
        activateConfiguration(
          settings: settings,
          plan: configurationPlan,
          completionHandler: completionHandler,
          handshakeAlreadyStarted: false
        )
      }
    } catch {
      finishFailedConfiguration(error, completionHandler: completionHandler)
    }
  }

  private func activatePendingFullTunnelIfNeeded(peerName: String) {
    guard
      peerNames.contains(peerName),
      let pending = pendingFullTunnelActivation
    else { return }
    pendingFullTunnelActivation = nil
    fullTunnelHandshakeTimeout?.cancel()
    fullTunnelHandshakeTimeout = nil
    logger.info(
      "Authenticated preflight completed for \(peerName, privacy: .public); installing full-tunnel routes and DNS"
    )
    activateConfiguration(
      settings: pending.settings,
      plan: pending.plan,
      completionHandler: pending.completionHandler,
      handshakeAlreadyStarted: true
    )
  }

  private func activateConfiguration(
    settings: NEPacketTunnelNetworkSettings,
    plan: HushWireConfigurationPlan,
    completionHandler: ((Data?) -> Void)?,
    handshakeAlreadyStarted: Bool
  ) {
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
        if !handshakeAlreadyStarted {
          self.startInitialHandshakes()
        }
        self.logger.info(
          "Packet Tunnel configured; routePolicy=\(self.networkPolicy.routePolicy.rawValue, privacy: .public) includedRoutes=\(plan.includedRoutes.count) excludedRoutes=\(plan.excludedRoutes.count) dnsServers=\(plan.dnsServers.count)"
        )
        completionHandler?(self.response(ok: true))
      }
    }
  }

  private func scheduleFullTunnelHandshakeTimeout() {
    fullTunnelHandshakeTimeout?.cancel()
    let timeout = DispatchWorkItem { [weak self] in
      guard let self, let pending = self.pendingFullTunnelActivation else { return }
      self.pendingFullTunnelActivation = nil
      self.fullTunnelHandshakeTimeout = nil
      let error = ProviderFailure.error(
        code: 11,
        description: "全隧道预握手在 15 秒内未完成；默认路由和 DNS 均未修改。"
      )
      self.finishFailedConfiguration(error, completionHandler: pending.completionHandler)
    }
    fullTunnelHandshakeTimeout = timeout
    workQueue.asyncAfter(deadline: .now() + 15, execute: timeout)
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
      "routePolicy": networkPolicy.routePolicy.rawValue,
      "dnsServers": networkPolicy.dnsServers,
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

  private func makeNetworkSettings(
    interface: HushWireInterfaceMetadata,
    routes: [HushWireRouteMetadata],
    plan: HushWireConfigurationPlan
  ) -> NEPacketTunnelNetworkSettings {
    let settings = NEPacketTunnelNetworkSettings(
      tunnelRemoteAddress: routes[0].endpoint.host
    )
    // Always use a /32 interface mask. This avoids macOS implicitly adding the
    // wider interface-address subnet as a connected route.
    let ipv4 = NEIPv4Settings(
      addresses: [interface.address],
      subnetMasks: ["255.255.255.255"]
    )
    ipv4.includedRoutes = plan.includedRoutes.map {
      NEIPv4Route(destinationAddress: $0.network, subnetMask: $0.subnetMask)
    }
    // A full tunnel must keep every transport endpoint on the primary
    // physical interface or its encrypted transport would recursively enter
    // the tunnel itself. The v1 policy currently permits exactly one endpoint.
    ipv4.excludedRoutes = plan.excludedRoutes.map {
      NEIPv4Route(destinationAddress: $0.network, subnetMask: $0.subnetMask)
    }
    settings.ipv4Settings = ipv4
    if !plan.dnsServers.isEmpty {
      let dns = NEDNSSettings(servers: plan.dnsServers)
      dns.matchDomains = [""]
      dns.matchDomainsNoSearch = true
      settings.dnsSettings = dns
    }
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
    guard maintenanceTimer == nil else { return }
    let timer = DispatchSource.makeTimerSource(queue: workQueue)
    timer.schedule(deadline: .now() + 1, repeating: 1, leeway: .milliseconds(100))
    timer.setEventHandler { [weak self] in
      guard
        let self,
        self.running || self.pendingFullTunnelActivation != nil,
        let core = self.core
      else { return }
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
    fullTunnelHandshakeTimeout?.cancel()
    fullTunnelHandshakeTimeout = nil
    let pendingCompletion = pendingFullTunnelActivation?.completionHandler
    pendingFullTunnelActivation = nil
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
    networkPolicy = .hostRoutesOnly
    lastHandshakeDescription = nil
    pendingCompletion?(response(ok: false, error: "隧道在全隧道预握手期间停止。"))
  }
}
