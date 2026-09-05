import Darwin
@preconcurrency import Foundation
import HushWireCore
@preconcurrency import NetworkExtension
import os

final class PacketTunnelProvider: NEPacketTunnelProvider, HushWireCoreRuntimeDelegate,
  @unchecked Sendable
{
  private enum ProviderFailure {
    static func error(code: Int, description: String) -> Error {
      NSError(
        domain: "com.jamie.HushWire.PacketTunnel",
        code: code,
        userInfo: [NSLocalizedDescriptionKey: description]
      )
    }
  }

  /// Network Extension completion handlers are designed to be invoked
  /// asynchronously but are not annotated `Sendable` in the imported API.
  private final class CallbackBox<Input>: @unchecked Sendable {
    private let callback: (Input) -> Void

    init(_ callback: @escaping (Input) -> Void) {
      self.callback = callback
    }

    func call(_ input: Input) {
      callback(input)
    }
  }

  private struct PendingProtectedActivation {
    let settings: NEPacketTunnelNetworkSettings
    let plan: HushWireConfigurationPlan
    let completionHandler: CallbackBox<Data?>?
  }

  private struct PendingEndpointRouteCleanup {
    let peerName: String
    let endpoint: HushWireEndpoint
    let settings: NEPacketTunnelNetworkSettings
  }

  private let workQueue = DispatchQueue(label: "com.jamie.HushWire.PacketTunnel.provider")
  private let endpointResolverQueue = DispatchQueue(
    label: "com.jamie.HushWire.PacketTunnel.endpoint-resolver",
    qos: .utility
  )
  private let logger = Logger(subsystem: "com.jamie.HushWire", category: "PacketTunnel")
  private var core: HushWireCoreRuntime?
  private var transport: HushWireNetworkTransport?
  private var maintenanceTimer: DispatchSourceTimer?
  private var configurationDeliveryTimeout: DispatchWorkItem?
  private var protectedHandshakeTimeout: DispatchWorkItem?
  private var pendingProtectedActivation: PendingProtectedActivation?
  private var peerNames: [String] = []
  private var interfaceMetadata: HushWireInterfaceMetadata?
  private var routeMetadata: [HushWireRouteMetadata] = []
  private var networkPolicy = HushWireNetworkPolicy.hostRoutesOnly
  private var lastHandshakeDescription: String?
  private var activeConfiguration: Data?
  private var duplicateConfigurationCompletionHandlers: [CallbackBox<Data?>] = []
  private var endpointRefreshInFlight = Set<String>()
  private var lastEndpointRefreshAttempt: [String: DispatchTime] = [:]
  private var pendingEndpointRouteCleanup: PendingEndpointRouteCleanup?
  private var awaitingConfiguration = false
  private var running = false

  override func startTunnel(
    options: [String: NSObject]?,
    completionHandler: @escaping (Error?) -> Void
  ) {
    let completion = CallbackBox(completionHandler)
    let fullTunnelApproved =
      (options?[HushWireNetworkPolicy.fullTunnelApprovalOptionKey] as? NSNumber)?.boolValue == true
    workQueue.async { [weak self] in
      guard let self else { return }
      do {
        guard !running, core == nil else {
          throw ProviderFailure.error(code: 1, description: "HushWire Packet Tunnel 已经在运行。")
        }
        let providerConfiguration = try validatedProviderConfiguration()
        guard
          let configurationStorage =
            providerConfiguration["configurationStorage"] as? String
        else {
          throw ProviderFailure.error(
            code: 2,
            description: "VPN 配置尚未引用安全配置通道。请先在 HushWire 中导入 TOML。"
          )
        }
        #if os(iOS)
          guard
            configurationStorage == HushWireConfigurationStore.providerStorageKind
              || configurationStorage == HushWireConfigurationStore.legacyProviderStorageKind
          else {
            throw ProviderFailure.error(
              code: 2,
              description: "VPN 配置引用了不受支持的安全配置通道。请在 HushWire 中重新保存策略。"
            )
          }
        #else
          guard configurationStorage == HushWireConfigurationStore.providerStorageKind else {
            throw ProviderFailure.error(
              code: 2,
              description: "VPN 配置引用了不受支持的安全配置通道。请在 HushWire 中重新保存配置。"
            )
          }
        #endif
        let networkPolicy = try HushWireNetworkPolicy(
          providerConfiguration: providerConfiguration
        )
        let schemaVersion =
          (providerConfiguration["schemaVersion"] as? NSNumber)?.intValue
          ?? providerConfiguration["schemaVersion"] as? Int
        guard let schemaVersion, (2...5).contains(schemaVersion)
        else {
          throw ProviderFailure.error(code: 3, description: "VPN 配置 schemaVersion 不受支持。")
        }
        #if os(iOS)
          let onDemandStartAuthorized =
            schemaVersion >= 5
            && (providerConfiguration[
              HushWireConfigurationStore.onDemandStartAuthorizedKey
            ] as? NSNumber)?.boolValue == true
        #else
          let onDemandStartAuthorized = false
        #endif
        if networkPolicy.routePolicy == .fullTunnel {
          guard schemaVersion >= 3 else {
            throw ProviderFailure.error(
              code: 3,
              description: "默认隧道要求 schemaVersion 3 或更高版本，请重新保存 VPN 配置。"
            )
          }
          guard fullTunnelApproved || onDemandStartAuthorized else {
            throw ProviderFailure.error(
              code: 3,
              description: "默认隧道启动既没有本次确认，也没有已保存的自动连接授权。"
            )
          }
        }
        if networkPolicy.routePolicy == .splitRoutes, schemaVersion != 4 {
          throw ProviderFailure.error(
            code: 3,
            description: "自定义分流要求 schemaVersion 4，请重新保存 VPN 配置。"
          )
        }
        self.networkPolicy = networkPolicy
        awaitingConfiguration = true
        #if os(iOS)
          if configurationStorage == HushWireConfigurationStore.providerStorageKind {
            guard schemaVersion >= 5 else {
              throw ProviderFailure.error(
                code: 3,
                description: "共享 Keychain 自动启动要求 schemaVersion 5，请重新保存 VPN 配置。"
              )
            }
            guard
              let profileIDValue = providerConfiguration[
                HushWireConfigurationStore.activeProfileIDKey
              ] as? String,
              let profileID = UUID(uuidString: profileIDValue)
            else {
              throw ProviderFailure.error(code: 2, description: "VPN 配置缺少有效的当前配置 ID。")
            }
            let configuration = try HushWireConfigurationStore.load(for: profileID)
            logger.info(
              "Packet Tunnel loaded its configuration from the shared Keychain; routePolicy=\(networkPolicy.routePolicy.rawValue, privacy: .public)"
            )
            completion.call(nil)
            installConfiguration(configuration, completionHandler: nil)
            return
          }
        #endif
        // Legacy iOS and current macOS starts receive the TOML over a private
        // provider-message channel. Secrets are never accepted in start options.
        scheduleConfigurationDeliveryTimeout()
        logger.info(
          "Packet Tunnel is waiting for private configuration delivery; routePolicy=\(networkPolicy.routePolicy.rawValue, privacy: .public)"
        )
        completion.call(nil)
      } catch {
        finishFailedStart(error, completionHandler: completion)
      }
    }
  }

  override func stopTunnel(
    with reason: NEProviderStopReason,
    completionHandler: @escaping () -> Void
  ) {
    let completion = CallbackBox<Void> { _ in completionHandler() }
    workQueue.async { [weak self] in
      guard let self else {
        completion.call(())
        return
      }
      self.logger.info("Packet Tunnel stopping; reason=\(reason.rawValue)")
      self.tearDownRuntime()
      // The system tears down the virtual interface and its routes when the
      // provider finishes stopTunnel. Trying to replace the network settings
      // with nil while that teardown is already under way races the system on
      // macOS and can report a spurious "Device not configured" error even
      // though the routes and DNS have been removed successfully.
      completion.call(())
    }
  }

  override func handleAppMessage(
    _ messageData: Data,
    completionHandler: ((Data?) -> Void)?
  ) {
    let completion = completionHandler.map { CallbackBox($0) }
    workQueue.async { [weak self] in
      guard let self else {
        completion?.call(nil)
        return
      }
      guard let command = messageData.first else {
        completion?.call(self.response(ok: false, error: "空的 provider message。"))
        return
      }
      switch command {
      case 0x01:
        completion?.call(self.statusResponse())
      case 0x02:
        self.installConfiguration(
          Data(messageData.dropFirst()),
          completionHandler: completion
        )
      default:
        completion?.call(self.response(ok: false, error: "未知的 provider message。"))
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
      self.activatePendingProtectedConfigurationIfNeeded(peerName: peerName)
      self.finishEndpointRouteTransitionIfNeeded(peerName: peerName, endpoint: endpoint)
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
    completionHandler: CallbackBox<Data?>?
  ) {
    do {
      if let activeConfiguration {
        guard activeConfiguration == configuration else {
          finishFailedConfiguration(
            ProviderFailure.error(
              code: 9,
              description: "收到与当前会话不一致的配置；隧道已安全停止，请重新连接。"
            ),
            completionHandler: completionHandler
          )
          return
        }
        if running {
          logger.info("Ignoring an identical duplicate configuration delivery")
          completionHandler?.call(response(ok: true))
        } else if let completionHandler {
          logger.info("Coalescing an identical configuration delivery during startup")
          duplicateConfigurationCompletionHandlers.append(completionHandler)
        }
        return
      }
      guard awaitingConfiguration, !running, core == nil else {
        throw ProviderFailure.error(code: 9, description: "隧道配置已经安装。")
      }
      guard !configuration.isEmpty, configuration.count <= 1_048_576 else {
        throw ProviderFailure.error(code: 10, description: "临时配置为空或超过 1 MiB。")
      }
      configurationDeliveryTimeout?.cancel()
      configurationDeliveryTimeout = nil

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

      activeConfiguration = configuration
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
      if networkPolicy.routePolicy.requiresAuthenticatedPreflight {
        pendingProtectedActivation = PendingProtectedActivation(
          settings: settings,
          plan: configurationPlan,
          completionHandler: completionHandler
        )
        startMaintenanceTimer()
        scheduleProtectedHandshakeTimeout()
        logger.info(
          "Protected network policy is waiting for an authenticated preflight handshake before routes or DNS are installed; routePolicy=\(self.networkPolicy.routePolicy.rawValue, privacy: .public)"
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

  private func activatePendingProtectedConfigurationIfNeeded(peerName: String) {
    guard
      peerNames.contains(peerName),
      let pending = pendingProtectedActivation
    else { return }
    pendingProtectedActivation = nil
    protectedHandshakeTimeout?.cancel()
    protectedHandshakeTimeout = nil
    logger.info(
      "Authenticated preflight completed for \(peerName, privacy: .public); installing routes and DNS for \(self.networkPolicy.routePolicy.rawValue, privacy: .public)"
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
    completionHandler: CallbackBox<Data?>?,
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
        let successResponse = self.response(ok: true)
        completionHandler?.call(successResponse)
        let duplicateCompletions = self.duplicateConfigurationCompletionHandlers
        self.duplicateConfigurationCompletionHandlers = []
        for duplicateCompletion in duplicateCompletions {
          duplicateCompletion.call(successResponse)
        }
      }
    }
  }

  private func scheduleProtectedHandshakeTimeout() {
    protectedHandshakeTimeout?.cancel()
    let timeout = DispatchWorkItem { [weak self] in
      guard let self, let pending = self.pendingProtectedActivation else { return }
      self.pendingProtectedActivation = nil
      self.protectedHandshakeTimeout = nil
      let error = ProviderFailure.error(
        code: 11,
        description: "认证预握手在 15 秒内未完成；隧道路由和 DNS 均未修改。"
      )
      self.finishFailedConfiguration(error, completionHandler: pending.completionHandler)
    }
    protectedHandshakeTimeout = timeout
    workQueue.asyncAfter(deadline: .now() + 15, execute: timeout)
  }

  private func scheduleConfigurationDeliveryTimeout() {
    configurationDeliveryTimeout?.cancel()
    let timeout = DispatchWorkItem { [weak self] in
      guard
        let self,
        self.awaitingConfiguration,
        self.activeConfiguration == nil
      else { return }
      self.configurationDeliveryTimeout = nil
      let error = ProviderFailure.error(
        code: 12,
        description: "15 秒内未收到安全隧道配置；Packet Tunnel 已自动停止。"
      )
      self.finishFailedConfiguration(error, completionHandler: nil)
    }
    configurationDeliveryTimeout = timeout
    workQueue.asyncAfter(deadline: .now() + 15, execute: timeout)
  }

  private func statusResponse() -> Data? {
    let statistics = (try? core?.peerStatistics()) ?? []
    let peers: [[String: Any]] = statistics.map { stats in
      let route = routeMetadata.first(where: { $0.peerName == stats.peerName })
      let recoveryTimeout =
        route.flatMap { route in
          interfaceMetadata.map {
            endpointRecoveryTimeoutMilliseconds(route: route, transport: $0.transport)
          }
        } ?? 0
      var value: [String: Any] = [
        "name": stats.peerName,
        "txBytes": stats.txBytes,
        "rxBytes": stats.rxBytes,
        "recoveryTimeoutMilliseconds": recoveryTimeout,
        "isStale": recoveryTimeout > 0
          && (stats.lastSeenMillisecondsAgo ?? 0) >= recoveryTimeout,
        "endpointRefreshInFlight": endpointRefreshInFlight.contains(stats.peerName),
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
      "configurationInstalled": activeConfiguration != nil,
      "running": running,
      "routePolicy": networkPolicy.routePolicy.rawValue,
      "dnsServers": networkPolicy.dnsServers,
      "interface": interfaceMetadata?.cidr ?? "",
      "transport": interfaceMetadata?.transport.title ?? "",
      "routes": routeMetadata.filter { $0.routeKind == .included }.map(\.cidr),
      "excludedRoutes": routeMetadata.filter { $0.routeKind == .excluded }.map(\.cidr),
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
    plan: HushWireConfigurationPlan,
    additionalExcludedRoutes: [HushWireIPv4RouteSpec] = []
  ) -> NEPacketTunnelNetworkSettings {
    let tunnelEndpoint =
      routes.first { $0.routeKind == .included }?.endpoint.host
      ?? routes[0].endpoint.host
    let settings = NEPacketTunnelNetworkSettings(
      tunnelRemoteAddress: tunnelEndpoint
    )
    // Always use a /32 interface mask. This avoids macOS implicitly adding the
    // wider interface-address subnet as a connected route.
    let ipv4 = NEIPv4Settings(
      addresses: [interface.address],
      subnetMasks: ["255.255.255.255"]
    )
    ipv4.includedRoutes = plan.packetTunnelIncludedRoutes.map {
      NEIPv4Route(destinationAddress: $0.network, subnetMask: $0.subnetMask)
    }
    // Direct-route exclusions include configured excluded_ips and any
    // automatically protected endpoint whose address an included route would
    // otherwise capture.
    let excludedRoutes = Array(Set(plan.excludedRoutes + additionalExcludedRoutes)).sorted {
      if $0.prefixLength != $1.prefixLength { return $0.prefixLength > $1.prefixLength }
      return $0.network < $1.network
    }
    ipv4.excludedRoutes = excludedRoutes.map {
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
        self.running || self.pendingProtectedActivation != nil,
        let core = self.core
      else { return }
      do {
        try core.tick()
        self.refreshDynamicEndpointsIfNeeded(runtime: core)
      } catch {
        self.logger.error("Session maintenance failed: \(error.localizedDescription)")
      }
    }
    maintenanceTimer = timer
    timer.resume()
  }

  private func refreshDynamicEndpointsIfNeeded(runtime: HushWireCoreRuntime) {
    guard running, let transportKind = interfaceMetadata?.transport else { return }
    let statistics = (try? runtime.peerStatistics()) ?? []
    let statisticsByPeer = Dictionary(uniqueKeysWithValues: statistics.map { ($0.peerName, $0) })
    var scheduledPeers = Set<String>()
    let now = DispatchTime.now()

    for route in routeMetadata {
      guard
        scheduledPeers.insert(route.peerName).inserted,
        route.configuredEndpoint != route.endpoint.displayString,
        let lastSeen = statisticsByPeer[route.peerName]?.lastSeenMillisecondsAgo
      else { continue }
      let timeout = endpointRecoveryTimeoutMilliseconds(route: route, transport: transportKind)
      guard timeout > 0, lastSeen >= timeout else { continue }
      guard !endpointRefreshInFlight.contains(route.peerName) else { continue }
      if let lastAttempt = lastEndpointRefreshAttempt[route.peerName],
        now.uptimeNanoseconds - lastAttempt.uptimeNanoseconds < 15_000_000_000
      {
        continue
      }

      endpointRefreshInFlight.insert(route.peerName)
      lastEndpointRefreshAttempt[route.peerName] = now
      resolveEndpoint(route.peerName, runtime: runtime)
    }
  }

  private func resolveEndpoint(_ peerName: String, runtime: HushWireCoreRuntime) {
    endpointResolverQueue.async { [weak self, weak runtime] in
      guard let self, let runtime else { return }
      do {
        let endpoint = try runtime.resolvePeerEndpoint(peerName: peerName)
        self.workQueue.async { [weak self, weak runtime] in
          guard let self, let runtime else { return }
          self.applyResolvedEndpoint(endpoint, peerName: peerName, runtime: runtime)
        }
      } catch {
        let detail = error.localizedDescription
        self.workQueue.async { [weak self] in
          guard let self else { return }
          self.endpointRefreshInFlight.remove(peerName)
          self.logger.error(
            "Could not refresh endpoint for \(peerName, privacy: .public): \(detail, privacy: .public)"
          )
        }
      }
    }
  }

  private func applyResolvedEndpoint(
    _ endpoint: HushWireEndpoint,
    peerName: String,
    runtime: HushWireCoreRuntime
  ) {
    endpointRefreshInFlight.remove(peerName)
    guard runtime === core, running, let interface = interfaceMetadata else { return }
    guard let currentRoute = routeMetadata.first(where: { $0.peerName == peerName }) else { return }
    guard currentRoute.endpoint != endpoint else { return }
    guard peerIsStale(peerName, runtime: runtime) else { return }

    do {
      let updatedRoutes = routeMetadata.map { route in
        route.peerName == peerName ? route.replacingEndpoint(endpoint) : route
      }
      let updatedPlan = try HushWireConfigurationPolicy.plan(
        interface: interface,
        routes: updatedRoutes,
        networkPolicy: networkPolicy
      )
      let finalSettings = makeNetworkSettings(
        interface: interface,
        routes: updatedRoutes,
        plan: updatedPlan
      )

      guard networkPolicy.routePolicy.requiresAuthenticatedPreflight else {
        activateResolvedEndpoint(
          endpoint,
          peerName: peerName,
          runtime: runtime,
          routes: updatedRoutes,
          finalSettings: nil
        )
        return
      }

      let oldEndpointException = HushWireIPv4RouteSpec(
        network: currentRoute.endpoint.host,
        prefixLength: 32
      )
      let transitionSettings = makeNetworkSettings(
        interface: interface,
        routes: updatedRoutes,
        plan: updatedPlan,
        additionalExcludedRoutes: [oldEndpointException]
      )
      setTunnelNetworkSettings(transitionSettings) { [weak self, weak runtime] error in
        guard let self, let runtime else { return }
        self.workQueue.async {
          guard runtime === self.core, self.running else { return }
          if let error {
            self.logger.error(
              "Could not protect refreshed endpoint route for \(peerName, privacy: .public): \(error.localizedDescription)"
            )
            return
          }
          self.activateResolvedEndpoint(
            endpoint,
            peerName: peerName,
            runtime: runtime,
            routes: updatedRoutes,
            finalSettings: finalSettings
          )
        }
      }
    } catch {
      logger.error(
        "Rejected refreshed endpoint for \(peerName, privacy: .public): \(error.localizedDescription)"
      )
    }
  }

  private func activateResolvedEndpoint(
    _ endpoint: HushWireEndpoint,
    peerName: String,
    runtime: HushWireCoreRuntime,
    routes: [HushWireRouteMetadata],
    finalSettings: NEPacketTunnelNetworkSettings?
  ) {
    do {
      guard try runtime.updatePeerEndpoint(peerName: peerName, endpoint: endpoint) else { return }
      routeMetadata = routes
      if let finalSettings {
        pendingEndpointRouteCleanup = PendingEndpointRouteCleanup(
          peerName: peerName,
          endpoint: endpoint,
          settings: finalSettings
        )
      }
      guard transport?.reset() == true else {
        throw ProviderFailure.error(code: 13, description: "transport 已停止。")
      }
      try runtime.initiateHandshake(peerName: peerName)
      logger.notice(
        "Peer endpoint changed after DNS refresh; peer=\(peerName, privacy: .public) endpoint=\(endpoint.displayString, privacy: .public)"
      )
    } catch {
      logger.error(
        "Could not activate refreshed endpoint for \(peerName, privacy: .public): \(error.localizedDescription)"
      )
    }
  }

  private func finishEndpointRouteTransitionIfNeeded(
    peerName: String,
    endpoint: HushWireEndpoint
  ) {
    guard
      let pending = pendingEndpointRouteCleanup,
      pending.peerName == peerName,
      pending.endpoint == endpoint
    else { return }
    pendingEndpointRouteCleanup = nil
    setTunnelNetworkSettings(pending.settings) { [weak self] error in
      if let error {
        self?.logger.error(
          "Could not remove previous endpoint route exception: \(error.localizedDescription)"
        )
      } else {
        self?.logger.info("Removed previous endpoint route exception after authenticated recovery")
      }
    }
  }

  private func peerIsStale(_ peerName: String, runtime: HushWireCoreRuntime) -> Bool {
    guard
      let route = routeMetadata.first(where: { $0.peerName == peerName }),
      let transportKind = interfaceMetadata?.transport,
      let lastSeen = try? runtime.peerStatistics().first(where: { $0.peerName == peerName })?
        .lastSeenMillisecondsAgo
    else { return false }
    let timeout = endpointRecoveryTimeoutMilliseconds(route: route, transport: transportKind)
    return timeout > 0 && lastSeen >= timeout
  }

  private func endpointRecoveryTimeoutMilliseconds(
    route: HushWireRouteMetadata,
    transport: HushWireTransportKind
  ) -> UInt64 {
    switch transport {
    case .udp: UInt64(route.udpRebindAfter) * 1_000
    case .tcp: route.sessionTimeout * 1_000
    }
  }

  private func finishFailedStart(
    _ error: Error,
    completionHandler: CallbackBox<Error?>
  ) {
    let safeError = sanitizedProviderError(error)
    logger.error("Packet Tunnel failed to start: \(safeError.localizedDescription)")
    tearDownRuntime()
    completionHandler.call(safeError)
  }

  private func finishFailedConfiguration(
    _ error: Error,
    completionHandler: CallbackBox<Data?>?
  ) {
    let safeError = sanitizedProviderError(error)
    logger.error("Packet Tunnel configuration failed: \(safeError.localizedDescription)")
    tearDownRuntime()
    completionHandler?.call(response(ok: false, error: safeError.localizedDescription))
    cancelTunnelWithError(safeError)
  }

  private func sanitizedProviderError(_ error: Error) -> Error {
    ProviderFailure.error(
      code: (error as NSError).code,
      description: HushWireRedactor.redact(error.localizedDescription)
    )
  }

  private func tearDownRuntime() {
    configurationDeliveryTimeout?.cancel()
    configurationDeliveryTimeout = nil
    protectedHandshakeTimeout?.cancel()
    protectedHandshakeTimeout = nil
    let pendingCompletion = pendingProtectedActivation?.completionHandler
    pendingProtectedActivation = nil
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
    activeConfiguration = nil
    let stoppedResponse = response(ok: false, error: "隧道在认证预握手期间停止。")
    pendingCompletion?.call(stoppedResponse)
    let duplicateCompletions = duplicateConfigurationCompletionHandlers
    duplicateConfigurationCompletionHandlers = []
    for duplicateCompletion in duplicateCompletions {
      duplicateCompletion.call(stoppedResponse)
    }
    endpointRefreshInFlight.removeAll()
    lastEndpointRefreshAttempt.removeAll()
    pendingEndpointRouteCleanup = nil
  }
}
