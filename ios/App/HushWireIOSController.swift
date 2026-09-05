import Combine
import Foundation
@preconcurrency import NetworkExtension

private final class HushWireUncheckedSendableBox<Value>: @unchecked Sendable {
  let value: Value

  init(_ value: Value) {
    self.value = value
  }
}

@MainActor
final class HushWireIOSController: ObservableObject {
  @Published private(set) var profiles: [HushWireProfile] = []
  @Published private(set) var selectedProfileID: UUID?
  @Published private(set) var profileInspection: HushWireProfileInspection?
  @Published private(set) var vpnStatus: NEVPNStatus = .invalid
  @Published private(set) var providerReady = false
  @Published private(set) var peerSessions: [HushWirePeerSession] = []
  @Published private(set) var lastHandshake = ""
  @Published private(set) var providerInterface = ""
  @Published private(set) var providerTransport = ""
  @Published private(set) var providerCoreVersion = ""
  @Published private(set) var providerRoutes: [String] = []
  @Published private(set) var providerExcludedRoutes: [String] = []
  @Published private(set) var providerDNSServers: [String] = []
  @Published private(set) var uploadRate = 0.0
  @Published private(set) var downloadRate = 0.0
  @Published private(set) var activity = "正在载入本地配置…"
  @Published private(set) var events: [HushWireActivityEvent] = []
  @Published private(set) var lastError: String?
  @Published private(set) var isBusy = false
  @Published private(set) var now = Date()
  @Published private(set) var lastSession: HushWireLastSession?

  private static let lastSessionKey = "hushwire.ios.last-session-v1"

  private enum ManagerSaveAction {
    case start(fullTunnelConfirmed: Bool)
    case persistPolicy

    var startsSession: Bool {
      if case .start = self { return true }
      return false
    }
  }

  private var manager: NETunnelProviderManager?
  private var statusObserver: HushWireUncheckedSendableBox<NSObjectProtocol>?
  private var pollTimer: DispatchSourceTimer?
  private var configurationDeliveryInFlight = false
  private var providerStatusEpoch: UInt64 = 0
  private var activeProfileID: UUID?
  private var stopRequestedByApp = false
  private var startRequestInFlight = false
  private var startRequestedAt: Date?
  private var sessionReadySince: Date?
  private var trafficSample: (date: Date, tx: UInt64, rx: UInt64)?
  private var sessionWasReady = false
  private var connectionFailed = false

  init() {
    loadLastSession()
    loadLocalProfiles()
    statusObserver = HushWireUncheckedSendableBox(
      NotificationCenter.default.addObserver(
        forName: .NEVPNStatusDidChange,
        object: nil,
        queue: .main
      ) { [weak self] _ in
        Task { @MainActor in
          self?.handleVPNStatusChange()
        }
      }
    )
    loadVPNManager()

    let timer = DispatchSource.makeTimerSource(queue: .main)
    timer.schedule(deadline: .now() + 1, repeating: 1, leeway: .milliseconds(100))
    timer.setEventHandler { [weak self] in
      guard let self else { return }
      self.now = Date()
      self.refreshProviderStatus()
      self.expireStalledStartIfNeeded()
    }
    pollTimer = timer
    timer.resume()
  }

  deinit {
    if let statusObserver {
      NotificationCenter.default.removeObserver(statusObserver.value)
    }
    pollTimer?.setEventHandler {}
    pollTimer?.cancel()
  }

  var selectedProfile: HushWireProfile? {
    profiles.first { $0.id == selectedProfileID }
  }

  var connectionPhase: HushWireConnectionPhase {
    if selectedProfile == nil, vpnStatus == .invalid || vpnStatus == .disconnected {
      return .noConfiguration
    }
    switch vpnStatus {
    case .invalid, .disconnected:
      if startRequestInFlight { return .connecting }
      return connectionFailed ? .failed : .disconnected
    case .connecting:
      return .connecting
    case .connected:
      guard providerReady else { return .connecting }
      return peerSessions.contains(where: { $0.isStale }) ? .recovering : .connected
    case .reasserting:
      return .recovering
    case .disconnecting:
      return .disconnecting
    @unknown default:
      return .failed
    }
  }

  var canEditProfiles: Bool {
    !isBusy && !startRequestInFlight && (vpnStatus == .invalid || vpnStatus == .disconnected)
  }

  var canConnect: Bool {
    canEditProfiles && selectedProfile != nil && profileInspection != nil
  }

  var canDisconnect: Bool {
    !isBusy && (vpnStatus == .connecting || vpnStatus == .connected || vpnStatus == .reasserting)
  }

  var totalUploadBytes: UInt64 {
    peerSessions.reduce(0) { $0 &+ $1.txBytes }
  }

  var totalDownloadBytes: UInt64 {
    peerSessions.reduce(0) { $0 &+ $1.rxBytes }
  }

  var connectionDuration: TimeInterval {
    guard let start = manager?.connection.connectedDate ?? sessionReadySince else { return 0 }
    return max(0, now.timeIntervalSince(start))
  }

  var routeImpactTitle: String {
    guard let summary = profileInspection?.summary else { return "尚未选择网络策略" }
    switch summary.routePolicy {
    case .hostRoutesOnly: return "仅指定地址"
    case .splitRoutes: return "自定义分流"
    case .fullTunnel: return "全局流量"
    }
  }

  var routeImpactDetail: String {
    guard let summary = profileInspection?.summary else { return "导入 TOML 后才会创建 VPN 配置" }
    let trustedWiFiDetail = trustedWiFiImpactDetail
    switch summary.routePolicy {
    case .hostRoutesOnly:
      return "仅接管 \(summary.routes.count) 条 /32 路由；默认路由与 DNS 不会修改\(trustedWiFiDetail)"
    case .splitRoutes:
      return "接管 \(summary.routes.count) 条路由；DNS：\(summary.dnsDescription)\(trustedWiFiDetail)"
    case .fullTunnel:
      let routeDetail =
        "默认 IPv4 流量进入隧道；\(summary.directRoutes.count) 条直连例外；"
        + "DNS：\(summary.dnsDescription)"
      return routeDetail + trustedWiFiDetail
    }
  }

  private var trustedWiFiImpactDetail: String {
    guard let count = selectedProfile?.trustedWiFiSSIDs.count, count > 0 else { return "" }
    let outsideBehavior =
      selectedProfile?.autoConnectOutsideTrustedWiFi == true
      ? "，离开后自动连接"
      : ""
    return "；\(count) 个可信 Wi-Fi 命中时自动断开\(outsideBehavior)"
  }

  func importConfiguration(from url: URL) {
    guard canEditProfiles else {
      setActivity("请先断开当前隧道，再导入配置。", kind: .warning)
      return
    }
    isBusy = true
    lastError = nil
    connectionFailed = false
    activity = "正在读取并验证配置…"
    let accessed = url.startAccessingSecurityScopedResource()
    defer {
      if accessed { url.stopAccessingSecurityScopedResource() }
    }

    do {
      let resourceValues = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
      guard resourceValues.isRegularFile != false else {
        throw HushWireCoreError.operation("所选项目不是普通 TOML 文件。")
      }
      if let fileSize = resourceValues.fileSize,
        fileSize > HushWireProfileInspector.maximumConfigurationSize
      {
        throw HushWireCoreError.operation("配置文件超过 1 MiB，已拒绝导入。")
      }
      let configuration = try Data(contentsOf: url, options: [.mappedIfSafe])
      let inspection = try HushWireProfileInspector.inspectWithInferredPolicy(configuration)
      let proposedName = url.deletingPathExtension().lastPathComponent
      let profile = try HushWireProfileStore.add(
        configuration: configuration,
        name: proposedName,
        inspection: inspection
      )
      loadLocalProfiles(preferredSelection: profile.id)
      profileInspection = inspection
      isBusy = false
      setActivity(
        "“\(profile.name)”已验证并保存到本机 Keychain；私钥和 PSK 不会显示在界面中。",
        kind: .success
      )
    } catch {
      isBusy = false
      fail("导入配置失败：\(error.localizedDescription)")
    }
  }

  func reportImportFailure(_ error: Error) {
    let nsError = error as NSError
    guard !(nsError.domain == NSCocoaErrorDomain && nsError.code == NSUserCancelledError) else {
      return
    }
    fail("打开配置文件失败：\(error.localizedDescription)")
  }

  func selectProfile(_ profile: HushWireProfile) {
    guard canEditProfiles else {
      setActivity("连接期间不能切换配置。", kind: .warning)
      return
    }
    selectedProfileID = profile.id
    HushWireProfileStore.selectedProfileID = profile.id
    reloadSelectedInspection()
    guard let inspection = profileInspection else { return }
    isBusy = true
    activeProfileID = profile.id
    lastError = nil
    connectionFailed = false
    activity = "已选择“\(profile.name)”；正在同步对应的 iOS 自动连接策略…"
    configureManager(for: profile, inspection: inspection, action: .persistPolicy)
  }

  func updateSelectedProfile(
    name: String,
    routePolicy: HushWireRoutePolicy,
    dnsServersText: String,
    trustedWiFiSSIDsText: String,
    autoConnectOutsideTrustedWiFi: Bool
  ) {
    guard canEditProfiles, var profile = selectedProfile else {
      setActivity("请先断开隧道，再修改配置。", kind: .warning)
      return
    }
    isBusy = true
    do {
      let configuration = try HushWireProfileStore.configuration(for: profile.id)
      let dnsServers = HushWireNetworkPolicy.parseDNSServers(dnsServersText)
      let trustedWiFiSSIDs = try HushWireTrustedWiFiPolicy.parse(trustedWiFiSSIDsText)
      if autoConnectOutsideTrustedWiFi, trustedWiFiSSIDs.isEmpty {
        throw HushWireCoreError.operation("自动连接至少需要一个可信 Wi-Fi，才能定义应保持断开的网络。")
      }
      let inspection = try HushWireProfileInspector.inspect(
        configuration,
        routePolicy: routePolicy,
        dnsServers: dnsServers
      )
      profile.name = HushWireProfileInspector.normalizedProfileName(name)
      profile.routePolicyRawValue = routePolicy.rawValue
      profile.dnsServers = inspection.summary.dnsServers
      profile.trustedWiFiSSIDs = trustedWiFiSSIDs
      profile.autoConnectOutsideTrustedWiFi = autoConnectOutsideTrustedWiFi
      profile.updatedAt = Date()
      try HushWireProfileStore.update(profile)
      loadLocalProfiles(preferredSelection: profile.id)
      profileInspection = inspection
      activeProfileID = profile.id
      activity = "正在把自动连接策略保存到 iOS…"
      configureManager(for: profile, inspection: inspection, action: .persistPolicy)
    } catch {
      isBusy = false
      fail("保存失败：\(error.localizedDescription)")
    }
  }

  func validateSelectedProfile() {
    guard let profile = selectedProfile else {
      setActivity("请先导入 TOML 配置。", kind: .warning)
      return
    }
    do {
      let configuration = try HushWireProfileStore.configuration(for: profile.id)
      profileInspection = try HushWireProfileInspector.inspect(
        configuration,
        routePolicy: profile.routePolicy,
        dnsServers: profile.dnsServers
      )
      lastError = nil
      setActivity("配置有效；密钥、路由与恢复参数均已通过 Core 校验。", kind: .success)
    } catch {
      fail("配置验证失败：\(error.localizedDescription)")
    }
  }

  func deleteProfile(_ profile: HushWireProfile) {
    guard canEditProfiles else {
      setActivity("请先断开当前隧道，再删除配置。", kind: .warning)
      return
    }
    do {
      try HushWireProfileStore.delete(profile)
      loadLocalProfiles()
      lastError = nil
      setActivity("已从本机删除“\(profile.name)”及其 Keychain 配置。", kind: .info)
    } catch {
      fail("删除配置失败：\(error.localizedDescription)")
    }
  }

  func connect(fullTunnelConfirmed: Bool = false) {
    guard canConnect, let profile = selectedProfile else {
      setActivity("当前配置尚未就绪。", kind: .warning)
      return
    }
    if profile.routePolicy == .fullTunnel, !fullTunnelConfirmed {
      setActivity("全局流量连接需要确认本次网络影响。", kind: .warning)
      return
    }

    isBusy = true
    lastError = nil
    connectionFailed = false
    stopRequestedByApp = false
    startRequestInFlight = true
    startRequestedAt = Date()
    activeProfileID = profile.id
    configurationDeliveryInFlight = false
    providerReady = false
    providerStatusEpoch &+= 1
    trafficSample = nil
    uploadRate = 0
    downloadRate = 0
    activity = "正在保存 iOS VPN 配置…"

    do {
      let configuration = try HushWireProfileStore.configuration(for: profile.id)
      let inspection = try HushWireProfileInspector.inspect(
        configuration,
        routePolicy: profile.routePolicy,
        dnsServers: profile.dnsServers
      )
      profileInspection = inspection
      configureManager(
        for: profile,
        inspection: inspection,
        action: .start(fullTunnelConfirmed: fullTunnelConfirmed)
      )
    } catch {
      isBusy = false
      startRequestInFlight = false
      fail("启动前验证失败：\(error.localizedDescription)", affectsConnection: true)
    }
  }

  func disconnect() {
    guard canDisconnect, let manager else { return }
    stopRequestedByApp = true
    startRequestInFlight = false
    manager.connection.stopVPNTunnel()
    vpnStatus = manager.connection.status
    setActivity("已请求 iOS 断开隧道；正在等待系统恢复路由与 DNS。", kind: .info)
  }

  func runConnectionCheck() {
    guard let profile = selectedProfile else {
      setActivity("没有可检查的配置。", kind: .warning)
      return
    }
    do {
      let configuration = try HushWireProfileStore.configuration(for: profile.id)
      _ = try HushWireProfileInspector.inspect(
        configuration,
        routePolicy: profile.routePolicy,
        dnsServers: profile.dnsServers
      )
      if vpnStatus == .connected {
        refreshProviderStatus()
        setActivity(
          providerReady ? "配置与 Packet Tunnel 运行状态正常。" : "配置有效；Packet Tunnel 仍在认证或应用网络设置。",
          kind: providerReady ? .success : .info
        )
      } else {
        setActivity("配置有效；当前未连接，因此未发送网络探测流量。", kind: .success)
      }
    } catch {
      fail("连接检查失败：\(error.localizedDescription)")
    }
  }

  func redactedDiagnostics() -> String {
    let profileName = selectedProfile?.name ?? "无"
    let summary = profileInspection?.summary
    var lines = [
      "HushWire iOS 诊断报告",
      "生成时间：\(DateFormatter.hushWireReport.string(from: Date()))",
      "配置：\(profileName)",
      "VPN 状态：\(vpnStatus.hushWireDescription)",
      "隧道运行：\(providerReady ? "是" : "否")",
      "Core：\(providerCoreVersion.isEmpty ? profileInspection?.coreVersion ?? "未知" : providerCoreVersion)",
      "接口：\(providerInterface.isEmpty ? summary?.interface ?? "未知" : providerInterface)",
      "传输：\(providerTransport.isEmpty ? summary?.transport ?? "未知" : providerTransport)",
      "路由策略：\(routeImpactTitle)",
      "DNS：\(summary?.dnsDescription ?? "未知")",
      "可信 Wi-Fi 自动断开：\((selectedProfile?.trustedWiFiSSIDs.isEmpty == false) ? "已启用（名称已隐藏）" : "未启用")",
      "离开可信 Wi-Fi 自动连接：\((selectedProfile?.autoConnectOutsideTrustedWiFi == true) ? "已启用" : "未启用")",
      "最近握手：\(lastHandshake.isEmpty ? "无" : lastHandshake)",
      "上传：\(HushWireFormatters.bytes(totalUploadBytes))",
      "下载：\(HushWireFormatters.bytes(totalDownloadBytes))",
      "",
      "最近活动：",
    ]
    lines.append(
      contentsOf: events.prefix(30).map {
        "\(DateFormatter.hushWireEvent.string(from: $0.date)) [\($0.kind.rawValue)] \($0.message)"
      })
    return HushWireRedactor.redact(lines.joined(separator: "\n"))
  }

  private func loadLocalProfiles(preferredSelection: UUID? = nil) {
    do {
      profiles = try HushWireProfileStore.loadProfiles()
      let candidate = preferredSelection ?? HushWireProfileStore.selectedProfileID
      selectedProfileID =
        profiles.contains(where: { $0.id == candidate })
        ? candidate
        : profiles.first?.id
      HushWireProfileStore.selectedProfileID = selectedProfileID
      reloadSelectedInspection()
      if profiles.isEmpty {
        activity = "导入一份 TOML 配置即可开始；文件会先在本机验证。"
      }
    } catch {
      profiles = []
      selectedProfileID = nil
      profileInspection = nil
      fail("读取本地配置失败：\(error.localizedDescription)")
    }
  }

  private func reloadSelectedInspection() {
    guard let profile = selectedProfile else {
      profileInspection = nil
      return
    }
    do {
      let configuration = try HushWireProfileStore.configuration(for: profile.id)
      profileInspection = try HushWireProfileInspector.inspect(
        configuration,
        routePolicy: profile.routePolicy,
        dnsServers: profile.dnsServers
      )
    } catch {
      profileInspection = nil
      fail("“\(profile.name)”无法读取或验证：\(error.localizedDescription)")
    }
  }

  private func loadVPNManager() {
    NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
      let result = HushWireUncheckedSendableBox((managers, error))
      Task { @MainActor in
        guard let self else { return }
        let (managers, error) = result.value
        if let error {
          self.fail("读取 iOS VPN 配置失败：\(error.localizedDescription)")
          return
        }
        self.manager = managers?.first { manager in
          (manager.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerBundleIdentifier == HushWireIOSConstants.extensionBundleIdentifier
        }
        if let manager = self.manager {
          self.vpnStatus = manager.connection.status
          if self.vpnStatus != .invalid && self.vpnStatus != .disconnected,
            let profileID = Self.activeProfileID(from: manager),
            self.profiles.contains(where: { $0.id == profileID })
          {
            self.activeProfileID = profileID
            self.selectedProfileID = profileID
            HushWireProfileStore.selectedProfileID = profileID
            self.reloadSelectedInspection()
          }
          if self.vpnStatus == .connected || self.vpnStatus == .reasserting {
            self.setActivity("已恢复 iOS 管理的现有 VPN 会话，正在读取实时状态。", kind: .info)
            self.refreshProviderStatus()
          } else if self.selectedProfile != nil, self.lastError == nil {
            self.activity = "配置已就绪；连接前可以检查路由与 DNS 影响。"
          }
        } else {
          self.vpnStatus = .invalid
          if self.selectedProfile != nil, self.lastError == nil {
            self.activity = "配置已就绪；首次连接时 iOS 会请求添加 VPN 配置。"
          }
        }
      }
    }
  }

  private func configureManager(
    for profile: HushWireProfile,
    inspection: HushWireProfileInspection,
    action: ManagerSaveAction
  ) {
    let networkPolicy: HushWireNetworkPolicy
    do {
      networkPolicy = try HushWireNetworkPolicy(
        routePolicy: profile.routePolicy,
        dnsServers: profile.dnsServers
      )
    } catch {
      isBusy = false
      startRequestInFlight = false
      fail(
        "保存 VPN 配置前的网络策略验证失败：\(error.localizedDescription)",
        affectsConnection: action.startsSession
      )
      return
    }

    let manager = manager ?? NETunnelProviderManager()
    let tunnelProtocol = NETunnelProviderProtocol()
    tunnelProtocol.providerBundleIdentifier = HushWireIOSConstants.extensionBundleIdentifier
    tunnelProtocol.serverAddress =
      inspection.summary.resolvedEndpoints.first
      ?? HushWireIOSConstants.serverAddress
    tunnelProtocol.enforceRoutes = true
    let onDemandStartAuthorized =
      profile.autoConnectOutsideTrustedWiFi
      && !profile.trustedWiFiSSIDs.isEmpty
    tunnelProtocol.providerConfiguration = networkPolicy.addingProviderConfiguration(to: [
      "schemaVersion": 5,
      "configurationStorage": HushWireConfigurationStore.providerStorageKind,
      HushWireConfigurationStore.activeProfileIDKey: profile.id.uuidString,
      HushWireConfigurationStore.onDemandStartAuthorizedKey:
        onDemandStartAuthorized,
    ])
    manager.localizedDescription = HushWireIOSConstants.profileDescription
    manager.protocolConfiguration = tunnelProtocol
    manager.isEnabled = true
    let onDemandRules = Self.makeOnDemandRules(for: profile)
    manager.onDemandRules = onDemandRules
    manager.isOnDemandEnabled = !onDemandRules.isEmpty
    self.manager = manager

    manager.saveToPreferences { [weak self, manager] error in
      Task { @MainActor in
        guard let self else { return }
        if let error {
          self.isBusy = false
          self.startRequestInFlight = false
          self.fail(
            "保存 iOS VPN 配置失败：\(error.localizedDescription)",
            affectsConnection: action.startsSession
          )
          return
        }
        manager.loadFromPreferences { [weak self, manager] error in
          Task { @MainActor in
            guard let self else { return }
            if let error {
              self.isBusy = false
              self.startRequestInFlight = false
              self.fail(
                "重新载入 iOS VPN 配置失败：\(error.localizedDescription)",
                affectsConnection: action.startsSession
              )
              return
            }
            self.manager = manager
            guard Self.onDemandPolicyIsPersisted(for: profile, in: manager) else {
              self.isBusy = false
              self.startRequestInFlight = false
              self.fail(
                "iOS 没有完整保存可信 Wi-Fi 与自动连接规则。",
                affectsConnection: action.startsSession
              )
              return
            }
            switch action {
            case .start(let fullTunnelConfirmed):
              self.startSession(
                manager: manager,
                profile: profile,
                fullTunnelConfirmed: fullTunnelConfirmed
              )
            case .persistPolicy:
              self.isBusy = false
              self.startRequestInFlight = false
              self.lastError = nil
              self.connectionFailed = false
              self.vpnStatus = manager.connection.status
              let mode =
                profile.autoConnectOutsideTrustedWiFi
                ? "可信 Wi-Fi 上自动断开，其他网络上自动连接"
                : profile.trustedWiFiSSIDs.isEmpty
                  ? "自动连接已关闭"
                  : "可信 Wi-Fi 上自动断开，离开后保持当前状态"
              self.setActivity("配置与 iOS 网络策略已保存：\(mode)。", kind: .success)
              if self.vpnStatus == .connected || self.vpnStatus == .reasserting {
                self.refreshProviderStatus()
              }
            }
          }
        }
      }
    }
  }

  private func startSession(
    manager: NETunnelProviderManager,
    profile: HushWireProfile,
    fullTunnelConfirmed: Bool
  ) {
    do {
      guard let session = manager.connection as? NETunnelProviderSession else {
        throw HushWireCoreError.operation("系统 VPN 配置不是 Packet Tunnel session。")
      }
      let options: [String: NSObject]? =
        profile.routePolicy == .fullTunnel
        ? [HushWireNetworkPolicy.fullTunnelApprovalOptionKey: NSNumber(value: fullTunnelConfirmed)]
        : nil
      startRequestInFlight = true
      startRequestedAt = Date()
      try session.startTunnel(options: options)
      vpnStatus = session.status
      isBusy = false
      if profile.trustedWiFiSSIDs.isEmpty {
        setActivity("Packet Tunnel 正在启动；认证成功前不会应用受保护路由或 DNS。", kind: .info)
      } else {
        setActivity("iOS 正在评估可信 Wi-Fi 规则并启动 Packet Tunnel。", kind: .info)
      }
      recordEvent(.info, "已向 iOS 提交连接请求")
    } catch {
      isBusy = false
      startRequestInFlight = false
      fail("启动连接失败：\(error.localizedDescription)", affectsConnection: true)
    }
  }

  private func handleVPNStatusChange() {
    guard let manager else { return }
    let previous = vpnStatus
    let current = manager.connection.status
    guard current != previous else { return }
    vpnStatus = current
    recordEvent(.info, "VPN 状态：\(current.hushWireDescription)")

    switch current {
    case .connecting:
      startRequestInFlight = false
      activity = "正在启动 Packet Tunnel…"
    case .connected:
      startRequestInFlight = false
      startRequestedAt = nil
      activeProfileID = Self.activeProfileID(from: manager) ?? activeProfileID
      activity = "Packet Tunnel 已启动，正在读取安全配置并完成认证…"
      deliverConfigurationIfNeeded()
      refreshProviderStatus()
    case .reasserting:
      activity = "iOS 正在重新建立网络路径；隧道会自动恢复。"
    case .disconnecting:
      activity = "正在断开；等待 iOS 移除隧道路由与 DNS。"
    case .disconnected, .invalid:
      startRequestInFlight = false
      startRequestedAt = nil
      completeLastSessionIfNeeded()
      clearLiveSession()
      if stopRequestedByApp {
        lastError = nil
        connectionFailed = false
        setActivity("已断开；iOS 已负责移除隧道路由与 DNS。", kind: .success)
      } else if manager.isOnDemandEnabled,
        selectedProfile?.trustedWiFiSSIDs.isEmpty == false,
        previous == .connecting || previous == .connected || previous == .reasserting
      {
        lastError = nil
        connectionFailed = false
        setActivity(
          "iOS 已断开隧道；若设备刚接入可信 Wi-Fi，这是自动断开规则正常生效。",
          kind: .success
        )
      } else if previous == .connecting || previous == .connected || previous == .reasserting {
        if lastError == nil {
          fail("隧道意外断开；设备网络已由 iOS 恢复。", affectsConnection: true)
        }
      }
      stopRequestedByApp = false
    @unknown default:
      fail("iOS 返回未知 VPN 状态。", affectsConnection: true)
    }
  }

  private func refreshProviderStatus() {
    guard
      let manager,
      manager.connection.status == .connected,
      let session = manager.connection as? NETunnelProviderSession
    else { return }
    let epoch = providerStatusEpoch
    do {
      try session.sendProviderMessage(Data([0x01])) { [weak self] response in
        guard let response else { return }
        Task { @MainActor in
          guard let self, self.providerStatusEpoch == epoch else { return }
          self.applyProviderStatus(response)
        }
      }
    } catch {
      // Polling is best-effort. Configuration delivery has its own surfaced error path.
    }
  }

  private func applyProviderStatus(_ data: Data) {
    guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      return
    }
    let wasReady = providerReady
    let wasRecovering = peerSessions.contains(where: { $0.isStale })
    let running = (object["running"] as? NSNumber)?.boolValue ?? false
    let awaitingConfiguration =
      (object["awaitingConfiguration"] as? NSNumber)?.boolValue ?? false
    let configurationInstalled =
      (object["configurationInstalled"] as? NSNumber)?.boolValue ?? false
    let newHandshake = object["lastHandshake"] as? String ?? ""

    providerReady = running
    providerInterface = object["interface"] as? String ?? ""
    providerTransport = object["transport"] as? String ?? ""
    providerCoreVersion = object["coreVersion"] as? String ?? ""
    providerRoutes = object["routes"] as? [String] ?? []
    providerExcludedRoutes = object["excludedRoutes"] as? [String] ?? []
    providerDNSServers = object["dnsServers"] as? [String] ?? []

    let peerObjects = object["peers"] as? [[String: Any]] ?? []
    peerSessions = peerObjects.compactMap { peer in
      guard let name = peer["name"] as? String else { return nil }
      return HushWirePeerSession(
        name: name,
        txBytes: Self.uint64(peer["txBytes"]),
        rxBytes: Self.uint64(peer["rxBytes"]),
        lastSeenMillisecondsAgo: peer["lastSeenMillisecondsAgo"].map(Self.uint64),
        endpoint: peer["endpoint"] as? String,
        recoveryTimeoutMilliseconds: Self.uint64(peer["recoveryTimeoutMilliseconds"]),
        isStale: (peer["isStale"] as? NSNumber)?.boolValue ?? false,
        endpointRefreshInFlight: (peer["endpointRefreshInFlight"] as? NSNumber)?.boolValue ?? false
      )
    }
    updateTrafficRates()

    if !newHandshake.isEmpty, newHandshake != lastHandshake {
      lastHandshake = newHandshake
      recordEvent(.success, "认证握手完成：\(newHandshake)")
    } else {
      lastHandshake = newHandshake
    }

    let recovering = peerSessions.contains(where: { $0.isStale })
    if running, !wasReady {
      sessionWasReady = true
      sessionReadySince = manager?.connection.connectedDate ?? Date()
      setActivity(readyActivityDescription(), kind: .success)
    } else if running, recovering, !wasRecovering {
      uploadRate = 0
      downloadRate = 0
      setActivity("认证流量已超时，正在自动更新 endpoint 并恢复会话。", kind: .warning)
    } else if running, !recovering, wasRecovering {
      setActivity("对端会话已自动恢复。\(readyActivityDescription())", kind: .success)
    }

    if awaitingConfiguration, !configurationInstalled, !running {
      if Self.configurationStorage(from: manager)
        == HushWireConfigurationStore
        .legacyProviderStorageKind
      {
        deliverConfigurationIfNeeded()
      } else if lastError == nil {
        fail("Packet Tunnel 未能从共享 Keychain 安装配置。", affectsConnection: true)
      }
    }
  }

  private func deliverConfigurationIfNeeded() {
    guard
      vpnStatus == .connected,
      !providerReady,
      !configurationDeliveryInFlight,
      let manager,
      Self.configurationStorage(from: manager)
        == HushWireConfigurationStore.legacyProviderStorageKind,
      let session = manager.connection as? NETunnelProviderSession
    else { return }

    do {
      let profileID = activeProfileID ?? Self.activeProfileID(from: manager)
      guard let profileID else {
        throw HushWireCoreError.operation("VPN 配置缺少当前配置 ID。")
      }
      let configuration = try HushWireProfileStore.configuration(for: profileID)
      var message = Data([0x02])
      message.append(configuration)
      configurationDeliveryInFlight = true
      activity = "正在通过 iOS 私有 provider channel 传递配置…"
      try session.sendProviderMessage(message) { [weak self] response in
        Task { @MainActor in
          guard let self else { return }
          self.configurationDeliveryInFlight = false
          guard
            let response,
            let object = try? JSONSerialization.jsonObject(with: response) as? [String: Any],
            (object["ok"] as? NSNumber)?.boolValue == true
          else {
            let detail =
              response.flatMap { data in
                (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"]
                  as? String
              } ?? "扩展没有返回成功响应"
            self.providerStatusEpoch &+= 1
            self.fail("安装隧道配置失败：\(detail)。", affectsConnection: true)
            self.refreshProviderStatus()
            return
          }
          self.providerStatusEpoch &+= 1
          self.providerReady = true
          self.sessionWasReady = true
          self.sessionReadySince = self.manager?.connection.connectedDate ?? Date()
          self.setActivity(self.readyActivityDescription(), kind: .success)
          self.refreshProviderStatus()
        }
      }
    } catch {
      configurationDeliveryInFlight = false
      providerStatusEpoch &+= 1
      fail("传递隧道配置失败：\(error.localizedDescription)", affectsConnection: true)
    }
  }

  private func updateTrafficRates() {
    let date = Date()
    let tx = totalUploadBytes
    let rx = totalDownloadBytes
    defer { trafficSample = (date, tx, rx) }
    guard let sample = trafficSample else {
      uploadRate = 0
      downloadRate = 0
      return
    }
    let elapsed = date.timeIntervalSince(sample.date)
    guard elapsed > 0 else { return }
    uploadRate = tx >= sample.tx ? Double(tx - sample.tx) / elapsed : 0
    downloadRate = rx >= sample.rx ? Double(rx - sample.rx) / elapsed : 0
    if peerSessions.contains(where: { $0.isStale }) {
      uploadRate = 0
      downloadRate = 0
    }
  }

  private func readyActivityDescription() -> String {
    switch profileInspection?.summary.routePolicy {
    case .hostRoutesOnly:
      "隧道已认证；仅指定的 /32 路由生效，默认路由与 DNS 未修改。"
    case .splitRoutes:
      "隧道已认证；自定义分流与所选 DNS 已生效。"
    case .fullTunnel:
      "隧道已认证；全局 IPv4 路由与所选 DNS 已生效。"
    case nil:
      "隧道已认证并就绪。"
    }
  }

  private func clearLiveSession() {
    providerStatusEpoch &+= 1
    providerReady = false
    configurationDeliveryInFlight = false
    activeProfileID = nil
    peerSessions = []
    lastHandshake = ""
    providerInterface = ""
    providerTransport = ""
    providerCoreVersion = ""
    providerRoutes = []
    providerExcludedRoutes = []
    providerDNSServers = []
    uploadRate = 0
    downloadRate = 0
    trafficSample = nil
    sessionReadySince = nil
  }

  private func completeLastSessionIfNeeded() {
    guard sessionWasReady, let profileID = activeProfileID else { return }
    let start = manager?.connection.connectedDate ?? sessionReadySince ?? Date()
    let value = HushWireLastSession(
      profileID: profileID,
      endedAt: Date(),
      duration: max(0, Date().timeIntervalSince(start)),
      txBytes: totalUploadBytes,
      rxBytes: totalDownloadBytes
    )
    lastSession = value
    if let data = try? JSONEncoder().encode(value) {
      UserDefaults.standard.set(data, forKey: Self.lastSessionKey)
    }
    sessionWasReady = false
  }

  private func loadLastSession() {
    guard let data = UserDefaults.standard.data(forKey: Self.lastSessionKey) else { return }
    lastSession = try? JSONDecoder().decode(HushWireLastSession.self, from: data)
  }

  private func expireStalledStartIfNeeded() {
    let hasTrustedWiFiPolicy =
      manager?.isOnDemandEnabled == true
      && selectedProfile?.trustedWiFiSSIDs.isEmpty == false
    let timeout: TimeInterval = hasTrustedWiFiPolicy ? 3 : 15
    guard
      startRequestInFlight,
      vpnStatus == .invalid || vpnStatus == .disconnected,
      let startRequestedAt,
      Date().timeIntervalSince(startRequestedAt) > timeout
    else { return }
    startRequestInFlight = false
    self.startRequestedAt = nil
    if hasTrustedWiFiPolicy {
      lastError = nil
      connectionFailed = false
      setActivity(
        "保持断开：当前网络可能命中可信 Wi-Fi 自动断开规则。",
        kind: .success
      )
      return
    }
    fail(
      "iOS 在 15 秒内没有进入连接状态；VPN 配置可能未获允许。",
      affectsConnection: true
    )
  }

  private func setActivity(_ message: String, kind: HushWireActivityEvent.Kind) {
    activity = message
    recordEvent(kind, message)
  }

  private func fail(_ message: String, affectsConnection: Bool = false) {
    let redacted = HushWireRedactor.redact(message)
    if affectsConnection {
      connectionFailed = true
    }
    lastError = redacted
    activity = redacted
    recordEvent(.failure, redacted)
  }

  private func recordEvent(_ kind: HushWireActivityEvent.Kind, _ message: String) {
    events.insert(
      HushWireActivityEvent(kind: kind, message: HushWireRedactor.redact(message)), at: 0)
    if events.count > 100 {
      events.removeLast(events.count - 100)
    }
  }

  private static func activeProfileID(from manager: NETunnelProviderManager) -> UUID? {
    guard
      let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol,
      let value = tunnelProtocol.providerConfiguration?[
        HushWireConfigurationStore.activeProfileIDKey
      ] as? String
    else { return nil }
    return UUID(uuidString: value)
  }

  private static func configurationStorage(
    from manager: NETunnelProviderManager?
  ) -> String? {
    guard
      let tunnelProtocol = manager?.protocolConfiguration as? NETunnelProviderProtocol
    else { return nil }
    return tunnelProtocol.providerConfiguration?["configurationStorage"] as? String
  }

  static func makeOnDemandRules(for profile: HushWireProfile) -> [NEOnDemandRule] {
    guard !profile.trustedWiFiSSIDs.isEmpty else { return [] }
    let disconnectRule = NEOnDemandRuleDisconnect()
    disconnectRule.interfaceTypeMatch = .wiFi
    disconnectRule.ssidMatch = profile.trustedWiFiSSIDs
    let fallbackRule: NEOnDemandRule =
      profile.autoConnectOutsideTrustedWiFi
      ? NEOnDemandRuleConnect()
      : NEOnDemandRuleIgnore()
    return [disconnectRule, fallbackRule]
  }

  private static func onDemandPolicyIsPersisted(
    for profile: HushWireProfile,
    in manager: NETunnelProviderManager
  ) -> Bool {
    if profile.trustedWiFiSSIDs.isEmpty {
      return !manager.isOnDemandEnabled
    }
    guard
      manager.isOnDemandEnabled,
      let rules = manager.onDemandRules,
      rules.count == 2,
      let disconnectRule = rules[0] as? NEOnDemandRuleDisconnect,
      disconnectRule.interfaceTypeMatch == .wiFi,
      disconnectRule.ssidMatch == profile.trustedWiFiSSIDs
    else { return false }
    if profile.autoConnectOutsideTrustedWiFi {
      return rules[1] is NEOnDemandRuleConnect
    }
    return rules[1] is NEOnDemandRuleIgnore
  }

  private static func uint64(_ value: Any?) -> UInt64 {
    if let number = value as? NSNumber { return number.uint64Value }
    if let value = value as? UInt64 { return value }
    return 0
  }
}

extension DateFormatter {
  fileprivate static let hushWireEvent: DateFormatter = {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "zh_Hans_CN")
    formatter.dateFormat = "HH:mm:ss"
    return formatter
  }()

  fileprivate static let hushWireReport: DateFormatter = {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "zh_Hans_CN")
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss ZZZZZ"
    return formatter
  }()
}
