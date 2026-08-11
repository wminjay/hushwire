import Combine
import Darwin
import Foundation
@preconcurrency import NetworkExtension
import SystemExtensions

enum SystemExtensionInstallationState: Equatable {
  case unknown
  case notInstalled
  case requesting
  case awaitingApproval
  case installed
  case uninstalling
  case failed(String)

  var title: String {
    switch self {
    case .unknown: "尚未检查"
    case .notInstalled: "未激活"
    case .requesting: "正在提交安装请求"
    case .awaitingApproval: "等待系统设置批准"
    case .installed: "扩展已激活"
    case .uninstalling: "正在卸载"
    case .failed(let message): "失败：\(message)"
    }
  }
}

struct HushWirePeerStatus: Identifiable, Equatable {
  var id: String { name }
  let name: String
  let txBytes: UInt64
  let rxBytes: UInt64
  let lastSeenMillisecondsAgo: UInt64?
  let endpoint: String?

  var lastSeenDescription: String {
    guard let milliseconds = lastSeenMillisecondsAgo else { return "从未收到认证流量" }
    if milliseconds < 1_000 { return "刚刚" }
    return "\(milliseconds / 1_000) 秒前"
  }

  var trafficDescription: String {
    let formatter = ByteCountFormatter()
    formatter.countStyle = .binary
    return "↑ \(formatter.string(fromByteCount: Int64(clamping: txBytes)))  "
      + "↓ \(formatter.string(fromByteCount: Int64(clamping: rxBytes)))"
  }
}

@MainActor
final class SystemExtensionController: NSObject, ObservableObject {
  @Published private(set) var installationState: SystemExtensionInstallationState = .unknown
  @Published private(set) var vpnStatus: NEVPNStatus = .invalid
  @Published private(set) var isBusy = false
  @Published private(set) var configurationSummary: HushWireConfigurationSummary?
  @Published private(set) var peerStatuses: [HushWirePeerStatus] = []
  @Published private(set) var lastHandshake = ""
  @Published private(set) var providerReady = false
  @Published private(set) var selectedRoutePolicy = HushWireRoutePolicy.hostRoutesOnly
  @Published var dnsServersText = ""
  @Published private(set) var activity = "请选择网络策略并导入匹配的 TOML；密钥不会写入 VPN 系统偏好。"

  private var manager: NETunnelProviderManager?
  private var statusObserver: NSObjectProtocol?
  private var providerPollTimer: DispatchSourceTimer?
  private var configurationDeliveryInFlight = false
  private var configurationDeliveryLeadership: FileHandle?
  private var awaitingExternalConfigurationConfirmation = false
  private var stopRequestedByThisController = false
  private var providerStatusEpoch: UInt64 = 0
  private var propertiesRequest: OSSystemExtensionRequest?

  override init() {
    super.init()
    statusObserver = NotificationCenter.default.addObserver(
      forName: .NEVPNStatusDidChange,
      object: nil,
      queue: .main
    ) { [weak self] _ in
      Task { @MainActor in
        guard let self, let manager = self.manager else { return }
        let status = manager.connection.status
        let wasProviderReady = self.providerReady
        let wasAwaitingExternalConfirmation = self.awaitingExternalConfigurationConfirmation
        if status != self.vpnStatus, status != .connected {
          self.providerStatusEpoch &+= 1
        }
        self.vpnStatus = status
        if self.vpnStatus == .connected {
          self.deliverConfigurationIfNeeded()
        } else if self.vpnStatus == .disconnected || self.vpnStatus == .invalid {
          self.releaseConfigurationDeliveryLeadership()
          self.awaitingExternalConfigurationConfirmation = false
          if self.stopRequestedByThisController {
            self.activity = "Packet Tunnel 已断开；系统路由与 DNS 已恢复。"
          } else if wasProviderReady {
            self.activity = "检测到 Packet Tunnel 已断开；系统路由与 DNS 已恢复。"
          } else if wasAwaitingExternalConfirmation {
            self.activity = "Packet Tunnel 已断开；当前窗口未收到最终配置确认，系统网络未被继续接管。"
          }
          self.stopRequestedByThisController = false
        }
        self.refreshProviderStatus()
      }
    }
    refreshSystemExtensionStatus()
    refreshStagedConfiguration(reportFailure: false)
    loadSavedConfiguration(reportResult: false)
    let timer = DispatchSource.makeTimerSource(queue: .main)
    timer.schedule(deadline: .now() + 1, repeating: 2)
    timer.setEventHandler { [weak self] in
      self?.refreshProviderStatus()
    }
    providerPollTimer = timer
    timer.resume()
  }

  deinit {
    if let statusObserver {
      NotificationCenter.default.removeObserver(statusObserver)
    }
    providerPollTimer?.setEventHandler {}
    providerPollTimer?.cancel()
  }

  var vpnStatusTitle: String {
    switch vpnStatus {
    case .invalid: "未配置"
    case .disconnected: "未连接"
    case .connecting: "正在连接"
    case .connected: providerReady ? "已连接（隧道就绪）" : "已连接（正在配置）"
    case .reasserting: "正在恢复"
    case .disconnecting: "正在断开"
    @unknown default: "未知状态"
    }
  }

  var canEditNetworkPolicy: Bool {
    !isBusy && (vpnStatus == .invalid || vpnStatus == .disconnected)
  }

  var isFullTunnelSelected: Bool {
    selectedRoutePolicy == .fullTunnel
  }

  var canConfigureDNS: Bool {
    selectedRoutePolicy.allowsDNS
  }

  func selectRoutePolicy(_ routePolicy: HushWireRoutePolicy) {
    guard canEditNetworkPolicy else {
      activity = "请先断开当前隧道，再修改网络策略。"
      return
    }
    selectedRoutePolicy = routePolicy
    if routePolicy == .hostRoutesOnly {
      dnsServersText = ""
    }
    refreshStagedConfiguration(reportFailure: true)
    if configurationSummary == nil {
      switch routePolicy {
      case .hostRoutesOnly:
        activity = "已选择 /32 主机路由；请导入只包含 /32 allowed_ips 的配置。"
      case .splitRoutes:
        activity = "已选择自定义分流；请导入单 Peer、最多 256 条非默认 IPv4 CIDR。"
      case .fullTunnel:
        activity = "已选择默认走隧道；请使用单 Peer、0.0.0.0/0，可用 excluded_ips 添加直连例外。"
      }
    }
  }

  func requestSystemExtensionActivation() {
    guard !isBusy else { return }
    isBusy = true
    installationState = .requesting
    activity = "正在请求 macOS 激活 \(SystemExtensionConstants.extensionBundleIdentifier)…"

    let request = OSSystemExtensionRequest.activationRequest(
      forExtensionWithIdentifier: SystemExtensionConstants.extensionBundleIdentifier,
      queue: .main
    )
    request.delegate = self
    OSSystemExtensionManager.shared.submitRequest(request)
  }

  private func refreshSystemExtensionStatus() {
    let request = OSSystemExtensionRequest.propertiesRequest(
      forExtensionWithIdentifier: SystemExtensionConstants.extensionBundleIdentifier,
      queue: .main
    )
    propertiesRequest = request
    request.delegate = self
    OSSystemExtensionManager.shared.submitRequest(request)
  }

  func importConfiguration(from url: URL) {
    guard !isBusy else { return }
    isBusy = true
    activity = "正在读取并验证配置…"
    let accessed = url.startAccessingSecurityScopedResource()
    defer {
      if accessed { url.stopAccessingSecurityScopedResource() }
    }

    do {
      let data = try Data(contentsOf: url, options: [.mappedIfSafe])
      guard data.count <= 1_048_576 else {
        throw HushWireCoreError.operation("配置文件超过 1 MiB，已拒绝导入。")
      }
      let summary = try inspectConfiguration(data)
      try HushWireConfigurationStore.install(data)
      configurationSummary = summary
      activity = "配置已验证并保存到受限 App Group 文件；正在更新 VPN 配置引用…"
      loadSavedConfiguration(reportResult: true, createIfMissing: true)
    } catch {
      isBusy = false
      activity = "导入配置失败：\(error.localizedDescription)"
    }
  }

  func saveVPNConfiguration() {
    guard !isBusy else { return }
    do {
      configurationSummary = try inspectConfiguration(HushWireConfigurationStore.load())
    } catch {
      activity = "无法保存 VPN 配置：\(error.localizedDescription)"
      return
    }
    isBusy = true
    activity = "正在保存由 macOS 管理的 Packet Tunnel 配置…"
    loadSavedConfiguration(reportResult: true, createIfMissing: true)
  }

  func startTunnel() {
    guard let manager else {
      activity = "请先保存 VPN 配置。"
      return
    }
    do {
      let selectedPolicy = try currentNetworkPolicy()
      let savedPolicy = try Self.networkPolicy(from: manager)
      guard savedPolicy == selectedPolicy else {
        throw HushWireCoreError.operation("网络策略或 DNS 已改变，请先保存 VPN 配置。")
      }
      configurationSummary = try HushWireConfigurationPolicy.inspect(
        HushWireConfigurationStore.load(),
        networkPolicy: selectedPolicy
      )
      guard let session = manager.connection as? NETunnelProviderSession else {
        throw HushWireCoreError.operation("VPN profile 不是 Packet Tunnel session。")
      }
      providerReady = false
      configurationDeliveryInFlight = false
      awaitingExternalConfigurationConfirmation = false
      stopRequestedByThisController = false
      releaseConfigurationDeliveryLeadership()
      providerStatusEpoch &+= 1
      let startOptions: [String: NSObject]? =
        selectedPolicy.routePolicy == .fullTunnel
        ? [HushWireNetworkPolicy.fullTunnelApprovalOptionKey: NSNumber(value: true)]
        : nil
      try session.startTunnel(options: startOptions)
      vpnStatus = manager.connection.status
      activity = "扩展正在启动；连接后将通过私有消息通道传递配置。"
    } catch {
      activity = "启动请求失败：\(error.localizedDescription)"
    }
  }

  func stopTunnel() {
    guard let manager else { return }
    manager.connection.stopVPNTunnel()
    providerReady = false
    configurationDeliveryInFlight = false
    awaitingExternalConfigurationConfirmation = false
    stopRequestedByThisController = true
    providerStatusEpoch &+= 1
    vpnStatus = manager.connection.status
    activity = "已请求 macOS 停止 Packet Tunnel；停止不再调用管理员提权脚本。"
  }

  private func refreshStagedConfiguration(reportFailure: Bool) {
    guard HushWireConfigurationStore.exists() else { return }
    do {
      configurationSummary = try inspectConfiguration(HushWireConfigurationStore.load())
    } catch {
      configurationSummary = nil
      if reportFailure {
        activity = "已保存配置无效：\(error.localizedDescription)"
      }
    }
  }

  private func inspectConfiguration(_ data: Data) throws -> HushWireConfigurationSummary {
    try HushWireConfigurationPolicy.inspect(data, networkPolicy: currentNetworkPolicy())
  }

  private func currentNetworkPolicy() throws -> HushWireNetworkPolicy {
    try HushWireNetworkPolicy(
      routePolicy: selectedRoutePolicy,
      dnsServers: HushWireNetworkPolicy.parseDNSServers(dnsServersText)
    )
  }

  private func refreshProviderStatus() {
    guard
      let manager,
      manager.connection.status == .connected,
      let session = manager.connection as? NETunnelProviderSession
    else {
      if manager?.connection.status == .disconnected {
        peerStatuses = []
        lastHandshake = ""
        providerReady = false
        configurationDeliveryInFlight = false
        awaitingExternalConfigurationConfirmation = false
        releaseConfigurationDeliveryLeadership()
      }
      return
    }
    let statusEpoch = providerStatusEpoch
    do {
      try session.sendProviderMessage(Data([0x01])) { [weak self] response in
        guard let response else { return }
        Task { @MainActor in
          guard let self, self.providerStatusEpoch == statusEpoch else { return }
          self.applyProviderStatus(response)
        }
      }
    } catch {
      // Status polling is best-effort and must not affect tunnel lifecycle.
    }
  }

  private func applyProviderStatus(_ data: Data) {
    guard
      let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    else { return }
    let running = (object["running"] as? NSNumber)?.boolValue ?? false
    let awaitingConfiguration =
      (object["awaitingConfiguration"] as? NSNumber)?.boolValue ?? false
    let recoveredFromAnotherWindow = running && awaitingExternalConfigurationConfirmation
    let becameReady = running && !providerReady
    providerReady = running
    lastHandshake = object["lastHandshake"] as? String ?? ""
    let peerObjects = object["peers"] as? [[String: Any]] ?? []
    peerStatuses = peerObjects.compactMap { peer in
      guard let name = peer["name"] as? String else { return nil }
      return HushWirePeerStatus(
        name: name,
        txBytes: Self.uint64(peer["txBytes"]),
        rxBytes: Self.uint64(peer["rxBytes"]),
        lastSeenMillisecondsAgo: peer["lastSeenMillisecondsAgo"].map(Self.uint64),
        endpoint: peer["endpoint"] as? String
      )
    }
    if recoveredFromAnotherWindow {
      awaitingExternalConfigurationConfirmation = false
      updateReadyActivity(prefix: "检测到隧道已由另一个 HushWire 窗口完成配置。")
    } else if becameReady {
      updateReadyActivity()
    }
    if awaitingConfiguration && !running {
      deliverConfigurationIfNeeded()
    }
  }

  private func deliverConfigurationIfNeeded() {
    guard
      vpnStatus == .connected,
      !providerReady,
      !configurationDeliveryInFlight,
      let manager,
      let session = manager.connection as? NETunnelProviderSession
    else { return }

    do {
      guard try acquireConfigurationDeliveryLeadership() else {
        awaitingExternalConfigurationConfirmation = true
        activity = "另一个 HushWire 窗口正在安装隧道配置；当前窗口等待扩展确认。"
        return
      }
      let configuration = try HushWireConfigurationStore.load()
      var message = Data([0x02])
      message.append(configuration)
      configurationDeliveryInFlight = true
      activity = "正在通过私有 provider message 安装隧道配置…"
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
              } ?? "扩展没有返回成功响应。"
            self.providerReady = false
            self.awaitingExternalConfigurationConfirmation = response == nil
            self.providerStatusEpoch &+= 1
            self.releaseConfigurationDeliveryLeadership()
            if response == nil {
              self.activity = "扩展配置响应未返回；正在确认是否已由另一个 HushWire 窗口完成配置。"
            } else {
              self.activity = "安装隧道配置失败：\(detail)。扩展将自行安全停止，当前窗口不会断开共享会话。"
            }
            self.refreshProviderStatus()
            return
          }
          // Any status request issued before this acknowledgement describes
          // the pre-configuration provider state. Invalidate those callbacks
          // before marking the provider ready so a late `awaitingConfiguration`
          // response cannot trigger a duplicate install and stop the tunnel.
          self.providerStatusEpoch &+= 1
          self.providerReady = true
          self.awaitingExternalConfigurationConfirmation = false
          self.updateReadyActivity()
          self.refreshProviderStatus()
        }
      }
    } catch {
      configurationDeliveryInFlight = false
      providerReady = false
      awaitingExternalConfigurationConfirmation = true
      releaseConfigurationDeliveryLeadership()
      activity = "传递隧道配置失败：\(error.localizedDescription)。正在确认扩展状态，不主动断开共享会话。"
      providerStatusEpoch &+= 1
      refreshProviderStatus()
    }
  }

  private func updateReadyActivity(prefix: String? = nil) {
    let detail: String
    if let summary = configurationSummary {
      switch summary.routePolicy {
      case .hostRoutesOnly:
        detail = "隧道已就绪：仅启用 /32 路由，默认路由与 DNS 未修改。"
      case .splitRoutes:
        detail = "自定义分流已就绪：\(summary.routes.count) 条路由；DNS：\(summary.dnsDescription)。"
      case .fullTunnel:
        detail =
          "默认隧道已就绪：\(summary.directRoutes.count) 条直连例外；DNS：\(summary.dnsDescription)。"
      }
    } else {
      detail = "隧道已就绪。"
    }
    activity = [prefix, detail].compactMap { $0 }.joined(separator: " ")
  }

  private func acquireConfigurationDeliveryLeadership() throws -> Bool {
    if configurationDeliveryLeadership != nil {
      return true
    }
    guard
      let containerURL = FileManager.default.containerURL(
        forSecurityApplicationGroupIdentifier: HushWireConfigurationStore.appGroupIdentifier
      )
    else {
      throw HushWireCoreError.operation("无法访问 HushWire App Group 配置容器。")
    }
    let lockURL = containerURL.appendingPathComponent(
      "configuration-delivery.lock",
      isDirectory: false
    )
    let descriptor = lockURL.path.withCString { path in
      Darwin.open(
        path,
        O_CREAT | O_RDWR | O_EXLOCK | O_NONBLOCK,
        S_IRUSR | S_IWUSR
      )
    }
    guard descriptor >= 0 else {
      if errno == EWOULDBLOCK || errno == EAGAIN {
        return false
      }
      throw NSError(
        domain: NSPOSIXErrorDomain,
        code: Int(errno),
        userInfo: [NSLocalizedDescriptionKey: "无法获取隧道配置投递锁。"]
      )
    }
    _ = Darwin.fchmod(descriptor, S_IRUSR | S_IWUSR)
    configurationDeliveryLeadership = FileHandle(
      fileDescriptor: descriptor,
      closeOnDealloc: true
    )
    return true
  }

  private func releaseConfigurationDeliveryLeadership() {
    guard let handle = configurationDeliveryLeadership else { return }
    try? handle.close()
    configurationDeliveryLeadership = nil
  }

  private static func uint64(_ value: Any?) -> UInt64 {
    if let number = value as? NSNumber { return number.uint64Value }
    if let value = value as? UInt64 { return value }
    return 0
  }

  private func loadSavedConfiguration(
    reportResult: Bool,
    createIfMissing: Bool = false
  ) {
    NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
      Task { @MainActor in
        guard let self else { return }
        if let error {
          self.isBusy = false
          if reportResult {
            self.activity = "读取 VPN 配置失败：\(error.localizedDescription)"
          }
          return
        }

        let existing = managers?.first { manager in
          (manager.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerBundleIdentifier == SystemExtensionConstants.extensionBundleIdentifier
        }
        if let existing {
          self.manager = existing
          self.vpnStatus = existing.connection.status
          if createIfMissing {
            self.configureAndSave(existing)
          } else {
            self.restoreNetworkPolicy(from: existing, reportFailure: reportResult)
            self.refreshStagedConfiguration(reportFailure: reportResult)
            self.isBusy = false
            if reportResult {
              self.activity = "VPN 配置已存在，并已重新载入系统状态。"
            } else if self.vpnStatus == .connected || self.vpnStatus == .reasserting {
              self.activity = "已从 macOS 恢复现有连接；正在读取实时会话。"
            }
          }
          return
        }

        guard createIfMissing else {
          self.isBusy = false
          return
        }
        self.configureAndSave(NETunnelProviderManager())
      }
    }
  }

  private func configureAndSave(_ manager: NETunnelProviderManager) {
    let networkPolicy: HushWireNetworkPolicy
    do {
      networkPolicy = try currentNetworkPolicy()
      configurationSummary = try HushWireConfigurationPolicy.inspect(
        HushWireConfigurationStore.load(),
        networkPolicy: networkPolicy
      )
    } catch {
      isBusy = false
      activity = "保存 VPN 配置失败：\(error.localizedDescription)"
      return
    }
    let tunnelProtocol = NETunnelProviderProtocol()
    tunnelProtocol.providerBundleIdentifier = SystemExtensionConstants.extensionBundleIdentifier
    tunnelProtocol.serverAddress =
      configurationSummary?.resolvedEndpoints.first
      ?? SystemExtensionConstants.serverAddress
    // Make included/excluded route intent deterministic even when the current
    // LAN has an overlapping route. The endpoint and explicit direct routes
    // are scoped to the physical interface by Network Extension.
    tunnelProtocol.enforceRoutes = true
    tunnelProtocol.providerConfiguration = networkPolicy.addingProviderConfiguration(to: [
      "schemaVersion": 4,
      "configurationStorage": HushWireConfigurationStore.providerStorageKind,
    ])
    manager.localizedDescription = SystemExtensionConstants.profileDescription
    manager.protocolConfiguration = tunnelProtocol
    manager.isEnabled = true

    manager.saveToPreferences { [weak self, weak manager] error in
      Task { @MainActor in
        guard let self else { return }
        if let error {
          self.isBusy = false
          self.activity = "保存 VPN 配置失败：\(error.localizedDescription)"
          return
        }
        self.manager = manager
        self.isBusy = false
        self.vpnStatus = manager?.connection.status ?? .invalid
        switch networkPolicy.routePolicy {
        case .hostRoutesOnly:
          self.activity = "VPN 配置已保存为 /32 主机路由；默认路由与 DNS 不会修改。"
        case .splitRoutes:
          self.activity = "VPN 配置已保存为自定义分流；连接前会先完成认证预握手。"
        case .fullTunnel:
          self.activity = "VPN 配置已保存为默认走隧道；连接前仍会再次确认网络影响。"
        }
      }
    }
  }

  private func restoreNetworkPolicy(
    from manager: NETunnelProviderManager,
    reportFailure: Bool
  ) {
    do {
      let networkPolicy = try Self.networkPolicy(from: manager)
      selectedRoutePolicy = networkPolicy.routePolicy
      dnsServersText = networkPolicy.dnsServers.joined(separator: ", ")
    } catch {
      selectedRoutePolicy = .hostRoutesOnly
      dnsServersText = ""
      if reportFailure {
        activity = "VPN 网络策略无效：\(error.localizedDescription)"
      }
    }
  }

  private static func networkPolicy(
    from manager: NETunnelProviderManager
  ) throws -> HushWireNetworkPolicy {
    guard
      let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol,
      let providerConfiguration = tunnelProtocol.providerConfiguration
    else {
      throw HushWireCoreError.operation("VPN 配置不存在。")
    }
    return try HushWireNetworkPolicy(providerConfiguration: providerConfiguration)
  }
}

extension SystemExtensionController: OSSystemExtensionRequestDelegate {
  nonisolated func request(
    _ request: OSSystemExtensionRequest,
    actionForReplacingExtension existing: OSSystemExtensionProperties,
    withExtension extension: OSSystemExtensionProperties
  ) -> OSSystemExtensionRequest.ReplacementAction {
    .replace
  }

  nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
    Task { @MainActor in
      installationState = .awaitingApproval
      isBusy = false
      activity = "请在“系统设置 → 通用 → 登录项与扩展”中批准 HushWire。"
    }
  }

  nonisolated func request(
    _ request: OSSystemExtensionRequest,
    didFinishWithResult result: OSSystemExtensionRequest.Result
  ) {
    Task { @MainActor in
      if request === propertiesRequest {
        return
      }
      installationState = .installed
      isBusy = false
      activity =
        result == .willCompleteAfterReboot
        ? "扩展已接受，将在重新启动后完成激活。"
        : "System Extension 已激活。"
    }
  }

  nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
    let nsError = error as NSError
    let detail = "\(nsError.localizedDescription) [\(nsError.domain) \(nsError.code)]"
    Task { @MainActor in
      if request === propertiesRequest {
        propertiesRequest = nil
        installationState = .failed("状态查询失败：\(detail)")
        return
      }
      installationState = .failed(detail)
      isBusy = false
      activity = "System Extension 激活失败：\(detail)"
    }
  }

  nonisolated func request(
    _ request: OSSystemExtensionRequest,
    foundProperties properties: [OSSystemExtensionProperties]
  ) {
    Task { @MainActor in
      guard request === propertiesRequest else { return }
      if properties.contains(where: { $0.isAwaitingUserApproval }) {
        installationState = .awaitingApproval
      } else if properties.contains(where: { $0.isEnabled && !$0.isUninstalling }) {
        installationState = .installed
      } else if properties.contains(where: { $0.isUninstalling }) {
        installationState = .uninstalling
      } else {
        installationState = .notInstalled
      }
    }
  }
}
