import Combine
import Foundation
@preconcurrency import NetworkExtension
import SystemExtensions

enum SystemExtensionInstallationState: Equatable {
  case unknown
  case requesting
  case awaitingApproval
  case installed
  case failed(String)

  var title: String {
    switch self {
    case .unknown: "尚未检查"
    case .requesting: "正在提交安装请求"
    case .awaitingApproval: "等待系统设置批准"
    case .installed: "扩展已激活"
    case .failed(let message): "失败：\(message)"
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

  var routeDescription: String {
    routes.joined(separator: ", ")
  }

  var endpointDescription: String {
    endpoints.joined(separator: ", ")
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
  @Published private(set) var activity = "请选择一份 /32 测试路由配置；密钥不会写入 VPN 系统偏好。"

  private var manager: NETunnelProviderManager?
  private var statusObserver: NSObjectProtocol?
  private var providerPollTimer: DispatchSourceTimer?
  private var configurationDeliveryInFlight = false

  override init() {
    super.init()
    statusObserver = NotificationCenter.default.addObserver(
      forName: .NEVPNStatusDidChange,
      object: nil,
      queue: .main
    ) { [weak self] _ in
      Task { @MainActor in
        guard let self, let manager = self.manager else { return }
        self.vpnStatus = manager.connection.status
        if self.vpnStatus == .connected {
          self.deliverConfigurationIfNeeded()
        }
        self.refreshProviderStatus()
      }
    }
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
    guard configurationSummary != nil else {
      activity = "请先导入并验证 TOML 配置。"
      return
    }
    isBusy = true
    activity = "正在保存由 macOS 管理的 Packet Tunnel 配置…"
    loadSavedConfiguration(reportResult: true, createIfMissing: true)
  }

  func startTunnel() {
    guard configurationSummary != nil else {
      activity = "请先导入测试配置。"
      return
    }
    guard let manager else {
      activity = "请先保存 VPN 配置。"
      return
    }
    do {
      guard let session = manager.connection as? NETunnelProviderSession else {
        throw HushWireCoreError.operation("VPN profile 不是 Packet Tunnel session。")
      }
      providerReady = false
      configurationDeliveryInFlight = false
      try session.startTunnel(options: nil)
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
      }
      return
    }
    do {
      try session.sendProviderMessage(Data([0x01])) { [weak self] response in
        guard let response else { return }
        Task { @MainActor in
          self?.applyProviderStatus(response)
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
            let detail = response.flatMap { data in
              (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"]
                as? String
            } ?? "扩展没有返回成功响应。"
            self.activity = "安装隧道配置失败：\(detail)"
            self.providerReady = false
            manager.connection.stopVPNTunnel()
            return
          }
          self.providerReady = true
          self.activity = "隧道已就绪：仅启用 /32 路由，默认路由与 DNS 未修改。"
          self.refreshProviderStatus()
        }
      }
    } catch {
      configurationDeliveryInFlight = false
      activity = "传递隧道配置失败：\(error.localizedDescription)"
      manager.connection.stopVPNTunnel()
    }
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
            self.isBusy = false
            if reportResult {
              self.activity = "VPN 配置已存在，并已重新载入系统状态。"
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
    let tunnelProtocol = NETunnelProviderProtocol()
    tunnelProtocol.providerBundleIdentifier = SystemExtensionConstants.extensionBundleIdentifier
    tunnelProtocol.serverAddress = configurationSummary?.endpoints.first
      ?? SystemExtensionConstants.serverAddress
    tunnelProtocol.providerConfiguration = [
      "schemaVersion": 2,
      "configurationStorage": HushWireConfigurationStore.providerStorageKind,
      "routePolicy": HushWireConfigurationStore.routePolicy,
    ]
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
        self.activity = "配置导入完成。VPN 仅引用 App Group 文件，当前只允许 /32 路由。"
      }
    }
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
      installationState = .installed
      isBusy = false
      activity = result == .willCompleteAfterReboot
        ? "扩展已接受，将在重新启动后完成激活。"
        : "System Extension 已激活。"
    }
  }

  nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
    let nsError = error as NSError
    let detail = "\(nsError.localizedDescription) [\(nsError.domain) \(nsError.code)]"
    Task { @MainActor in
      installationState = .failed(detail)
      isBusy = false
      activity = "System Extension 激活失败：\(detail)"
    }
  }
}
