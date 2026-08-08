import AppKit
import Combine
import Darwin
import Foundation
import UniformTypeIdentifiers

enum TunnelState: Equatable {
  case disconnected
  case connecting
  case connected(pid: Int32)
  case stopping

  var isConnected: Bool {
    if case .connected = self { return true }
    return false
  }

  var title: String {
    switch self {
    case .disconnected:
      return "未连接"
    case .connecting:
      return "正在连接"
    case .connected:
      return "已连接"
    case .stopping:
      return "正在断开"
    }
  }
}

@MainActor
final class TunnelController: ObservableObject {
  @Published var state: TunnelState = .disconnected
  @Published var configURL: URL?
  @Published var isBusy = false
  @Published var commandOutput = "尚未运行任何操作。"
  @Published var daemonLog = ""
  @Published var statusMessage = "请选择一个 HushWire TOML 配置文件。"
  @Published var lastOperationFailed = false
  @Published var hideAfterConnecting: Bool {
    didSet { defaults.set(hideAfterConnecting, forKey: Keys.hideAfterConnecting) }
  }

  private enum Keys {
    static let configPath = "selectedConfigPath"
    static let hideAfterConnecting = "hideAfterConnecting"
  }

  private let defaults: UserDefaults
  private let userID: uid_t
  private let logDirectory: URL
  private let logFile: URL
  private var pollingTimer: Timer?

  init(defaults: UserDefaults = .standard) {
    self.defaults = defaults
    self.userID = getuid()
    self.hideAfterConnecting = defaults.bool(forKey: Keys.hideAfterConnecting)

    let logs = FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent("Library/Logs/HushWire", isDirectory: true)
    self.logDirectory = logs
    self.logFile = logs.appendingPathComponent("tunnel.log", isDirectory: false)

    try? FileManager.default.createDirectory(
      at: logs,
      withIntermediateDirectories: true,
      attributes: nil
    )
    if !FileManager.default.fileExists(atPath: logFile.path) {
      FileManager.default.createFile(atPath: logFile.path, contents: nil)
    }

    if let path = defaults.string(forKey: Keys.configPath) {
      self.configURL = URL(fileURLWithPath: path)
    }

    refreshRuntimeState()
    refreshLog()

    pollingTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
      Task { @MainActor in
        self?.refreshRuntimeState()
        self?.refreshLog()
      }
    }
  }

  deinit {
    pollingTimer?.invalidate()
  }

  var runningPID: Int32? {
    if case .connected(let pid) = state { return pid }
    return nil
  }

  var configDisplayPath: String {
    configURL?.path(percentEncoded: false) ?? "尚未选择配置文件"
  }

  var displayText: String {
    let parts = [commandOutput, daemonLog]
      .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
      .filter { !$0.isEmpty }
    return parts.joined(separator: "\n\n—— 隧道日志 ——\n\n")
  }

  func chooseConfiguration() {
    let panel = NSOpenPanel()
    panel.title = "选择 HushWire 配置"
    panel.prompt = "选择"
    panel.canChooseDirectories = false
    panel.allowsMultipleSelection = false
    if let tomlType = UTType(filenameExtension: "toml") {
      panel.allowedContentTypes = [tomlType]
    }
    if let currentDirectory = configURL?.deletingLastPathComponent() {
      panel.directoryURL = currentDirectory
    }

    guard panel.runModal() == .OK, let selected = panel.url else { return }
    configURL = selected
    defaults.set(selected.path(percentEncoded: false), forKey: Keys.configPath)
    statusMessage = "已选择 \(selected.lastPathComponent)，连接前建议先检查配置。"
    lastOperationFailed = false
  }

  func revealConfiguration() {
    guard let configURL else { return }
    NSWorkspace.shared.activateFileViewerSelecting([configURL])
  }

  func openLogDirectory() {
    NSWorkspace.shared.open(logDirectory)
  }

  func clearDisplay() {
    commandOutput = ""
    daemonLog = ""
  }

  func validateConfiguration() {
    guard let configURL else { return }
    guard let hushwire = bundledHushWireURL else {
      reportMissingBundleComponent("hushwire")
      return
    }

    beginOperation(message: "正在检查配置…")
    runInBackground {
      CommandRunner.run(
        executable: hushwire,
        arguments: ["check", "--config", configURL.path(percentEncoded: false)]
      )
    } completion: { [weak self] result in
      self?.finishOperation(
        result,
        successMessage: "配置检查通过。",
        failureMessage: "配置检查失败。"
      )
    }
  }

  func generateKeyPair() {
    guard let hushwire = bundledHushWireURL else {
      reportMissingBundleComponent("hushwire")
      return
    }

    beginOperation(message: "正在生成密钥…")
    runInBackground {
      CommandRunner.run(executable: hushwire, arguments: ["genkey"])
    } completion: { [weak self] result in
      self?.finishOperation(
        result,
        successMessage: "密钥已生成；可从运行记录中复制。",
        failureMessage: "密钥生成失败。"
      )
    }
  }

  func connect() {
    guard let configURL else { return }
    guard FileManager.default.fileExists(atPath: configURL.path) else {
      statusMessage = "配置文件不存在，请重新选择。"
      lastOperationFailed = true
      return
    }
    guard let hushwire = bundledHushWireURL else {
      reportMissingBundleComponent("hushwire")
      return
    }
    guard let control = bundledControlURL else {
      reportMissingBundleComponent("hushwire-control")
      return
    }

    beginOperation(message: "正在检查配置…")
    state = .connecting
    let configPath = configURL.path(percentEncoded: false)
    let logPath = logFile.path(percentEncoded: false)
    let currentUserID = userID
    let uid = String(currentUserID)

    runInBackground {
      let validation = CommandRunner.run(
        executable: hushwire,
        arguments: ["check", "--config", configPath]
      )
      guard validation.succeeded else { return validation }

      do {
        let staged = try ConfigurationStager.stage(
          sourceURL: configURL,
          userID: currentUserID
        )
        defer { staged.remove() }

        return CommandRunner.runWithAdministratorPrivileges(arguments: [
          control.path(percentEncoded: false),
          "start",
          uid,
          hushwire.path(percentEncoded: false),
          staged.fileURL.path(percentEncoded: false),
          logPath,
        ])
      } catch {
        return CommandResult(
          exitCode: 74,
          output: "Unable to stage configuration for privileged startup: \(error.localizedDescription)"
        )
      }
    } completion: { [weak self] result in
      guard let self else { return }
      self.isBusy = false
      self.commandOutput = result.output.isEmpty ? "连接命令已完成。" : result.output
      self.lastOperationFailed = !result.succeeded
      self.refreshRuntimeState()

      if result.succeeded, self.state.isConnected {
        self.statusMessage = "隧道已启动。断开时 macOS 会再次请求管理员授权。"
        if self.hideAfterConnecting {
          NSApplication.shared.keyWindow?.orderOut(nil)
        }
      } else {
        self.state = .disconnected
        self.statusMessage =
          result.output.localizedCaseInsensitiveContains("canceled")
          ? "已取消管理员授权。"
          : "连接失败，请查看运行记录。"
      }
    }
  }

  func disconnect() {
    guard let control = bundledControlURL else {
      reportMissingBundleComponent("hushwire-control")
      return
    }

    beginOperation(message: "正在断开；macOS 将请求管理员授权…")
    state = .stopping
    let uid = String(userID)

    runInBackground {
      CommandRunner.runWithAdministratorPrivileges(arguments: [
        control.path(percentEncoded: false),
        "stop",
        uid,
      ])
    } completion: { [weak self] result in
      guard let self else { return }
      self.isBusy = false
      self.commandOutput = result.output.isEmpty ? "断开命令已完成。" : result.output
      self.lastOperationFailed = !result.succeeded
      self.refreshRuntimeState()

      if result.succeeded, !self.state.isConnected {
        self.statusMessage = "隧道已断开，路由清理完成。"
      } else {
        self.statusMessage =
          result.output.localizedCaseInsensitiveContains("canceled")
          ? "已取消管理员授权，隧道仍在运行。"
          : "未能正常断开，请查看运行记录。"
      }
    }
  }

  private var bundledHushWireURL: URL? {
    if let override = ProcessInfo.processInfo.environment["HUSHWIRE_BINARY"], !override.isEmpty {
      return URL(fileURLWithPath: override)
    }
    return Bundle.main.url(forResource: "hushwire", withExtension: nil, subdirectory: "bin")
  }

  private var bundledControlURL: URL? {
    Bundle.main.url(forResource: "hushwire-control", withExtension: nil, subdirectory: "bin")
  }

  private var pidFile: URL {
    URL(fileURLWithPath: "/var/run/hushwire-\(userID).pid")
  }

  private func refreshRuntimeState() {
    guard !isBusy else { return }
    guard let pid = readPID(), processExists(pid) else {
      if state.isConnected {
        statusMessage = "隧道进程已停止。"
      }
      state = .disconnected
      return
    }
    state = .connected(pid: pid)
  }

  private func readPID() -> Int32? {
    guard let text = try? String(contentsOf: pidFile, encoding: .utf8),
      let pid = Int32(text.trimmingCharacters(in: .whitespacesAndNewlines)),
      pid > 1
    else {
      return nil
    }
    return pid
  }

  private func processExists(_ pid: Int32) -> Bool {
    if Darwin.kill(pid, 0) == 0 { return true }
    return errno == EPERM
  }

  private func refreshLog() {
    let maximumBytes: UInt64 = 160_000
    guard let handle = try? FileHandle(forReadingFrom: logFile) else { return }
    defer { try? handle.close() }

    do {
      let size = try handle.seekToEnd()
      try handle.seek(toOffset: size > maximumBytes ? size - maximumBytes : 0)
      let data = try handle.readToEnd() ?? Data()
      daemonLog = String(decoding: data, as: UTF8.self)
    } catch {
      // A log refresh is best-effort and must not affect tunnel state.
    }
  }

  private func beginOperation(message: String) {
    isBusy = true
    lastOperationFailed = false
    statusMessage = message
  }

  private func finishOperation(
    _ result: CommandResult,
    successMessage: String,
    failureMessage: String
  ) {
    isBusy = false
    commandOutput = result.output.isEmpty ? "命令没有返回内容。" : result.output
    lastOperationFailed = !result.succeeded
    statusMessage = result.succeeded ? successMessage : failureMessage
    refreshRuntimeState()
  }

  private func reportMissingBundleComponent(_ name: String) {
    commandOutput = "应用包中缺少 \(name)。请重新运行 macos/scripts/build-app.sh。"
    statusMessage = "客户端构建不完整。"
    lastOperationFailed = true
  }

  private func runInBackground(
    operation: @escaping () -> CommandResult,
    completion: @escaping (CommandResult) -> Void
  ) {
    DispatchQueue.global(qos: .userInitiated).async {
      let result = operation()
      DispatchQueue.main.async {
        completion(result)
      }
    }
  }
}
