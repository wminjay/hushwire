import Foundation
import NetworkExtension

struct HushWirePeerSession: Identifiable, Equatable, Sendable {
  var id: String { name }
  let name: String
  let txBytes: UInt64
  let rxBytes: UInt64
  let lastSeenMillisecondsAgo: UInt64?
  let endpoint: String?
  let recoveryTimeoutMilliseconds: UInt64
  let isStale: Bool
  let endpointRefreshInFlight: Bool

  var healthDescription: String {
    if endpointRefreshInFlight { return "正在更新 endpoint" }
    if isStale { return "认证流量已超时，正在恢复" }
    guard let milliseconds = lastSeenMillisecondsAgo else { return "尚未完成握手" }
    if milliseconds < 1_000 { return "刚刚" }
    return "\(milliseconds / 1_000) 秒前"
  }
}

struct HushWireActivityEvent: Identifiable, Equatable, Sendable {
  enum Kind: String, Sendable {
    case info
    case success
    case warning
    case failure
  }

  let id: UUID
  let date: Date
  let kind: Kind
  let message: String

  init(kind: Kind, message: String, date: Date = Date()) {
    id = UUID()
    self.date = date
    self.kind = kind
    self.message = message
  }
}

struct HushWireLastSession: Codable, Equatable, Sendable {
  let profileID: UUID
  let endedAt: Date
  let duration: TimeInterval
  let txBytes: UInt64
  let rxBytes: UInt64
}

enum HushWireConnectionPhase: Equatable, Sendable {
  case noConfiguration
  case disconnected
  case connecting
  case connected
  case recovering
  case disconnecting
  case failed

  var title: String {
    switch self {
    case .noConfiguration: "尚未配置"
    case .disconnected: "未连接"
    case .connecting: "正在建立安全连接"
    case .connected: "已连接"
    case .recovering: "正在自动恢复"
    case .disconnecting: "正在断开"
    case .failed: "连接失败"
    }
  }
}

extension NEVPNStatus {
  var hushWireDescription: String {
    switch self {
    case .invalid: "未配置"
    case .disconnected: "未连接"
    case .connecting: "正在连接"
    case .connected: "已连接"
    case .reasserting: "正在恢复"
    case .disconnecting: "正在断开"
    @unknown default: "未知"
    }
  }
}

enum HushWireFormatters {
  static func bytes(_ value: UInt64) -> String {
    guard value >= 1_024 else { return "\(value) B" }
    let units = ["KB", "MB", "GB", "TB"]
    var amount = Double(value)
    var unitIndex = -1
    repeat {
      amount /= 1_024
      unitIndex += 1
    } while amount >= 1_024 && unitIndex < units.count - 1
    let precision = amount < 10 ? 1 : 0
    return String(format: "%.*f %@", precision, amount, units[unitIndex])
  }

  static func rate(_ value: Double) -> String {
    guard value >= 1 else { return "0 B/s" }
    return "\(bytes(UInt64(value.rounded())))/s"
  }

  static func duration(_ interval: TimeInterval) -> String {
    let seconds = max(0, Int(interval))
    let hours = seconds / 3_600
    let minutes = (seconds % 3_600) / 60
    let remainder = seconds % 60
    return String(format: "%02d:%02d:%02d", hours, minutes, remainder)
  }
}
