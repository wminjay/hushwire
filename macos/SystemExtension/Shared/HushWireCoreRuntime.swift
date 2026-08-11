import Foundation
import HushWireCore
import Network

enum HushWireCoreError: LocalizedError {
  case abiMismatch(expected: UInt32, actual: UInt32)
  case operation(String)

  var errorDescription: String? {
    switch self {
    case .abiMismatch(let expected, let actual):
      return "HushWireCore ABI 不匹配（需要 \(expected)，实际 \(actual)）。"
    case .operation(let message):
      return message
    }
  }
}

enum HushWireTransportKind: UInt8, Sendable {
  case udp = 1
  case tcp = 2

  var title: String {
    switch self {
    case .udp: "UDP"
    case .tcp: "TCP"
    }
  }
}

enum HushWireRouteKind: UInt8, Sendable {
  case included = 1
  case excluded = 2
}

struct HushWireEndpoint: Hashable, Sendable {
  let family: UInt8
  let addressBytes: [UInt8]
  let port: UInt16
  let scopeID: UInt32

  var host: String {
    switch family {
    case 4:
      return addressBytes.prefix(4).map(String.init).joined(separator: ".")
    case 6:
      return IPv6Address(Data(addressBytes.prefix(16)))?.debugDescription ?? "::"
    default:
      return ""
    }
  }

  var displayString: String {
    family == 6 ? "[\(host)]:\(port)" : "\(host):\(port)"
  }

  fileprivate init(_ endpoint: HWEndpoint) {
    family = endpoint.family
    addressBytes = withUnsafeBytes(of: endpoint.address) { Array($0) }
    port = endpoint.port
    scopeID = endpoint.scope_id
  }
}

struct HushWireInterfaceMetadata: Sendable {
  let addressBytes: [UInt8]
  let prefixLength: UInt8
  let transport: HushWireTransportKind
  let mtu: UInt16
  let listen: HushWireEndpoint

  var address: String {
    addressBytes.prefix(4).map(String.init).joined(separator: ".")
  }

  var cidr: String { "\(address)/\(prefixLength)" }
}

struct HushWireRouteMetadata: Sendable {
  let peerName: String
  let networkBytes: [UInt8]
  let prefixLength: UInt8
  let routeKind: HushWireRouteKind
  let configuredEndpoint: String
  let endpoint: HushWireEndpoint
  let persistentKeepalive: UInt16
  let udpRebindAfter: UInt16
  let sessionTimeout: UInt64

  var network: String {
    networkBytes.prefix(4).map(String.init).joined(separator: ".")
  }

  var cidr: String { "\(network)/\(prefixLength)" }

  var endpointDescription: String {
    configuredEndpoint == endpoint.displayString
      ? endpoint.displayString
      : "\(configuredEndpoint) → \(endpoint.displayString)"
  }
}

struct HushWirePeerStatistics: Sendable {
  let peerName: String
  let txBytes: UInt64
  let rxBytes: UInt64
  let lastSeenMillisecondsAgo: UInt64?
  let endpoint: HushWireEndpoint?
}

protocol HushWireCoreRuntimeDelegate: AnyObject {
  func coreRuntime(
    _ runtime: HushWireCoreRuntime,
    sendTransport frame: Data,
    to endpoint: HushWireEndpoint,
    peerName: String
  )
  func coreRuntime(
    _ runtime: HushWireCoreRuntime,
    writeIPPacket packet: Data,
    from endpoint: HushWireEndpoint,
    peerName: String
  )
  func coreRuntime(
    _ runtime: HushWireCoreRuntime,
    handshakeCompletedFor peerName: String,
    endpoint: HushWireEndpoint,
    role: UInt8
  )
  func coreRuntimeRebindUDP(
    _ runtime: HushWireCoreRuntime,
    peerName: String,
    silenceMilliseconds: UInt64
  ) -> Bool
}

extension HushWireCoreRuntimeDelegate {
  func coreRuntime(
    _ runtime: HushWireCoreRuntime,
    handshakeCompletedFor peerName: String,
    endpoint: HushWireEndpoint,
    role: UInt8
  ) {}

  func coreRuntimeRebindUDP(
    _ runtime: HushWireCoreRuntime,
    peerName: String,
    silenceMilliseconds: UInt64
  ) -> Bool { false }
}

final class HushWireCoreRuntime {
  weak var delegate: HushWireCoreRuntimeDelegate?

  private var handle: OpaquePointer?

  init(configuration: Data) throws {
    let actualABI = hw_core_abi_version()
    guard actualABI == HW_CORE_ABI_VERSION else {
      throw HushWireCoreError.abiMismatch(expected: HW_CORE_ABI_VERSION, actual: actualABI)
    }

    var callbacks = HWCallbacks(
      context: Unmanaged.passUnretained(self).toOpaque(),
      send_transport: hushWireSendTransport,
      write_ip_packet: hushWireWriteIPPacket,
      handshake_completed: hushWireHandshakeCompleted
    )
    var error = HWError()
    handle = configuration.withUnsafeBytes { bytes in
      hw_runtime_create(
        bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
        bytes.count,
        &callbacks,
        &error
      )
    }
    guard handle != nil else {
      throw HushWireCoreError.operation(Self.message(from: &error))
    }
  }

  deinit {
    if let handle {
      var error = HWError()
      _ = hw_runtime_stop(handle, &error)
      hw_runtime_destroy(handle)
    }
  }

  var coreVersion: String {
    String(cString: hw_core_version_string())
  }

  func start() throws {
    try call("启动 Rust Core") { handle, error in
      hw_runtime_start(handle, error)
    }
  }

  func stop() throws {
    try call("停止 Rust Core") { handle, error in
      hw_runtime_stop(handle, error)
    }
  }

  func tick() throws {
    try call("执行会话维护") { handle, error in
      hw_runtime_tick(handle, hushWireRebindUDP, error)
    }
  }

  func initiateHandshake(peerName: String) throws {
    try withPeerName(peerName, operation: "发起握手") { handle, bytes, error in
      hw_runtime_initiate_handshake(handle, bytes.baseAddress, bytes.count, error)
    }
  }

  func submitOutboundIP(_ packet: Data) throws {
    try call("提交出站 IP 包") { handle, error in
      packet.withUnsafeBytes { bytes in
        hw_runtime_submit_outbound_ip(
          handle,
          bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
          bytes.count,
          error
        )
      }
    }
  }

  func submitInboundTransport(_ frame: Data, source: HushWireEndpoint) throws {
    var endpoint = source.ffiValue
    try call("提交入站隧道帧") { handle, error in
      frame.withUnsafeBytes { bytes in
        hw_runtime_submit_inbound_transport(
          handle,
          bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
          bytes.count,
          &endpoint,
          error
        )
      }
    }
  }

  func recordTransportSent(peerName: String, byteCount: Int) throws {
    try withPeerName(peerName, operation: "记录隧道发送") { handle, bytes, error in
      hw_runtime_record_transport_sent(
        handle,
        bytes.baseAddress,
        bytes.count,
        byteCount,
        error
      )
    }
  }

  func interfaceMetadata() throws -> HushWireInterfaceMetadata {
    guard let handle else { throw HushWireCoreError.operation("Rust Core 已释放。") }
    var value = HWInterfaceConfig()
    var error = HWError()
    let status = hw_runtime_get_interface_config(handle, &value, &error)
    try Self.check(status, error: &error, operation: "读取接口配置")
    guard let transport = HushWireTransportKind(rawValue: value.transport) else {
      throw HushWireCoreError.operation("配置包含未知传输类型 \(value.transport)。")
    }
    return HushWireInterfaceMetadata(
      addressBytes: withUnsafeBytes(of: value.address) { Array($0) },
      prefixLength: value.prefix_length,
      transport: transport,
      mtu: value.mtu,
      listen: HushWireEndpoint(value.listen)
    )
  }

  func routes() throws -> [HushWireRouteMetadata] {
    guard let handle else { throw HushWireCoreError.operation("Rust Core 已释放。") }
    let collector = HushWireRouteCollector()
    var error = HWError()
    let status = hw_runtime_visit_routes(
      handle,
      Unmanaged.passUnretained(collector).toOpaque(),
      hushWireVisitRoute,
      &error
    )
    try Self.check(status, error: &error, operation: "读取路由配置")
    if let invalidRouteKind = collector.invalidRouteKind {
      throw HushWireCoreError.operation("Core 返回未知路由类型 \(invalidRouteKind)。")
    }
    return collector.routes
  }

  func peerStatistics() throws -> [HushWirePeerStatistics] {
    guard let handle else { throw HushWireCoreError.operation("Rust Core 已释放。") }
    let collector = HushWireStatsCollector()
    var error = HWError()
    let status = hw_runtime_visit_peer_stats(
      handle,
      Unmanaged.passUnretained(collector).toOpaque(),
      hushWireVisitPeerStats,
      &error
    )
    try Self.check(status, error: &error, operation: "读取 Peer 状态")
    return collector.statistics
  }

  private func call(
    _ operation: String,
    _ body: (OpaquePointer, UnsafeMutablePointer<HWError>) -> HWStatus
  ) throws {
    guard let handle else { throw HushWireCoreError.operation("Rust Core 已释放。") }
    var error = HWError()
    let status = body(handle, &error)
    try Self.check(status, error: &error, operation: operation)
  }

  private func withPeerName(
    _ peerName: String,
    operation: String,
    _ body: (
      OpaquePointer,
      UnsafeBufferPointer<UInt8>,
      UnsafeMutablePointer<HWError>
    ) -> HWStatus
  ) throws {
    let data = Data(peerName.utf8)
    try call(operation) { handle, error in
      data.withUnsafeBytes { rawBytes in
        let bytes = rawBytes.bindMemory(to: UInt8.self)
        return body(handle, bytes, error)
      }
    }
  }

  private static func check(
    _ status: HWStatus,
    error: inout HWError,
    operation: String
  ) throws {
    guard status == HW_STATUS_OK else {
      let detail = message(from: &error)
      throw HushWireCoreError.operation("\(operation)失败：\(detail)")
    }
  }

  private static func message(from error: inout HWError) -> String {
    withUnsafePointer(to: &error.message) { pointer in
      pointer.withMemoryRebound(to: CChar.self, capacity: Int(HW_ERROR_MESSAGE_CAPACITY)) {
        String(cString: $0)
      }
    }
  }
}

private final class HushWireRouteCollector {
  var routes: [HushWireRouteMetadata] = []
  var invalidRouteKind: UInt8?
}

private final class HushWireStatsCollector {
  var statistics: [HushWirePeerStatistics] = []
}

private func copiedString(_ pointer: UnsafePointer<UInt8>?, length: Int) -> String {
  guard let pointer, length > 0 else { return "" }
  return String(decoding: UnsafeBufferPointer(start: pointer, count: length), as: UTF8.self)
}

private func hushWireSendTransport(
  _ context: UnsafeMutableRawPointer?,
  _ peerName: UnsafePointer<UInt8>?,
  _ peerNameLength: Int,
  _ endpoint: UnsafePointer<HWEndpoint>?,
  _ frame: UnsafePointer<UInt8>?,
  _ frameLength: Int
) -> UInt8 {
  guard let context, let endpoint, let frame, frameLength > 0 else { return 0 }
  let runtime = Unmanaged<HushWireCoreRuntime>.fromOpaque(context).takeUnretainedValue()
  runtime.delegate?.coreRuntime(
    runtime,
    sendTransport: Data(bytes: frame, count: frameLength),
    to: HushWireEndpoint(endpoint.pointee),
    peerName: copiedString(peerName, length: peerNameLength)
  )
  return 0
}

private func hushWireWriteIPPacket(
  _ context: UnsafeMutableRawPointer?,
  _ peerName: UnsafePointer<UInt8>?,
  _ peerNameLength: Int,
  _ source: UnsafePointer<HWEndpoint>?,
  _ packet: UnsafePointer<UInt8>?,
  _ packetLength: Int
) {
  guard let context, let source, let packet, packetLength > 0 else { return }
  let runtime = Unmanaged<HushWireCoreRuntime>.fromOpaque(context).takeUnretainedValue()
  runtime.delegate?.coreRuntime(
    runtime,
    writeIPPacket: Data(bytes: packet, count: packetLength),
    from: HushWireEndpoint(source.pointee),
    peerName: copiedString(peerName, length: peerNameLength)
  )
}

private func hushWireHandshakeCompleted(
  _ context: UnsafeMutableRawPointer?,
  _ peerName: UnsafePointer<UInt8>?,
  _ peerNameLength: Int,
  _ endpoint: UnsafePointer<HWEndpoint>?,
  _ role: UInt8
) {
  guard let context, let endpoint else { return }
  let runtime = Unmanaged<HushWireCoreRuntime>.fromOpaque(context).takeUnretainedValue()
  runtime.delegate?.coreRuntime(
    runtime,
    handshakeCompletedFor: copiedString(peerName, length: peerNameLength),
    endpoint: HushWireEndpoint(endpoint.pointee),
    role: role
  )
}

private func hushWireRebindUDP(
  _ context: UnsafeMutableRawPointer?,
  _ peerName: UnsafePointer<UInt8>?,
  _ peerNameLength: Int,
  _ silenceMilliseconds: UInt64
) -> UInt8 {
  guard let context else { return 0 }
  let runtime = Unmanaged<HushWireCoreRuntime>.fromOpaque(context).takeUnretainedValue()
  return runtime.delegate?.coreRuntimeRebindUDP(
    runtime,
    peerName: copiedString(peerName, length: peerNameLength),
    silenceMilliseconds: silenceMilliseconds
  ) == true ? 1 : 0
}

private func hushWireVisitRoute(
  _ context: UnsafeMutableRawPointer?,
  _ peerName: UnsafePointer<UInt8>?,
  _ peerNameLength: Int,
  _ configuredEndpoint: UnsafePointer<UInt8>?,
  _ configuredEndpointLength: Int,
  _ route: UnsafePointer<HWRouteConfig>?
) {
  guard let context, let route else { return }
  let collector = Unmanaged<HushWireRouteCollector>.fromOpaque(context).takeUnretainedValue()
  let value = route.pointee
  guard let routeKind = HushWireRouteKind(rawValue: value.route_kind) else {
    collector.invalidRouteKind = value.route_kind
    return
  }
  collector.routes.append(
    HushWireRouteMetadata(
      peerName: copiedString(peerName, length: peerNameLength),
      networkBytes: withUnsafeBytes(of: value.network) { Array($0) },
      prefixLength: value.prefix_length,
      routeKind: routeKind,
      configuredEndpoint: copiedString(
        configuredEndpoint,
        length: configuredEndpointLength
      ),
      endpoint: HushWireEndpoint(value.endpoint),
      persistentKeepalive: value.persistent_keepalive,
      udpRebindAfter: value.udp_rebind_after,
      sessionTimeout: value.session_timeout
    )
  )
}

private func hushWireVisitPeerStats(
  _ context: UnsafeMutableRawPointer?,
  _ peerName: UnsafePointer<UInt8>?,
  _ peerNameLength: Int,
  _ stats: UnsafePointer<HWPeerStats>?
) {
  guard let context, let stats else { return }
  let collector = Unmanaged<HushWireStatsCollector>.fromOpaque(context).takeUnretainedValue()
  let value = stats.pointee
  collector.statistics.append(
    HushWirePeerStatistics(
      peerName: copiedString(peerName, length: peerNameLength),
      txBytes: value.tx_bytes,
      rxBytes: value.rx_bytes,
      lastSeenMillisecondsAgo: value.has_last_seen == 0
        ? nil
        : value.last_seen_milliseconds_ago,
      endpoint: value.has_endpoint == 0 ? nil : HushWireEndpoint(value.endpoint)
    )
  )
}

private extension HushWireEndpoint {
  var ffiValue: HWEndpoint {
    var value = HWEndpoint()
    value.family = family
    value.port = port
    value.scope_id = scopeID
    withUnsafeMutableBytes(of: &value.address) { destination in
      destination.copyBytes(from: addressBytes.prefix(destination.count))
    }
    return value
  }
}
