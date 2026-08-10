import Foundation
import Network

/// Network.framework transport owned by the Packet Tunnel provider.
///
/// HushWire's UDP wire packets map one-to-one to datagrams. TCP adds the same
/// two-byte big-endian length prefix used by the Rust CLI transport.
final class HushWireNetworkTransport: @unchecked Sendable {
  typealias FrameHandler = @Sendable (Data, HushWireEndpoint) -> Void
  typealias EventHandler = @Sendable (String) -> Void

  private final class ConnectionState {
    let connection: NWConnection
    let endpoint: HushWireEndpoint
    var tcpReadBuffer = Data()

    init(connection: NWConnection, endpoint: HushWireEndpoint) {
      self.connection = connection
      self.endpoint = endpoint
    }
  }

  private let mode: HushWireTransportKind
  private let queue = DispatchQueue(label: "com.jamie.HushWire.PacketTunnel.transport")
  private let frameHandler: FrameHandler
  private let eventHandler: EventHandler
  private var connections: [HushWireEndpoint: ConnectionState] = [:]
  private var running = true

  init(
    mode: HushWireTransportKind,
    frameHandler: @escaping FrameHandler,
    eventHandler: @escaping EventHandler
  ) {
    self.mode = mode
    self.frameHandler = frameHandler
    self.eventHandler = eventHandler
  }

  func send(
    _ frame: Data,
    to endpoint: HushWireEndpoint,
    completion: @escaping @Sendable (Bool) -> Void
  ) {
    queue.async { [weak self] in
      guard let self, running else {
        completion(false)
        return
      }
      guard endpoint.family == 4 || endpoint.family == 6, endpoint.port != 0 else {
        eventHandler("拒绝无效的 Peer endpoint：\(endpoint.displayString)")
        completion(false)
        return
      }
      guard mode != .tcp || frame.count <= Int(UInt16.max) else {
        eventHandler("TCP 隧道帧超过 65535 字节，已丢弃。")
        completion(false)
        return
      }

      let state = connection(for: endpoint)
      let content = mode == .tcp ? Self.tcpFrame(frame) : frame
      state.connection.send(
        content: content,
        contentContext: .defaultMessage,
        isComplete: true,
        completion: .contentProcessed { [weak self, weak state] error in
          guard let self else {
            completion(false)
            return
          }
          self.queue.async {
            if let error {
              self.eventHandler("向 \(endpoint.displayString) 发送失败：\(error.localizedDescription)")
              if let state {
                self.remove(state)
              }
              completion(false)
            } else {
              completion(true)
            }
          }
        }
      )
    }
  }

  /// Cancel every UDP flow synchronously. The next send creates a new socket
  /// and therefore a new local/NAT port before the recovery handshake leaves.
  func rebindUDP() -> Bool {
    queue.sync {
      guard running, mode == .udp else { return false }
      let oldConnections = Array(connections.values)
      connections.removeAll()
      oldConnections.forEach { $0.connection.cancel() }
      eventHandler("UDP transport 已切换到新的本地流。")
      return true
    }
  }

  func stop() {
    queue.sync {
      guard running else { return }
      running = false
      let oldConnections = Array(connections.values)
      connections.removeAll()
      oldConnections.forEach { $0.connection.cancel() }
    }
  }

  private func connection(for endpoint: HushWireEndpoint) -> ConnectionState {
    if let existing = connections[endpoint] {
      return existing
    }

    let parameters: NWParameters = mode == .udp ? .udp : .tcp
    // A restarted tunnel must get a fresh local flow. Reusing the just-cancelled
    // five-tuple can leave the responder addressing its previous encrypted
    // session until the configured recovery timeout forces a UDP rebind.
    parameters.allowLocalEndpointReuse = false
    let connection = NWConnection(
      host: NWEndpoint.Host(endpoint.host),
      port: NWEndpoint.Port(rawValue: endpoint.port)!,
      using: parameters
    )
    let state = ConnectionState(connection: connection, endpoint: endpoint)
    connections[endpoint] = state

    connection.stateUpdateHandler = { [weak self, weak state] newState in
      guard let self, let state else { return }
      self.queue.async {
        switch newState {
        case .failed(let error):
          self.eventHandler(
            "到 \(state.endpoint.displayString) 的连接失败：\(error.localizedDescription)"
          )
          self.remove(state)
        case .waiting(let error):
          self.eventHandler(
            "到 \(state.endpoint.displayString) 的连接正在等待网络：\(error.localizedDescription)"
          )
        case .cancelled:
          self.remove(state)
        default:
          break
        }
      }
    }
    connection.start(queue: queue)
    receiveNext(on: state)
    return state
  }

  private func receiveNext(on state: ConnectionState) {
    guard running, connections[state.endpoint] === state else { return }
    if mode == .udp {
      state.connection.receiveMessage { [weak self, weak state] content, _, _, error in
        guard let self, let state else { return }
        self.queue.async {
          guard self.running, self.connections[state.endpoint] === state else { return }
          if let content, !content.isEmpty {
            self.frameHandler(content, state.endpoint)
          }
          if let error {
            self.eventHandler(
              "从 \(state.endpoint.displayString) 接收失败：\(error.localizedDescription)"
            )
            self.remove(state)
          } else {
            self.receiveNext(on: state)
          }
        }
      }
      return
    }

    state.connection.receive(
      minimumIncompleteLength: 1,
      maximumLength: 65_537
    ) { [weak self, weak state] content, _, isComplete, error in
      guard let self, let state else { return }
      self.queue.async {
        guard self.running, self.connections[state.endpoint] === state else { return }
        if let content, !content.isEmpty {
          state.tcpReadBuffer.append(content)
          self.deliverTCPFrames(from: state)
        }
        if let error {
          self.eventHandler(
            "从 \(state.endpoint.displayString) 接收失败：\(error.localizedDescription)"
          )
          self.remove(state)
        } else if isComplete {
          self.eventHandler("Peer \(state.endpoint.displayString) 已关闭 TCP 连接。")
          self.remove(state)
        } else {
          self.receiveNext(on: state)
        }
      }
    }
  }

  private func deliverTCPFrames(from state: ConnectionState) {
    while state.tcpReadBuffer.count >= 2 {
      let first = state.tcpReadBuffer.startIndex
      let second = state.tcpReadBuffer.index(after: first)
      let length = (Int(state.tcpReadBuffer[first]) << 8) | Int(state.tcpReadBuffer[second])
      guard state.tcpReadBuffer.count >= 2 + length else { return }
      let payloadStart = state.tcpReadBuffer.index(first, offsetBy: 2)
      let payloadEnd = state.tcpReadBuffer.index(payloadStart, offsetBy: length)
      frameHandler(Data(state.tcpReadBuffer[payloadStart..<payloadEnd]), state.endpoint)
      state.tcpReadBuffer.removeSubrange(first..<payloadEnd)
    }
  }

  private func remove(_ state: ConnectionState) {
    guard connections[state.endpoint] === state else { return }
    connections.removeValue(forKey: state.endpoint)
    state.connection.cancel()
  }

  private static func tcpFrame(_ frame: Data) -> Data {
    var length = UInt16(frame.count).bigEndian
    var output = Data(bytes: &length, count: MemoryLayout<UInt16>.size)
    output.append(frame)
    return output
  }
}
