import Foundation
import HushWireCore

private func sendTransport(
  _ context: UnsafeMutableRawPointer?,
  _ peerName: UnsafePointer<UInt8>?,
  _ peerNameLength: Int,
  _ endpoint: UnsafePointer<HWEndpoint>?,
  _ frame: UnsafePointer<UInt8>?,
  _ frameLength: Int
) -> UInt8 {
  1
}

private func writeIPPacket(
  _ context: UnsafeMutableRawPointer?,
  _ peerName: UnsafePointer<UInt8>?,
  _ peerNameLength: Int,
  _ source: UnsafePointer<HWEndpoint>?,
  _ packet: UnsafePointer<UInt8>?,
  _ packetLength: Int
) {}

let configuration = Data(
  """
  [interface]
  name = "utun-test"
  address = "10.77.99.1/30"
  listen = "0.0.0.0:0"
  transport = "udp"
  mtu = 1280
  private_key = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
  """.utf8
)

var callbacks = HWCallbacks(
  context: nil,
  send_transport: sendTransport,
  write_ip_packet: writeIPPacket,
  handshake_completed: nil
)
var error = HWError()
let runtime = configuration.withUnsafeBytes { bytes in
  hw_runtime_create(
    bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
    bytes.count,
    &callbacks,
    &error
  )
}

guard let runtime else {
  fatalError("HushWire runtime creation failed with status \(error.code)")
}
defer { hw_runtime_destroy(runtime) }

precondition(hw_core_abi_version() == HW_CORE_ABI_VERSION)
precondition(hw_runtime_start(runtime, &error) == HW_STATUS_OK)
precondition(hw_runtime_is_running(runtime) == 1)
precondition(hw_runtime_tick(runtime, nil, &error) == HW_STATUS_OK)

var interface = HWInterfaceConfig()
precondition(hw_runtime_get_interface_config(runtime, &interface, &error) == HW_STATUS_OK)
precondition(interface.prefix_length == 30)
precondition(interface.transport == 1)
precondition(interface.mtu == 1280)

precondition(hw_runtime_stop(runtime, &error) == HW_STATUS_OK)
precondition(hw_runtime_stop(runtime, &error) == HW_STATUS_OK)
precondition(hw_runtime_is_running(runtime) == 0)

print("HushWireCore Swift ABI smoke test passed")
