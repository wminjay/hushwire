#ifndef HUSHWIRE_CORE_H
#define HUSHWIRE_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HW_CORE_ABI_VERSION 3u
#define HW_ERROR_MESSAGE_CAPACITY 512u

typedef int32_t HWStatus;
enum {
  HW_STATUS_OK = 0,
  HW_STATUS_INVALID_ARGUMENT = 1,
  HW_STATUS_INVALID_STATE = 2,
  HW_STATUS_CONFIG_ERROR = 3,
  HW_STATUS_ENGINE_ERROR = 4,
  HW_STATUS_INTERNAL_ERROR = 5,
  HW_STATUS_PANIC = 6,
};

typedef struct HWRuntime HWRuntime;

typedef struct {
  int32_t code;
  char message[HW_ERROR_MESSAGE_CAPACITY];
} HWError;

typedef struct {
  uint8_t family; /* 4 for IPv4, 6 for IPv6. */
  uint8_t address[16];
  uint16_t port; /* Host byte order. */
  uint32_t scope_id;
} HWEndpoint;

typedef struct {
  uint8_t address[4];
  uint8_t prefix_length;
  uint8_t transport; /* 1 for UDP, 2 for TCP. */
  uint16_t mtu;
  HWEndpoint listen;
} HWInterfaceConfig;

typedef struct {
  uint8_t network[4];
  uint8_t prefix_length;
  uint8_t route_kind; /* 1 for included, 2 for direct-route exclusion. */
  uint8_t reserved[2];
  HWEndpoint endpoint;
  uint16_t persistent_keepalive;
  uint16_t udp_rebind_after;
  uint64_t session_timeout;
} HWRouteConfig;

typedef struct {
  uint64_t tx_bytes;
  uint64_t rx_bytes;
  uint64_t last_seen_milliseconds_ago;
  HWEndpoint endpoint;
  uint8_t has_last_seen;
  uint8_t has_endpoint;
  uint8_t reserved[6];
} HWPeerStats;

/*
 * Callback buffers are borrowed and remain valid only until the callback
 * returns. Copy anything needed by asynchronous Swift or C code.
 *
 * send_transport returns nonzero when the frame was accepted for sending; the
 * core then records its byte count immediately. Return zero for an asynchronous
 * transport and call hw_runtime_record_transport_sent after confirmed success.
 *
 * Do not call start, stop, or destroy synchronously from a callback. Stop waits
 * for every in-flight callback to return before erasing session state.
 */
typedef uint8_t (*HWSendTransportCallback)(
    void *context,
    const uint8_t *peer_name,
    size_t peer_name_length,
    const HWEndpoint *endpoint,
    const uint8_t *frame,
    size_t frame_length);

typedef void (*HWWriteIPPacketCallback)(
    void *context,
    const uint8_t *peer_name,
    size_t peer_name_length,
    const HWEndpoint *source,
    const uint8_t *packet,
    size_t packet_length);

typedef void (*HWHandshakeCallback)(
    void *context,
    const uint8_t *peer_name,
    size_t peer_name_length,
    const HWEndpoint *endpoint,
    uint8_t role /* 1 for initiator, 2 for responder. */);

typedef void (*HWRouteCallback)(
    void *context,
    const uint8_t *peer_name,
    size_t peer_name_length,
    const uint8_t *configured_endpoint,
    size_t configured_endpoint_length,
    const HWRouteConfig *route);

typedef void (*HWPeerStatsCallback)(
    void *context,
    const uint8_t *peer_name,
    size_t peer_name_length,
    const HWPeerStats *stats);

/*
 * Synchronously switch the adapter's shared UDP transport to a fresh local
 * port. Return nonzero only after the new transport can accept sends.
 */
typedef uint8_t (*HWRebindTransportCallback)(
    void *context,
    const uint8_t *peer_name,
    size_t peer_name_length,
    uint64_t silence_milliseconds);

typedef struct {
  void *context;
  HWSendTransportCallback send_transport; /* Required. */
  HWWriteIPPacketCallback write_ip_packet; /* Required. */
  HWHandshakeCallback handshake_completed; /* Optional. */
} HWCallbacks;

uint32_t hw_core_abi_version(void);
const char *hw_core_version_string(void);

HWRuntime *hw_runtime_create(
    const uint8_t *config_toml,
    size_t config_length,
    const HWCallbacks *callbacks,
    HWError *error);

void hw_runtime_destroy(HWRuntime *runtime);

HWStatus hw_runtime_start(HWRuntime *runtime, HWError *error);
HWStatus hw_runtime_stop(HWRuntime *runtime, HWError *error);
uint8_t hw_runtime_is_running(const HWRuntime *runtime);

HWStatus hw_runtime_submit_outbound_ip(
    HWRuntime *runtime,
    const uint8_t *packet,
    size_t packet_length,
    HWError *error);

HWStatus hw_runtime_submit_inbound_transport(
    HWRuntime *runtime,
    const uint8_t *frame,
    size_t frame_length,
    const HWEndpoint *source,
    HWError *error);

HWStatus hw_runtime_initiate_handshake(
    HWRuntime *runtime,
    const uint8_t *peer_name,
    size_t peer_name_length,
    HWError *error);

/* Call once per second to share CLI-equivalent maintenance/recovery policy. */
HWStatus hw_runtime_tick(
    HWRuntime *runtime,
    HWRebindTransportCallback rebind_transport,
    HWError *error);

HWStatus hw_runtime_create_keepalive(
    HWRuntime *runtime,
    const uint8_t *peer_name,
    size_t peer_name_length,
    const uint8_t *payload,
    size_t payload_length,
    HWError *error);

HWStatus hw_runtime_invalidate_peer(
    HWRuntime *runtime,
    const uint8_t *peer_name,
    size_t peer_name_length,
    uint8_t *invalidated,
    HWError *error);

HWStatus hw_runtime_resolve_peer_endpoint(
    HWRuntime *runtime,
    const uint8_t *peer_name,
    size_t peer_name_length,
    HWEndpoint *output,
    HWError *error);

HWStatus hw_runtime_update_peer_endpoint(
    HWRuntime *runtime,
    const uint8_t *peer_name,
    size_t peer_name_length,
    const HWEndpoint *endpoint,
    uint8_t *changed,
    HWError *error);

HWStatus hw_runtime_record_transport_sent(
    HWRuntime *runtime,
    const uint8_t *peer_name,
    size_t peer_name_length,
    size_t byte_count,
    HWError *error);

HWStatus hw_runtime_get_interface_config(
    const HWRuntime *runtime,
    HWInterfaceConfig *output,
    HWError *error);

HWStatus hw_runtime_visit_routes(
    const HWRuntime *runtime,
    void *context,
    HWRouteCallback callback,
    HWError *error);

HWStatus hw_runtime_visit_peer_stats(
    HWRuntime *runtime,
    void *context,
    HWPeerStatsCallback callback,
    HWError *error);

#ifdef __cplusplus
}
#endif

#endif /* HUSHWIRE_CORE_H */
