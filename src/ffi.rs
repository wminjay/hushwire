//! Stable C ABI for embedding the platform-independent packet engine.
//!
//! The ABI is deliberately synchronous: the platform owns transport sockets,
//! packet-flow scheduling, routes, and DNS. Buffers passed to callbacks are
//! borrowed only for the duration of that callback. No Rust allocation ever
//! has to be released by Swift or C.

use std::ffi::{c_char, c_void};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;
use std::str;
use std::sync::{Condvar, Mutex};
use std::time::Instant;

use crate::config::{Config, TransportConfig};
use crate::engine::{Engine, EngineAction, EngineEvent, EngineOutput, HandshakeRole};
use crate::router::Router;
use crate::scheduler::EngineScheduler;

pub const HW_CORE_ABI_VERSION: u32 = 2;
const ERROR_MESSAGE_CAPACITY: usize = 512;

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HwStatus {
    Ok = 0,
    InvalidArgument = 1,
    InvalidState = 2,
    ConfigError = 3,
    EngineError = 4,
    InternalError = 5,
    Panic = 6,
}

#[repr(C)]
pub struct HwError {
    pub code: i32,
    pub message: [c_char; ERROR_MESSAGE_CAPACITY],
}

impl Default for HwError {
    fn default() -> Self {
        Self {
            code: HwStatus::Ok as i32,
            message: [0; ERROR_MESSAGE_CAPACITY],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HwEndpoint {
    /// `4` for IPv4 and `6` for IPv6.
    pub family: u8,
    pub address: [u8; 16],
    /// Host-byte-order port.
    pub port: u16,
    /// IPv6 scope identifier; zero for IPv4 and unscoped IPv6.
    pub scope_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HwInterfaceConfig {
    pub address: [u8; 4],
    pub prefix_length: u8,
    /// `1` for UDP and `2` for TCP.
    pub transport: u8,
    pub mtu: u16,
    pub listen: HwEndpoint,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HwRouteConfig {
    pub network: [u8; 4],
    pub prefix_length: u8,
    /// `1` for an included tunnel route and `2` for a direct-route exclusion.
    pub route_kind: u8,
    pub reserved: [u8; 2],
    pub endpoint: HwEndpoint,
    pub persistent_keepalive: u16,
    pub udp_rebind_after: u16,
    pub session_timeout: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HwPeerStats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_seen_milliseconds_ago: u64,
    pub endpoint: HwEndpoint,
    pub has_last_seen: u8,
    pub has_endpoint: u8,
    pub reserved: [u8; 6],
}

pub type HwSendTransportCallback = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        peer_name: *const u8,
        peer_name_length: usize,
        endpoint: *const HwEndpoint,
        frame: *const u8,
        frame_length: usize,
    ) -> u8,
>;

pub type HwWriteIpPacketCallback = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        peer_name: *const u8,
        peer_name_length: usize,
        source: *const HwEndpoint,
        packet: *const u8,
        packet_length: usize,
    ),
>;

pub type HwHandshakeCallback = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        peer_name: *const u8,
        peer_name_length: usize,
        endpoint: *const HwEndpoint,
        // `1` for initiator and `2` for responder.
        role: u8,
    ),
>;

pub type HwRouteCallback = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        peer_name: *const u8,
        peer_name_length: usize,
        configured_endpoint: *const u8,
        configured_endpoint_length: usize,
        route: *const HwRouteConfig,
    ),
>;

pub type HwPeerStatsCallback = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        peer_name: *const u8,
        peer_name_length: usize,
        stats: *const HwPeerStats,
    ),
>;

/// Synchronously switch the platform adapter's shared UDP transport to a new
/// local port. Returns nonzero after the fresh transport is ready for sends.
pub type HwRebindTransportCallback = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        peer_name: *const u8,
        peer_name_length: usize,
        silence_milliseconds: u64,
    ) -> u8,
>;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HwCallbacks {
    pub context: *mut c_void,
    pub send_transport: HwSendTransportCallback,
    pub write_ip_packet: HwWriteIpPacketCallback,
    pub handshake_completed: HwHandshakeCallback,
}

#[derive(Clone, Copy)]
struct RuntimeCallbacks {
    context: usize,
    send_transport: unsafe extern "C" fn(
        *mut c_void,
        *const u8,
        usize,
        *const HwEndpoint,
        *const u8,
        usize,
    ) -> u8,
    write_ip_packet:
        unsafe extern "C" fn(*mut c_void, *const u8, usize, *const HwEndpoint, *const u8, usize),
    handshake_completed: HwHandshakeCallback,
}

struct Lifecycle {
    engine: Option<Engine>,
    active_calls: usize,
    stopping: bool,
}

/// Opaque runtime handle exposed to C.
pub struct HwRuntime {
    config: Config,
    router: Router,
    callbacks: RuntimeCallbacks,
    lifecycle: Mutex<Lifecycle>,
    scheduler: Mutex<Option<EngineScheduler>>,
    idle: Condvar,
}

struct RuntimeCall<'a> {
    runtime: &'a HwRuntime,
    engine: Engine,
}

impl Drop for RuntimeCall<'_> {
    fn drop(&mut self) {
        if let Ok(mut lifecycle) = self.runtime.lifecycle.lock() {
            lifecycle.active_calls = lifecycle.active_calls.saturating_sub(1);
            if lifecycle.active_calls == 0 {
                self.runtime.idle.notify_all();
            }
        }
    }
}

#[derive(Debug)]
struct FfiFailure {
    status: HwStatus,
    message: String,
}

impl FfiFailure {
    fn new(status: HwStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl HwRuntime {
    fn begin_call(&self) -> Result<RuntimeCall<'_>, FfiFailure> {
        let mut lifecycle = self.lifecycle.lock().map_err(|_| {
            FfiFailure::new(
                HwStatus::InternalError,
                "runtime lifecycle lock is poisoned",
            )
        })?;
        let engine = lifecycle
            .engine
            .as_ref()
            .filter(|_| !lifecycle.stopping)
            .cloned()
            .ok_or_else(|| FfiFailure::new(HwStatus::InvalidState, "runtime is not running"))?;
        lifecycle.active_calls += 1;
        Ok(RuntimeCall {
            runtime: self,
            engine,
        })
    }

    fn dispatch(&self, engine: &Engine, output: EngineOutput) {
        let context = self.callbacks.context as *mut c_void;

        for event in output.events {
            let Some(callback) = self.callbacks.handshake_completed else {
                continue;
            };
            let EngineEvent::HandshakeCompleted {
                peer_name,
                endpoint,
                role,
            } = event;
            let endpoint = endpoint_to_ffi(endpoint);
            let role = match role {
                HandshakeRole::Initiator => 1,
                HandshakeRole::Responder => 2,
            };
            unsafe {
                callback(
                    context,
                    peer_name.as_ptr(),
                    peer_name.len(),
                    &endpoint,
                    role,
                );
            }
        }

        for action in output.actions {
            match action {
                EngineAction::SendTransport {
                    peer_name,
                    endpoint,
                    frame,
                } => {
                    let endpoint = endpoint_to_ffi(endpoint);
                    let accepted = unsafe {
                        (self.callbacks.send_transport)(
                            context,
                            peer_name.as_ptr(),
                            peer_name.len(),
                            &endpoint,
                            frame.as_ptr(),
                            frame.len(),
                        )
                    };
                    if accepted != 0 {
                        engine.record_transport_sent(&peer_name, frame.len());
                    }
                }
                EngineAction::WriteIpPacket {
                    peer_name,
                    source,
                    packet,
                } => {
                    let source = endpoint_to_ffi(source);
                    unsafe {
                        (self.callbacks.write_ip_packet)(
                            context,
                            peer_name.as_ptr(),
                            peer_name.len(),
                            &source,
                            packet.as_ptr(),
                            packet.len(),
                        );
                    }
                }
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn hw_core_abi_version() -> u32 {
    HW_CORE_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn hw_core_version_string() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Create a stopped runtime from UTF-8 TOML.
///
/// # Safety
/// `config_toml` must reference `config_length` readable bytes when nonzero.
/// `callbacks` and `error` must reference writable/readable values as required
/// by their types for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn hw_runtime_create(
    config_toml: *const u8,
    config_length: usize,
    callbacks: *const HwCallbacks,
    error: *mut HwError,
) -> *mut HwRuntime {
    clear_error(error);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let bytes = borrowed_bytes(config_toml, config_length, "config_toml")?;
        let text = str::from_utf8(bytes).map_err(|_| {
            FfiFailure::new(HwStatus::ConfigError, "configuration is not valid UTF-8")
        })?;
        let config = Config::parse(text)
            .map_err(|cause| FfiFailure::new(HwStatus::ConfigError, cause.to_string()))?;
        let router = Router::new(&config)
            .map_err(|cause| FfiFailure::new(HwStatus::ConfigError, cause.to_string()))?;
        Engine::with_router(&config, router.clone())
            .map_err(|cause| FfiFailure::new(HwStatus::ConfigError, cause.to_string()))?;

        let callbacks = callbacks.as_ref().ok_or_else(|| {
            FfiFailure::new(HwStatus::InvalidArgument, "callbacks must not be null")
        })?;
        let send_transport = callbacks.send_transport.ok_or_else(|| {
            FfiFailure::new(
                HwStatus::InvalidArgument,
                "send_transport callback must not be null",
            )
        })?;
        let write_ip_packet = callbacks.write_ip_packet.ok_or_else(|| {
            FfiFailure::new(
                HwStatus::InvalidArgument,
                "write_ip_packet callback must not be null",
            )
        })?;

        Ok::<_, FfiFailure>(Box::into_raw(Box::new(HwRuntime {
            config,
            router,
            callbacks: RuntimeCallbacks {
                context: callbacks.context as usize,
                send_transport,
                write_ip_packet,
                handshake_completed: callbacks.handshake_completed,
            },
            lifecycle: Mutex::new(Lifecycle {
                engine: None,
                active_calls: 0,
                stopping: false,
            }),
            scheduler: Mutex::new(None),
            idle: Condvar::new(),
        })))
    }));

    match result {
        Ok(Ok(runtime)) => runtime,
        Ok(Err(failure)) => {
            write_error(error, &failure);
            std::ptr::null_mut()
        }
        Err(_) => {
            write_error(
                error,
                &FfiFailure::new(HwStatus::Panic, "Rust core panicked while creating runtime"),
            );
            std::ptr::null_mut()
        }
    }
}

/// Destroy a runtime after all callers have stopped using its pointer.
///
/// # Safety
/// `runtime` must be null or a pointer returned by `hw_runtime_create` that has
/// not already been destroyed. No concurrent call may use it.
#[no_mangle]
pub unsafe extern "C" fn hw_runtime_destroy(runtime: *mut HwRuntime) {
    if runtime.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(Box::from_raw(runtime));
    }));
}

/// # Safety
/// `runtime` and `error` must be null or valid pointers of their declared type.
#[no_mangle]
pub unsafe extern "C" fn hw_runtime_start(
    runtime: *mut HwRuntime,
    error: *mut HwError,
) -> HwStatus {
    guarded_status(error, || {
        let runtime = runtime_ref(runtime)?;
        let mut lifecycle = runtime.lifecycle.lock().map_err(|_| {
            FfiFailure::new(
                HwStatus::InternalError,
                "runtime lifecycle lock is poisoned",
            )
        })?;
        if lifecycle.stopping {
            return Err(FfiFailure::new(
                HwStatus::InvalidState,
                "runtime is currently stopping",
            ));
        }
        if lifecycle.engine.is_none() {
            lifecycle.engine = Some(
                Engine::with_router(&runtime.config, runtime.router.clone())
                    .map_err(|cause| FfiFailure::new(HwStatus::EngineError, cause.to_string()))?,
            );
            *runtime.scheduler.lock().map_err(|_| {
                FfiFailure::new(
                    HwStatus::InternalError,
                    "runtime scheduler lock is poisoned",
                )
            })? = Some(EngineScheduler::new(&runtime.config));
        }
        Ok(())
    })
}

/// Stop accepting packets, wait for in-flight callbacks, and erase sessions.
///
/// Lifecycle functions must not be called synchronously from a runtime
/// callback because stop intentionally waits for that callback to return.
///
/// # Safety
/// `runtime` and `error` must be null or valid pointers of their declared type.
#[no_mangle]
pub unsafe extern "C" fn hw_runtime_stop(runtime: *mut HwRuntime, error: *mut HwError) -> HwStatus {
    guarded_status(error, || {
        let runtime = runtime_ref(runtime)?;
        let mut lifecycle = runtime.lifecycle.lock().map_err(|_| {
            FfiFailure::new(
                HwStatus::InternalError,
                "runtime lifecycle lock is poisoned",
            )
        })?;
        if lifecycle.engine.is_none() {
            return Ok(());
        }
        lifecycle.stopping = true;
        while lifecycle.active_calls != 0 {
            lifecycle = runtime.idle.wait(lifecycle).map_err(|_| {
                FfiFailure::new(
                    HwStatus::InternalError,
                    "runtime lifecycle lock is poisoned",
                )
            })?;
        }
        lifecycle.engine = None;
        *runtime.scheduler.lock().map_err(|_| {
            FfiFailure::new(
                HwStatus::InternalError,
                "runtime scheduler lock is poisoned",
            )
        })? = None;
        lifecycle.stopping = false;
        runtime.idle.notify_all();
        Ok(())
    })
}

/// # Safety
/// `runtime` must be null or a live runtime pointer.
#[no_mangle]
pub unsafe extern "C" fn hw_runtime_is_running(runtime: *const HwRuntime) -> u8 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(runtime) = runtime.as_ref() else {
            return false;
        };
        runtime
            .lifecycle
            .lock()
            .map(|lifecycle| lifecycle.engine.is_some() && !lifecycle.stopping)
            .unwrap_or(false)
    }));
    u8::from(result.unwrap_or(false))
}

/// # Safety
/// Packet and error pointers must be valid for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn hw_runtime_submit_outbound_ip(
    runtime: *mut HwRuntime,
    packet: *const u8,
    packet_length: usize,
    error: *mut HwError,
) -> HwStatus {
    guarded_status(error, || {
        let runtime = runtime_ref(runtime)?;
        let packet = borrowed_bytes(packet, packet_length, "packet")?;
        let call = runtime.begin_call()?;
        let output = call
            .engine
            .process_outbound_ip(packet, Instant::now())
            .map_err(|cause| FfiFailure::new(HwStatus::EngineError, cause.to_string()))?;
        runtime.dispatch(&call.engine, output);
        Ok(())
    })
}

/// # Safety
/// Frame, endpoint, runtime, and error pointers must be valid for this call.
#[no_mangle]
pub unsafe extern "C" fn hw_runtime_submit_inbound_transport(
    runtime: *mut HwRuntime,
    frame: *const u8,
    frame_length: usize,
    source: *const HwEndpoint,
    error: *mut HwError,
) -> HwStatus {
    guarded_status(error, || {
        let runtime = runtime_ref(runtime)?;
        let frame = borrowed_bytes(frame, frame_length, "frame")?;
        let source = source
            .as_ref()
            .ok_or_else(|| FfiFailure::new(HwStatus::InvalidArgument, "source must not be null"))?;
        let source = endpoint_from_ffi(source)?;
        let call = runtime.begin_call()?;
        let output = call
            .engine
            .process_inbound_transport(frame, source, Instant::now())
            .map_err(|cause| FfiFailure::new(HwStatus::EngineError, cause.to_string()))?;
        runtime.dispatch(&call.engine, output);
        Ok(())
    })
}

/// # Safety
/// Peer-name and error pointers must be valid for this call.
#[no_mangle]
pub unsafe extern "C" fn hw_runtime_initiate_handshake(
    runtime: *mut HwRuntime,
    peer_name: *const u8,
    peer_name_length: usize,
    error: *mut HwError,
) -> HwStatus {
    guarded_status(error, || {
        let runtime = runtime_ref(runtime)?;
        let peer_name = borrowed_string(peer_name, peer_name_length, "peer_name")?;
        let call = runtime.begin_call()?;
        let output = call
            .engine
            .initiate_handshake(peer_name, Instant::now())
            .map_err(|cause| FfiFailure::new(HwStatus::EngineError, cause.to_string()))?;
        runtime.dispatch(&call.engine, output);
        Ok(())
    })
}

/// Run one shared handshake/keepalive/recovery scheduling tick.
///
/// Platform adapters normally call this once per second. If UDP liveness
/// recovery is configured, `rebind_transport` is invoked synchronously before
/// replacement handshake frames are dispatched through `send_transport`.
///
/// # Safety
/// Runtime, callback, callback context, and error pointers must remain valid
/// for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn hw_runtime_tick(
    runtime: *mut HwRuntime,
    rebind_transport: HwRebindTransportCallback,
    error: *mut HwError,
) -> HwStatus {
    guarded_status(error, || {
        let runtime = runtime_ref(runtime)?;
        let call = runtime.begin_call()?;
        let context = runtime.callbacks.context as *mut c_void;
        let mut scheduler_guard = runtime.scheduler.lock().map_err(|_| {
            FfiFailure::new(
                HwStatus::InternalError,
                "runtime scheduler lock is poisoned",
            )
        })?;
        let scheduler = scheduler_guard.as_mut().ok_or_else(|| {
            FfiFailure::new(HwStatus::InvalidState, "runtime scheduler is not running")
        })?;
        let tick = scheduler.tick(&call.engine, Instant::now(), |peer_name, silence| {
            let Some(callback) = rebind_transport else {
                return false;
            };
            let silence_milliseconds = silence.as_millis().min(u128::from(u64::MAX)) as u64;
            callback(
                context,
                peer_name.as_ptr(),
                peer_name.len(),
                silence_milliseconds,
            ) != 0
        });
        drop(scheduler_guard);

        for scheduled in tick.outputs {
            runtime.dispatch(&call.engine, scheduled.output);
        }
        if let Some(failure) = tick.errors.into_iter().next() {
            return Err(FfiFailure::new(
                HwStatus::EngineError,
                format!(
                    "{} for peer {} failed: {}",
                    failure.operation.label(),
                    failure.peer_name,
                    failure.error
                ),
            ));
        }
        Ok(())
    })
}

/// # Safety
/// Peer-name, payload, runtime, and error pointers must be valid for this call.
#[no_mangle]
pub unsafe extern "C" fn hw_runtime_create_keepalive(
    runtime: *mut HwRuntime,
    peer_name: *const u8,
    peer_name_length: usize,
    payload: *const u8,
    payload_length: usize,
    error: *mut HwError,
) -> HwStatus {
    guarded_status(error, || {
        let runtime = runtime_ref(runtime)?;
        let peer_name = borrowed_string(peer_name, peer_name_length, "peer_name")?;
        let payload = borrowed_bytes(payload, payload_length, "payload")?;
        let call = runtime.begin_call()?;
        let output = call
            .engine
            .create_keepalive(peer_name, payload, Instant::now())
            .map_err(|cause| FfiFailure::new(HwStatus::EngineError, cause.to_string()))?;
        runtime.dispatch(&call.engine, output);
        Ok(())
    })
}

/// # Safety
/// All pointers must be null or valid for this call. `invalidated` is optional.
#[no_mangle]
pub unsafe extern "C" fn hw_runtime_invalidate_peer(
    runtime: *mut HwRuntime,
    peer_name: *const u8,
    peer_name_length: usize,
    invalidated: *mut u8,
    error: *mut HwError,
) -> HwStatus {
    guarded_status(error, || {
        let runtime = runtime_ref(runtime)?;
        let peer_name = borrowed_string(peer_name, peer_name_length, "peer_name")?;
        let call = runtime.begin_call()?;
        let removed = call.engine.invalidate_peer(peer_name);
        if let Some(invalidated) = invalidated.as_mut() {
            *invalidated = u8::from(removed);
        }
        Ok(())
    })
}

/// Record a transport send that completed asynchronously after its callback.
///
/// A transport callback that returns nonzero is recorded automatically and
/// must not call this function for the same frame.
///
/// # Safety
/// Peer-name, runtime, and error pointers must be valid for this call.
#[no_mangle]
pub unsafe extern "C" fn hw_runtime_record_transport_sent(
    runtime: *mut HwRuntime,
    peer_name: *const u8,
    peer_name_length: usize,
    byte_count: usize,
    error: *mut HwError,
) -> HwStatus {
    guarded_status(error, || {
        let runtime = runtime_ref(runtime)?;
        let peer_name = borrowed_string(peer_name, peer_name_length, "peer_name")?;
        let call = runtime.begin_call()?;
        call.engine.record_transport_sent(peer_name, byte_count);
        Ok(())
    })
}

/// # Safety
/// Output, runtime, and error pointers must be valid for this call.
#[no_mangle]
pub unsafe extern "C" fn hw_runtime_get_interface_config(
    runtime: *const HwRuntime,
    output: *mut HwInterfaceConfig,
    error: *mut HwError,
) -> HwStatus {
    guarded_status(error, || {
        let runtime = runtime_const_ref(runtime)?;
        let output = output
            .as_mut()
            .ok_or_else(|| FfiFailure::new(HwStatus::InvalidArgument, "output must not be null"))?;
        *output = HwInterfaceConfig {
            address: runtime.config.interface.address.addr().octets(),
            prefix_length: runtime.config.interface.address.prefix_len(),
            transport: match runtime.config.interface.transport {
                TransportConfig::Udp => 1,
                TransportConfig::Tcp => 2,
            },
            mtu: runtime.config.interface.mtu,
            listen: endpoint_to_ffi(runtime.config.interface.listen),
        };
        Ok(())
    })
}

/// Visit public route metadata without exposing keys or the source TOML.
///
/// # Safety
/// Runtime and error pointers must be valid; callback must remain callable for
/// the duration of this function.
#[no_mangle]
pub unsafe extern "C" fn hw_runtime_visit_routes(
    runtime: *const HwRuntime,
    context: *mut c_void,
    callback: HwRouteCallback,
    error: *mut HwError,
) -> HwStatus {
    guarded_status(error, || {
        let runtime = runtime_const_ref(runtime)?;
        let callback = callback.ok_or_else(|| {
            FfiFailure::new(HwStatus::InvalidArgument, "route callback must not be null")
        })?;
        for configured_route in runtime.router.routes() {
            let peer = &configured_route.peer;
            let configured_endpoint = peer.configured_endpoint.to_string();
            let route = HwRouteConfig {
                network: configured_route.prefix.network().octets(),
                prefix_length: configured_route.prefix.prefix_len(),
                route_kind: 1,
                reserved: [0; 2],
                endpoint: endpoint_to_ffi(peer.endpoint),
                persistent_keepalive: peer.persistent_keepalive,
                udp_rebind_after: peer.udp_rebind_after,
                session_timeout: peer.session_timeout,
            };
            callback(
                context,
                peer.name.as_ptr(),
                peer.name.len(),
                configured_endpoint.as_ptr(),
                configured_endpoint.len(),
                &route,
            );
        }
        for configured_route in runtime.router.excluded_routes() {
            let peer = &configured_route.peer;
            let configured_endpoint = peer.configured_endpoint.to_string();
            let route = HwRouteConfig {
                network: configured_route.prefix.network().octets(),
                prefix_length: configured_route.prefix.prefix_len(),
                route_kind: 2,
                reserved: [0; 2],
                endpoint: endpoint_to_ffi(peer.endpoint),
                persistent_keepalive: peer.persistent_keepalive,
                udp_rebind_after: peer.udp_rebind_after,
                session_timeout: peer.session_timeout,
            };
            callback(
                context,
                peer.name.as_ptr(),
                peer.name.len(),
                configured_endpoint.as_ptr(),
                configured_endpoint.len(),
                &route,
            );
        }
        Ok(())
    })
}

/// # Safety
/// Runtime and error pointers must be valid; callback must remain callable for
/// the duration of this function.
#[no_mangle]
pub unsafe extern "C" fn hw_runtime_visit_peer_stats(
    runtime: *mut HwRuntime,
    context: *mut c_void,
    callback: HwPeerStatsCallback,
    error: *mut HwError,
) -> HwStatus {
    guarded_status(error, || {
        let runtime = runtime_ref(runtime)?;
        let callback = callback.ok_or_else(|| {
            FfiFailure::new(HwStatus::InvalidArgument, "stats callback must not be null")
        })?;
        let call = runtime.begin_call()?;
        let mut snapshot: Vec<_> = call.engine.peer_stats().into_iter().collect();
        snapshot.sort_by(|left, right| left.0.cmp(&right.0));
        for (peer_name, stats) in snapshot {
            let endpoint = stats.current_endpoint.map(endpoint_to_ffi);
            let last_seen = stats.last_seen.map(|seen| seen.elapsed());
            let ffi_stats = HwPeerStats {
                tx_bytes: stats.tx_bytes,
                rx_bytes: stats.rx_bytes,
                last_seen_milliseconds_ago: last_seen
                    .map(|elapsed| elapsed.as_millis().min(u128::from(u64::MAX)) as u64)
                    .unwrap_or(0),
                endpoint: endpoint.unwrap_or_default(),
                has_last_seen: u8::from(last_seen.is_some()),
                has_endpoint: u8::from(endpoint.is_some()),
                reserved: [0; 6],
            };
            callback(context, peer_name.as_ptr(), peer_name.len(), &ffi_stats);
        }
        Ok(())
    })
}

fn endpoint_to_ffi(endpoint: SocketAddr) -> HwEndpoint {
    match endpoint {
        SocketAddr::V4(endpoint) => {
            let mut address = [0; 16];
            address[..4].copy_from_slice(&endpoint.ip().octets());
            HwEndpoint {
                family: 4,
                address,
                port: endpoint.port(),
                scope_id: 0,
            }
        }
        SocketAddr::V6(endpoint) => HwEndpoint {
            family: 6,
            address: endpoint.ip().octets(),
            port: endpoint.port(),
            scope_id: endpoint.scope_id(),
        },
    }
}

fn endpoint_from_ffi(endpoint: &HwEndpoint) -> Result<SocketAddr, FfiFailure> {
    match endpoint.family {
        4 => Ok(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(
                endpoint.address[0],
                endpoint.address[1],
                endpoint.address[2],
                endpoint.address[3],
            ),
            endpoint.port,
        ))),
        6 => Ok(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(endpoint.address),
            endpoint.port,
            0,
            endpoint.scope_id,
        ))),
        family => Err(FfiFailure::new(
            HwStatus::InvalidArgument,
            format!("unsupported endpoint address family: {family}"),
        )),
    }
}

fn guarded_status(
    error: *mut HwError,
    operation: impl FnOnce() -> Result<(), FfiFailure>,
) -> HwStatus {
    clear_error(error);
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => HwStatus::Ok,
        Ok(Err(failure)) => {
            write_error(error, &failure);
            failure.status
        }
        Err(_) => {
            let failure = FfiFailure::new(HwStatus::Panic, "Rust core panicked across ABI call");
            write_error(error, &failure);
            failure.status
        }
    }
}

fn clear_error(error: *mut HwError) {
    if let Some(error) = unsafe { error.as_mut() } {
        *error = HwError::default();
    }
}

fn write_error(error: *mut HwError, failure: &FfiFailure) {
    let Some(error) = (unsafe { error.as_mut() }) else {
        return;
    };
    *error = HwError::default();
    error.code = failure.status as i32;
    let bytes = failure.message.as_bytes();
    let length = bytes.len().min(ERROR_MESSAGE_CAPACITY - 1);
    for (destination, source) in error.message[..length].iter_mut().zip(&bytes[..length]) {
        *destination = *source as c_char;
    }
}

unsafe fn runtime_ref<'a>(runtime: *mut HwRuntime) -> Result<&'a HwRuntime, FfiFailure> {
    runtime
        .as_ref()
        .ok_or_else(|| FfiFailure::new(HwStatus::InvalidArgument, "runtime must not be null"))
}

unsafe fn runtime_const_ref<'a>(runtime: *const HwRuntime) -> Result<&'a HwRuntime, FfiFailure> {
    runtime
        .as_ref()
        .ok_or_else(|| FfiFailure::new(HwStatus::InvalidArgument, "runtime must not be null"))
}

unsafe fn borrowed_bytes<'a>(
    pointer: *const u8,
    length: usize,
    name: &str,
) -> Result<&'a [u8], FfiFailure> {
    if length == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err(FfiFailure::new(
            HwStatus::InvalidArgument,
            format!("{name} must not be null when length is nonzero"),
        ));
    }
    Ok(slice::from_raw_parts(pointer, length))
}

unsafe fn borrowed_string<'a>(
    pointer: *const u8,
    length: usize,
    name: &str,
) -> Result<&'a str, FfiFailure> {
    let bytes = borrowed_bytes(pointer, length, name)?;
    str::from_utf8(bytes).map_err(|_| {
        FfiFailure::new(
            HwStatus::InvalidArgument,
            format!("{name} is not valid UTF-8"),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::ptr;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;

    #[derive(Debug)]
    struct CapturedTransport {
        peer: String,
        endpoint: HwEndpoint,
        frame: Vec<u8>,
    }

    #[derive(Default)]
    struct Capture {
        transport: VecDeque<CapturedTransport>,
        packets: Vec<Vec<u8>>,
        handshakes: Vec<(String, u8)>,
    }

    unsafe extern "C" fn capture_transport(
        context: *mut c_void,
        peer_name: *const u8,
        peer_name_length: usize,
        endpoint: *const HwEndpoint,
        frame: *const u8,
        frame_length: usize,
    ) -> u8 {
        let capture = &mut *(context.cast::<Capture>());
        capture.transport.push_back(CapturedTransport {
            peer: String::from_utf8_lossy(slice::from_raw_parts(peer_name, peer_name_length))
                .into_owned(),
            endpoint: *endpoint,
            frame: slice::from_raw_parts(frame, frame_length).to_vec(),
        });
        1
    }

    unsafe extern "C" fn capture_packet(
        context: *mut c_void,
        _peer_name: *const u8,
        _peer_name_length: usize,
        _source: *const HwEndpoint,
        packet: *const u8,
        packet_length: usize,
    ) {
        let capture = &mut *(context.cast::<Capture>());
        capture
            .packets
            .push(slice::from_raw_parts(packet, packet_length).to_vec());
    }

    unsafe extern "C" fn capture_handshake(
        context: *mut c_void,
        peer_name: *const u8,
        peer_name_length: usize,
        _endpoint: *const HwEndpoint,
        role: u8,
    ) {
        let capture = &mut *(context.cast::<Capture>());
        capture.handshakes.push((
            String::from_utf8_lossy(slice::from_raw_parts(peer_name, peer_name_length))
                .into_owned(),
            role,
        ));
    }

    struct TestConfig<'a> {
        name: &'a str,
        address: &'a str,
        listen: String,
        private_key: [u8; 32],
        peer_name: &'a str,
        peer_address: &'a str,
        peer_endpoint: String,
        peer_public_key: [u8; 32],
        psk: [u8; 32],
    }

    fn config(test: TestConfig<'_>) -> String {
        let TestConfig {
            name,
            address,
            listen,
            private_key,
            peer_name,
            peer_address,
            peer_endpoint,
            peer_public_key,
            psk,
        } = test;
        format!(
            r#"[interface]
name = "{name}"
address = "{address}"
listen = "{listen}"
transport = "udp"
mtu = 1280
private_key = "{}"

[[peer]]
name = "{peer_name}"
endpoint = "{peer_endpoint}"
allowed_ips = ["{peer_address}"]
psk = "{}"
public_key = "{}"
persistent_keepalive = 5
udp_rebind_after = 20
"#,
            STANDARD.encode(private_key),
            STANDARD.encode(psk),
            STANDARD.encode(peer_public_key),
        )
    }

    fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        let packet_length = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&packet_length.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet
    }

    unsafe fn create_runtime(config: &str, capture: &mut Capture) -> *mut HwRuntime {
        let callbacks = HwCallbacks {
            context: (capture as *mut Capture).cast(),
            send_transport: Some(capture_transport),
            write_ip_packet: Some(capture_packet),
            handshake_completed: Some(capture_handshake),
        };
        let mut error = HwError::default();
        let runtime = hw_runtime_create(config.as_ptr(), config.len(), &callbacks, &mut error);
        assert!(
            !runtime.is_null(),
            "runtime creation failed: {}",
            error_text(&error)
        );
        assert_eq!(hw_runtime_start(runtime, &mut error), HwStatus::Ok);
        runtime
    }

    fn error_text(error: &HwError) -> String {
        let bytes: Vec<u8> = error
            .message
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| *byte as u8)
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    unsafe fn deliver(
        destination: *mut HwRuntime,
        captured: CapturedTransport,
        source: SocketAddr,
    ) {
        let source = endpoint_to_ffi(source);
        let mut error = HwError::default();
        assert_eq!(
            hw_runtime_submit_inbound_transport(
                destination,
                captured.frame.as_ptr(),
                captured.frame.len(),
                &source,
                &mut error,
            ),
            HwStatus::Ok,
            "{}",
            error_text(&error)
        );
    }

    #[test]
    fn ffi_engines_handshake_exchange_packets_and_reset_on_stop() {
        let private_a = [0x11; 32];
        let private_b = [0x22; 32];
        let public_a = PublicKey::from(&StaticSecret::from(private_a)).to_bytes();
        let public_b = PublicKey::from(&StaticSecret::from(private_b)).to_bytes();
        let psk = [0x33; 32];
        let endpoint_a: SocketAddr = "127.0.0.1:41001".parse().unwrap();
        let endpoint_b: SocketAddr = "127.0.0.1:41002".parse().unwrap();
        let config_a = config(TestConfig {
            name: "ffi-a",
            address: "10.77.90.1/30",
            listen: endpoint_a.to_string(),
            private_key: private_a,
            peer_name: "b",
            peer_address: "10.77.90.2/32",
            peer_endpoint: endpoint_b.to_string(),
            peer_public_key: public_b,
            psk,
        });
        let config_b = config(TestConfig {
            name: "ffi-b",
            address: "10.77.90.2/30",
            listen: endpoint_b.to_string(),
            private_key: private_b,
            peer_name: "a",
            peer_address: "10.77.90.1/32",
            peer_endpoint: endpoint_a.to_string(),
            peer_public_key: public_a,
            psk,
        });
        let mut capture_a = Capture::default();
        let mut capture_b = Capture::default();

        unsafe {
            let runtime_a = create_runtime(&config_a, &mut capture_a);
            let runtime_b = create_runtime(&config_b, &mut capture_b);
            let packet = ipv4_packet(Ipv4Addr::new(10, 77, 90, 1), Ipv4Addr::new(10, 77, 90, 2));
            let mut error = HwError::default();

            assert_eq!(
                hw_runtime_submit_outbound_ip(runtime_a, packet.as_ptr(), packet.len(), &mut error,),
                HwStatus::Ok
            );
            let request = capture_a.transport.pop_front().unwrap();
            assert_eq!(request.peer, "b");
            assert_eq!(request.endpoint, endpoint_to_ffi(endpoint_b));
            deliver(runtime_b, request, endpoint_a);

            let response = capture_b.transport.pop_front().unwrap();
            deliver(runtime_a, response, endpoint_b);
            assert_eq!(capture_a.handshakes, vec![("b".to_string(), 1)]);

            let confirmation = capture_a.transport.pop_front().unwrap();
            deliver(runtime_b, confirmation, endpoint_a);
            assert_eq!(capture_b.handshakes, vec![("a".to_string(), 2)]);

            let acknowledgement = capture_b.transport.pop_front().unwrap();
            deliver(runtime_a, acknowledgement, endpoint_b);
            assert!(capture_a.transport.is_empty());

            assert_eq!(
                hw_runtime_submit_outbound_ip(runtime_a, packet.as_ptr(), packet.len(), &mut error,),
                HwStatus::Ok
            );
            let encrypted = capture_a.transport.pop_front().unwrap();
            deliver(runtime_b, encrypted, endpoint_a);
            assert_eq!(capture_b.packets, vec![packet.clone()]);

            assert_eq!(hw_runtime_stop(runtime_a, &mut error), HwStatus::Ok);
            assert_eq!(hw_runtime_stop(runtime_a, &mut error), HwStatus::Ok);
            assert_eq!(hw_runtime_is_running(runtime_a), 0);
            assert_eq!(
                hw_runtime_submit_outbound_ip(runtime_a, packet.as_ptr(), packet.len(), &mut error,),
                HwStatus::InvalidState
            );
            assert_eq!(hw_runtime_start(runtime_a, &mut error), HwStatus::Ok);
            assert_eq!(hw_runtime_start(runtime_a, &mut error), HwStatus::Ok);
            assert_eq!(hw_runtime_is_running(runtime_a), 1);

            hw_runtime_destroy(runtime_a);
            hw_runtime_destroy(runtime_b);
        }
    }

    #[test]
    fn ffi_rejects_invalid_inputs_without_unwinding() {
        let mut error = HwError::default();
        unsafe {
            let runtime = hw_runtime_create(ptr::null(), 1, ptr::null(), &mut error);
            assert!(runtime.is_null());
            assert_eq!(error.code, HwStatus::InvalidArgument as i32);
            assert!(error_text(&error).contains("config_toml"));

            assert_eq!(
                hw_runtime_start(ptr::null_mut(), &mut error),
                HwStatus::InvalidArgument
            );
            assert!(error_text(&error).contains("runtime"));
        }
    }

    #[test]
    fn endpoint_round_trip_preserves_ipv4_and_ipv6() {
        for endpoint in [
            "192.0.2.10:27777".parse().unwrap(),
            "[2001:db8::5]:27778".parse().unwrap(),
        ] {
            let encoded = endpoint_to_ffi(endpoint);
            assert_eq!(endpoint_from_ffi(&encoded).unwrap(), endpoint);
        }
    }
}
