use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context;
use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use tracing::{debug, error, info, warn};
use x25519_dalek::StaticSecret;

use crate::config::Config;
use crate::firewall;
use crate::packet::Ipv4Packet;
use crate::router::Router;
use crate::routing::{self, InstalledRoute};
use crate::state::PeerState;
use crate::transport;
use hushwire::auth;
use hushwire::noise::{self, Session};
use hushwire::replay;

const MAX_PACKET_SIZE: usize = 65_535;
const PACKET_INFO_SIZE: usize = 4;

/// Per-peer session state, shared across threads.
///
/// Holds the active session (if handshake completed) keyed by peer name.
/// The sender thread reads `send_key` + `session_id` to encrypt data; the
/// receiver thread looks up by `session_id` to find `recv_key`.
#[derive(Default)]
struct SessionManager {
    /// peer_name → active session
    sessions: Mutex<HashMap<String, Session>>,
    /// peer_name → pending initiator state (sender creates, receiver completes)
    pending_init: Mutex<HashMap<String, noise::InitiatorState>>,
}

impl SessionManager {
    fn new() -> Self {
        Self::default()
    }

    /// Get send_key + session_id for encrypting outgoing data.
    fn get_send_key(
        &self,
        peer_name: &str,
    ) -> Option<([u8; auth::KEY_SIZE], [u8; auth::SESSION_ID_SIZE])> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions.get(peer_name)?;
        if session.needs_rekey() {
            return None;
        }
        Some((session.send_key, session.session_id))
    }

    /// Get recv_key for a session identified by session_id (for decrypting incoming data).
    fn get_recv_key_by_session_id(
        &self,
        session_id: &[u8; auth::SESSION_ID_SIZE],
    ) -> Option<([u8; auth::KEY_SIZE], String)> {
        let sessions = self.sessions.lock().unwrap();
        for (peer_name, session) in sessions.iter() {
            if &session.session_id == session_id {
                return Some((session.recv_key, peer_name.clone()));
            }
        }
        None
    }

    /// Store a newly negotiated session for a peer (replaces any existing one).
    fn store(&self, peer_name: &str, session: Session) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(peer_name.to_string(), session);
    }

    /// Store a pending initiator handshake state (created by sender thread,
    /// completed by receiver thread when the response arrives).
    fn store_pending_init(&self, peer_name: &str, state: noise::InitiatorState) {
        let mut pending = self.pending_init.lock().unwrap();
        pending.insert(peer_name.to_string(), state);
    }

    /// Take a pending initiator handshake state (consumes it).
    fn take_pending_init(&self, peer_name: &str) -> Option<noise::InitiatorState> {
        let mut pending = self.pending_init.lock().unwrap();
        pending.remove(peer_name)
    }

    /// Check if a pending initiator handshake exists for a peer.
    fn has_pending_init(&self, peer_name: &str) -> bool {
        let pending = self.pending_init.lock().unwrap();
        pending.contains_key(peer_name)
    }
}

pub fn run(config: Config, exit_node: bool) -> anyhow::Result<()> {
    let router = Router::new(&config)?;

    // Create the TUN interface before installing routes or firewall rules,
    // since both reference the interface by name.
    let device = create_tun(&config)?;
    let transport = transport::bind(&config)?;

    // Load local static private key for Noise handshake.
    let local_static_bytes =
        crate::config::decode_key(&config.interface.private_key).context("invalid private_key")?;
    let local_static = Arc::new(StaticSecret::from(local_static_bytes));

    // Per-peer session manager (shared across threads).
    let session_mgr = Arc::new(SessionManager::new());

    let mut route_manager = routing::RouteManager::new(config.interface.name.clone());
    route_manager.setup(&router)?;
    let installed_routes: Vec<routing::InstalledRoute> = route_manager.installed().to_vec();

    let mut firewall = if exit_node {
        let subnet = firewall::subnet_cidr(&config.interface.address);
        let mut fw = firewall::FirewallManager::new(config.interface.name.clone(), subnet);
        fw.setup()?;
        Some(fw)
    } else {
        None
    };

    let cleanup = Arc::new(Cleanup {
        routes: Arc::new(Mutex::new(installed_routes.clone())),
        firewall: Arc::new(Mutex::new(firewall.take())),
    });
    let cleanup_for_signal = cleanup.clone();

    let mut signals =
        Signals::new([SIGINT, SIGTERM, SIGHUP]).context("registering signal handlers")?;
    thread::spawn(move || {
        // `forever()` yields an unbounded stream of signals. Each branch below
        // currently exits the process, but `while let` keeps the door open for
        // a graceful-reload path (returning to the loop) without a rewrite.
        #[allow(clippy::never_loop)]
        while let Some(sig) = signals.forever().next() {
            cleanup_for_signal.run();
            match sig {
                SIGHUP => {
                    info!("received SIGHUP, restarting tunnel");
                    std::process::exit(1);
                }
                _ => {
                    info!(signal = sig, "received termination signal, shutting down");
                    std::process::exit(0);
                }
            }
        }
    });

    info!(
        interface = %config.interface.name,
        address = %config.interface.address,
        listen = %transport.local_addr()?,
        transport = transport.label(),
        mtu = config.interface.mtu,
        routes = router.routes().len(),
        "tunnel started"
    );

    for route in router.routes() {
        info!(
            peer = %route.peer.name,
            endpoint = %route.peer.endpoint,
            prefix = %route.prefix,
            keepalive = route.peer.persistent_keepalive,
            "route installed"
        );
    }

    let packet_information = device.packet_information;
    let mut tun_reader = device.reader;
    let mut tun_writer = device.writer;
    let transport_writer = transport.try_clone_box()?;
    let keepalive_transport = transport.try_clone_box()?;
    let router_for_reader = router.clone();
    let router_for_receiver = router.clone();
    let router_for_keepalive = router.clone();

    let state = PeerState::new();
    let state_for_sender = state.clone();
    let state_for_receiver = state.clone();
    let state_for_keepalive = state.clone();
    let state_for_stats = state.clone();

    // Session manager + local static key for each thread that needs them.
    let sessions_for_sender = session_mgr.clone();
    let sessions_for_receiver = session_mgr.clone();
    let sessions_for_keepalive = session_mgr.clone();
    let static_for_sender = local_static.clone();
    let static_for_receiver = local_static.clone();

    let tun_to_transport = thread::spawn(move || {
        let mut packet = vec![0_u8; MAX_PACKET_SIZE];
        loop {
            let size = match tun_reader.read(&mut packet) {
                Ok(size) => size,
                Err(error) => {
                    error!(%error, "failed to read from TUN device");
                    continue;
                }
            };

            let Some(frame) = strip_packet_information(&packet[..size], packet_information) else {
                warn!(bytes = size, "dropping short packet-info frame from TUN");
                continue;
            };

            let ipv4 = match Ipv4Packet::parse(frame) {
                Ok(packet) => packet,
                Err(error) => {
                    warn!(%error, bytes = size, "dropping non-routable TUN packet");
                    continue;
                }
            };

            let destination = ipv4.destination();
            let Some(route) = router_for_reader.lookup(destination) else {
                debug!(
                    src = %ipv4.source(),
                    dst = %destination,
                    proto = ipv4.protocol(),
                    bytes = size,
                    "no route for packet"
                );
                continue;
            };

            // Get session key for this peer; if no session yet, initiate handshake.
            let (send_key, session_id) = match sessions_for_sender.get_send_key(&route.peer.name) {
                Some(keys) => keys,
                None => {
                    // No active session — initiate Noise handshake, then drop this packet.
                    // Avoid spamming: only initiate if no pending handshake exists.
                    if sessions_for_sender.has_pending_init(&route.peer.name) {
                        continue;
                    }
                    let handshake = noise::initiator_start(
                        &static_for_sender,
                        &route.peer.public_key,
                        &route.peer.psk,
                    );
                    let (msg1, state) = handshake.into_parts();
                    sessions_for_sender.store_pending_init(&route.peer.name, state);
                    let endpoint =
                        resolve_endpoint(&state_for_sender, &route.peer.name, route.peer.endpoint);
                    // Wrap msg1 in a HushWire handshake packet (encrypted with PSK).
                    let hs_packet = auth::encode_packet(
                        &msg1,
                        &route.peer.psk,
                        auth::MsgType::HandshakeInit,
                        &[0u8; auth::SESSION_ID_SIZE],
                    );
                    if let Err(e) = transport_writer.send_to(&hs_packet, endpoint) {
                        warn!(%e, peer = %route.peer.name, "failed to send handshake init");
                    }
                    debug!(peer = %route.peer.name, "initiated handshake, dropping data packet until session established");
                    continue;
                }
            };

            let encoded = auth::encode_packet(frame, &send_key, auth::MsgType::Data, &session_id);
            let endpoint =
                resolve_endpoint(&state_for_sender, &route.peer.name, route.peer.endpoint);
            if let Err(error) = transport_writer.send_to(&encoded, endpoint) {
                error!(
                    %error,
                    peer = %route.peer.name,
                    endpoint = %endpoint,
                    bytes = size,
                    "failed to send UDP packet"
                );
                continue;
            }

            state_for_sender.record_tx(&route.peer.name, encoded.len());

            debug!(
                peer = %route.peer.name,
                endpoint = %endpoint,
                route = %route.prefix,
                src = %ipv4.source(),
                dst = %destination,
                proto = ipv4.protocol(),
                bytes = size,
                "forwarded TUN packet to transport"
            );
        }
    });

    let transport_to_tun = thread::spawn(move || {
        let mut packet = vec![0_u8; MAX_PACKET_SIZE];
        let mut tun_frame = vec![0_u8; MAX_PACKET_SIZE + PACKET_INFO_SIZE];
        let mut replay: HashMap<String, replay::ReplayFilter> = HashMap::new();
        loop {
            let received = match transport.recv_from(&mut packet) {
                Ok(received) => received,
                Err(error) => {
                    error!(%error, "failed to receive transport packet");
                    continue;
                }
            };
            let size = received.bytes;
            let source = received.source;
            let frame = &packet[..size];

            // First, peek at msg_type to decide how to handle.
            if frame.len() < 2 || frame[0] != 0x02 {
                continue;
            }
            let msg_type = match auth::MsgType::from_u8(frame[1]) {
                Some(mt) => mt,
                None => continue,
            };

            // For handshake messages: decrypt with PSK (try each peer).
            // For data/keepalive: extract session_id, look up session, decrypt with session key.
            if msg_type.is_handshake() {
                let (peer_name, payload) = match decode_handshake_from_peers(
                    frame,
                    &router_for_receiver,
                ) {
                    Some(r) => r,
                    None => {
                        warn!(source = %source, bytes = size, "dropping unauthenticated handshake packet");
                        continue;
                    }
                };

                match msg_type {
                    auth::MsgType::HandshakeInit => {
                        // We are the responder. Find this peer's config to get PSK + our static key.
                        let route = router_for_receiver
                            .routes()
                            .iter()
                            .find(|r| r.peer.name == peer_name);
                        let Some(route) = route else {
                            continue;
                        };
                        let hs = noise::responder_respond(
                            &static_for_receiver,
                            &route.peer.psk,
                            &payload,
                        );
                        if let Some(hs) = hs {
                            // Store the new session.
                            sessions_for_receiver.store(&peer_name, hs.session);
                            // Reset replay filter for this peer (new session = new nonce space).
                            replay.insert(peer_name.clone(), replay::ReplayFilter::new());
                            // Send msg2 back.
                            let hs_packet = auth::encode_packet(
                                &hs.message,
                                &route.peer.psk,
                                auth::MsgType::HandshakeResponse,
                                &[0u8; auth::SESSION_ID_SIZE],
                            );
                            let endpoint = resolve_endpoint(
                                &state_for_receiver,
                                &peer_name,
                                route.peer.endpoint,
                            );
                            if let Err(e) = transport.send_to(&hs_packet, endpoint) {
                                warn!(%e, peer = %peer_name, "failed to send handshake response");
                            }
                            info!(peer = %peer_name, source = %source, "handshake completed (responder), session established");
                        }
                    }
                    auth::MsgType::HandshakeResponse => {
                        // We are the initiator completing the handshake.
                        let route = router_for_receiver
                            .routes()
                            .iter()
                            .find(|r| r.peer.name == peer_name);
                        let Some(route) = route else {
                            continue;
                        };
                        // Take the pending initiator state (created by sender thread).
                        let Some(pending) = sessions_for_receiver.take_pending_init(&peer_name)
                        else {
                            debug!(peer = %peer_name, "handshake response without pending init, ignoring");
                            continue;
                        };
                        let session = noise::initiator_finalize(
                            pending,
                            &static_for_receiver,
                            &route.peer.public_key,
                            &payload,
                        );
                        if let Some(session) = session {
                            sessions_for_receiver.store(&peer_name, session);
                            replay.insert(peer_name.clone(), replay::ReplayFilter::new());
                            info!(peer = %peer_name, source = %source, "handshake completed (initiator), session established");
                        } else {
                            warn!(peer = %peer_name, "handshake finalization failed");
                        }
                    }
                    _ => unreachable!(),
                }
                state_for_receiver.record_keepalive(&peer_name, source);
                continue;
            }

            // Data or Keepalive: extract session_id, find session, decrypt with session key.
            let session_id = match auth::extract_session_id(frame) {
                Some(sid) => sid,
                None => continue,
            };
            let (recv_key, peer_name) =
                match sessions_for_receiver.get_recv_key_by_session_id(&session_id) {
                    Some(r) => r,
                    None => {
                        // No session for this session_id — might be a stale packet or
                        // we haven't completed handshake yet. Drop silently.
                        debug!(source = %source, "no session for session_id, dropping");
                        continue;
                    }
                };

            let (decoded_msg_type, payload) = match auth::decode_packet(frame, &recv_key) {
                Some(r) => r,
                None => {
                    warn!(source = %source, peer = %peer_name, "failed to decrypt data packet with session key");
                    continue;
                }
            };

            // Extract nonce for replay filtering.
            let mut nonce = [0u8; auth::NONCE_SIZE];
            nonce.copy_from_slice(&frame[auth::SESSION_ID_OFFSET..auth::HEADER_SIZE]);

            // Reject replays.
            let filter = replay.entry(peer_name.clone()).or_default();
            if !filter.check_and_insert(&nonce) {
                warn!(source = %source, peer = %peer_name, "dropping replayed packet");
                continue;
            }

            match decoded_msg_type {
                auth::MsgType::Keepalive => {
                    state_for_receiver.record_keepalive(&peer_name, source);
                    continue;
                }
                auth::MsgType::Data => {
                    state_for_receiver.record_rx(&peer_name, source, payload.len());
                }
                _ => continue, // handshake types already handled above
            }

            match Ipv4Packet::parse(&payload) {
                Ok(ipv4) => {
                    debug!(
                        source = %source,
                        peer = %peer_name,
                        src = %ipv4.source(),
                        dst = %ipv4.destination(),
                        proto = ipv4.protocol(),
                        bytes = payload.len(),
                        "received authenticated transport packet for TUN"
                    );
                }
                Err(error) => {
                    warn!(%error, source = %source, peer = %peer_name, bytes = payload.len(), "dropping invalid transport payload");
                    continue;
                }
            }

            let output = add_packet_information(&payload, packet_information, &mut tun_frame);
            if let Err(error) = tun_writer.write_all(output) {
                error!(%error, source = %source, peer = %peer_name, bytes = payload.len(), "failed to write to TUN device");
            }
        }
    });

    let keepalive = thread::spawn(move || {
        let mut last_sent: HashMap<String, Instant> = HashMap::new();
        loop {
            thread::sleep(Duration::from_secs(1));
            let now = Instant::now();
            for route in router_for_keepalive.routes() {
                let interval = route.peer.persistent_keepalive as u64;
                if interval == 0 {
                    continue;
                }
                let sent = last_sent.entry(route.peer.name.clone()).or_insert(now);
                if now.duration_since(*sent).as_secs() >= interval {
                    // Use session key if available, otherwise skip (no session yet).
                    let Some((send_key, session_id)) =
                        sessions_for_keepalive.get_send_key(&route.peer.name)
                    else {
                        *sent = now;
                        continue;
                    };
                    let packet =
                        auth::encode_packet(b"", &send_key, auth::MsgType::Keepalive, &session_id);
                    let endpoint = resolve_endpoint(
                        &state_for_keepalive,
                        &route.peer.name,
                        route.peer.endpoint,
                    );
                    if keepalive_transport.send_to(&packet, endpoint).is_ok() {
                        state_for_keepalive.record_tx(&route.peer.name, packet.len());
                    }
                    *sent = now;
                }
            }
        }
    });

    let stats = thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(30));
        let snapshot = state_for_stats.snapshot();
        if snapshot.is_empty() {
            continue;
        }
        for (name, stats) in snapshot {
            let ago = stats
                .last_seen
                .map(|t| t.elapsed().as_secs())
                .map_or("never".to_string(), |s| format!("{s}s ago"));
            info!(
                peer = %name,
                tx_bytes = stats.tx_bytes,
                rx_bytes = stats.rx_bytes,
                last_seen = %ago,
                endpoint = ?stats.current_endpoint,
                "peer stats"
            );
        }
    });

    tun_to_transport.join().expect("TUN reader thread panicked");
    transport_to_tun
        .join()
        .expect("transport reader thread panicked");
    keepalive.join().expect("keepalive thread panicked");
    stats.join().expect("stats thread panicked");

    cleanup.run();
    Ok(())
}

struct TunDevice {
    reader: tun::platform::posix::Reader,
    writer: tun::platform::posix::Writer,
    packet_information: bool,
}

/// Resolve the destination endpoint for outbound packets to a peer.
///
/// Prefers the address learned from a recent inbound packet (NAT traversal /
/// roaming) and falls back to the statically configured endpoint when no
/// packet has been received from the peer yet. This lets peers behind NAT
/// establish connectivity by sending keepalives: once the server sees a
/// packet from the peer's real source address, it replies there instead of
/// the (possibly unreachable) configured endpoint.
fn resolve_endpoint(state: &PeerState, peer_name: &str, configured: SocketAddr) -> SocketAddr {
    let snapshot = state.snapshot();
    snapshot
        .get(peer_name)
        .and_then(|stats| stats.current_endpoint)
        .filter(|learned| *learned != configured)
        .unwrap_or(configured)
}

fn create_tun(config: &Config) -> anyhow::Result<TunDevice> {
    let mut tun_config = tun::Configuration::default();
    tun_config
        .name(&config.interface.name)
        .address(config.interface.address.addr())
        .netmask(config.interface.address.netmask())
        .mtu(i32::from(config.interface.mtu))
        .up();

    #[cfg(target_os = "linux")]
    tun_config.platform(|platform| {
        platform.packet_information(false);
    });

    // `mut` is required on Linux where `has_packet_information` takes `&mut
    // self`; on macOS it takes `&self` and the mut is unused there.
    #[allow(unused_mut)]
    let mut device = tun::create(&tun_config)
        .with_context(|| format!("failed to create TUN interface {}", config.interface.name))?;
    let packet_information = device.has_packet_information();
    let (reader, writer) = device.split();

    Ok(TunDevice {
        reader,
        writer,
        packet_information,
    })
}

fn strip_packet_information(frame: &[u8], packet_information: bool) -> Option<&[u8]> {
    if packet_information {
        frame.get(PACKET_INFO_SIZE..)
    } else {
        Some(frame)
    }
}

fn add_packet_information<'a>(
    frame: &'a [u8],
    packet_information: bool,
    output: &'a mut [u8],
) -> &'a [u8] {
    if !packet_information {
        return frame;
    }

    let header = (libc::AF_INET as u32).to_be_bytes();
    output[..PACKET_INFO_SIZE].copy_from_slice(&header);
    output[PACKET_INFO_SIZE..PACKET_INFO_SIZE + frame.len()].copy_from_slice(frame);
    &output[..PACKET_INFO_SIZE + frame.len()]
}

/// Try to authenticate a handshake `frame` against any configured peer (using PSK).
/// Returns the peer name and the decrypted handshake payload.
fn decode_handshake_from_peers(frame: &[u8], router: &Router) -> Option<(String, Vec<u8>)> {
    for route in router.routes() {
        if let Some((_msg_type, payload)) = auth::decode_packet(frame, &route.peer.psk) {
            return Some((route.peer.name.clone(), payload));
        }
    }
    None
}

#[derive(Clone)]
struct Cleanup {
    routes: Arc<Mutex<Vec<InstalledRoute>>>,
    firewall: Arc<Mutex<Option<firewall::FirewallManager>>>,
}

impl Cleanup {
    fn run(&self) {
        let routes = self.routes.lock().unwrap();
        routing::cleanup_routes(&routes);
        let fw = self.firewall.lock().unwrap();
        if let Some(ref f) = *fw {
            f.cleanup();
        }
    }
}
