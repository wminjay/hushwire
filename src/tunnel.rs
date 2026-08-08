use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context;
use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use tracing::{debug, error, info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::{Config, TransportConfig};
use crate::firewall;
use crate::packet::Ipv4Packet;
use crate::router::{Peer, Router};
use crate::routing::{self, InstalledRoute};
use crate::state::PeerState;
use crate::transport;
use hushwire::auth;
use hushwire::noise::{self, Session};
use hushwire::replay;

const MAX_PACKET_SIZE: usize = 65_535;
const PACKET_INFO_SIZE: usize = 4;
const HANDSHAKE_RETRY_INTERVAL: Duration = Duration::from_secs(5);

struct PendingInitiator {
    state: noise::InitiatorState,
    message: Vec<u8>,
    last_sent: Instant,
}

struct CachedResponderHandshake {
    request: Vec<u8>,
    response: Vec<u8>,
}

#[derive(Default)]
struct SessionState {
    sessions: HashMap<String, Session>,
    pending_init: HashMap<String, PendingInitiator>,
    responder_cache: HashMap<String, CachedResponderHandshake>,
}

/// Per-peer session state, shared across threads.
///
/// Holds the active session (if handshake completed) keyed by peer name.
/// The sender thread reads `send_key` + `session_id` to encrypt data; the
/// receiver thread looks up by `session_id` to find `recv_key`.
#[derive(Default)]
struct SessionManager {
    inner: Mutex<SessionState>,
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
        let state = self.inner.lock().unwrap();
        let session = state.sessions.get(peer_name)?;
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
        let state = self.inner.lock().unwrap();
        for (peer_name, session) in &state.sessions {
            if &session.session_id == session_id {
                return Some((session.recv_key, peer_name.clone()));
            }
        }
        None
    }

    /// Store an initiator-side session, replacing any prior responder cache.
    fn store_initiator(&self, peer_name: &str, session: Session) {
        let mut state = self.inner.lock().unwrap();
        state.sessions.insert(peer_name.to_string(), session);
        state.responder_cache.remove(peer_name);
    }

    /// Store a responder-side session and cache its response. Retransmitted
    /// copies of the same msg1 must receive the same msg2; generating a new
    /// responder session for every retry can leave the two sides on different
    /// keys when responses are delayed or reordered.
    fn store_responder(
        &self,
        peer_name: &str,
        session: Session,
        request: Vec<u8>,
        response: Vec<u8>,
    ) {
        let mut state = self.inner.lock().unwrap();
        state.sessions.insert(peer_name.to_string(), session);
        state.responder_cache.insert(
            peer_name.to_string(),
            CachedResponderHandshake { request, response },
        );
    }

    fn cached_responder_response(&self, peer_name: &str, request: &[u8]) -> Option<Vec<u8>> {
        let state = self.inner.lock().unwrap();
        let cached = state.responder_cache.get(peer_name)?;
        (cached.request == request).then(|| cached.response.clone())
    }

    /// Start a new initiator handshake, or retransmit the exact same msg1 when
    /// its response has not arrived within the retry interval.
    fn start_or_retry_handshake(
        &self,
        peer_name: &str,
        local_static: &StaticSecret,
        remote_static_pub: &PublicKey,
        psk: &[u8; 32],
        now: Instant,
    ) -> Option<Vec<u8>> {
        let mut state = self.inner.lock().unwrap();

        if state
            .sessions
            .get(peer_name)
            .is_some_and(|session| !session.needs_rekey())
        {
            return None;
        }
        // A session that reached its rekey threshold must not continue to
        // suppress a fresh handshake.
        state.sessions.remove(peer_name);
        state.responder_cache.remove(peer_name);

        if let Some(pending) = state.pending_init.get_mut(peer_name) {
            if now.saturating_duration_since(pending.last_sent) < HANDSHAKE_RETRY_INTERVAL {
                return None;
            }
            pending.last_sent = now;
            return Some(pending.message.clone());
        }

        let handshake = noise::initiator_start(local_static, remote_static_pub, psk);
        let (message, initiator_state) = handshake.into_parts();
        state.pending_init.insert(
            peer_name.to_string(),
            PendingInitiator {
                state: initiator_state,
                message: message.clone(),
                last_sent: now,
            },
        );
        Some(message)
    }

    /// Take a pending initiator handshake state (consumes it).
    fn take_pending_init(&self, peer_name: &str) -> Option<noise::InitiatorState> {
        let mut state = self.inner.lock().unwrap();
        state
            .pending_init
            .remove(peer_name)
            .map(|pending| pending.state)
    }

    /// Check if a pending initiator handshake exists for a peer.
    fn has_pending_init(&self, peer_name: &str) -> bool {
        self.inner
            .lock()
            .unwrap()
            .pending_init
            .contains_key(peer_name)
    }

    fn has_active_session(&self, peer_name: &str) -> bool {
        self.inner
            .lock()
            .unwrap()
            .sessions
            .get(peer_name)
            .is_some_and(|session| !session.needs_rekey())
    }

    /// Discard all cryptographic state for a peer before recovery. Keeping an
    /// old session after the remote process restarted prevents a new handshake
    /// because both sides continue speaking with unrelated session IDs/keys.
    fn invalidate_peer(&self, peer_name: &str) -> bool {
        let mut state = self.inner.lock().unwrap();
        let removed_session = state.sessions.remove(peer_name).is_some();
        let removed_pending = state.pending_init.remove(peer_name).is_some();
        state.responder_cache.remove(peer_name);
        removed_session || removed_pending
    }
}

pub fn run(config: Config, exit_node: bool) -> anyhow::Result<()> {
    let transport_kind = config.interface.transport;
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

    normalize_shutdown_signal_state().context("preparing shutdown signal handlers")?;
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
            udp_rebind_after = route.peer.udp_rebind_after,
            session_timeout = route.peer.session_timeout,
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
    let static_for_keepalive = local_static.clone();

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
                    // No active session — initiate (or retry) the Noise
                    // handshake, then drop this packet until it completes.
                    send_handshake_init(
                        &sessions_for_sender,
                        &static_for_sender,
                        &route.peer,
                        &state_for_sender,
                        transport_writer.as_ref(),
                        Instant::now(),
                    );
                    continue;
                }
            };

            let encoded = auth::encode_packet(frame, &send_key, auth::MsgType::Data, &session_id);
            let Some(endpoint) =
                resolve_endpoint(&state_for_sender, &route.peer.name, route.peer.endpoint)
            else {
                warn!(
                    peer = %route.peer.name,
                    configured_endpoint = %route.peer.endpoint,
                    "cannot send data without a usable configured or learned endpoint"
                );
                continue;
            };
            if let Err(error) = transport_writer.send_to(&encoded, endpoint) {
                error!(
                    %error,
                    peer = %route.peer.name,
                    endpoint = %endpoint,
                    bytes = size,
                    "failed to send transport packet"
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

                        // A retried msg1 must receive the original msg2. If we
                        // generated a fresh responder session for the same
                        // initiator state, reordered responses could make each
                        // side install a different key pair.
                        if let Some(response) =
                            sessions_for_receiver.cached_responder_response(&peer_name, &payload)
                        {
                            let hs_packet = auth::encode_packet(
                                &response,
                                &route.peer.psk,
                                auth::MsgType::HandshakeResponse,
                                &[0u8; auth::SESSION_ID_SIZE],
                            );
                            match transport.send_to(&hs_packet, source) {
                                Ok(_) => debug!(
                                    peer = %peer_name,
                                    source = %source,
                                    "re-sent cached handshake response"
                                ),
                                Err(error) => warn!(
                                    %error,
                                    peer = %peer_name,
                                    "failed to re-send cached handshake response"
                                ),
                            }
                            state_for_receiver.record_keepalive(&peer_name, source);
                            continue;
                        }

                        let hs = noise::responder_respond(
                            &static_for_receiver,
                            &route.peer.psk,
                            &payload,
                        );
                        if let Some(hs) = hs {
                            let response = hs.message;
                            // Store the new session and enough handshake state
                            // to answer an identical retransmission safely.
                            sessions_for_receiver.store_responder(
                                &peer_name,
                                hs.session,
                                payload.clone(),
                                response.clone(),
                            );
                            // Reset replay filter for this peer (new session = new nonce space).
                            replay.insert(peer_name.clone(), replay::ReplayFilter::new());
                            // Send msg2 back.
                            let hs_packet = auth::encode_packet(
                                &response,
                                &route.peer.psk,
                                auth::MsgType::HandshakeResponse,
                                &[0u8; auth::SESSION_ID_SIZE],
                            );
                            if let Err(e) = transport.send_to(&hs_packet, source) {
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
                            sessions_for_receiver.store_initiator(&peer_name, session);
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
                    if payload == auth::KEEPALIVE_PROBE_PAYLOAD {
                        let Some((send_key, session_id)) =
                            sessions_for_receiver.get_send_key(&peer_name)
                        else {
                            debug!(peer = %peer_name, "cannot acknowledge keepalive probe without an active send session");
                            continue;
                        };
                        let acknowledgement = auth::encode_packet(
                            auth::KEEPALIVE_ACK_PAYLOAD,
                            &send_key,
                            auth::MsgType::Keepalive,
                            &session_id,
                        );
                        match transport.send_to(&acknowledgement, source) {
                            Ok(_) => {
                                state_for_receiver.record_tx(&peer_name, acknowledgement.len());
                                debug!(peer = %peer_name, endpoint = %source, "acknowledged keepalive probe");
                            }
                            Err(error) => {
                                warn!(%error, peer = %peer_name, endpoint = %source, "failed to acknowledge keepalive probe");
                            }
                        }
                    } else if !payload.is_empty() && payload != auth::KEEPALIVE_ACK_PAYLOAD {
                        debug!(peer = %peer_name, bytes = payload.len(), "ignored unknown keepalive payload");
                    }
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
        // A UDP rebind affects every peer on the shared socket, so its rate
        // limit is interface-wide. Session-only recovery is independent per
        // peer (notably for TCP connections).
        let mut last_udp_rebind_attempt: Option<Instant> = None;
        let mut last_session_recovery_attempt: HashMap<String, Instant> = HashMap::new();
        loop {
            thread::sleep(Duration::from_secs(1));
            let now = Instant::now();
            let snapshot = state_for_keepalive.snapshot();
            let mut checked_peers = HashSet::new();
            let mut rebound = false;

            // A lost handshake response used to leave pending_init occupied
            // forever. Retry the same msg1 on a timer even when the triggering
            // TUN packet was a one-off and no further traffic arrives.
            let mut handshake_peers = HashSet::new();
            for route in router_for_keepalive.routes() {
                if !handshake_peers.insert(route.peer.name.clone())
                    || !sessions_for_keepalive.has_pending_init(&route.peer.name)
                {
                    continue;
                }
                send_handshake_init(
                    &sessions_for_keepalive,
                    &static_for_keepalive,
                    &route.peer,
                    &state_for_keepalive,
                    keepalive_transport.as_ref(),
                    now,
                );
            }

            // Active probes turn last_seen into a bidirectional health signal.
            // UDP recovery optionally changes the source port; TCP recovery
            // keeps the listener but must still discard the stale Noise
            // session that a restarted peer no longer knows about.
            for route in router_for_keepalive.routes() {
                let Some(policy) = recovery_policy(
                    transport_kind,
                    route.peer.udp_rebind_after,
                    route.peer.session_timeout,
                ) else {
                    continue;
                };
                if !checked_peers.insert(route.peer.name.clone())
                    || !last_sent.contains_key(&route.peer.name)
                    || !sessions_for_keepalive.has_active_session(&route.peer.name)
                {
                    continue;
                }

                let Some(stats) = snapshot.get(&route.peer.name) else {
                    continue;
                };
                let Some(last_seen) = stats.last_seen else {
                    continue;
                };
                let last_attempt = if policy.rebind_udp {
                    last_udp_rebind_attempt
                } else {
                    last_session_recovery_attempt.get(&route.peer.name).copied()
                };
                if !recovery_due(now, last_seen, last_attempt, policy.timeout) {
                    continue;
                }

                if policy.rebind_udp {
                    last_udp_rebind_attempt = Some(now);
                    match keepalive_transport.rebind_to_ephemeral() {
                        Ok(Some(result)) => {
                            warn!(
                                peer = %route.peer.name,
                                silence_seconds = now.duration_since(last_seen).as_secs(),
                                previous_listen = %result.previous,
                                current_listen = %result.current,
                                "no authenticated keepalive response; rebound UDP socket to recover the NAT path"
                            );
                            rebound = true;
                        }
                        Ok(None) => {
                            error!(peer = %route.peer.name, "configured UDP rebind is unsupported by the active transport");
                        }
                        Err(error) => {
                            warn!(%error, peer = %route.peer.name, "failed to rebind UDP socket after peer liveness timeout");
                        }
                    }
                } else {
                    last_session_recovery_attempt.insert(route.peer.name.clone(), now);
                    warn!(
                        peer = %route.peer.name,
                        transport = ?transport_kind,
                        silence_seconds = now.duration_since(last_seen).as_secs(),
                        "no authenticated keepalive response; session recovery timeout reached"
                    );
                }

                // A remote process restart destroys its in-memory session.
                // Keeping our old key would make all new handshakes impossible
                // until this process is manually restarted as well.
                let had_stale_state = sessions_for_keepalive.invalidate_peer(&route.peer.name);
                warn!(
                    peer = %route.peer.name,
                    had_stale_state,
                    "peer liveness timeout invalidated the old session; starting a fresh handshake"
                );
                send_handshake_init(
                    &sessions_for_keepalive,
                    &static_for_keepalive,
                    &route.peer,
                    &state_for_keepalive,
                    keepalive_transport.as_ref(),
                    now,
                );
                break;
            }

            // A rebind affects the interface-wide socket. Immediately notify
            // every peer with an active session so learned endpoints roam to
            // the fresh port, even if periodic keepalives are disabled there.
            let mut sent_peers = HashSet::new();
            for route in router_for_keepalive.routes() {
                if !sent_peers.insert(route.peer.name.clone()) {
                    continue;
                }
                let interval = Duration::from_secs(route.peer.persistent_keepalive as u64);
                let recovery_enabled = recovery_policy(
                    transport_kind,
                    route.peer.udp_rebind_after,
                    route.peer.session_timeout,
                )
                .is_some();
                let should_send = keepalive_should_send(
                    now,
                    last_sent.get(&route.peer.name).copied(),
                    interval,
                    recovery_enabled,
                    rebound,
                );
                if !should_send {
                    if !interval.is_zero() {
                        last_sent.entry(route.peer.name.clone()).or_insert(now);
                    }
                    continue;
                }

                // Use the session key if available. Cold-start handshakes are
                // initiated by real TUN traffic and then retried by this loop.
                let Some((send_key, session_id)) =
                    sessions_for_keepalive.get_send_key(&route.peer.name)
                else {
                    if !recovery_enabled {
                        last_sent.insert(route.peer.name.clone(), now);
                    }
                    continue;
                };
                let payload = if recovery_enabled {
                    auth::KEEPALIVE_PROBE_PAYLOAD
                } else {
                    b""
                };
                let packet =
                    auth::encode_packet(payload, &send_key, auth::MsgType::Keepalive, &session_id);
                let Some(endpoint) =
                    resolve_endpoint(&state_for_keepalive, &route.peer.name, route.peer.endpoint)
                else {
                    warn!(
                        peer = %route.peer.name,
                        configured_endpoint = %route.peer.endpoint,
                        "cannot send keepalive without a usable configured or learned endpoint"
                    );
                    last_sent.insert(route.peer.name.clone(), now);
                    continue;
                };
                match keepalive_transport.send_to(&packet, endpoint) {
                    Ok(_) => state_for_keepalive.record_tx(&route.peer.name, packet.len()),
                    Err(error) => {
                        warn!(%error, peer = %route.peer.name, endpoint = %endpoint, "failed to send keepalive");
                    }
                }
                last_sent.insert(route.peer.name.clone(), now);
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

fn send_handshake_init(
    sessions: &SessionManager,
    local_static: &StaticSecret,
    peer: &Peer,
    state: &PeerState,
    transport: &dyn transport::PacketTransport,
    now: Instant,
) {
    // `0.0.0.0:<port>` and `[::]:<port>` are valid listen addresses but not
    // peer destinations. On some systems sending to an unspecified address
    // loops the datagram back to localhost, creating a false self-session.
    let Some(endpoint) = resolve_endpoint(state, &peer.name, peer.endpoint) else {
        debug!(
            peer = %peer.name,
            configured_endpoint = %peer.endpoint,
            "cannot initiate handshake until a usable peer endpoint is learned"
        );
        return;
    };

    let Some(message) = sessions.start_or_retry_handshake(
        &peer.name,
        local_static,
        &peer.public_key,
        &peer.psk,
        now,
    ) else {
        return;
    };

    let packet = auth::encode_packet(
        &message,
        &peer.psk,
        auth::MsgType::HandshakeInit,
        &[0u8; auth::SESSION_ID_SIZE],
    );
    match transport.send_to(&packet, endpoint) {
        Ok(_) => debug!(
            peer = %peer.name,
            endpoint = %endpoint,
            "sent handshake init; data waits for session establishment"
        ),
        Err(error) => warn!(
            %error,
            peer = %peer.name,
            endpoint = %endpoint,
            "failed to send handshake init"
        ),
    }
}

/// Resolve the destination endpoint for outbound packets to a peer.
///
/// Prefers the address learned from a recent inbound packet (NAT traversal /
/// roaming) and falls back to the statically configured endpoint when no
/// packet has been received from the peer yet. This lets peers behind NAT
/// establish connectivity by sending keepalives: once the server sees a
/// packet from the peer's real source address, it replies there instead of
/// the (possibly unreachable) configured endpoint.
fn resolve_endpoint(
    state: &PeerState,
    peer_name: &str,
    configured: SocketAddr,
) -> Option<SocketAddr> {
    let snapshot = state.snapshot();
    snapshot
        .get(peer_name)
        .and_then(|stats| stats.current_endpoint)
        .filter(|endpoint| usable_peer_endpoint(*endpoint))
        .or_else(|| usable_peer_endpoint(configured).then_some(configured))
}

fn usable_peer_endpoint(endpoint: SocketAddr) -> bool {
    !endpoint.ip().is_unspecified() && endpoint.port() != 0
}

/// Privileged GUI launchers and non-interactive shells may leave termination
/// signals ignored or blocked in their children. Reset these signals before
/// signal-hook installs HushWire's handlers so GUI disconnect can always
/// trigger route, firewall, and TUN cleanup.
fn normalize_shutdown_signal_state() -> std::io::Result<()> {
    let shutdown_signals = [SIGHUP, SIGINT, SIGTERM];

    // SAFETY: all pointers refer to initialized local storage, the signal
    // numbers are platform constants, and this runs before HushWire spawns its
    // worker threads or installs its own signal handlers.
    unsafe {
        let mut signal_set: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(&mut signal_set) == -1 {
            return Err(std::io::Error::last_os_error());
        }

        for signal in shutdown_signals {
            if libc::signal(signal, libc::SIG_DFL) == libc::SIG_ERR {
                return Err(std::io::Error::last_os_error());
            }
            if libc::sigaddset(&mut signal_set, signal) == -1 {
                return Err(std::io::Error::last_os_error());
            }
        }

        let result = libc::pthread_sigmask(libc::SIG_UNBLOCK, &signal_set, std::ptr::null_mut());
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result));
        }
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecoveryPolicy {
    timeout: Duration,
    rebind_udp: bool,
}

fn recovery_policy(
    transport: TransportConfig,
    udp_rebind_after: u16,
    session_timeout: u64,
) -> Option<RecoveryPolicy> {
    if transport == TransportConfig::Udp && udp_rebind_after > 0 {
        return Some(RecoveryPolicy {
            timeout: Duration::from_secs(u64::from(udp_rebind_after)),
            rebind_udp: true,
        });
    }
    (session_timeout > 0).then_some(RecoveryPolicy {
        timeout: Duration::from_secs(session_timeout),
        rebind_udp: false,
    })
}

fn recovery_due(
    now: Instant,
    last_seen: Instant,
    last_recovery_attempt: Option<Instant>,
    timeout: Duration,
) -> bool {
    let health_baseline = last_recovery_attempt
        .map(|attempt| attempt.max(last_seen))
        .unwrap_or(last_seen);
    now.saturating_duration_since(health_baseline) >= timeout
}

fn keepalive_should_send(
    now: Instant,
    last_sent: Option<Instant>,
    interval: Duration,
    recovery_enabled: bool,
    rebound: bool,
) -> bool {
    if rebound {
        // Rebinding changes the interface-wide source port, so even peers with
        // periodic keepalives disabled need a one-shot authenticated packet.
        return true;
    }
    if interval.is_zero() {
        return false;
    }
    last_sent
        .map(|sent| now.saturating_duration_since(sent) >= interval)
        // Recovery-enabled peers probe as soon as their session becomes
        // available, establishing a health baseline.
        .unwrap_or(recovery_enabled)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_managed_handshake(
        initiator: &SessionManager,
        responder: &SessionManager,
        initiator_static: &StaticSecret,
        responder_static: &StaticSecret,
        responder_public: &PublicKey,
        psk: &[u8; 32],
        now: Instant,
    ) -> [u8; auth::SESSION_ID_SIZE] {
        let request = initiator
            .start_or_retry_handshake("peer", initiator_static, responder_public, psk, now)
            .expect("handshake request");
        let response =
            noise::responder_respond(responder_static, psk, &request).expect("handshake response");
        let responder_send_key = response.session.send_key;
        let responder_recv_key = response.session.recv_key;
        let response_message = response.message.clone();
        responder.store_responder("peer", response.session, request, response_message.clone());

        let pending = initiator
            .take_pending_init("peer")
            .expect("pending initiator state");
        let session = noise::initiator_finalize(
            pending,
            initiator_static,
            responder_public,
            &response_message,
        )
        .expect("finalized initiator session");
        assert_eq!(session.send_key, responder_recv_key);
        assert_eq!(session.recv_key, responder_send_key);
        let session_id = session.session_id;
        initiator.store_initiator("peer", session);

        assert!(initiator.has_active_session("peer"));
        assert!(responder.has_active_session("peer"));
        session_id
    }

    #[test]
    fn one_sided_restart_can_replace_the_surviving_old_session() {
        let initiator_static = StaticSecret::from([0x11; 32]);
        let responder_static = StaticSecret::from([0x22; 32]);
        let responder_public = PublicKey::from(&responder_static);
        let psk = [0x33; 32];
        let initiator = SessionManager::new();
        let responder_before_restart = SessionManager::new();
        let now = Instant::now();

        let old_session_id = complete_managed_handshake(
            &initiator,
            &responder_before_restart,
            &initiator_static,
            &responder_static,
            &responder_public,
            &psk,
            now,
        );

        // The responder process restarts and loses all in-memory crypto state.
        let responder_after_restart = SessionManager::new();
        assert!(initiator.invalidate_peer("peer"));
        assert!(!initiator.has_active_session("peer"));
        assert!(initiator
            .get_recv_key_by_session_id(&old_session_id)
            .is_none());

        complete_managed_handshake(
            &initiator,
            &responder_after_restart,
            &initiator_static,
            &responder_static,
            &responder_public,
            &psk,
            now + Duration::from_secs(1),
        );
    }

    #[test]
    fn lost_handshake_response_retries_the_same_exchange() {
        let initiator_static = StaticSecret::from([0x44; 32]);
        let responder_static = StaticSecret::from([0x55; 32]);
        let responder_public = PublicKey::from(&responder_static);
        let psk = [0x66; 32];
        let initiator = SessionManager::new();
        let responder = SessionManager::new();
        let now = Instant::now();

        let first_request = initiator
            .start_or_retry_handshake("peer", &initiator_static, &responder_public, &psk, now)
            .expect("initial request");
        let response =
            noise::responder_respond(&responder_static, &psk, &first_request).expect("response");
        let responder_send_key = response.session.send_key;
        let responder_recv_key = response.session.recv_key;
        let response_message = response.message.clone();
        responder.store_responder(
            "peer",
            response.session,
            first_request.clone(),
            response_message.clone(),
        );

        // Simulate dropping msg2. The retry timer must neither spin nor create
        // a new initiator ephemeral key.
        assert!(initiator
            .start_or_retry_handshake(
                "peer",
                &initiator_static,
                &responder_public,
                &psk,
                now + (HANDSHAKE_RETRY_INTERVAL - Duration::from_millis(1)),
            )
            .is_none());
        let retry = initiator
            .start_or_retry_handshake(
                "peer",
                &initiator_static,
                &responder_public,
                &psk,
                now + HANDSHAKE_RETRY_INTERVAL,
            )
            .expect("timed retry");
        assert_eq!(retry, first_request);

        // The responder also returns its cached msg2 for the duplicate msg1,
        // preserving one session even if packets are delayed or reordered.
        let cached_response = responder
            .cached_responder_response("peer", &retry)
            .expect("cached response");
        assert_eq!(cached_response, response_message);

        let pending = initiator
            .take_pending_init("peer")
            .expect("pending initiator state");
        let session = noise::initiator_finalize(
            pending,
            &initiator_static,
            &responder_public,
            &cached_response,
        )
        .expect("finalized retry");
        assert_eq!(session.send_key, responder_recv_key);
        assert_eq!(session.recv_key, responder_send_key);
        initiator.store_initiator("peer", session);
        assert!(!initiator.has_pending_init("peer"));
        assert!(initiator.has_active_session("peer"));
    }

    #[test]
    fn unspecified_configured_endpoint_requires_a_learned_peer_address() {
        let state = PeerState::new();
        let configured: SocketAddr = "0.0.0.0:27777".parse().unwrap();
        assert_eq!(resolve_endpoint(&state, "peer", configured), None);
        assert_eq!(
            resolve_endpoint(&state, "peer", "[::]:27777".parse().unwrap()),
            None
        );
        assert_eq!(
            resolve_endpoint(&state, "peer", "203.0.113.10:0".parse().unwrap()),
            None
        );

        let learned: SocketAddr = "198.51.100.24:45123".parse().unwrap();
        state.record_keepalive("peer", learned);
        assert_eq!(resolve_endpoint(&state, "peer", configured), Some(learned));
    }

    #[test]
    fn routable_configured_endpoint_is_used_before_roaming_is_learned() {
        let state = PeerState::new();
        let configured: SocketAddr = "203.0.113.10:27777".parse().unwrap();
        assert_eq!(
            resolve_endpoint(&state, "peer", configured),
            Some(configured)
        );
    }

    #[test]
    fn recovery_becomes_due_after_inbound_silence() {
        let now = Instant::now();
        let last_seen = now.checked_sub(Duration::from_secs(91)).unwrap();
        assert!(recovery_due(now, last_seen, None, Duration::from_secs(90)));
    }

    #[test]
    fn recent_inbound_packet_cancels_recovery() {
        let now = Instant::now();
        let last_seen = now.checked_sub(Duration::from_secs(5)).unwrap();
        let old_attempt = now.checked_sub(Duration::from_secs(120));
        assert!(!recovery_due(
            now,
            last_seen,
            old_attempt,
            Duration::from_secs(90)
        ));
    }

    #[test]
    fn failed_recovery_attempt_is_rate_limited() {
        let now = Instant::now();
        let last_seen = now.checked_sub(Duration::from_secs(180)).unwrap();
        let recent_attempt = now.checked_sub(Duration::from_secs(5));
        assert!(!recovery_due(
            now,
            last_seen,
            recent_attempt,
            Duration::from_secs(90)
        ));
    }

    #[test]
    fn udp_rebind_policy_takes_precedence_over_session_only_timeout() {
        assert_eq!(
            recovery_policy(TransportConfig::Udp, 90, 30),
            Some(RecoveryPolicy {
                timeout: Duration::from_secs(90),
                rebind_udp: true,
            })
        );
    }

    #[test]
    fn tcp_recovery_policy_invalidates_session_without_udp_rebind() {
        assert_eq!(
            recovery_policy(TransportConfig::Tcp, 0, 15),
            Some(RecoveryPolicy {
                timeout: Duration::from_secs(15),
                rebind_udp: false,
            })
        );
    }

    #[test]
    fn zero_timeouts_disable_session_recovery() {
        assert_eq!(recovery_policy(TransportConfig::Udp, 0, 0), None);
        assert_eq!(recovery_policy(TransportConfig::Tcp, 0, 0), None);
    }

    #[test]
    fn rebind_notifies_peer_with_periodic_keepalive_disabled() {
        assert!(keepalive_should_send(
            Instant::now(),
            None,
            Duration::ZERO,
            false,
            true
        ));
    }

    #[test]
    fn peer_without_keepalive_stays_silent_without_rebind() {
        assert!(!keepalive_should_send(
            Instant::now(),
            None,
            Duration::ZERO,
            false,
            false
        ));
    }
}
