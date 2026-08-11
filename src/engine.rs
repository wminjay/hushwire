//! Platform-independent cryptographic session state.
//!
//! This module owns handshake, rekey, replay-protected transport encryption,
//! and one-sided restart recovery. It performs no TUN, socket, route,
//! firewall, signal, or process management, so both the CLI adapter and a
//! Network Extension can drive it.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::auth;
use crate::config::{self, Config};
use crate::noise::{self, Session};
use crate::packet::{Ipv4Packet, PacketError};
use crate::router::{Peer, Router, RouterError};
use crate::state::{PeerState, PeerStats};

pub const HANDSHAKE_RETRY_INTERVAL: Duration = Duration::from_secs(5);
pub const HANDSHAKE_ATTEMPT_LIFETIME: Duration = Duration::from_secs(30);
pub const HANDSHAKE_CACHE_LIFETIME: Duration = Duration::from_secs(60);

struct PendingInitiator {
    handshake_id: [u8; auth::SESSION_ID_SIZE],
    state: noise::InitiatorState,
    packet: Vec<u8>,
    created_at: Instant,
    last_sent: Instant,
}

struct CachedResponderHandshake {
    handshake_id: [u8; auth::SESSION_ID_SIZE],
    request: Vec<u8>,
    response: Vec<u8>,
    created_at: Instant,
}

#[derive(Default)]
struct SessionState {
    sessions: HashMap<String, Session>,
    previous_sessions: HashMap<String, Session>,
    responder_candidates: HashMap<String, Session>,
    pending_init: HashMap<String, PendingInitiator>,
    responder_cache: HashMap<String, CachedResponderHandshake>,
    inbound_recovery_preference: HashSet<String>,
}

pub struct DecryptedTransport {
    pub peer_name: String,
    pub msg_type: auth::MsgType,
    pub payload: Vec<u8>,
    pub promoted_responder_session: bool,
}

/// Per-peer session state, shared across threads.
///
/// Holds one active session per peer, one receive-only previous session, and a
/// responder candidate. A candidate cannot replace the active session until
/// the initiator proves it received msg2 by sending an authenticated transport
/// packet. The previous session remains replay-protected and expires at the
/// normal hard reject deadline, allowing in-flight packets to survive rekey.
#[derive(Default)]
pub struct SessionManager {
    inner: Mutex<SessionState>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn encrypt_for_peer(
        &self,
        peer_name: &str,
        msg_type: auth::MsgType,
        payload: &[u8],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, noise::NoiseError> {
        let mut state = self.inner.lock().unwrap();
        state
            .previous_sessions
            .retain(|_, session| !session.is_expired(now));
        if state
            .sessions
            .get(peer_name)
            .is_some_and(|session| session.is_expired(now))
        {
            state.sessions.remove(peer_name);
        }
        state
            .sessions
            .get_mut(peer_name)
            .map(|session| session.encrypt(msg_type, payload))
            .transpose()
    }

    pub fn decrypt_transport(
        &self,
        session_id: &[u8; auth::SESSION_ID_SIZE],
        counter: u64,
        ciphertext: &[u8],
        now: Instant,
    ) -> Result<Option<DecryptedTransport>, noise::NoiseError> {
        let mut state = self.inner.lock().unwrap();
        state.sessions.retain(|_, session| !session.is_expired(now));
        state
            .previous_sessions
            .retain(|_, session| !session.is_expired(now));
        state
            .responder_candidates
            .retain(|_, session| !session.is_expired(now));

        let active_peer = state
            .sessions
            .iter()
            .find_map(|(peer, session)| (&session.session_id == session_id).then(|| peer.clone()));
        if let Some(peer_name) = active_peer {
            let (msg_type, payload) = state
                .sessions
                .get_mut(&peer_name)
                .expect("active session disappeared while locked")
                .decrypt(session_id, counter, ciphertext)?;
            return Ok(Some(DecryptedTransport {
                peer_name,
                msg_type,
                payload,
                promoted_responder_session: false,
            }));
        }

        let previous_peer = state
            .previous_sessions
            .iter()
            .find_map(|(peer, session)| (&session.session_id == session_id).then(|| peer.clone()));
        if let Some(peer_name) = previous_peer {
            let (msg_type, payload) = state
                .previous_sessions
                .get_mut(&peer_name)
                .expect("previous session disappeared while locked")
                .decrypt(session_id, counter, ciphertext)?;
            return Ok(Some(DecryptedTransport {
                peer_name,
                msg_type,
                payload,
                promoted_responder_session: false,
            }));
        }

        let candidate_peer = state
            .responder_candidates
            .iter()
            .find_map(|(peer, session)| (&session.session_id == session_id).then(|| peer.clone()));
        let Some(peer_name) = candidate_peer else {
            return Ok(None);
        };
        let (msg_type, payload) = state
            .responder_candidates
            .get_mut(&peer_name)
            .expect("candidate session disappeared while locked")
            .decrypt(session_id, counter, ciphertext)?;
        let session = state
            .responder_candidates
            .remove(&peer_name)
            .expect("authenticated candidate disappeared while locked");
        install_active_session(&mut state, &peer_name, session);
        state.pending_init.remove(&peer_name);
        state.responder_cache.remove(&peer_name);
        Ok(Some(DecryptedTransport {
            peer_name,
            msg_type,
            payload,
            promoted_responder_session: true,
        }))
    }

    pub fn store_responder_candidate(
        &self,
        peer_name: &str,
        session: Session,
        handshake_id: [u8; auth::SESSION_ID_SIZE],
        request: Vec<u8>,
        response: Vec<u8>,
    ) -> bool {
        let mut state = self.inner.lock().unwrap();
        if session_id_in_use(&state, &session.session_id) {
            return false;
        }
        // `accept_inbound_initiation` already selected the remote exchange.
        // Clear any local rekey that raced between accepting msg1 and storing
        // its responder candidate, so two fresh sessions cannot replace each
        // other back-to-back.
        state.pending_init.remove(peer_name);
        state
            .responder_candidates
            .insert(peer_name.to_string(), session);
        state.responder_cache.insert(
            peer_name.to_string(),
            CachedResponderHandshake {
                handshake_id,
                request,
                response,
                created_at: Instant::now(),
            },
        );
        true
    }

    pub fn cached_responder_response(
        &self,
        peer_name: &str,
        handshake_id: &[u8; auth::SESSION_ID_SIZE],
        request: &[u8],
    ) -> Option<Vec<u8>> {
        let mut state = self.inner.lock().unwrap();
        let expired = state
            .responder_cache
            .get(peer_name)
            .is_some_and(|cached| cached.created_at.elapsed() >= HANDSHAKE_CACHE_LIFETIME);
        if expired {
            state.responder_cache.remove(peer_name);
            state.responder_candidates.remove(peer_name);
            return None;
        }
        let cached = state.responder_cache.get(peer_name)?;
        (cached.handshake_id == *handshake_id && cached.request == request)
            .then(|| cached.response.clone())
    }

    /// Resolve simultaneous initiation deterministically. Both sides compare
    /// the same two random IDs; the smaller ID remains the initiator.
    ///
    /// A peer with no configured destination is intentionally passive and
    /// relies on a learned roaming endpoint. After explicit stale-session
    /// invalidation, its locally pending recovery exchange can still target
    /// the old learned endpoint. In that one recovery state, an authenticated
    /// inbound initiation wins. Normal rekeys always retain the symmetric ID
    /// comparison so both peers cannot become responders simultaneously.
    pub fn accept_inbound_initiation(
        &self,
        peer_name: &str,
        remote_handshake_id: &[u8; auth::SESSION_ID_SIZE],
        passive_peer: bool,
    ) -> bool {
        let mut state = self.inner.lock().unwrap();
        if state
            .pending_init
            .get(peer_name)
            .is_some_and(|pending| pending.created_at.elapsed() >= HANDSHAKE_ATTEMPT_LIFETIME)
        {
            state.pending_init.remove(peer_name);
        }
        if passive_peer && state.inbound_recovery_preference.remove(peer_name) {
            state.pending_init.remove(peer_name);
            return true;
        }
        let Some(local) = state.pending_init.get(peer_name) else {
            return true;
        };
        if local.handshake_id <= *remote_handshake_id {
            return false;
        }
        state.pending_init.remove(peer_name);
        true
    }

    /// Start a new initiator handshake, or retransmit the exact same msg1 when
    /// its response has not arrived within the retry interval.
    pub fn start_or_retry_handshake(
        &self,
        peer_name: &str,
        local_static: &StaticSecret,
        remote_static_pub: &PublicKey,
        psk: &[u8; 32],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, noise::NoiseError> {
        let mut state = self.inner.lock().unwrap();

        if state.pending_init.get(peer_name).is_some_and(|pending| {
            now.saturating_duration_since(pending.created_at) >= HANDSHAKE_ATTEMPT_LIFETIME
        }) {
            state.pending_init.remove(peer_name);
        }
        if let Some(pending) = state.pending_init.get_mut(peer_name) {
            if now.saturating_duration_since(pending.last_sent) < HANDSHAKE_RETRY_INTERVAL {
                return Ok(None);
            }
            pending.last_sent = now;
            return Ok(Some(pending.packet.clone()));
        }

        let candidate_expired = state
            .responder_candidates
            .get(peer_name)
            .is_some_and(|session| session.is_expired(now));
        if candidate_expired {
            state.responder_candidates.remove(peer_name);
            state.responder_cache.remove(peer_name);
        }
        // A valid inbound rekey is already waiting for authenticated
        // confirmation. Keep sending through the current session meanwhile,
        // but do not start a competing local exchange.
        if state.responder_candidates.contains_key(peer_name) {
            return Ok(None);
        }

        if state
            .sessions
            .get(peer_name)
            .is_some_and(|session| session.is_expired(now))
        {
            state.sessions.remove(peer_name);
        }
        if let Some(session) = state.sessions.get(peer_name) {
            if !session.should_rekey(now) {
                return Ok(None);
            }
        }

        let handshake = noise::initiator_start(local_static, remote_static_pub, psk)?;
        let (handshake_id, message, initiator_state) = handshake.into_parts();
        let packet =
            auth::encode_handshake(auth::PacketKind::HandshakeInit, &handshake_id, &message);
        state.pending_init.insert(
            peer_name.to_string(),
            PendingInitiator {
                handshake_id,
                state: initiator_state,
                packet: packet.clone(),
                created_at: now,
                last_sent: now,
            },
        );
        Ok(Some(packet))
    }

    pub fn finalize_initiator(
        &self,
        handshake_id: &[u8; auth::SESSION_ID_SIZE],
        response: &[u8],
    ) -> Result<Option<(String, Vec<u8>)>, noise::NoiseError> {
        let mut state = self.inner.lock().unwrap();
        let peer_name = state.pending_init.iter().find_map(|(peer, pending)| {
            (pending.handshake_id == *handshake_id).then(|| peer.clone())
        });
        let Some(peer_name) = peer_name else {
            return Ok(None);
        };
        let pending = state
            .pending_init
            .remove(&peer_name)
            .expect("pending initiator disappeared while locked");
        let mut session = noise::initiator_finalize(pending.state, response)?;
        if session_id_in_use(&state, &session.session_id) {
            return Err(noise::NoiseError::WrongSession);
        }
        let confirmation =
            session.encrypt(auth::MsgType::Keepalive, auth::KEEPALIVE_PROBE_PAYLOAD)?;
        install_active_session(&mut state, &peer_name, session);
        state.responder_candidates.remove(&peer_name);
        state.responder_cache.remove(&peer_name);
        Ok(Some((peer_name, confirmation)))
    }

    /// Check if a pending initiator handshake exists for a peer.
    pub fn has_pending_init(&self, peer_name: &str) -> bool {
        self.inner
            .lock()
            .unwrap()
            .pending_init
            .contains_key(peer_name)
    }

    pub fn has_active_session(&self, peer_name: &str) -> bool {
        let now = Instant::now();
        self.inner
            .lock()
            .unwrap()
            .sessions
            .get(peer_name)
            .is_some_and(|session| !session.is_expired(now))
    }

    /// Discard all cryptographic state for a peer before recovery. Keeping an
    /// old session after the remote process restarted prevents a new handshake
    /// because both sides continue speaking with unrelated session IDs/keys.
    pub fn invalidate_peer(&self, peer_name: &str) -> bool {
        let mut state = self.inner.lock().unwrap();
        let removed_session = state.sessions.remove(peer_name).is_some();
        let removed_previous = state.previous_sessions.remove(peer_name).is_some();
        let removed_candidate = state.responder_candidates.remove(peer_name).is_some();
        let removed_pending = state.pending_init.remove(peer_name).is_some();
        state.responder_cache.remove(peer_name);
        state
            .inbound_recovery_preference
            .insert(peer_name.to_string());
        removed_session || removed_previous || removed_candidate || removed_pending
    }

    /// Return the active wire-session identifier for diagnostics and tests.
    ///
    /// Session identifiers are not secret key material. Exposing the value
    /// lets platform adapters report session replacement without gaining
    /// access to encryption state.
    pub fn active_session_id(&self, peer_name: &str) -> Option<[u8; auth::SESSION_ID_SIZE]> {
        self.inner
            .lock()
            .unwrap()
            .sessions
            .get(peer_name)
            .map(|session| session.session_id)
    }
}

fn session_id_in_use(state: &SessionState, session_id: &[u8; auth::SESSION_ID_SIZE]) -> bool {
    state
        .sessions
        .iter()
        .chain(state.previous_sessions.iter())
        .chain(state.responder_candidates.iter())
        .any(|(_, session)| &session.session_id == session_id)
}

fn install_active_session(state: &mut SessionState, peer_name: &str, session: Session) {
    state.inbound_recovery_preference.remove(peer_name);
    if let Some(previous) = state.sessions.insert(peer_name.to_string(), session) {
        state
            .previous_sessions
            .insert(peer_name.to_string(), previous);
    }
}

/// A platform adapter operation produced by [`Engine`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EngineAction {
    /// Send an encoded HushWire frame through UDP, TCP, or another transport.
    SendTransport {
        peer_name: String,
        endpoint: SocketAddr,
        frame: Vec<u8>,
    },
    /// Deliver an authenticated IP packet to the platform packet interface.
    WriteIpPacket {
        peer_name: String,
        source: SocketAddr,
        packet: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

/// State changes suitable for logs and future GUI callbacks.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EngineEvent {
    HandshakeCompleted {
        peer_name: String,
        endpoint: SocketAddr,
        role: HandshakeRole,
    },
}

/// All work produced while processing one packet or timer event.
#[derive(Debug, Default)]
pub struct EngineOutput {
    pub actions: Vec<EngineAction>,
    pub events: Vec<EngineEvent>,
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("interface has an invalid private key")]
    InvalidPrivateKey,
    #[error(transparent)]
    Router(#[from] RouterError),
    #[error(transparent)]
    Packet(#[from] PacketError),
    #[error(transparent)]
    Noise(#[from] noise::NoiseError),
    #[error("unknown peer: {0}")]
    UnknownPeer(String),
}

/// Platform-independent HushWire packet engine.
///
/// The caller owns packet I/O and lifecycle. `Engine` owns only immutable
/// routing metadata, cryptographic sessions, roaming endpoint state, and peer
/// counters. All mutable state is internally synchronized so packetFlow and
/// transport callbacks may call it from different queues.
#[derive(Clone)]
pub struct Engine {
    router: Router,
    local_static: Arc<StaticSecret>,
    sessions: Arc<SessionManager>,
    peers: PeerState,
}

impl Engine {
    pub fn new(config: &Config) -> Result<Self, EngineError> {
        let router = Router::new(config)?;
        let local_static = config::decode_key(&config.interface.private_key)
            .ok_or(EngineError::InvalidPrivateKey)?;
        Ok(Self {
            router,
            local_static: Arc::new(StaticSecret::from(local_static)),
            sessions: Arc::new(SessionManager::new()),
            peers: PeerState::new(),
        })
    }

    /// Process one IP packet read from a TUN device or NEPacketTunnelFlow.
    pub fn process_outbound_ip(
        &self,
        packet: &[u8],
        now: Instant,
    ) -> Result<EngineOutput, EngineError> {
        let ipv4 = Ipv4Packet::parse(packet)?;
        let Some(route) = self.router.lookup(ipv4.destination()) else {
            return Ok(EngineOutput::default());
        };

        let peer = &route.peer;
        let mut output = EngineOutput::default();
        match self
            .sessions
            .encrypt_for_peer(&peer.name, auth::MsgType::Data, packet, now)
        {
            Ok(Some(frame)) => {
                // A young session produces no handshake. Once its soft rekey
                // threshold is reached, the replacement handshake and data
                // frame are emitted together.
                if let Some(action) = self.initiate_peer(peer, now)? {
                    output.actions.push(action);
                }
                if let Some(endpoint) = self.resolve_endpoint(peer) {
                    output.actions.push(EngineAction::SendTransport {
                        peer_name: peer.name.clone(),
                        endpoint,
                        frame,
                    });
                }
            }
            Ok(None) => {
                if let Some(action) = self.initiate_peer(peer, now)? {
                    output.actions.push(action);
                }
            }
            Err(_) => {
                self.sessions.invalidate_peer(&peer.name);
                if let Some(action) = self.initiate_peer(peer, now)? {
                    output.actions.push(action);
                }
            }
        }

        Ok(output)
    }

    /// Process one framed packet received from the configured transport.
    pub fn process_inbound_transport(
        &self,
        frame: &[u8],
        source: SocketAddr,
        now: Instant,
    ) -> Result<EngineOutput, EngineError> {
        let Some(parsed) = auth::decode_packet(frame) else {
            return Ok(EngineOutput::default());
        };
        let mut output = EngineOutput::default();

        match parsed {
            auth::ParsedPacket::Handshake {
                kind: auth::PacketKind::HandshakeInit,
                handshake_id,
                message,
            } => {
                let Some((peer_name, handshake)) =
                    self.decode_handshake_init(handshake_id, message)
                else {
                    return Ok(output);
                };

                if !self.sessions.accept_inbound_initiation(
                    &peer_name,
                    &handshake_id,
                    self.peer(&peer_name)
                        .is_some_and(|peer| !usable_peer_endpoint(peer.endpoint)),
                ) {
                    return Ok(output);
                }
                if let Some(response) =
                    self.sessions
                        .cached_responder_response(&peer_name, &handshake_id, message)
                {
                    output.actions.push(EngineAction::SendTransport {
                        peer_name,
                        endpoint: source,
                        frame: response,
                    });
                    return Ok(output);
                }

                let response = auth::encode_handshake(
                    auth::PacketKind::HandshakeResponse,
                    &handshake_id,
                    &handshake.message,
                );
                if self.sessions.store_responder_candidate(
                    &peer_name,
                    handshake.session,
                    handshake_id,
                    message.to_vec(),
                    response.clone(),
                ) {
                    output.actions.push(EngineAction::SendTransport {
                        peer_name,
                        endpoint: source,
                        frame: response,
                    });
                }
            }
            auth::ParsedPacket::Handshake {
                kind: auth::PacketKind::HandshakeResponse,
                handshake_id,
                message,
            } => {
                if let Some((peer_name, confirmation)) =
                    self.sessions.finalize_initiator(&handshake_id, message)?
                {
                    self.peers.record_keepalive(&peer_name, source);
                    output.actions.push(EngineAction::SendTransport {
                        peer_name: peer_name.clone(),
                        endpoint: source,
                        frame: confirmation,
                    });
                    output.events.push(EngineEvent::HandshakeCompleted {
                        peer_name,
                        endpoint: source,
                        role: HandshakeRole::Initiator,
                    });
                }
            }
            auth::ParsedPacket::Handshake { .. } => {}
            auth::ParsedPacket::Transport {
                session_id,
                counter,
                ciphertext,
            } => {
                let Some(decrypted) =
                    self.sessions
                        .decrypt_transport(&session_id, counter, ciphertext, now)?
                else {
                    return Ok(output);
                };
                let peer_name = decrypted.peer_name;
                if decrypted.promoted_responder_session {
                    output.events.push(EngineEvent::HandshakeCompleted {
                        peer_name: peer_name.clone(),
                        endpoint: source,
                        role: HandshakeRole::Responder,
                    });
                }

                match decrypted.msg_type {
                    auth::MsgType::Keepalive => {
                        self.peers.record_keepalive(&peer_name, source);
                        if decrypted.payload.as_slice() == auth::KEEPALIVE_PROBE_PAYLOAD {
                            if let Some(acknowledgement) = self.sessions.encrypt_for_peer(
                                &peer_name,
                                auth::MsgType::Keepalive,
                                auth::KEEPALIVE_ACK_PAYLOAD,
                                now,
                            )? {
                                output.actions.push(EngineAction::SendTransport {
                                    peer_name,
                                    endpoint: source,
                                    frame: acknowledgement,
                                });
                            }
                        }
                    }
                    auth::MsgType::Data => {
                        self.peers
                            .record_rx(&peer_name, source, decrypted.payload.len());
                        Ipv4Packet::parse(&decrypted.payload)?;
                        output.actions.push(EngineAction::WriteIpPacket {
                            peer_name,
                            source,
                            packet: decrypted.payload,
                        });
                    }
                }
            }
        }

        Ok(output)
    }

    /// Record a transport action only after the adapter successfully sent it.
    pub fn record_transport_sent(&self, peer_name: &str, bytes: usize) {
        self.peers.record_tx(peer_name, bytes);
    }

    pub fn peer_stats(&self) -> HashMap<String, PeerStats> {
        self.peers.snapshot()
    }

    pub fn active_session_id(&self, peer_name: &str) -> Option<[u8; auth::SESSION_ID_SIZE]> {
        self.sessions.active_session_id(peer_name)
    }

    pub fn has_pending_handshake(&self, peer_name: &str) -> bool {
        self.sessions.has_pending_init(peer_name)
    }

    pub fn has_active_session(&self, peer_name: &str) -> bool {
        self.sessions.has_active_session(peer_name)
    }

    pub fn invalidate_peer(&self, peer_name: &str) -> bool {
        self.sessions.invalidate_peer(peer_name)
    }

    /// Start or retry a handshake for a named peer.
    pub fn initiate_handshake(
        &self,
        peer_name: &str,
        now: Instant,
    ) -> Result<EngineOutput, EngineError> {
        let peer = self
            .peer(peer_name)
            .ok_or_else(|| EngineError::UnknownPeer(peer_name.to_string()))?;
        let mut output = EngineOutput::default();
        if let Some(action) = self.initiate_peer(peer, now)? {
            output.actions.push(action);
        }
        Ok(output)
    }

    /// Encrypt a keepalive or initiate a session when none is active.
    pub fn create_keepalive(
        &self,
        peer_name: &str,
        payload: &[u8],
        now: Instant,
    ) -> Result<EngineOutput, EngineError> {
        let peer = self
            .peer(peer_name)
            .ok_or_else(|| EngineError::UnknownPeer(peer_name.to_string()))?;
        let mut output = EngineOutput::default();
        match self
            .sessions
            .encrypt_for_peer(peer_name, auth::MsgType::Keepalive, payload, now)
        {
            Ok(Some(frame)) => {
                if let Some(action) = self.initiate_peer(peer, now)? {
                    output.actions.push(action);
                }
                if let Some(endpoint) = self.resolve_endpoint(peer) {
                    output.actions.push(EngineAction::SendTransport {
                        peer_name: peer_name.to_string(),
                        endpoint,
                        frame,
                    });
                }
            }
            Ok(None) => {
                if let Some(action) = self.initiate_peer(peer, now)? {
                    output.actions.push(action);
                }
            }
            Err(_) => {
                self.sessions.invalidate_peer(peer_name);
                if let Some(action) = self.initiate_peer(peer, now)? {
                    output.actions.push(action);
                }
            }
        }
        Ok(output)
    }

    fn initiate_peer(
        &self,
        peer: &Peer,
        now: Instant,
    ) -> Result<Option<EngineAction>, noise::NoiseError> {
        let Some(endpoint) = self.resolve_endpoint(peer) else {
            return Ok(None);
        };
        self.sessions
            .start_or_retry_handshake(
                &peer.name,
                &self.local_static,
                &peer.public_key,
                &peer.psk,
                now,
            )
            .map(|frame| {
                frame.map(|frame| EngineAction::SendTransport {
                    peer_name: peer.name.clone(),
                    endpoint,
                    frame,
                })
            })
    }

    fn decode_handshake_init(
        &self,
        handshake_id: [u8; auth::SESSION_ID_SIZE],
        message: &[u8],
    ) -> Option<(String, noise::ResponderHandshake)> {
        let mut checked = HashSet::new();
        for route in self.router.routes() {
            if !checked.insert(route.peer.name.clone()) {
                continue;
            }
            if let Ok(handshake) = noise::responder_respond(
                &self.local_static,
                &route.peer.public_key,
                &route.peer.psk,
                handshake_id,
                message,
            ) {
                return Some((route.peer.name.clone(), handshake));
            }
        }
        None
    }

    fn peer(&self, peer_name: &str) -> Option<&Peer> {
        self.router
            .routes()
            .iter()
            .find(|route| route.peer.name == peer_name)
            .map(|route| route.peer.as_ref())
    }

    fn resolve_endpoint(&self, peer: &Peer) -> Option<SocketAddr> {
        self.peers
            .snapshot()
            .get(&peer.name)
            .and_then(|stats| stats.current_endpoint)
            .filter(|endpoint| usable_peer_endpoint(*endpoint))
            .or_else(|| usable_peer_endpoint(peer.endpoint).then_some(peer.endpoint))
    }
}

fn usable_peer_endpoint(endpoint: SocketAddr) -> bool {
    !endpoint.ip().is_unspecified() && endpoint.port() != 0
}

#[cfg(test)]
mod engine_tests {
    use std::net::Ipv4Addr;

    use base64::{engine::general_purpose::STANDARD, Engine as _};

    use super::*;
    use crate::config::{InterfaceConfig, PeerConfig, TransportConfig};

    struct TestConfig<'a> {
        name: &'a str,
        address: &'a str,
        listen: SocketAddr,
        private_key: [u8; 32],
        peer_name: &'a str,
        peer_address: &'a str,
        peer_endpoint: SocketAddr,
        peer_public_key: [u8; 32],
        psk: [u8; 32],
    }

    fn config(test: TestConfig<'_>) -> Config {
        Config {
            interface: InterfaceConfig {
                name: test.name.to_string(),
                address: test.address.parse().unwrap(),
                listen: test.listen,
                transport: TransportConfig::Udp,
                mtu: 1280,
                private_key: STANDARD.encode(test.private_key),
            },
            gateway: None,
            peer: vec![PeerConfig {
                name: test.peer_name.to_string(),
                endpoint: test.peer_endpoint,
                allowed_ips: vec![test.peer_address.parse().unwrap()],
                psk: STANDARD.encode(test.psk),
                public_key: STANDARD.encode(test.peer_public_key),
                persistent_keepalive: 5,
                udp_rebind_after: 20,
                session_timeout: None,
            }],
        }
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

    fn take_send(output: EngineOutput) -> (String, SocketAddr, Vec<u8>, Vec<EngineEvent>) {
        assert_eq!(output.actions.len(), 1, "expected one transport action");
        let EngineAction::SendTransport {
            peer_name,
            endpoint,
            frame,
        } = output.actions.into_iter().next().unwrap()
        else {
            panic!("expected transport action");
        };
        (peer_name, endpoint, frame, output.events)
    }

    fn take_ip(output: EngineOutput) -> (String, SocketAddr, Vec<u8>) {
        assert_eq!(output.actions.len(), 1, "expected one IP action");
        let EngineAction::WriteIpPacket {
            peer_name,
            source,
            packet,
        } = output.actions.into_iter().next().unwrap()
        else {
            panic!("expected IP action");
        };
        assert!(output.events.is_empty());
        (peer_name, source, packet)
    }

    #[test]
    fn two_engines_handshake_and_exchange_ip_packets_in_memory() {
        let private_a = [0x11; 32];
        let private_b = [0x22; 32];
        let public_a = PublicKey::from(&StaticSecret::from(private_a)).to_bytes();
        let public_b = PublicKey::from(&StaticSecret::from(private_b)).to_bytes();
        let psk = [0x33; 32];
        let endpoint_a: SocketAddr = "127.0.0.1:31001".parse().unwrap();
        let endpoint_b: SocketAddr = "127.0.0.1:31002".parse().unwrap();

        let engine_a = Engine::new(&config(TestConfig {
            name: "memory-a",
            address: "10.77.80.1/30",
            listen: endpoint_a,
            private_key: private_a,
            peer_name: "b",
            peer_address: "10.77.80.2/32",
            peer_endpoint: endpoint_b,
            peer_public_key: public_b,
            psk,
        }))
        .unwrap();
        let engine_b = Engine::new(&config(TestConfig {
            name: "memory-b",
            address: "10.77.80.2/30",
            listen: endpoint_b,
            private_key: private_b,
            peer_name: "a",
            peer_address: "10.77.80.1/32",
            peer_endpoint: endpoint_a,
            peer_public_key: public_a,
            psk,
        }))
        .unwrap();
        let now = Instant::now();
        let packet_a_to_b = ipv4_packet(Ipv4Addr::new(10, 77, 80, 1), Ipv4Addr::new(10, 77, 80, 2));

        // The first IP packet starts the handshake and is intentionally
        // dropped until a session exists.
        let (_, destination, init, events) =
            take_send(engine_a.process_outbound_ip(&packet_a_to_b, now).unwrap());
        assert_eq!(destination, endpoint_b);
        assert!(events.is_empty());

        let (_, destination, response, events) = take_send(
            engine_b
                .process_inbound_transport(&init, endpoint_a, now)
                .unwrap(),
        );
        assert_eq!(destination, endpoint_a);
        assert!(events.is_empty());

        let (_, destination, confirmation, events) = take_send(
            engine_a
                .process_inbound_transport(&response, endpoint_b, now)
                .unwrap(),
        );
        assert_eq!(destination, endpoint_b);
        assert_eq!(
            events,
            vec![EngineEvent::HandshakeCompleted {
                peer_name: "b".to_string(),
                endpoint: endpoint_b,
                role: HandshakeRole::Initiator,
            }]
        );

        let (_, destination, acknowledgement, events) = take_send(
            engine_b
                .process_inbound_transport(&confirmation, endpoint_a, now)
                .unwrap(),
        );
        assert_eq!(destination, endpoint_a);
        assert_eq!(
            events,
            vec![EngineEvent::HandshakeCompleted {
                peer_name: "a".to_string(),
                endpoint: endpoint_a,
                role: HandshakeRole::Responder,
            }]
        );
        let acknowledgement_output = engine_a
            .process_inbound_transport(&acknowledgement, endpoint_b, now)
            .unwrap();
        assert!(acknowledgement_output.actions.is_empty());
        assert!(acknowledgement_output.events.is_empty());
        assert_eq!(
            engine_a.active_session_id("b"),
            engine_b.active_session_id("a")
        );

        let (peer, destination, encrypted, events) =
            take_send(engine_a.process_outbound_ip(&packet_a_to_b, now).unwrap());
        assert_eq!(peer, "b");
        assert_eq!(destination, endpoint_b);
        assert!(events.is_empty());
        engine_a.record_transport_sent(&peer, encrypted.len());
        let (peer, source, received) = take_ip(
            engine_b
                .process_inbound_transport(&encrypted, endpoint_a, now)
                .unwrap(),
        );
        assert_eq!(peer, "a");
        assert_eq!(source, endpoint_a);
        assert_eq!(received, packet_a_to_b);

        let packet_b_to_a = ipv4_packet(Ipv4Addr::new(10, 77, 80, 2), Ipv4Addr::new(10, 77, 80, 1));
        let (_, destination, encrypted, _) =
            take_send(engine_b.process_outbound_ip(&packet_b_to_a, now).unwrap());
        assert_eq!(destination, endpoint_a);
        let (_, source, received) = take_ip(
            engine_a
                .process_inbound_transport(&encrypted, endpoint_b, now)
                .unwrap(),
        );
        assert_eq!(source, endpoint_b);
        assert_eq!(received, packet_b_to_a);

        let stats_a = engine_a.peer_stats();
        assert!(stats_a["b"].tx_bytes > 0);
        assert_eq!(stats_a["b"].current_endpoint, Some(endpoint_b));
    }

    #[test]
    fn engine_rejects_non_ipv4_platform_packets_without_side_effects() {
        let private_a = [0x41; 32];
        let private_b = [0x42; 32];
        let public_b = PublicKey::from(&StaticSecret::from(private_b)).to_bytes();
        let engine = Engine::new(&config(TestConfig {
            name: "memory-a",
            address: "10.77.81.1/30",
            listen: "127.0.0.1:31101".parse().unwrap(),
            private_key: private_a,
            peer_name: "b",
            peer_address: "10.77.81.2/32",
            peer_endpoint: "127.0.0.1:31102".parse().unwrap(),
            peer_public_key: public_b,
            psk: [0x43; 32],
        }))
        .unwrap();
        let ipv6_header = [0x60_u8; 40];

        assert!(matches!(
            engine.process_outbound_ip(&ipv6_header, Instant::now()),
            Err(EngineError::Packet(PacketError::NotIpv4(6)))
        ));
        assert!(engine.peer_stats().is_empty());
    }
}
