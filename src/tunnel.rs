use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context;
use hushwire::config::Config;
use hushwire::engine::{Engine, EngineAction, EngineEvent, EngineOutput, HandshakeRole};
use hushwire::packet::Ipv4Packet;
use hushwire::router::Router;
use hushwire::scheduler::{EngineScheduler, SchedulerEvent};
use hushwire::transport;
use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use tracing::{debug, error, info, warn};

use crate::firewall;
use crate::routing::{self, InstalledRoute};
use hushwire::auth;

const MAX_PACKET_SIZE: usize = 65_535;
const PACKET_INFO_SIZE: usize = 4;

pub fn run(config: Config, exit_node: bool) -> anyhow::Result<()> {
    let router = Router::new(&config)?;
    let engine = Engine::new(&config)?;
    let mut engine_scheduler = EngineScheduler::new(&config);

    // Create the TUN interface before installing routes or firewall rules,
    // since both reference the interface by name.
    let device = create_tun(&config)?;
    let transport = transport::bind(&config)?;

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
    let engine_for_sender = engine.clone();
    let engine_for_receiver = engine.clone();
    let engine_for_keepalive = engine.clone();
    let engine_for_stats = engine.clone();

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

            let output = match engine_for_sender.process_outbound_ip(frame, Instant::now()) {
                Ok(output) => output,
                Err(error) => {
                    warn!(%error, bytes = frame.len(), "packet engine rejected outbound IP packet");
                    continue;
                }
            };
            log_engine_events(&output.events);
            for action in output.actions {
                match action {
                    EngineAction::SendTransport {
                        peer_name,
                        endpoint,
                        frame: encoded,
                    } => {
                        if send_engine_frame(
                            &engine_for_sender,
                            transport_writer.as_ref(),
                            &peer_name,
                            endpoint,
                            &encoded,
                            "outbound IP",
                        ) {
                            debug!(
                                peer = %peer_name,
                                endpoint = %endpoint,
                                src = %ipv4.source(),
                                dst = %ipv4.destination(),
                                proto = ipv4.protocol(),
                                bytes = frame.len(),
                                "forwarded IP packet to transport"
                            );
                        }
                    }
                    EngineAction::WriteIpPacket { peer_name, .. } => {
                        warn!(peer = %peer_name, "packet engine returned an inbound action while processing outbound IP");
                    }
                }
            }
        }
    });

    let transport_to_tun = thread::spawn(move || {
        let mut packet = vec![0_u8; MAX_PACKET_SIZE];
        let mut tun_frame = vec![0_u8; MAX_PACKET_SIZE + PACKET_INFO_SIZE];
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
            if auth::decode_packet(frame).is_none() {
                debug!(source = %source, bytes = size, "dropping malformed or incompatible wire packet");
                continue;
            }

            let output = match engine_for_receiver.process_inbound_transport(
                frame,
                source,
                Instant::now(),
            ) {
                Ok(output) => output,
                Err(error) => {
                    warn!(%error, source = %source, bytes = size, "packet engine rejected inbound transport frame");
                    continue;
                }
            };
            log_engine_events(&output.events);

            for action in output.actions {
                match action {
                    EngineAction::SendTransport {
                        peer_name,
                        endpoint,
                        frame,
                    } => {
                        send_engine_frame(
                            &engine_for_receiver,
                            transport.as_ref(),
                            &peer_name,
                            endpoint,
                            &frame,
                            "inbound response",
                        );
                    }
                    EngineAction::WriteIpPacket {
                        peer_name,
                        source,
                        packet,
                    } => {
                        let ipv4 = Ipv4Packet::parse(&packet)
                            .expect("packet engine emitted an invalid IPv4 packet");
                        debug!(
                            source = %source,
                            peer = %peer_name,
                            src = %ipv4.source(),
                            dst = %ipv4.destination(),
                            proto = ipv4.protocol(),
                            bytes = packet.len(),
                            "received authenticated transport packet for TUN"
                        );

                        let output =
                            add_packet_information(&packet, packet_information, &mut tun_frame);
                        if let Err(error) = tun_writer.write_all(output) {
                            error!(%error, source = %source, peer = %peer_name, bytes = packet.len(), "failed to write to TUN device");
                        }
                    }
                }
            }
        }
    });

    let keepalive = thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(1));
        let tick = engine_scheduler.tick(&engine_for_keepalive, Instant::now(), |peer, silence| {
            match keepalive_transport.rebind_to_ephemeral() {
                Ok(Some(result)) => {
                    warn!(
                        peer,
                        silence_seconds = silence.as_secs(),
                        previous_listen = %result.previous,
                        current_listen = %result.current,
                        "no authenticated keepalive response; rebound UDP socket to recover the NAT path"
                    );
                    true
                }
                Ok(None) => {
                    error!(peer, "configured UDP rebind is unsupported by the active transport");
                    false
                }
                Err(error) => {
                    warn!(%error, peer, "failed to rebind UDP socket after peer liveness timeout");
                    false
                }
            }
        });

        for event in tick.events {
            let SchedulerEvent::Recovery {
                peer_name,
                silence,
                rebind_udp,
                had_stale_state,
                ..
            } = event;
            if !rebind_udp {
                warn!(
                    peer = %peer_name,
                    silence_seconds = silence.as_secs(),
                    "no authenticated keepalive response; session recovery timeout reached"
                );
            }
            warn!(
                peer = %peer_name,
                had_stale_state,
                "peer liveness timeout invalidated the old session; starting a fresh handshake"
            );
        }

        for failure in tick.errors {
            warn!(
                error = %failure.error,
                peer = %failure.peer_name,
                operation = failure.operation.label(),
                "session-maintenance operation failed"
            );
        }

        for scheduled in tick.outputs {
            send_engine_transport_output(
                &engine_for_keepalive,
                keepalive_transport.as_ref(),
                scheduled.output,
                scheduled.operation.label(),
            );
        }
    });

    let stats = thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(30));
        let snapshot = engine_for_stats.peer_stats();
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

fn send_engine_frame(
    engine: &Engine,
    transport: &dyn transport::PacketTransport,
    peer_name: &str,
    endpoint: SocketAddr,
    frame: &[u8],
    operation: &'static str,
) -> bool {
    match transport.send_to(frame, endpoint) {
        Ok(_) => {
            engine.record_transport_sent(peer_name, frame.len());
            debug!(peer = %peer_name, endpoint = %endpoint, bytes = frame.len(), operation, "sent packet-engine transport frame");
            true
        }
        Err(error) => {
            warn!(%error, peer = %peer_name, endpoint = %endpoint, bytes = frame.len(), operation, "failed to send packet-engine transport frame");
            false
        }
    }
}

fn send_engine_transport_output(
    engine: &Engine,
    transport: &dyn transport::PacketTransport,
    output: EngineOutput,
    operation: &'static str,
) {
    log_engine_events(&output.events);
    for action in output.actions {
        match action {
            EngineAction::SendTransport {
                peer_name,
                endpoint,
                frame,
            } => {
                send_engine_frame(engine, transport, &peer_name, endpoint, &frame, operation);
            }
            EngineAction::WriteIpPacket { peer_name, .. } => {
                warn!(peer = %peer_name, operation, "packet engine returned an IP write from a timer operation");
            }
        }
    }
}

fn log_engine_events(events: &[EngineEvent]) {
    for event in events {
        match event {
            EngineEvent::HandshakeCompleted {
                peer_name,
                endpoint,
                role: HandshakeRole::Initiator,
            } => {
                info!(peer = %peer_name, source = %endpoint, "handshake completed (initiator), session established")
            }
            EngineEvent::HandshakeCompleted {
                peer_name,
                endpoint,
                role: HandshakeRole::Responder,
            } => {
                info!(peer = %peer_name, source = %endpoint, "handshake completed (responder), authenticated confirmation received")
            }
        }
    }
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
#[cfg(test)]
fn resolve_endpoint(
    state: &hushwire::state::PeerState,
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

#[cfg(test)]
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

#[derive(Clone)]
struct Cleanup {
    routes: Arc<Mutex<Vec<InstalledRoute>>>,
    firewall: Arc<Mutex<Option<firewall::FirewallManager>>>,
}

impl Cleanup {
    fn run(&self) {
        let routes = {
            let mut installed = self.routes.lock().unwrap();
            std::mem::take(&mut *installed)
        };
        routing::cleanup_routes(&routes);
        let firewall = self.firewall.lock().unwrap().take();
        if let Some(f) = firewall {
            f.cleanup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hushwire::engine::{SessionManager, HANDSHAKE_ATTEMPT_LIFETIME, HANDSHAKE_RETRY_INTERVAL};
    use hushwire::noise;
    use hushwire::state::PeerState;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn complete_managed_handshake(
        initiator: &SessionManager,
        responder: &SessionManager,
        initiator_static: &StaticSecret,
        responder_static: &StaticSecret,
        responder_public: &PublicKey,
        psk: &[u8; 32],
        now: Instant,
    ) -> [u8; auth::SESSION_ID_SIZE] {
        let request_packet = initiator
            .start_or_retry_handshake("peer", initiator_static, responder_public, psk, now)
            .expect("create handshake")
            .expect("handshake request");
        let auth::ParsedPacket::Handshake {
            kind: auth::PacketKind::HandshakeInit,
            handshake_id,
            message: request,
        } = auth::decode_packet(&request_packet).expect("framed request")
        else {
            panic!("handshake init");
        };
        let initiator_public = PublicKey::from(initiator_static);
        let response = noise::responder_respond(
            responder_static,
            &initiator_public,
            psk,
            handshake_id,
            request,
        )
        .expect("handshake response");
        let session_id = response.session.session_id;
        let response_message = response.message.clone();
        let response_packet = auth::encode_handshake(
            auth::PacketKind::HandshakeResponse,
            &handshake_id,
            &response_message,
        );
        assert!(responder.store_responder_candidate(
            "peer",
            response.session,
            handshake_id,
            request.to_vec(),
            response_packet,
        ));

        // Receiving msg2 installs the initiator session and produces the
        // authenticated confirmation that promotes the responder candidate.
        let (peer, confirmation) = initiator
            .finalize_initiator(&handshake_id, &response_message)
            .expect("finalize handshake")
            .expect("matching pending handshake");
        assert_eq!(peer, "peer");
        let auth::ParsedPacket::Transport {
            session_id: confirmation_id,
            counter,
            ciphertext,
        } = auth::decode_packet(&confirmation).expect("confirmation packet")
        else {
            panic!("transport confirmation");
        };
        let confirmation = responder
            .decrypt_transport(&confirmation_id, counter, ciphertext, now)
            .expect("authenticate confirmation")
            .expect("candidate session");
        assert!(confirmation.promoted_responder_session);
        assert_eq!(confirmation.msg_type, auth::MsgType::Keepalive);
        assert_eq!(confirmation.payload, auth::KEEPALIVE_PROBE_PAYLOAD);

        assert!(initiator.has_active_session("peer"));
        assert!(responder.has_active_session("peer"));
        session_id
    }

    fn decrypt_managed_transport(
        manager: &SessionManager,
        packet: &[u8],
        now: Instant,
    ) -> Option<(auth::MsgType, Vec<u8>, bool)> {
        let auth::ParsedPacket::Transport {
            session_id,
            counter,
            ciphertext,
        } = auth::decode_packet(packet).expect("transport packet")
        else {
            panic!("expected transport packet");
        };
        manager
            .decrypt_transport(&session_id, counter, ciphertext, now)
            .expect("decrypt transport")
            .map(|decrypted| {
                (
                    decrypted.msg_type,
                    decrypted.payload,
                    decrypted.promoted_responder_session,
                )
            })
    }

    #[test]
    fn rekey_keeps_previous_session_for_in_flight_packets() {
        let initiator_static = StaticSecret::from([0x31; 32]);
        let responder_static = StaticSecret::from([0x32; 32]);
        let responder_public = PublicKey::from(&responder_static);
        let psk = [0x33; 32];
        let initiator = SessionManager::new();
        let responder = SessionManager::new();
        let now = Instant::now();

        let old_session_id = complete_managed_handshake(
            &initiator,
            &responder,
            &initiator_static,
            &responder_static,
            &responder_public,
            &psk,
            now,
        );
        let delayed_to_responder = initiator
            .encrypt_for_peer(
                "peer",
                auth::MsgType::Data,
                b"old initiator packet",
                now + Duration::from_secs(1),
            )
            .unwrap()
            .unwrap();
        let expired_to_responder = initiator
            .encrypt_for_peer(
                "peer",
                auth::MsgType::Data,
                b"expired old packet",
                now + Duration::from_secs(1),
            )
            .unwrap()
            .unwrap();
        let delayed_to_initiator = responder
            .encrypt_for_peer(
                "peer",
                auth::MsgType::Data,
                b"old responder packet",
                now + Duration::from_secs(1),
            )
            .unwrap()
            .unwrap();

        let rekey_at = now + noise::REKEY_AFTER_TIME + Duration::from_secs(1);
        let new_session_id = complete_managed_handshake(
            &initiator,
            &responder,
            &initiator_static,
            &responder_static,
            &responder_public,
            &psk,
            rekey_at,
        );
        assert_ne!(old_session_id, new_session_id);

        let received = decrypt_managed_transport(
            &responder,
            &delayed_to_responder,
            rekey_at + Duration::from_secs(1),
        )
        .expect("responder accepts previous session");
        assert_eq!(received.0, auth::MsgType::Data);
        assert_eq!(received.1, b"old initiator packet");
        assert!(!received.2);

        let received = decrypt_managed_transport(
            &initiator,
            &delayed_to_initiator,
            rekey_at + Duration::from_secs(1),
        )
        .expect("initiator accepts previous session");
        assert_eq!(received.0, auth::MsgType::Data);
        assert_eq!(received.1, b"old responder packet");
        assert!(!received.2);

        assert!(decrypt_managed_transport(
            &responder,
            &expired_to_responder,
            now + noise::REJECT_AFTER_TIME + Duration::from_secs(1),
        )
        .is_none());
    }

    #[test]
    fn responder_candidate_suppresses_competing_local_rekey() {
        let initiator_static = StaticSecret::from([0x34; 32]);
        let responder_static = StaticSecret::from([0x35; 32]);
        let initiator_public = PublicKey::from(&initiator_static);
        let responder_public = PublicKey::from(&responder_static);
        let psk = [0x36; 32];
        let initiator = SessionManager::new();
        let responder = SessionManager::new();
        let now = Instant::now();

        complete_managed_handshake(
            &initiator,
            &responder,
            &initiator_static,
            &responder_static,
            &responder_public,
            &psk,
            now,
        );
        let rekey_at = now + noise::REKEY_AFTER_TIME + Duration::from_secs(1);
        assert!(responder
            .start_or_retry_handshake("peer", &responder_static, &initiator_public, &psk, rekey_at,)
            .unwrap()
            .is_some());
        assert!(responder.has_pending_init("peer"));

        let remote = noise::initiator_start(&initiator_static, &responder_public, &psk).unwrap();
        let candidate = noise::responder_respond(
            &responder_static,
            &initiator_public,
            &psk,
            remote.handshake_id,
            &remote.message,
        )
        .unwrap();
        let response = auth::encode_handshake(
            auth::PacketKind::HandshakeResponse,
            &remote.handshake_id,
            &candidate.message,
        );
        assert!(responder.store_responder_candidate(
            "peer",
            candidate.session,
            remote.handshake_id,
            remote.message,
            response,
        ));

        assert!(!responder.has_pending_init("peer"));
        assert!(responder
            .start_or_retry_handshake(
                "peer",
                &responder_static,
                &initiator_public,
                &psk,
                rekey_at + HANDSHAKE_RETRY_INTERVAL,
            )
            .unwrap()
            .is_none());
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
        assert_eq!(initiator.active_session_id("peer"), Some(old_session_id));
        assert!(initiator.invalidate_peer("peer"));
        assert!(!initiator.has_active_session("peer"));
        assert_eq!(initiator.active_session_id("peer"), None);

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

        let first_request_packet = initiator
            .start_or_retry_handshake("peer", &initiator_static, &responder_public, &psk, now)
            .expect("create request")
            .expect("initial request");
        let auth::ParsedPacket::Handshake {
            handshake_id,
            message: first_request,
            ..
        } = auth::decode_packet(&first_request_packet).unwrap()
        else {
            panic!("handshake init");
        };
        let initiator_public = PublicKey::from(&initiator_static);
        let response = noise::responder_respond(
            &responder_static,
            &initiator_public,
            &psk,
            handshake_id,
            first_request,
        )
        .expect("response");
        let response_message = response.message.clone();
        let response_packet = auth::encode_handshake(
            auth::PacketKind::HandshakeResponse,
            &handshake_id,
            &response_message,
        );
        assert!(responder.store_responder_candidate(
            "peer",
            response.session,
            handshake_id,
            first_request.to_vec(),
            response_packet.clone(),
        ));

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
            .unwrap()
            .is_none());
        let retry = initiator
            .start_or_retry_handshake(
                "peer",
                &initiator_static,
                &responder_public,
                &psk,
                now + HANDSHAKE_RETRY_INTERVAL,
            )
            .expect("retry operation")
            .expect("timed retry");
        assert_eq!(retry, first_request_packet);

        // The responder also returns its cached msg2 for the duplicate msg1,
        // preserving one session even if packets are delayed or reordered.
        let cached_response = responder
            .cached_responder_response("peer", &handshake_id, first_request)
            .expect("cached response");
        assert_eq!(cached_response, response_packet);

        let (_, confirmation) = initiator
            .finalize_initiator(&handshake_id, &response_message)
            .expect("finalized retry")
            .expect("pending retry");
        let auth::ParsedPacket::Transport {
            session_id,
            counter,
            ciphertext,
        } = auth::decode_packet(&confirmation).unwrap()
        else {
            panic!("confirmation");
        };
        let promoted = responder
            .decrypt_transport(&session_id, counter, ciphertext, now)
            .unwrap()
            .unwrap();
        assert!(promoted.promoted_responder_session);
        assert!(!initiator.has_pending_init("peer"));
        assert!(initiator.has_active_session("peer"));
        assert!(responder.has_active_session("peer"));
    }

    #[test]
    fn unanswered_handshake_is_replaced_after_attempt_lifetime() {
        let initiator_static = StaticSecret::from([0x67; 32]);
        let responder_static = StaticSecret::from([0x68; 32]);
        let responder_public = PublicKey::from(&responder_static);
        let sessions = SessionManager::new();
        let psk = [0x69; 32];
        let now = Instant::now();

        let first = sessions
            .start_or_retry_handshake("peer", &initiator_static, &responder_public, &psk, now)
            .unwrap()
            .unwrap();
        let replacement = sessions
            .start_or_retry_handshake(
                "peer",
                &initiator_static,
                &responder_public,
                &psk,
                now + HANDSHAKE_ATTEMPT_LIFETIME,
            )
            .unwrap()
            .unwrap();
        assert_ne!(first, replacement);

        let auth::ParsedPacket::Handshake {
            handshake_id: first_id,
            ..
        } = auth::decode_packet(&first).unwrap()
        else {
            panic!("first handshake");
        };
        let auth::ParsedPacket::Handshake {
            handshake_id: replacement_id,
            ..
        } = auth::decode_packet(&replacement).unwrap()
        else {
            panic!("replacement handshake");
        };
        assert_ne!(first_id, replacement_id);
    }

    #[test]
    fn simultaneous_initiation_converges_on_the_smaller_identifier() {
        let static_a = StaticSecret::from([0x6a; 32]);
        let static_b = StaticSecret::from([0x6b; 32]);
        let public_a = PublicKey::from(&static_a);
        let public_b = PublicKey::from(&static_b);
        let psk = [0x6c; 32];
        let manager_a = SessionManager::new();
        let manager_b = SessionManager::new();
        let now = Instant::now();

        let packet_a = manager_a
            .start_or_retry_handshake("peer", &static_a, &public_b, &psk, now)
            .unwrap()
            .unwrap();
        let packet_b = manager_b
            .start_or_retry_handshake("peer", &static_b, &public_a, &psk, now)
            .unwrap()
            .unwrap();
        let auth::ParsedPacket::Handshake {
            handshake_id: id_a,
            message: message_a,
            ..
        } = auth::decode_packet(&packet_a).unwrap()
        else {
            panic!("handshake A");
        };
        let auth::ParsedPacket::Handshake {
            handshake_id: id_b,
            message: message_b,
            ..
        } = auth::decode_packet(&packet_b).unwrap()
        else {
            panic!("handshake B");
        };
        assert_ne!(id_a, id_b);

        let a_accepts_b = manager_a.accept_inbound_initiation("peer", &id_b, false);
        let b_accepts_a = manager_b.accept_inbound_initiation("peer", &id_a, false);
        assert_ne!(a_accepts_b, b_accepts_a);

        let (
            winner_manager,
            responder_manager,
            winner_id,
            winner_message,
            winner_public,
            responder_static,
        ) = if id_a < id_b {
            assert!(!a_accepts_b && b_accepts_a);
            (
                &manager_a, &manager_b, id_a, message_a, &public_a, &static_b,
            )
        } else {
            assert!(a_accepts_b && !b_accepts_a);
            (
                &manager_b, &manager_a, id_b, message_b, &public_b, &static_a,
            )
        };

        let response = noise::responder_respond(
            responder_static,
            winner_public,
            &psk,
            winner_id,
            winner_message,
        )
        .unwrap();
        let response_message = response.message.clone();
        let response_packet = auth::encode_handshake(
            auth::PacketKind::HandshakeResponse,
            &winner_id,
            &response_message,
        );
        assert!(responder_manager.store_responder_candidate(
            "peer",
            response.session,
            winner_id,
            winner_message.to_vec(),
            response_packet,
        ));
        let (_, confirmation) = winner_manager
            .finalize_initiator(&winner_id, &response_message)
            .unwrap()
            .unwrap();
        let auth::ParsedPacket::Transport {
            session_id,
            counter,
            ciphertext,
        } = auth::decode_packet(&confirmation).unwrap()
        else {
            panic!("confirmation");
        };
        assert!(
            responder_manager
                .decrypt_transport(&session_id, counter, ciphertext, now)
                .unwrap()
                .unwrap()
                .promoted_responder_session
        );
        assert!(winner_manager.has_active_session("peer"));
        assert!(responder_manager.has_active_session("peer"));
    }

    #[test]
    fn passive_peer_prefers_authenticated_inbound_restart_handshake() {
        let local_static = StaticSecret::from([0x71; 32]);
        let remote_static = StaticSecret::from([0x72; 32]);
        let remote_public = PublicKey::from(&remote_static);
        let manager = SessionManager::new();
        let now = Instant::now();
        let local_packet = manager
            .start_or_retry_handshake("peer", &local_static, &remote_public, &[0x73; 32], now)
            .unwrap()
            .unwrap();
        let auth::ParsedPacket::Handshake {
            handshake_id: local_id,
            ..
        } = auth::decode_packet(&local_packet).unwrap()
        else {
            panic!("local handshake");
        };

        let mut remote_id = local_id;
        let position = remote_id
            .iter()
            .position(|byte| *byte != u8::MAX)
            .expect("random identifier cannot be all 0xff in this test");
        remote_id[position] += 1;
        remote_id[position + 1..].fill(0);

        // Normal symmetric resolution keeps the smaller local exchange.
        assert!(!manager.accept_inbound_initiation("peer", &remote_id, false));
        assert!(manager.has_pending_init("peer"));

        // A passive peer cannot use its stale learned endpoint after the
        // remote process restarts, so the fresh authenticated inbound exchange
        // must replace that pending local attempt deterministically.
        assert!(manager.accept_inbound_initiation("peer", &remote_id, true));
        assert!(!manager.has_pending_init("peer"));
    }

    #[test]
    fn replayed_handshake_cannot_replace_an_active_responder_session() {
        let initiator_static = StaticSecret::from([0x71; 32]);
        let responder_static = StaticSecret::from([0x72; 32]);
        let initiator_public = PublicKey::from(&initiator_static);
        let responder_public = PublicKey::from(&responder_static);
        let psk = [0x73; 32];
        let initiator = SessionManager::new();
        let responder = SessionManager::new();
        let now = Instant::now();
        let active_id = complete_managed_handshake(
            &initiator,
            &responder,
            &initiator_static,
            &responder_static,
            &responder_public,
            &psk,
            now,
        );

        // A valid historical/new msg1 creates only a candidate. Until a valid
        // transport confirmation arrives, the existing active session stays.
        let replay = noise::initiator_start(&initiator_static, &responder_public, &psk).unwrap();
        let candidate = noise::responder_respond(
            &responder_static,
            &initiator_public,
            &psk,
            replay.handshake_id,
            &replay.message,
        )
        .unwrap();
        let response = auth::encode_handshake(
            auth::PacketKind::HandshakeResponse,
            &replay.handshake_id,
            &candidate.message,
        );
        assert!(responder.store_responder_candidate(
            "peer",
            candidate.session,
            replay.handshake_id,
            replay.message,
            response,
        ));

        assert_eq!(responder.active_session_id("peer"), Some(active_id));
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
}
