use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context;
use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use tracing::{debug, error, info, warn};

use crate::auth;
use crate::config::Config;
use crate::firewall;
use crate::packet::Ipv4Packet;
use crate::replay;
use crate::router::Router;
use crate::routing::{self, InstalledRoute};
use crate::state::PeerState;
use crate::transport;

const MAX_PACKET_SIZE: usize = 65_535;
const PACKET_INFO_SIZE: usize = 4;

pub fn run(config: Config, exit_node: bool) -> anyhow::Result<()> {
    let router = Router::new(&config)?;

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

            let encoded = auth::encode_packet(frame, &route.peer.psk, auth::MsgType::Data);
            if let Err(error) = transport_writer.send_to(&encoded, route.peer.endpoint) {
                error!(
                    %error,
                    peer = %route.peer.name,
                    endpoint = %route.peer.endpoint,
                    bytes = size,
                    "failed to send UDP packet"
                );
                continue;
            }

            state_for_sender.record_tx(&route.peer.name, encoded.len());

            debug!(
                peer = %route.peer.name,
                endpoint = %route.peer.endpoint,
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

            // Authenticate against all configured peers.
            let (peer_name, nonce, msg_type, payload) = match decode_from_peers(
                frame,
                &router_for_receiver,
            ) {
                Some(result) => result,
                None => {
                    warn!(source = %source, bytes = size, "dropping unauthenticated transport packet");
                    continue;
                }
            };

            // Reject replays before touching peer state or the TUN device.
            let filter = replay.entry(peer_name.clone()).or_default();
            if !filter.check_and_insert(&nonce) {
                warn!(source = %source, peer = %peer_name, "dropping replayed packet");
                continue;
            }

            match msg_type {
                auth::MsgType::Keepalive => {
                    state_for_receiver.record_keepalive(&peer_name, source);
                    continue;
                }
                auth::MsgType::Data => {
                    state_for_receiver.record_rx(&peer_name, source, payload.len());
                }
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
                    let packet =
                        auth::encode_packet(b"", &route.peer.psk, auth::MsgType::Keepalive);
                    if keepalive_transport
                        .send_to(&packet, route.peer.endpoint)
                        .is_ok()
                    {
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

/// Try to authenticate `frame` against any configured peer.
/// On success returns the peer name, the packet nonce, the message type and the
/// decoded payload.
fn decode_from_peers(
    frame: &[u8],
    router: &Router,
) -> Option<(String, [u8; auth::NONCE_SIZE], auth::MsgType, Vec<u8>)> {
    for route in router.routes() {
        if let Some((msg_type, payload)) = auth::decode_packet(frame, &route.peer.psk) {
            let mut nonce = [0u8; auth::NONCE_SIZE];
            nonce.copy_from_slice(&frame[auth::NONCE_OFFSET..auth::HEADER_SIZE]);
            return Some((route.peer.name.clone(), nonce, msg_type, payload));
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
