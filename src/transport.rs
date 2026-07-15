use std::io::{self, ErrorKind};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Context;

use crate::config::{Config, TransportConfig};

#[derive(Debug)]
pub struct ReceivedPacket {
    pub bytes: usize,
    pub source: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RebindResult {
    pub previous: SocketAddr,
    pub current: SocketAddr,
}

pub trait PacketTransport: Send + Sync + 'static {
    fn send_to(&self, frame: &[u8], endpoint: SocketAddr) -> std::io::Result<usize>;
    fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<ReceivedPacket>;
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
    fn label(&self) -> &'static str;
    fn try_clone_box(&self) -> anyhow::Result<Box<dyn PacketTransport>>;

    /// Rebind a connectionless transport to a fresh ephemeral local port.
    ///
    /// Transports that cannot safely rebind return `Ok(None)`. UDP clones all
    /// share the replacement socket, so senders and the receiver switch as one
    /// logical transport.
    fn rebind_to_ephemeral(&self) -> io::Result<Option<RebindResult>> {
        Ok(None)
    }
}

pub fn bind(config: &Config) -> anyhow::Result<Box<dyn PacketTransport>> {
    match config.interface.transport {
        TransportConfig::Udp => UdpTransport::bind(config.interface.listen),
        TransportConfig::Tcp => crate::tcp_transport::TcpTransport::bind(config.interface.listen),
    }
}

#[derive(Debug)]
struct UdpTransport {
    socket: Arc<RwLock<Arc<UdpSocket>>>,
}

impl UdpTransport {
    fn bind(listen: SocketAddr) -> anyhow::Result<Box<dyn PacketTransport>> {
        let socket = bind_udp_socket(listen)
            .with_context(|| format!("failed to bind UDP socket {listen}"))?;
        Ok(Box::new(Self {
            socket: Arc::new(RwLock::new(Arc::new(socket))),
        }))
    }

    fn active_socket(&self) -> io::Result<Arc<UdpSocket>> {
        self.socket
            .read()
            .map(|socket| Arc::clone(&socket))
            .map_err(|_| io::Error::other("UDP socket lock poisoned"))
    }
}

fn bind_udp_socket(listen: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(listen)?;
    // A finite timeout lets a receiver blocked on the previous socket notice
    // an atomic rebind. Timeouts are swallowed inside `recv_from`, so callers
    // still observe the normal blocking PacketTransport contract.
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    Ok(socket)
}

impl PacketTransport for UdpTransport {
    fn send_to(&self, frame: &[u8], endpoint: SocketAddr) -> std::io::Result<usize> {
        self.active_socket()?.send_to(frame, endpoint)
    }

    fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<ReceivedPacket> {
        loop {
            let socket = self.active_socket()?;
            match socket.recv_from(buffer) {
                Ok((bytes, source)) => return Ok(ReceivedPacket { bytes, source }),
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.active_socket()?.local_addr()
    }

    fn label(&self) -> &'static str {
        "udp"
    }

    fn try_clone_box(&self) -> anyhow::Result<Box<dyn PacketTransport>> {
        Ok(Box::new(Self {
            socket: Arc::clone(&self.socket),
        }))
    }

    fn rebind_to_ephemeral(&self) -> io::Result<Option<RebindResult>> {
        let previous = self.local_addr()?;
        let mut bind_addr = previous;
        bind_addr.set_port(0);

        let replacement = Arc::new(bind_udp_socket(bind_addr)?);
        let current = replacement.local_addr()?;

        let mut active = self
            .socket
            .write()
            .map_err(|_| io::Error::other("UDP socket lock poisoned"))?;
        *active = replacement;

        Ok(Some(RebindResult { previous, current }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn udp_rebind_switches_all_clones_to_new_port() {
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let clone = transport.try_clone_box().unwrap();
        let previous = transport.local_addr().unwrap();

        let rebound = clone
            .rebind_to_ephemeral()
            .unwrap()
            .expect("UDP supports rebinding");
        assert_eq!(rebound.previous, previous);
        assert_ne!(rebound.current.port(), previous.port());
        assert_eq!(transport.local_addr().unwrap(), rebound.current);
        assert_eq!(clone.local_addr().unwrap(), rebound.current);

        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        transport
            .send_to(b"after-rebind", peer.local_addr().unwrap())
            .unwrap();
        let mut buffer = [0_u8; 64];
        let (bytes, source) = peer.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..bytes], b"after-rebind");
        assert_eq!(source, rebound.current);
    }

    #[test]
    fn blocked_udp_receiver_moves_to_rebound_socket() {
        let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let receiver = transport.try_clone_box().unwrap();
        let receive_thread = thread::spawn(move || {
            let mut buffer = [0_u8; 64];
            let packet = receiver.recv_from(&mut buffer).unwrap();
            (buffer, packet)
        });

        thread::sleep(Duration::from_millis(50));
        let rebound = transport
            .rebind_to_ephemeral()
            .unwrap()
            .expect("UDP supports rebinding");

        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        // The receiver may still be blocked on the old socket for up to the
        // one-second poll timeout. Keep the datagram queued on the new socket.
        peer.send_to(b"new-socket", rebound.current).unwrap();

        let (buffer, packet) = receive_thread.join().unwrap();
        assert_eq!(&buffer[..packet.bytes], b"new-socket");
        assert_eq!(packet.source, peer.local_addr().unwrap());
    }

    #[test]
    fn udp_peer_can_roam_and_reply_to_rebound_source() {
        let client = UdpTransport::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let server = UdpTransport::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let previous_client_addr = client.local_addr().unwrap();

        client.send_to(b"before", server_addr).unwrap();
        let mut buffer = [0_u8; 64];
        let first = server.recv_from(&mut buffer).unwrap();
        assert_eq!(first.source, previous_client_addr);

        let rebound = client
            .rebind_to_ephemeral()
            .unwrap()
            .expect("UDP supports rebinding");
        client.send_to(b"probe", server_addr).unwrap();
        let probe = server.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..probe.bytes], b"probe");
        assert_eq!(probe.source, rebound.current);

        server.send_to(b"ack", probe.source).unwrap();
        let acknowledgement = client.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..acknowledgement.bytes], b"ack");
        assert_eq!(acknowledgement.source, server_addr);
    }
}
