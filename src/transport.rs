use std::net::{SocketAddr, UdpSocket};

use anyhow::Context;

use crate::config::{Config, TransportConfig};

#[derive(Debug)]
pub struct ReceivedPacket {
    pub bytes: usize,
    pub source: SocketAddr,
}

pub trait PacketTransport: Send + Sync + 'static {
    fn send_to(&self, frame: &[u8], endpoint: SocketAddr) -> std::io::Result<usize>;
    fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<ReceivedPacket>;
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
    fn label(&self) -> &'static str;
    fn try_clone_box(&self) -> anyhow::Result<Box<dyn PacketTransport>>;
}

pub fn bind(config: &Config) -> anyhow::Result<Box<dyn PacketTransport>> {
    match config.interface.transport {
        TransportConfig::Udp => UdpTransport::bind(config.interface.listen),
    }
}

#[derive(Debug)]
struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    fn bind(listen: SocketAddr) -> anyhow::Result<Box<dyn PacketTransport>> {
        let socket = UdpSocket::bind(listen)
            .with_context(|| format!("failed to bind UDP socket {listen}"))?;
        Ok(Box::new(Self { socket }))
    }
}

impl PacketTransport for UdpTransport {
    fn send_to(&self, frame: &[u8], endpoint: SocketAddr) -> std::io::Result<usize> {
        self.socket.send_to(frame, endpoint)
    }

    fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<ReceivedPacket> {
        let (bytes, source) = self.socket.recv_from(buffer)?;
        Ok(ReceivedPacket { bytes, source })
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn label(&self) -> &'static str {
        "udp"
    }

    fn try_clone_box(&self) -> anyhow::Result<Box<dyn PacketTransport>> {
        let socket = self
            .socket
            .try_clone()
            .context("failed to clone UDP socket")?;
        Ok(Box::new(Self { socket }))
    }
}
