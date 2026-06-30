//! TCP transport for HushWire.
//!
//! Implements the `PacketTransport` trait over TCP. Unlike UDP (connectionless
//! datagrams), TCP is a byte stream, so we add a 2-byte length prefix for
//! framing. Connections are managed internally: both sides listen, and a side
//! dials on first `send_to` to an endpoint. This keeps the peer model symmetric
//! (like UDP) — no explicit listener/dialer role in config.
//!
//! All I/O is synchronous (std::net + set_nonblocking), matching the existing
//! thread-per-concern architecture. No async runtime is introduced.

use std::collections::HashMap;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::Context;

use crate::transport::{PacketTransport, ReceivedPacket};

/// Per-connection read state: accumulates bytes until a full frame is available.
struct ConnState {
    stream: TcpStream,
    /// Bytes read from the stream but not yet assembled into a full frame.
    read_buf: Vec<u8>,
}

impl ConnState {
    fn new(stream: TcpStream) -> Self {
        stream
            .set_nonblocking(true)
            .context("failed to set nonblocking")
            .ok();
        // Disable Nagle's algorithm — we want low latency for tunnel packets,
        // and TCP_NODELAY ensures small handshake/data frames are sent immediately
        // rather than being batched by the kernel.
        stream
            .set_nodelay(true)
            .context("failed to set TCP_NODELAY")
            .ok();
        Self {
            stream,
            read_buf: Vec::new(),
        }
    }

    /// Try to read a complete frame from the connection. Returns:
    /// - Ok(Some(frame)) — a complete frame was assembled
    /// - Ok(None) — not enough data yet, try again later
    /// - Err(_) — connection is broken
    fn try_read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        // Read available bytes into the buffer.
        let mut tmp = [0u8; 65_535];
        loop {
            match self.stream.read(&mut tmp) {
                Ok(0) => {
                    // Connection closed by peer.
                    return Err(io::Error::new(ErrorKind::ConnectionReset, "peer closed"));
                }
                Ok(n) => {
                    self.read_buf.extend_from_slice(&tmp[..n]);
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    break; // No more data right now.
                }
                Err(ref e)
                    if e.kind() == ErrorKind::Interrupted || e.kind() == ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        // Try to assemble a frame: 2-byte length prefix + payload.
        if self.read_buf.len() < 2 {
            return Ok(None);
        }
        let frame_len = u16::from_be_bytes([self.read_buf[0], self.read_buf[1]]) as usize;
        if frame_len > 65_535 {
            // Invalid frame — discard the connection.
            return Err(io::Error::new(ErrorKind::InvalidData, "frame too large"));
        }
        if self.read_buf.len() < 2 + frame_len {
            return Ok(None); // Need more bytes.
        }

        // Extract the frame.
        let frame = self.read_buf[2..2 + frame_len].to_vec();
        // Remove consumed bytes from the buffer.
        self.read_buf.drain(..2 + frame_len);
        Ok(Some(frame))
    }

    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        let len = frame.len() as u16;
        let mut buf = Vec::with_capacity(2 + frame.len());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(frame);
        self.stream.write_all(&buf)
    }
}

/// TCP transport: maintains a listener + a map of active connections.
pub struct TcpTransport {
    listener: TcpListener,
    /// peer_addr → connection state. Shared across clones (Arc) and
    /// protected by Mutex. The ConnState itself is also Mutex-protected
    /// because the accept thread and recv_from may both touch it.
    connections: Arc<Mutex<HashMap<SocketAddr, Arc<Mutex<ConnState>>>>>,
}

impl TcpTransport {
    pub fn bind(listen: SocketAddr) -> anyhow::Result<Box<dyn PacketTransport>> {
        let listener =
            TcpListener::bind(listen).with_context(|| format!("failed to bind TCP {listen}"))?;
        listener
            .set_nonblocking(true)
            .context("failed to set listener nonblocking")?;
        let connections = Arc::new(Mutex::new(HashMap::new()));

        // Background thread: accept inbound connections.
        let conns_for_accept = connections.clone();
        let listener_for_accept = listener
            .try_clone()
            .context("failed to clone TCP listener for accept thread")?;
        thread::spawn(move || loop {
            match listener_for_accept.accept() {
                Ok((stream, addr)) => {
                    tracing::debug!(%addr, "TCP accept: new inbound connection");
                    let state = ConnState::new(stream);
                    conns_for_accept
                        .lock()
                        .unwrap()
                        .insert(addr, Arc::new(Mutex::new(state)));
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {
                    continue;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "TCP accept error");
                    thread::sleep(Duration::from_millis(100));
                }
            }
        });

        Ok(Box::new(Self {
            listener,
            connections,
        }))
    }

    /// Get an existing connection or dial a new one.
    ///
    /// Uses a short connect timeout (2s) so that an unreachable endpoint
    /// doesn't block the calling thread for minutes (TCP default SYN timeout).
    fn get_or_dial(&self, endpoint: SocketAddr) -> io::Result<Arc<Mutex<ConnState>>> {
        // Fast path: connection exists.
        if let Some(conn) = self.connections.lock().unwrap().get(&endpoint) {
            return Ok(Arc::clone(conn));
        }
        // Slow path: dial with timeout.
        let addrs = std::net::ToSocketAddrs::to_socket_addrs(&endpoint)?;
        let mut last_err = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                Ok(stream) => {
                    let state = ConnState::new(stream);
                    let arc = Arc::new(Mutex::new(state));
                    self.connections
                        .lock()
                        .unwrap()
                        .insert(endpoint, Arc::clone(&arc));
                    return Ok(arc);
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(ErrorKind::AddrNotAvailable, "no addresses to connect to")
        }))
    }
}

impl PacketTransport for TcpTransport {
    fn send_to(&self, frame: &[u8], endpoint: SocketAddr) -> io::Result<usize> {
        let conn = self.get_or_dial(endpoint).map_err(|e| {
            tracing::warn!(%endpoint, error = %e, "TCP send_to: get_or_dial failed");
            e
        })?;
        let mut c = conn
            .lock()
            .map_err(|_| io::Error::other("connection mutex poisoned"))?;
        c.write_frame(frame)?;
        Ok(frame.len())
    }

    fn recv_from(&self, buffer: &mut [u8]) -> io::Result<ReceivedPacket> {
        loop {
            // Snapshot the connection addresses to avoid holding the lock
            // while reading.
            let entries: Vec<(SocketAddr, Arc<Mutex<ConnState>>)> = self
                .connections
                .lock()
                .unwrap()
                .iter()
                .map(|(k, v)| (*k, Arc::clone(v)))
                .collect();

            for (addr, conn) in &entries {
                let mut c = match conn.lock() {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                match c.try_read_frame() {
                    Ok(Some(frame)) => {
                        let len = frame.len().min(buffer.len());
                        buffer[..len].copy_from_slice(&frame[..len]);
                        return Ok(ReceivedPacket {
                            bytes: len,
                            source: *addr,
                        });
                    }
                    Ok(None) => continue,
                    Err(_) => {
                        // Connection broken — remove it.
                        drop(c);
                        self.connections.lock().unwrap().remove(addr);
                    }
                }
            }
            // No data on any connection — sleep briefly to avoid busy-spin.
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    fn label(&self) -> &'static str {
        "tcp"
    }

    fn try_clone_box(&self) -> anyhow::Result<Box<dyn PacketTransport>> {
        Ok(Box::new(Self {
            listener: self.listener.try_clone()?,
            connections: self.connections.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_frame_round_trip() {
        // Bind a TCP listener, connect, write a frame, read it back.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let writer_stream = TcpStream::connect(addr).unwrap();
        let (reader_stream, _) = listener.accept().unwrap();

        // Write a frame with length prefix.
        let payload = b"hello tcp";
        let mut state = ConnState::new(writer_stream);
        state.write_frame(payload).unwrap();

        // Read it on the other side. Non-blocking, so may need to retry
        // until the data arrives in the kernel buffer.
        let mut state2 = ConnState::new(reader_stream);
        let frame = loop {
            if let Some(f) = state2.try_read_frame().unwrap() {
                break f;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        };
        assert_eq!(frame, payload.to_vec());
    }

    #[test]
    fn tcp_frame_partial_read_assembles() {
        // Send two frames, read them one at a time.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_stream = TcpStream::connect(addr).unwrap();
        let (client_stream, _) = listener.accept().unwrap();

        let mut state = ConnState::new(client_stream);
        state.write_frame(b"first").unwrap();
        state.write_frame(b"second").unwrap();

        let mut state2 = ConnState::new(server_stream);
        // Wait for both frames to arrive.
        thread::sleep(Duration::from_millis(50));
        let f1 = state2.try_read_frame().unwrap();
        let f2 = state2.try_read_frame().unwrap();
        assert_eq!(f1, Some(b"first".to_vec()));
        assert_eq!(f2, Some(b"second".to_vec()));
    }

    /// End-to-end test: two TcpTransport instances on loopback, one sends,
    /// the other receives. This mirrors the real tunnel.rs usage pattern.
    #[test]
    fn tcp_transport_e2e_send_recv() {
        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = TcpTransport::bind(server_addr).unwrap();
        let server_addr = server.local_addr().unwrap();

        let client_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let client = TcpTransport::bind(client_addr).unwrap();

        // Client sends to server.
        let payload = b"hello over tcp transport";
        client.send_to(payload, server_addr).unwrap();

        // Server receives. Give the connection + data time to arrive.
        let mut buf = vec![0u8; 1024];
        let received = loop {
            match server.recv_from(&mut buf) {
                Ok(pkt) => break pkt,
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        };
        assert_eq!(&buf[..received.bytes], payload);
    }

    /// Bidirectional: both sides send and receive.
    #[test]
    fn tcp_transport_e2e_bidirectional() {
        let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = TcpTransport::bind(server_addr).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let client = TcpTransport::bind(client_addr).unwrap();

        // Client → Server
        client.send_to(b"c2s", server_addr).unwrap();
        let mut buf = vec![0u8; 1024];
        let pkt = server.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..pkt.bytes], b"c2s");

        // Server → Client (server now knows client's addr from the connection)
        server.send_to(b"s2c", pkt.source).unwrap();
        let pkt2 = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..pkt2.bytes], b"s2c");
    }
}
