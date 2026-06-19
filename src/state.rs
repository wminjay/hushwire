use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tracing::debug;

/// Runtime statistics for a single peer.
#[derive(Debug, Clone, Default)]
pub struct PeerStats {
    pub last_seen: Option<Instant>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub current_endpoint: Option<SocketAddr>,
}

/// Thread-safe container for all peer stats.
#[derive(Debug, Clone, Default)]
pub struct PeerState {
    inner: Arc<Mutex<HashMap<String, PeerStats>>>,
}

impl PeerState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_tx(&self, peer_name: &str, bytes: usize) {
        let mut map = self.inner.lock().unwrap();
        let entry = map.entry(peer_name.to_string()).or_default();
        entry.tx_bytes += bytes as u64;
    }

    pub fn record_rx(&self, peer_name: &str, source: SocketAddr, bytes: usize) {
        let mut map = self.inner.lock().unwrap();
        let entry = map.entry(peer_name.to_string()).or_default();
        entry.rx_bytes += bytes as u64;
        entry.last_seen = Some(Instant::now());
        entry.current_endpoint = Some(source);
    }

    pub fn record_keepalive(&self, peer_name: &str, source: SocketAddr) {
        let mut map = self.inner.lock().unwrap();
        let entry = map.entry(peer_name.to_string()).or_default();
        entry.last_seen = Some(Instant::now());
        entry.current_endpoint = Some(source);
        debug!(peer = %peer_name, source = %source, "received keepalive");
    }

    pub fn snapshot(&self) -> HashMap<String, PeerStats> {
        self.inner.lock().unwrap().clone()
    }
}
