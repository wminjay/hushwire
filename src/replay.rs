use std::collections::{HashMap, VecDeque};

use crate::auth::NONCE_SIZE;

/// Default number of recent nonces kept per peer. Picked to cover typical
/// bursts of replayed traffic while bounding per-peer memory (~48 KB for the
/// map plus the deque of fixed-size keys).
const DEFAULT_CAPACITY: usize = 4096;

/// A bounded FIFO set of recently seen AEAD nonces.
///
/// `HushWire` uses random 96-bit nonces (see `auth::encode_packet`), so the
/// classic counter-based sliding window used by WireGuard does not apply.
/// Instead each peer keeps the most recent `capacity` nonces and rejects any
/// packet whose nonce is already in the set. Nonces older than `capacity`
/// packets ago are evicted and would theoretically be replayable; this matches
/// the bounded-window trade-off of other tunnel implementations.
///
/// Random 96-bit nonces collide within the window with negligible probability
/// (~2^-48 at the boundary), so a fresh nonce is essentially never misjudged as
/// a replay.
pub struct ReplayFilter {
    capacity: usize,
    seen: HashMap<[u8; NONCE_SIZE], ()>,
    order: VecDeque<[u8; NONCE_SIZE]>,
}

impl ReplayFilter {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Build a filter with a custom window size. Mainly used by tests.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            seen: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
        }
    }

    /// Record a nonce. Returns `true` if the nonce was fresh (and has now been
    /// inserted), or `false` if it was already in the window and is therefore a
    /// replay.
    ///
    /// The check and insert happen atomically within this call, so the filter
    /// stays correct even if it were ever shared across threads behind a lock.
    pub fn check_and_insert(&mut self, nonce: &[u8; NONCE_SIZE]) -> bool {
        // Capacity 0 is degenerate: retain nothing, so every packet is treated
        // as fresh.
        if self.capacity == 0 {
            return true;
        }
        if self.seen.contains_key(nonce) {
            return false;
        }
        if self.order.len() == self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        self.order.push_back(*nonce);
        self.seen.insert(*nonce, ());
        true
    }
}

impl Default for ReplayFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce(byte: u8) -> [u8; NONCE_SIZE] {
        [byte; NONCE_SIZE]
    }

    #[test]
    fn accepts_fresh_nonce() {
        let mut filter = ReplayFilter::new();
        assert!(filter.check_and_insert(&nonce(1)));
    }

    #[test]
    fn rejects_duplicate_nonce() {
        let mut filter = ReplayFilter::new();
        assert!(filter.check_and_insert(&nonce(1)));
        assert!(!filter.check_and_insert(&nonce(1)));
    }

    #[test]
    fn evicts_oldest_beyond_capacity() {
        // A full window must still accept a fresh, distinct nonce: that can
        // only happen if the oldest entry is evicted rather than the new one
        // being rejected.
        let mut filter = ReplayFilter::with_capacity(3);
        assert!(filter.check_and_insert(&nonce(1)));
        assert!(filter.check_and_insert(&nonce(2)));
        assert!(filter.check_and_insert(&nonce(3)));
        // Window is full; a 4th distinct nonce is still accepted (oldest
        // evicted), not rejected as if the window were closed.
        assert!(filter.check_and_insert(&nonce(4)));
        // The remaining in-window duplicates are rejected.
        assert!(!filter.check_and_insert(&nonce(2)));
        assert!(!filter.check_and_insert(&nonce(4)));
    }

    #[test]
    fn capacity_plus_one_distinct_nonces_all_accepted() {
        let mut filter = ReplayFilter::with_capacity(4);
        for i in 0..4 {
            assert!(
                filter.check_and_insert(&nonce(i)),
                "nonce {i} should be fresh"
            );
        }
        // Distinct nonce beyond capacity: accepted, oldest evicted.
        assert!(filter.check_and_insert(&nonce(200)));
    }

    #[test]
    fn zero_capacity_accepts_everything() {
        let mut filter = ReplayFilter::with_capacity(0);
        assert!(filter.check_and_insert(&nonce(1)));
        // Even an identical nonce is re-accepted because nothing is retained.
        assert!(filter.check_and_insert(&nonce(1)));
    }
}
