//! Counter-based anti-replay protection for Noise transport messages.
//!
//! Every direction of a v3 session uses a monotonically increasing `u64`
//! counter as its AEAD nonce. The receiver remembers a sliding window so a
//! packet may arrive out of order, but an authenticated counter can never be
//! accepted twice.

pub const DEFAULT_WINDOW_SIZE: usize = 4096;
const WORD_BITS: usize = u64::BITS as usize;
const WINDOW_WORDS: usize = DEFAULT_WINDOW_SIZE / WORD_BITS;

/// A 4096-packet replay window. Bit zero represents `highest`, bit one
/// `highest - 1`, and so on.
#[derive(Clone)]
pub struct ReplayWindow {
    highest: Option<u64>,
    bits: [u64; WINDOW_WORDS],
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            highest: None,
            bits: [0; WINDOW_WORDS],
        }
    }

    /// Cheap pre-authentication check. This never mutates state: a forged
    /// packet with a very large counter therefore cannot advance the window
    /// and discard legitimate packets.
    pub fn would_accept(&self, counter: u64) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        if counter > highest {
            return true;
        }

        let distance = highest - counter;
        if distance >= DEFAULT_WINDOW_SIZE as u64 {
            return false;
        }
        !self.bit_is_set(distance as usize)
    }

    /// Record a counter only after its AEAD tag has authenticated. Returns
    /// false if another thread/path already recorded it or it is too old.
    pub fn mark_authenticated(&mut self, counter: u64) -> bool {
        if !self.would_accept(counter) {
            return false;
        }

        match self.highest {
            None => {
                self.highest = Some(counter);
                self.bits[0] = 1;
            }
            Some(highest) if counter > highest => {
                self.shift_older(counter - highest);
                self.highest = Some(counter);
                self.bits[0] |= 1;
            }
            Some(highest) => {
                self.set_bit((highest - counter) as usize);
            }
        }
        true
    }

    #[cfg(test)]
    fn highest(&self) -> Option<u64> {
        self.highest
    }

    fn bit_is_set(&self, distance: usize) -> bool {
        let word = distance / WORD_BITS;
        let bit = distance % WORD_BITS;
        self.bits[word] & (1u64 << bit) != 0
    }

    fn set_bit(&mut self, distance: usize) {
        let word = distance / WORD_BITS;
        let bit = distance % WORD_BITS;
        self.bits[word] |= 1u64 << bit;
    }

    fn shift_older(&mut self, amount: u64) {
        if amount >= DEFAULT_WINDOW_SIZE as u64 {
            self.bits.fill(0);
            return;
        }

        let amount = amount as usize;
        let word_shift = amount / WORD_BITS;
        let bit_shift = amount % WORD_BITS;
        let old = self.bits;
        self.bits.fill(0);

        for (source_word, value) in old.into_iter().enumerate() {
            let destination_word = source_word + word_shift;
            if destination_word >= WINDOW_WORDS {
                break;
            }
            self.bits[destination_word] |= value << bit_shift;
            if bit_shift != 0 && destination_word + 1 < WINDOW_WORDS {
                self.bits[destination_word + 1] |= value >> (WORD_BITS - bit_shift);
            }
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_first_new_and_out_of_order_counters_once() {
        let mut window = ReplayWindow::new();
        assert!(window.mark_authenticated(10));
        assert!(window.mark_authenticated(12));
        assert!(window.mark_authenticated(11));
        assert!(!window.mark_authenticated(10));
        assert!(!window.mark_authenticated(11));
        assert!(!window.mark_authenticated(12));
    }

    #[test]
    fn rejects_counters_older_than_the_window() {
        let mut window = ReplayWindow::new();
        assert!(window.mark_authenticated(0));
        assert!(window.mark_authenticated(DEFAULT_WINDOW_SIZE as u64));
        assert!(!window.would_accept(0));
        assert!(!window.mark_authenticated(0));
        assert!(window.mark_authenticated(1));
    }

    #[test]
    fn large_jump_clears_old_history() {
        let mut window = ReplayWindow::new();
        assert!(window.mark_authenticated(20));
        assert!(window.mark_authenticated(10_000));
        assert_eq!(window.highest(), Some(10_000));
        assert!(!window.would_accept(20));
        assert!(window.mark_authenticated(9_999));
    }

    #[test]
    fn unauthenticated_precheck_does_not_advance_window() {
        let mut window = ReplayWindow::new();
        assert!(window.mark_authenticated(50));
        assert!(window.would_accept(u64::MAX));
        assert_eq!(window.highest(), Some(50));
        assert!(window.mark_authenticated(49));
    }

    #[test]
    fn shifts_across_word_and_window_boundaries() {
        let mut window = ReplayWindow::new();
        for counter in [0, 1, 63, 64, 65, 4094, 4095] {
            assert!(window.mark_authenticated(counter));
        }
        assert!(window.mark_authenticated(4096));
        assert!(!window.would_accept(0));
        for counter in [1, 63, 64, 65, 4094, 4095, 4096] {
            assert!(!window.would_accept(counter), "counter {counter}");
        }
    }
}
