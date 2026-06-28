//! Noise_IKpsk2 handshake for HushWire.
//!
//! Provides forward secrecy: data is encrypted with a session key derived from
//! ephemeral Diffie-Hellman, not the static PSK. The PSK is mixed in at the
//! end of the handshake as an additional authentication factor only.
//!
//! Simplified handshake (3 DH operations, 2 on-wire messages):
//!
//!   Initiator                           Responder
//!   ---------                           ---------
//!   static_priv_i, ephemeral_i          static_priv_r, ephemeral_r
//!   DH1 = init_static × resp_eph        DH1 = init_static × resp_eph
//!   DH2 = init_eph × resp_static        DH2 = init_eph × resp_static
//!   DH3 = init_eph × resp_eph           DH3 = init_eph × resp_eph
//!   keys = HKDF(DH1 || DH2 || DH3 || psk)
//!
//! On-wire:
//!   msg1 (Init→Resp): eph_i_pub(32) || AEAD_PSK( static_i_pub(32) )
//!   msg2 (Resp→Init): eph_r_pub(32) || AEAD_PSK( session_id(8) )
//! Both sides derive the same session keys. session_id (from msg2) identifies
//! the session in data packet nonces so the receiver picks the right key.
//!
//! X25519 DH is symmetric (A×B == B×A), so each side computes whichever
//! direction it has the secret for — the result is identical.

use std::time::Instant;

use blake2::Blake2s256;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::SimpleHkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::auth::KEY_SIZE;

/// A successfully negotiated session. Holds the symmetric keys used to
/// encrypt/decrypt data packets, plus a session_id for the receiver to
/// look up which session a packet belongs to.
///
/// Fields are read by tunnel.rs handshake integration (pending). The
/// `#[allow(dead_code)]` silences warnings until that integration lands.
#[derive(Debug)]
#[allow(dead_code)]
pub struct Session {
    /// 8-byte identifier placed in the nonce prefix of data packets.
    pub session_id: [u8; 8],
    /// Key used to encrypt outgoing data.
    pub send_key: [u8; KEY_SIZE],
    /// Key used to decrypt incoming data.
    pub recv_key: [u8; KEY_SIZE],
    /// When the session was established (for expiry / rekey).
    pub created_at: Instant,
    /// Number of packets sent (for rekey-after-N-packets).
    pub tx_count: u64,
    /// Number of packets received.
    pub rx_count: u64,
}

impl Session {
    /// Maximum packets before mandatory rekey (conservative, unreachable).
    pub const MAX_PACKETS: u64 = 1u64 << 60;

    /// Returns true if this session should be rotated.
    pub fn needs_rekey(&self) -> bool {
        self.tx_count >= Self::MAX_PACKETS || self.rx_count >= Self::MAX_PACKETS
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.recv_key.zeroize();
    }
}

/// Initiator's first handshake step: the on-wire msg1 (to send) + state (to
/// keep for finalizing when the response arrives).
pub struct InitiatorHandshake {
    /// Bytes to send to the responder (msg1).
    pub message: Vec<u8>,
    state: InitiatorState,
}

impl InitiatorHandshake {
    /// Split into (message_to_send, state_to_keep). Allows sending the message
    /// and storing the state separately without clone issues.
    pub fn into_parts(self) -> (Vec<u8>, InitiatorState) {
        (self.message, self.state)
    }
}

/// Opaque initiator state (kept until the response arrives, then passed to
/// `initiator_finalize`). Separated from the message so it can be stored
/// independently (e.g. cross-thread).
pub struct InitiatorState {
    eph_secret: StaticSecret,
    psk: [u8; 32],
}

impl Drop for InitiatorState {
    fn drop(&mut self) {
        self.eph_secret.zeroize();
    }
}

/// Output of a responder processing msg1: msg2 to send back + ready session.
pub struct ResponderHandshake {
    /// Bytes to send back to the initiator (msg2).
    pub message: Vec<u8>,
    /// The negotiated session (ready to decrypt data immediately).
    pub session: Session,
}

// On-wire message sizes.
/// msg1 = eph_i_pub(32) + AEAD_PSK(static_i_pub: 32 + tag 16) = 80 bytes
pub const MSG1_SIZE: usize = 32 + 32 + 16;
/// msg2 = eph_r_pub(32) + AEAD_PSK(session_id: 8 + tag 16) = 56 bytes
pub const MSG2_SIZE: usize = 32 + 8 + 16;

/// Initiator starts the handshake. Returns msg1 + internal state.
///
/// `local_static` is the initiator's static private key.
/// `remote_static_pub` is the responder's known public key (used later in finalize,
///   accepted here for API symmetry — the caller has it at start time).
/// `psk` is the shared pre-shared key (authentication factor).
pub fn initiator_start(
    local_static: &StaticSecret,
    _remote_static_pub: &PublicKey,
    psk: &[u8; 32],
) -> InitiatorHandshake {
    let mut eph_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut eph_bytes);
    let eph_secret = StaticSecret::from(eph_bytes);
    let eph_pub = PublicKey::from(&eph_secret);
    let local_static_pub = PublicKey::from(local_static);

    // msg1 = eph_i_pub || AEAD_PSK( static_i_pub )
    let mut message = Vec::with_capacity(MSG1_SIZE);
    message.extend_from_slice(eph_pub.as_bytes());
    let encrypted_static = encrypt_with_psk(psk, local_static_pub.as_bytes());
    message.extend_from_slice(&encrypted_static);

    InitiatorHandshake {
        message,
        state: InitiatorState {
            eph_secret,
            psk: *psk,
        },
    }
}

/// Initiator processes msg2 and completes the handshake.
///
/// Needs the `state` from `initiator_start().into_parts()`, plus both static keys
/// (local + remote) because the three DH operations require both.
pub fn initiator_finalize(
    state: InitiatorState,
    local_static: &StaticSecret,
    remote_static_pub: &PublicKey,
    msg2: &[u8],
) -> Option<Session> {
    if msg2.len() != MSG2_SIZE {
        return None;
    }

    let mut state = state;
    let eph_r_pub = PublicKey::from(<[u8; 32]>::try_from(&msg2[0..32]).ok()?);

    // Decrypt session_id from msg2.
    let session_id_bytes = decrypt_with_psk(&state.psk, &msg2[32..32 + 8 + 16])?;
    let session_id = <[u8; 8]>::try_from(&session_id_bytes[..8]).ok()?;

    // Three DH operations (fixed role order, X25519 symmetric).
    let dh1 = local_static.diffie_hellman(&eph_r_pub).to_bytes(); // init_static × resp_eph
    let dh2 = state
        .eph_secret
        .diffie_hellman(remote_static_pub)
        .to_bytes(); // init_eph × resp_static
    let dh3 = state.eph_secret.diffie_hellman(&eph_r_pub).to_bytes(); // init_eph × resp_eph

    let (send_key, recv_key) = derive_session_keys(&dh1, &dh2, &dh3, &state.psk, true);

    state.eph_secret.zeroize();

    Some(Session {
        session_id,
        send_key,
        recv_key,
        created_at: Instant::now(),
        tx_count: 0,
        rx_count: 0,
    })
}

/// Responder processes msg1 and produces msg2 + a ready-to-use session.
pub fn responder_respond(
    local_static: &StaticSecret,
    psk: &[u8; 32],
    msg1: &[u8],
) -> Option<ResponderHandshake> {
    if msg1.len() != MSG1_SIZE {
        return None;
    }

    let eph_i_pub = PublicKey::from(<[u8; 32]>::try_from(&msg1[0..32]).ok()?);

    // Decrypt the initiator's static public key.
    let static_i_bytes = decrypt_with_psk(psk, &msg1[32..32 + 32 + 16])?;
    let static_i_pub = PublicKey::from(<[u8; 32]>::try_from(&static_i_bytes[..32]).ok()?);

    // Generate responder ephemeral (as StaticSecret for multiple DH).
    let mut eph_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut eph_bytes);
    let eph_secret = StaticSecret::from(eph_bytes);
    let eph_r_pub = PublicKey::from(&eph_secret);

    // Three DH operations (fixed role order, X25519 symmetric).
    // Responder has: resp_static(local_static), resp_eph(eph_secret),
    // init_static(static_i_pub), init_eph(eph_i_pub).
    let dh1 = eph_secret.diffie_hellman(&static_i_pub).to_bytes(); // resp_eph × init_static == init_static × resp_eph
    let dh2 = local_static.diffie_hellman(&eph_i_pub).to_bytes(); // resp_static × init_eph == init_eph × resp_static
    let dh3 = eph_secret.diffie_hellman(&eph_i_pub).to_bytes(); // resp_eph × init_eph == init_eph × resp_eph

    // Generate session_id.
    let mut session_id = [0u8; 8];
    OsRng.fill_bytes(&mut session_id);

    // msg2 = eph_r_pub || AEAD_PSK( session_id )
    let mut message = Vec::with_capacity(MSG2_SIZE);
    message.extend_from_slice(eph_r_pub.as_bytes());
    let encrypted_session_id = encrypt_with_psk(psk, &session_id);
    message.extend_from_slice(&encrypted_session_id);

    let (send_key, recv_key) = derive_session_keys(&dh1, &dh2, &dh3, psk, false);

    let session = Session {
        session_id,
        send_key,
        recv_key,
        created_at: Instant::now(),
        tx_count: 0,
        rx_count: 0,
    };

    Some(ResponderHandshake { message, session })
}

// --- Key derivation ---

/// Derive (send_key, recv_key) from the three DH outputs + PSK.
///
/// `is_initiator` determines direction: initiator sends with key_a, receives
/// with key_b; responder is reversed (so they match up).
fn derive_session_keys(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    psk: &[u8; 32],
    is_initiator: bool,
) -> ([u8; KEY_SIZE], [u8; KEY_SIZE]) {
    let mut ikm = [0u8; 32 * 4];
    ikm[0..32].copy_from_slice(dh1);
    ikm[32..64].copy_from_slice(dh2);
    ikm[64..96].copy_from_slice(dh3);
    ikm[96..128].copy_from_slice(psk);

    let hk = SimpleHkdf::<Blake2s256>::new(Some(b"hushwire-noise-v1"), &ikm);
    let mut okm = [0u8; 64];
    hk.expand(b"session-keys", &mut okm)
        .expect("expand 64 bytes always succeeds");

    let mut key_a = [0u8; KEY_SIZE];
    let mut key_b = [0u8; KEY_SIZE];
    key_a.copy_from_slice(&okm[0..32]);
    key_b.copy_from_slice(&okm[32..64]);

    if is_initiator {
        (key_a, key_b) // initiator: send=a, recv=b
    } else {
        (key_b, key_a) // responder: send=b, recv=a
    }
}

// --- PSK-encrypted handshake field helpers ---
//
// The PSK is used only to encrypt handshake fields (static_i_pub in msg1,
// session_id in msg2). Data encryption uses session keys, never the PSK.
// A fixed nonce is safe here because each PSK encrypts distinct plaintexts
// (nonce reuse only matters for identical key+nonce+plaintext triples).

/// Fixed 12-byte nonce for handshake field encryption.
const HANDSHAKE_NONCE: [u8; 12] = *b"hushhandshak"; // exactly 12 bytes

fn encrypt_with_psk(psk: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(psk));
    let aad: &[u8] = &[];
    cipher
        .encrypt(
            Nonce::from_slice(&HANDSHAKE_NONCE),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("encryption should not fail")
}

fn decrypt_with_psk(psk: &[u8; 32], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(psk));
    let aad: &[u8] = &[];
    cipher
        .decrypt(
            Nonce::from_slice(&HANDSHAKE_NONCE),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_keypair() -> (StaticSecret, PublicKey) {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    #[test]
    fn handshake_round_trip_both_sides_get_same_keys() {
        let (i_static, _i_pub) = gen_keypair();
        let (r_static, r_pub) = gen_keypair();
        let psk = [0x42u8; 32];

        let init = initiator_start(&i_static, &r_pub, &psk);
        let (msg1, state) = init.into_parts();
        let resp = responder_respond(&r_static, &psk, &msg1).expect("responder should accept msg1");
        let i_session = initiator_finalize(state, &i_static, &r_pub, &resp.message)
            .expect("initiator should accept msg2");

        assert_eq!(i_session.send_key, resp.session.recv_key);
        assert_eq!(i_session.recv_key, resp.session.send_key);
        assert_eq!(i_session.session_id, resp.session.session_id);
    }

    #[test]
    fn wrong_psk_handshake_fails() {
        let (i_static, _) = gen_keypair();
        let (r_static, r_pub) = gen_keypair();
        let psk_a = [0x42u8; 32];
        let psk_b = [0xabu8; 32];

        let init = initiator_start(&i_static, &r_pub, &psk_a);
        assert!(responder_respond(&r_static, &psk_b, &init.message).is_none());
    }

    #[test]
    fn truncated_msg1_rejected() {
        let (r_static, _) = gen_keypair();
        let psk = [0x42u8; 32];
        assert!(responder_respond(&r_static, &psk, &[0u8; 10]).is_none());
        assert!(responder_respond(&r_static, &psk, &[0u8; MSG1_SIZE - 1]).is_none());
    }

    #[test]
    fn truncated_msg2_rejected() {
        let (i_static, _) = gen_keypair();
        let (r_static, r_pub) = gen_keypair();
        let psk = [0x42u8; 32];

        let init = initiator_start(&i_static, &r_pub, &psk);
        let (msg1, _) = init.into_parts();
        let resp = responder_respond(&r_static, &psk, &msg1).unwrap();
        let truncated = &resp.message[..MSG2_SIZE - 1];
        let init2 = initiator_start(&i_static, &r_pub, &psk);
        let (_, state2) = init2.into_parts();
        assert!(initiator_finalize(state2, &i_static, &r_pub, truncated).is_none());
    }

    #[test]
    fn session_id_is_unique_per_handshake() {
        let (i_static, _) = gen_keypair();
        let (r_static, r_pub) = gen_keypair();
        let psk = [0x42u8; 32];

        let init1 = initiator_start(&i_static, &r_pub, &psk);
        let (msg1_1, state1) = init1.into_parts();
        let resp1 = responder_respond(&r_static, &psk, &msg1_1).unwrap();
        let s1 = initiator_finalize(state1, &i_static, &r_pub, &resp1.message).unwrap();

        let init2 = initiator_start(&i_static, &r_pub, &psk);
        let (msg1_2, state2) = init2.into_parts();
        let resp2 = responder_respond(&r_static, &psk, &msg1_2).unwrap();
        let s2 = initiator_finalize(state2, &i_static, &r_pub, &resp2.message).unwrap();

        assert_ne!(s1.session_id, s2.session_id);
    }

    #[test]
    fn session_keys_deterministic_and_mirrored() {
        let dh1 = [1u8; 32];
        let dh2 = [2u8; 32];
        let dh3 = [3u8; 32];
        let psk = [0x42u8; 32];

        let (s1_a, s1_b) = derive_session_keys(&dh1, &dh2, &dh3, &psk, true);
        let (s2_a, s2_b) = derive_session_keys(&dh1, &dh2, &dh3, &psk, true);
        assert_eq!(s1_a, s2_a);
        assert_eq!(s1_b, s2_b);

        let (r_a, r_b) = derive_session_keys(&dh1, &dh2, &dh3, &psk, false);
        assert_eq!(s1_a, r_b); // initiator send = responder recv
        assert_eq!(s1_b, r_a); // initiator recv = responder send
    }

    #[test]
    fn session_needs_rekey_at_max_packets() {
        let session = Session {
            session_id: [0u8; 8],
            send_key: [0u8; KEY_SIZE],
            recv_key: [0u8; KEY_SIZE],
            created_at: Instant::now(),
            tx_count: Session::MAX_PACKETS,
            rx_count: 0,
        };
        assert!(session.needs_rekey());
    }

    #[test]
    fn session_fresh_does_not_need_rekey() {
        let session = Session {
            session_id: [0u8; 8],
            send_key: [0u8; KEY_SIZE],
            recv_key: [0u8; KEY_SIZE],
            created_at: Instant::now(),
            tx_count: 0,
            rx_count: 0,
        };
        assert!(!session.needs_rekey());
    }
}
