//! Standards-based Noise session handling for the HushWire v3 wire protocol.
//!
//! v3 uses `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` through the audited `snow`
//! state-machine implementation. The public packet counter is passed to
//! Noise's stateless transport API as the ChaCha20-Poly1305 nonce; it is never
//! random and never reused within a sending key.

use std::fmt;
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;
use snow::{Builder, HandshakeState, StatelessTransportState};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::auth::{self, MsgType, ParsedPacket, SESSION_ID_SIZE};
use crate::replay::ReplayWindow;

pub const NOISE_PATTERN: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
pub const REKEY_AFTER_MESSAGES: u64 = 1u64 << 32;

const AEAD_TAG_SIZE: usize = 16;
const MAX_NOISE_MESSAGE_SIZE: usize = 65_535;

#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("Noise operation failed: {0}")]
    Snow(#[from] snow::Error),
    #[error("handshake did not reveal the configured remote static key")]
    MissingRemoteStatic,
    #[error("handshake remote static key does not match the configured peer")]
    RemoteStaticMismatch,
    #[error("handshake response contained an invalid session identifier")]
    InvalidSessionId,
    #[error("transport packet belongs to another session")]
    WrongSession,
    #[error("transport packet is malformed")]
    MalformedTransport,
    #[error("transport counter is a replay or outside the receive window")]
    Replay,
    #[error("transport sending counter is exhausted")]
    CounterExhausted,
}

/// A negotiated bidirectional transport keypair.
pub struct Session {
    pub session_id: [u8; SESSION_ID_SIZE],
    transport: StatelessTransportState,
    created_at: Instant,
    send_counter: u64,
    received_messages: u64,
    replay: ReplayWindow,
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Session")
            .field("session_id", &self.session_id)
            .field("created_at", &self.created_at)
            .field("send_counter", &self.send_counter)
            .field("received_messages", &self.received_messages)
            .finish_non_exhaustive()
    }
}

impl Session {
    fn new(session_id: [u8; SESSION_ID_SIZE], transport: StatelessTransportState) -> Self {
        Self {
            session_id,
            transport,
            created_at: Instant::now(),
            send_counter: 0,
            received_messages: 0,
            replay: ReplayWindow::new(),
        }
    }

    /// Encrypt and frame a v3 transport message. The counter is reserved
    /// before encryption, so even a local error can never cause nonce reuse.
    pub fn encrypt(&mut self, msg_type: MsgType, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let counter = self.send_counter;
        self.send_counter = self
            .send_counter
            .checked_add(1)
            .ok_or(NoiseError::CounterExhausted)?;

        let plaintext = auth::encode_transport_plaintext(msg_type, payload);
        let mut ciphertext = vec![0u8; plaintext.len() + AEAD_TAG_SIZE];
        let written = self
            .transport
            .write_message(counter, &plaintext, &mut ciphertext)?;
        ciphertext.truncate(written);
        Ok(auth::encode_transport(
            &self.session_id,
            counter,
            &ciphertext,
        ))
    }

    /// Authenticate, replay-check, and decrypt a parsed v3 transport packet.
    /// The replay window advances only after Noise validates the AEAD tag.
    pub fn decrypt(
        &mut self,
        session_id: &[u8; SESSION_ID_SIZE],
        counter: u64,
        ciphertext: &[u8],
    ) -> Result<(MsgType, Vec<u8>), NoiseError> {
        if session_id != &self.session_id {
            return Err(NoiseError::WrongSession);
        }
        if !self.replay.would_accept(counter) {
            return Err(NoiseError::Replay);
        }
        if ciphertext.len() < AEAD_TAG_SIZE + 1 {
            return Err(NoiseError::MalformedTransport);
        }

        let mut plaintext = vec![0u8; ciphertext.len() - AEAD_TAG_SIZE];
        let written = self
            .transport
            .read_message(counter, ciphertext, &mut plaintext)?;
        plaintext.truncate(written);

        // With Session behind one mutex this cannot normally race, but keep
        // the second check as a hard invariant at the state boundary.
        if !self.replay.mark_authenticated(counter) {
            return Err(NoiseError::Replay);
        }
        self.received_messages = self.received_messages.saturating_add(1);

        let (msg_type, payload) =
            auth::decode_transport_plaintext(&plaintext).ok_or(NoiseError::MalformedTransport)?;
        Ok((msg_type, payload.to_vec()))
    }

    pub fn decrypt_packet(&mut self, packet: &[u8]) -> Result<(MsgType, Vec<u8>), NoiseError> {
        let ParsedPacket::Transport {
            session_id,
            counter,
            ciphertext,
        } = auth::decode_packet(packet).ok_or(NoiseError::MalformedTransport)?
        else {
            return Err(NoiseError::MalformedTransport);
        };
        self.decrypt(&session_id, counter, ciphertext)
    }

    pub fn should_rekey(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created_at) >= REKEY_AFTER_TIME
            || self.send_counter >= REKEY_AFTER_MESSAGES
            || self.received_messages >= REKEY_AFTER_MESSAGES
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created_at) >= REJECT_AFTER_TIME
            || self.send_counter == u64::MAX
    }

    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    #[cfg(test)]
    fn set_created_at(&mut self, created_at: Instant) {
        self.created_at = created_at;
    }

    #[cfg(test)]
    fn set_send_counter(&mut self, counter: u64) {
        self.send_counter = counter;
    }
}

/// Initiator's first Noise message plus the state needed to process msg2.
pub struct InitiatorHandshake {
    pub handshake_id: [u8; SESSION_ID_SIZE],
    pub message: Vec<u8>,
    state: InitiatorState,
}

impl InitiatorHandshake {
    pub fn into_parts(self) -> ([u8; SESSION_ID_SIZE], Vec<u8>, InitiatorState) {
        (self.handshake_id, self.message, self.state)
    }
}

pub struct InitiatorState {
    handshake_id: [u8; SESSION_ID_SIZE],
    state: HandshakeState,
}

impl InitiatorState {
    pub fn handshake_id(&self) -> [u8; SESSION_ID_SIZE] {
        self.handshake_id
    }
}

/// Responder output. The session remains a candidate until the first
/// authenticated transport packet proves the initiator received msg2.
pub struct ResponderHandshake {
    pub message: Vec<u8>,
    pub session: Session,
}

pub fn initiator_start(
    local_static: &StaticSecret,
    remote_static_pub: &PublicKey,
    psk: &[u8; 32],
) -> Result<InitiatorHandshake, NoiseError> {
    let mut handshake_id = [0u8; SESSION_ID_SIZE];
    OsRng.fill_bytes(&mut handshake_id);
    initiator_start_with_id(local_static, remote_static_pub, psk, handshake_id)
}

fn initiator_start_with_id(
    local_static: &StaticSecret,
    remote_static_pub: &PublicKey,
    psk: &[u8; 32],
    handshake_id: [u8; SESSION_ID_SIZE],
) -> Result<InitiatorHandshake, NoiseError> {
    let parameters = NOISE_PATTERN.parse()?;
    let prologue = auth::handshake_prologue(&handshake_id);
    let mut state = Builder::new(parameters)
        .local_private_key(local_static.as_bytes())?
        .remote_public_key(remote_static_pub.as_bytes())?
        .psk(2, psk)?
        .prologue(&prologue)?
        .build_initiator()?;

    let mut message = vec![0u8; MAX_NOISE_MESSAGE_SIZE];
    let written = state.write_message(&[], &mut message)?;
    message.truncate(written);

    Ok(InitiatorHandshake {
        handshake_id,
        message,
        state: InitiatorState {
            handshake_id,
            state,
        },
    })
}

pub fn initiator_finalize(
    mut initiator: InitiatorState,
    message: &[u8],
) -> Result<Session, NoiseError> {
    let mut payload = [0u8; SESSION_ID_SIZE + AEAD_TAG_SIZE];
    let written = initiator.state.read_message(message, &mut payload)?;
    if written != SESSION_ID_SIZE {
        return Err(NoiseError::InvalidSessionId);
    }
    let session_id = payload[..SESSION_ID_SIZE]
        .try_into()
        .map_err(|_| NoiseError::InvalidSessionId)?;
    let transport = initiator.state.into_stateless_transport_mode()?;
    Ok(Session::new(session_id, transport))
}

pub fn responder_respond(
    local_static: &StaticSecret,
    expected_remote_static: &PublicKey,
    psk: &[u8; 32],
    handshake_id: [u8; SESSION_ID_SIZE],
    message: &[u8],
) -> Result<ResponderHandshake, NoiseError> {
    let parameters = NOISE_PATTERN.parse()?;
    let prologue = auth::handshake_prologue(&handshake_id);
    let mut state = Builder::new(parameters)
        .local_private_key(local_static.as_bytes())?
        .psk(2, psk)?
        .prologue(&prologue)?
        .build_responder()?;

    let mut payload = [0u8; MAX_NOISE_MESSAGE_SIZE];
    let written = state.read_message(message, &mut payload)?;
    if written != 0 {
        return Err(NoiseError::MalformedTransport);
    }

    let remote_static = state
        .get_remote_static()
        .ok_or(NoiseError::MissingRemoteStatic)?;
    if remote_static != expected_remote_static.as_bytes() {
        return Err(NoiseError::RemoteStaticMismatch);
    }

    let mut session_id = [0u8; SESSION_ID_SIZE];
    OsRng.fill_bytes(&mut session_id);
    let mut response = vec![0u8; MAX_NOISE_MESSAGE_SIZE];
    let response_size = state.write_message(&session_id, &mut response)?;
    response.truncate(response_size);
    let transport = state.into_stateless_transport_mode()?;

    Ok(ResponderHandshake {
        message: response,
        session: Session::new(session_id, transport),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_pair() -> (Session, Session) {
        let initiator_static = StaticSecret::from([0x11; 32]);
        let responder_static = StaticSecret::from([0x22; 32]);
        let initiator_public = PublicKey::from(&initiator_static);
        let responder_public = PublicKey::from(&responder_static);
        let psk = [0x33; 32];

        let handshake = initiator_start(&initiator_static, &responder_public, &psk).unwrap();
        let (handshake_id, message, state) = handshake.into_parts();
        let response = responder_respond(
            &responder_static,
            &initiator_public,
            &psk,
            handshake_id,
            &message,
        )
        .unwrap();
        let initiator_session = initiator_finalize(state, &response.message).unwrap();
        (initiator_session, response.session)
    }

    #[test]
    fn standard_noise_handshake_and_transport_are_bidirectional() {
        let (mut initiator, mut responder) = session_pair();

        let first = initiator.encrypt(MsgType::Data, b"hello").unwrap();
        assert_eq!(
            responder.decrypt_packet(&first).unwrap(),
            (MsgType::Data, b"hello".to_vec())
        );

        let second = responder
            .encrypt(MsgType::Keepalive, auth::KEEPALIVE_ACK_PAYLOAD)
            .unwrap();
        assert_eq!(
            initiator.decrypt_packet(&second).unwrap(),
            (MsgType::Keepalive, auth::KEEPALIVE_ACK_PAYLOAD.to_vec())
        );
    }

    #[test]
    fn consecutive_packets_use_consecutive_unique_counters() {
        let (mut initiator, _) = session_pair();
        let first = initiator.encrypt(MsgType::Data, b"one").unwrap();
        let second = initiator.encrypt(MsgType::Data, b"two").unwrap();

        let ParsedPacket::Transport { counter: a, .. } = auth::decode_packet(&first).unwrap()
        else {
            panic!("transport packet");
        };
        let ParsedPacket::Transport { counter: b, .. } = auth::decode_packet(&second).unwrap()
        else {
            panic!("transport packet");
        };
        assert_eq!((a, b), (0, 1));
        assert_eq!(initiator.send_counter(), 2);
    }

    #[test]
    fn replay_is_rejected_but_out_of_order_packets_are_accepted() {
        let (mut initiator, mut responder) = session_pair();
        let zero = initiator.encrypt(MsgType::Data, b"zero").unwrap();
        let one = initiator.encrypt(MsgType::Data, b"one").unwrap();

        assert!(responder.decrypt_packet(&one).is_ok());
        assert!(responder.decrypt_packet(&zero).is_ok());
        assert!(matches!(
            responder.decrypt_packet(&zero),
            Err(NoiseError::Replay)
        ));
    }

    #[test]
    fn forged_high_counter_does_not_poison_replay_window() {
        let (mut initiator, mut responder) = session_pair();
        let legitimate = initiator.encrypt(MsgType::Data, b"valid").unwrap();
        let mut forged = legitimate.clone();
        forged[auth::HANDSHAKE_HEADER_SIZE..auth::TRANSPORT_HEADER_SIZE]
            .copy_from_slice(&u64::MAX.to_be_bytes());

        assert!(responder.decrypt_packet(&forged).is_err());
        assert_eq!(responder.decrypt_packet(&legitimate).unwrap().1, b"valid");
    }

    #[test]
    fn wrong_psk_and_wrong_configured_static_are_rejected() {
        let initiator_static = StaticSecret::from([0x41; 32]);
        let responder_static = StaticSecret::from([0x42; 32]);
        let responder_public = PublicKey::from(&responder_static);
        let real_initiator_public = PublicKey::from(&initiator_static);
        let wrong_initiator_public = PublicKey::from([0x44; 32]);
        let psk = [0x43; 32];

        let handshake = initiator_start(&initiator_static, &responder_public, &psk).unwrap();
        let (handshake_id, message, initiator_state) = handshake.into_parts();
        let wrong_psk_response = responder_respond(
            &responder_static,
            &real_initiator_public,
            &[0x99; 32],
            handshake_id,
            &message,
        )
        .expect("IK authenticates the initiator static before psk2 is mixed");
        assert!(initiator_finalize(initiator_state, &wrong_psk_response.message).is_err());

        let handshake = initiator_start(&initiator_static, &responder_public, &psk).unwrap();

        assert!(matches!(
            responder_respond(
                &responder_static,
                &wrong_initiator_public,
                &psk,
                handshake.handshake_id,
                &handshake.message,
            ),
            Err(NoiseError::RemoteStaticMismatch)
        ));
    }

    #[test]
    fn handshake_identifier_is_authenticated_by_the_transcript() {
        let initiator_static = StaticSecret::from([0x51; 32]);
        let responder_static = StaticSecret::from([0x52; 32]);
        let initiator_public = PublicKey::from(&initiator_static);
        let responder_public = PublicKey::from(&responder_static);
        let psk = [0x53; 32];
        let handshake = initiator_start(&initiator_static, &responder_public, &psk).unwrap();
        let mut changed_id = handshake.handshake_id;
        changed_id[0] ^= 1;

        assert!(responder_respond(
            &responder_static,
            &initiator_public,
            &psk,
            changed_id,
            &handshake.message,
        )
        .is_err());
    }

    #[test]
    fn sessions_request_rekey_and_eventually_expire() {
        let (mut session, _) = session_pair();
        let now = Instant::now();
        session.set_created_at(now - REKEY_AFTER_TIME);
        assert!(session.should_rekey(now));
        assert!(!session.is_expired(now));

        session.set_created_at(now - REJECT_AFTER_TIME);
        assert!(session.is_expired(now));

        session.set_created_at(now);
        session.set_send_counter(REKEY_AFTER_MESSAGES);
        assert!(session.should_rekey(now));
    }
}
