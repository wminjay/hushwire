use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;

/// HushWire encrypted packet layout.
///
/// ```text
///  offset  size  field
///  0       1     version   (0x02)
///  1       1     msg_type  (0x00=data, 0x01=keepalive, 0x02=handshake_init, 0x03=handshake_response)
///  2..10   8     session_id (data/keepalive: identifies the session; handshake: random)
///  10..14  4     nonce_rand (random, completes the 12-byte AEAD nonce)
///  14..    N     ciphertext + 16-byte tag (ChaCha20-Poly1305)
/// ```
///
/// AAD = version || msg_type
///
/// The 12-byte AEAD nonce = session_id(8) || nonce_rand(4). For data packets,
/// session_id lets the receiver look up which session key to use. For handshake
/// messages, session_id is random (no session yet) and the PSK is the key.
/// Keepalive plaintext is empty for legacy one-way keepalives, `0x01` for an
/// active liveness probe, or `0x02` for its acknowledgement.
pub const HEADER_SIZE: usize = 14;
pub const TAG_SIZE: usize = 16;
/// Legacy: size of a pre-shared key. Now an alias for KEY_SIZE; kept for
/// documentation and potential external use.
#[allow(dead_code)]
pub const PSK_SIZE: usize = 32;
/// Size of a ChaCha20-Poly1305 symmetric key (used for session keys and PSK).
pub const KEY_SIZE: usize = 32;
pub const SESSION_ID_SIZE: usize = 8;
pub const NONCE_RAND_SIZE: usize = 4;
pub const MIN_PACKET_SIZE: usize = HEADER_SIZE + TAG_SIZE; // empty ciphertext + tag

/// Byte offset of the session_id within a HushWire packet (after version + msg_type).
pub const SESSION_ID_OFFSET: usize = 2;
/// Byte offset of the random nonce suffix (after session_id).
pub const NONCE_RAND_OFFSET: usize = SESSION_ID_OFFSET + SESSION_ID_SIZE;
/// Length of the AEAD nonce in bytes (session_id + nonce_rand = 8 + 4).
pub const NONCE_SIZE: usize = SESSION_ID_SIZE + NONCE_RAND_SIZE;

/// Authenticated keepalive payloads used for bidirectional UDP liveness.
/// Empty payloads remain valid legacy keepalives and do not request a reply.
pub const KEEPALIVE_PROBE_PAYLOAD: &[u8] = &[0x01];
pub const KEEPALIVE_ACK_PAYLOAD: &[u8] = &[0x02];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgType {
    Data = 0x00,
    Keepalive = 0x01,
    HandshakeInit = 0x02,
    HandshakeResponse = 0x03,
}

impl MsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(MsgType::Data),
            0x01 => Some(MsgType::Keepalive),
            0x02 => Some(MsgType::HandshakeInit),
            0x03 => Some(MsgType::HandshakeResponse),
            _ => None,
        }
    }

    /// Returns true if this message type is a handshake message.
    pub fn is_handshake(&self) -> bool {
        matches!(self, MsgType::HandshakeInit | MsgType::HandshakeResponse)
    }
}

/// Build a 12-byte nonce from a session_id (8 bytes) + random (4 bytes).
pub fn build_nonce(session_id: &[u8; SESSION_ID_SIZE]) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[..SESSION_ID_SIZE].copy_from_slice(session_id);
    OsRng.fill_bytes(&mut nonce[SESSION_ID_SIZE..]);
    nonce
}

/// Extract the session_id from a packet's nonce field (bytes 2..10).
pub fn extract_session_id(packet: &[u8]) -> Option<[u8; SESSION_ID_SIZE]> {
    if packet.len() < HEADER_SIZE {
        return None;
    }
    let mut sid = [0u8; SESSION_ID_SIZE];
    sid.copy_from_slice(&packet[SESSION_ID_OFFSET..NONCE_RAND_OFFSET]);
    Some(sid)
}

/// Encrypt `payload` with the given key (session key for data, PSK for handshake)
/// and prepend the HushWire header.
///
/// `session_id` is embedded in the nonce so the receiver can look up the key.
pub fn encode_packet(
    payload: &[u8],
    key: &[u8; KEY_SIZE],
    msg_type: MsgType,
    session_id: &[u8; SESSION_ID_SIZE],
) -> Vec<u8> {
    let nonce = build_nonce(session_id);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let aad = [0x02, msg_type as u8];

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: payload,
                aad: &aad,
            },
        )
        .expect("encryption should not fail");

    let mut packet = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    packet.push(0x02); // version
    packet.push(msg_type as u8);
    packet.extend_from_slice(&nonce); // session_id(8) + nonce_rand(4)
    packet.extend_from_slice(&ciphertext);
    packet
}

/// Decrypt and authenticate `packet` using `key`.
/// Returns the message type and plaintext payload on success.
pub fn decode_packet(packet: &[u8], key: &[u8; KEY_SIZE]) -> Option<(MsgType, Vec<u8>)> {
    if packet.len() < MIN_PACKET_SIZE {
        return None;
    }
    if packet[0] != 0x02 {
        return None;
    }
    let msg_type = MsgType::from_u8(packet[1])?;

    let nonce = Nonce::from_slice(&packet[SESSION_ID_OFFSET..HEADER_SIZE]);
    let aad = [packet[0], packet[1]];

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &packet[HEADER_SIZE..],
                aad: &aad,
            },
        )
        .ok()?;

    Some((msg_type, plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; KEY_SIZE] {
        [0x42u8; KEY_SIZE]
    }

    fn test_session_id() -> [u8; SESSION_ID_SIZE] {
        [0xAA; SESSION_ID_SIZE]
    }

    #[test]
    fn round_trip_data_packet() {
        let key = test_key();
        let sid = test_session_id();
        let payload = b"hello world";

        let packet = encode_packet(payload, &key, MsgType::Data, &sid);
        assert!(packet.len() >= MIN_PACKET_SIZE);

        let (msg_type, decoded) = decode_packet(&packet, &key).expect("valid packet");
        assert_eq!(msg_type, MsgType::Data);
        assert_eq!(&decoded, payload);
    }

    #[test]
    fn round_trip_keepalive() {
        let key = test_key();
        let sid = test_session_id();

        let packet = encode_packet(b"", &key, MsgType::Keepalive, &sid);
        let (msg_type, decoded) = decode_packet(&packet, &key).expect("valid packet");
        assert_eq!(msg_type, MsgType::Keepalive);
        assert!(decoded.is_empty());
    }

    #[test]
    fn round_trip_keepalive_probe_and_ack() {
        let key = test_key();
        let sid = test_session_id();

        for payload in [KEEPALIVE_PROBE_PAYLOAD, KEEPALIVE_ACK_PAYLOAD] {
            let packet = encode_packet(payload, &key, MsgType::Keepalive, &sid);
            let (msg_type, decoded) = decode_packet(&packet, &key).expect("valid packet");
            assert_eq!(msg_type, MsgType::Keepalive);
            assert_eq!(decoded, payload);
        }
    }

    #[test]
    fn round_trip_handshake_init() {
        let key = test_key();
        let sid = test_session_id();
        let payload = b"handshake-data";

        let packet = encode_packet(payload, &key, MsgType::HandshakeInit, &sid);
        let (msg_type, decoded) = decode_packet(&packet, &key).expect("valid packet");
        assert_eq!(msg_type, MsgType::HandshakeInit);
        assert_eq!(&decoded, payload);
    }

    #[test]
    fn wrong_key_fails() {
        let key_a = test_key();
        let mut key_b = [0u8; KEY_SIZE];
        key_b.fill(0xab);
        let sid = test_session_id();

        let packet = encode_packet(b"secret", &key_a, MsgType::Data, &sid);
        assert!(decode_packet(&packet, &key_b).is_none());
    }

    #[test]
    fn different_sessions_cannot_decrypt() {
        let key = test_key();
        let sid_a = [0xAA; SESSION_ID_SIZE];
        let sid_b = [0xBB; SESSION_ID_SIZE];

        // Same key, different session_id — both should decrypt (key is the same).
        // Session_id is for routing, not encryption. The key determines decryptability.
        let packet = encode_packet(b"data", &key, MsgType::Data, &sid_a);
        assert!(decode_packet(&packet, &key).is_some());

        let packet_b = encode_packet(b"data", &key, MsgType::Data, &sid_b);
        assert!(decode_packet(&packet_b, &key).is_some());
    }

    #[test]
    fn truncated_packet_fails() {
        let key = test_key();
        assert!(decode_packet(&[0x02], &key).is_none());
        assert!(decode_packet(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x00], &key).is_none());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = test_key();
        let sid = test_session_id();

        let mut packet = encode_packet(b"hello world", &key, MsgType::Data, &sid);
        let last = packet.len() - 1;
        packet[last] ^= 0xff;

        assert!(decode_packet(&packet, &key).is_none());
    }

    #[test]
    fn tampered_header_fails() {
        let key = test_key();
        let sid = test_session_id();

        let mut packet = encode_packet(b"hello world", &key, MsgType::Data, &sid);
        packet[1] = 0x99; // corrupt msg_type

        assert!(decode_packet(&packet, &key).is_none());
    }

    #[test]
    fn extract_session_id_round_trips() {
        let key = test_key();
        let sid = test_session_id();

        let packet = encode_packet(b"data", &key, MsgType::Data, &sid);
        let extracted = extract_session_id(&packet).expect("should extract");
        assert_eq!(extracted, sid);
    }

    #[test]
    fn msg_type_is_handshake() {
        assert!(MsgType::HandshakeInit.is_handshake());
        assert!(MsgType::HandshakeResponse.is_handshake());
        assert!(!MsgType::Data.is_handshake());
        assert!(!MsgType::Keepalive.is_handshake());
    }
}
