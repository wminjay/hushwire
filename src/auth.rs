use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;

/// HushWire encrypted packet layout.
///
/// ```text
///  offset  size  field
///  0       1     version   (0x02)
///  1       1     msg_type  (0x00 = data)
///  2..13   12    nonce     (random)
///  13..    N     ciphertext + 16-byte tag (ChaCha20-Poly1305)
/// ```
///
/// AAD = version || msg_type
pub const HEADER_SIZE: usize = 14;
pub const TAG_SIZE: usize = 16;
pub const PSK_SIZE: usize = 32;
pub const MIN_PACKET_SIZE: usize = HEADER_SIZE + TAG_SIZE; // empty ciphertext + tag

/// Byte offset of the AEAD nonce within a HushWire packet (after the
/// 1-byte version and 1-byte msg_type).
pub const NONCE_OFFSET: usize = 2;
/// Length of the AEAD nonce in bytes.
pub const NONCE_SIZE: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgType {
    Data = 0x00,
    Keepalive = 0x01,
}

impl MsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(MsgType::Data),
            0x01 => Some(MsgType::Keepalive),
            _ => None,
        }
    }
}

/// Encrypt `payload` and prepend the HushWire header keyed by `psk`.
pub fn encode_packet(payload: &[u8], psk: &[u8; PSK_SIZE], msg_type: MsgType) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(psk));
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
    packet.extend_from_slice(&nonce);
    packet.extend_from_slice(&ciphertext);
    packet
}

/// Decrypt and authenticate `packet` using `psk`.
/// Returns the message type and plaintext payload on success.
pub fn decode_packet(packet: &[u8], psk: &[u8; PSK_SIZE]) -> Option<(MsgType, Vec<u8>)> {
    if packet.len() < MIN_PACKET_SIZE {
        return None;
    }
    if packet[0] != 0x02 {
        return None;
    }
    let msg_type = MsgType::from_u8(packet[1])?;

    let nonce = Nonce::from_slice(&packet[2..HEADER_SIZE]);
    let aad = [packet[0], packet[1]];

    let cipher = ChaCha20Poly1305::new(Key::from_slice(psk));
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

    #[test]
    fn round_trip_data_packet() {
        let psk = [0x42u8; PSK_SIZE];
        let payload = b"hello world";

        let packet = encode_packet(payload, &psk, MsgType::Data);
        assert!(packet.len() >= MIN_PACKET_SIZE);

        let (msg_type, decoded) = decode_packet(&packet, &psk).expect("valid packet");
        assert_eq!(msg_type, MsgType::Data);
        assert_eq!(&decoded, payload);
    }

    #[test]
    fn wrong_psk_fails() {
        let psk_a = [0x42u8; PSK_SIZE];
        let psk_b = [0xabu8; PSK_SIZE];
        let payload = b"secret";

        let packet = encode_packet(payload, &psk_a, MsgType::Data);
        assert!(decode_packet(&packet, &psk_b).is_none());
    }

    #[test]
    fn truncated_packet_fails() {
        let psk = [0x42u8; PSK_SIZE];
        assert!(decode_packet(&[0x02], &psk).is_none());
        assert!(decode_packet(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x00], &psk).is_none());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let psk = [0x42u8; PSK_SIZE];
        let payload = b"hello world";

        let mut packet = encode_packet(payload, &psk, MsgType::Data);
        let last = packet.len() - 1;
        packet[last] ^= 0xff;

        assert!(decode_packet(&packet, &psk).is_none());
    }

    #[test]
    fn tampered_header_fails() {
        let psk = [0x42u8; PSK_SIZE];
        let payload = b"hello world";

        let mut packet = encode_packet(payload, &psk, MsgType::Data);
        packet[1] = 0x99; // corrupt msg_type

        assert!(decode_packet(&packet, &psk).is_none());
    }
}
