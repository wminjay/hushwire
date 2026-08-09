//! HushWire v3 packet framing.
//!
//! Cryptography is provided by the standard Noise implementation in
//! `crate::noise`. This module only encodes and parses the small public header
//! needed to route handshake and transport packets.

pub const WIRE_VERSION: u8 = 0x03;
pub const SESSION_ID_SIZE: usize = 8;
pub const COUNTER_SIZE: usize = 8;

/// `version || kind || id`.
pub const HANDSHAKE_HEADER_SIZE: usize = 1 + 1 + SESSION_ID_SIZE;
/// `version || kind || session_id || counter`.
pub const TRANSPORT_HEADER_SIZE: usize = HANDSHAKE_HEADER_SIZE + COUNTER_SIZE;
/// Every Noise transport ciphertext contains a 16-byte AEAD tag and our
/// encrypted one-byte message type.
pub const MIN_TRANSPORT_PACKET_SIZE: usize = TRANSPORT_HEADER_SIZE + 1 + 16;

pub const KEEPALIVE_PROBE_PAYLOAD: &[u8] = &[0x01];
pub const KEEPALIVE_ACK_PAYLOAD: &[u8] = &[0x02];

const HANDSHAKE_PROLOGUE_PREFIX: &[u8] = b"HushWire-v3-handshake";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PacketKind {
    Transport = 0x00,
    HandshakeInit = 0x01,
    HandshakeResponse = 0x02,
}

impl PacketKind {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Transport),
            0x01 => Some(Self::HandshakeInit),
            0x02 => Some(Self::HandshakeResponse),
            _ => None,
        }
    }

    pub fn is_handshake(self) -> bool {
        matches!(self, Self::HandshakeInit | Self::HandshakeResponse)
    }
}

/// The semantic type is encrypted inside every Noise transport message so it
/// cannot be changed independently of the authenticated payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MsgType {
    Data = 0x00,
    Keepalive = 0x01,
}

impl MsgType {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Data),
            0x01 => Some(Self::Keepalive),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParsedPacket<'a> {
    Handshake {
        kind: PacketKind,
        handshake_id: [u8; SESSION_ID_SIZE],
        message: &'a [u8],
    },
    Transport {
        session_id: [u8; SESSION_ID_SIZE],
        counter: u64,
        ciphertext: &'a [u8],
    },
}

pub fn encode_handshake(
    kind: PacketKind,
    handshake_id: &[u8; SESSION_ID_SIZE],
    message: &[u8],
) -> Vec<u8> {
    debug_assert!(kind.is_handshake());
    let mut packet = Vec::with_capacity(HANDSHAKE_HEADER_SIZE + message.len());
    packet.push(WIRE_VERSION);
    packet.push(kind as u8);
    packet.extend_from_slice(handshake_id);
    packet.extend_from_slice(message);
    packet
}

pub fn encode_transport(
    session_id: &[u8; SESSION_ID_SIZE],
    counter: u64,
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(TRANSPORT_HEADER_SIZE + ciphertext.len());
    packet.push(WIRE_VERSION);
    packet.push(PacketKind::Transport as u8);
    packet.extend_from_slice(session_id);
    packet.extend_from_slice(&counter.to_be_bytes());
    packet.extend_from_slice(ciphertext);
    packet
}

pub fn decode_packet(packet: &[u8]) -> Option<ParsedPacket<'_>> {
    if packet.len() < HANDSHAKE_HEADER_SIZE || packet[0] != WIRE_VERSION {
        return None;
    }

    let kind = PacketKind::from_u8(packet[1])?;
    let mut id = [0u8; SESSION_ID_SIZE];
    id.copy_from_slice(&packet[2..HANDSHAKE_HEADER_SIZE]);

    if kind.is_handshake() {
        let message = packet.get(HANDSHAKE_HEADER_SIZE..)?;
        if message.is_empty() {
            return None;
        }
        return Some(ParsedPacket::Handshake {
            kind,
            handshake_id: id,
            message,
        });
    }

    if packet.len() < MIN_TRANSPORT_PACKET_SIZE {
        return None;
    }
    let counter = u64::from_be_bytes(
        packet[HANDSHAKE_HEADER_SIZE..TRANSPORT_HEADER_SIZE]
            .try_into()
            .ok()?,
    );
    Some(ParsedPacket::Transport {
        session_id: id,
        counter,
        ciphertext: &packet[TRANSPORT_HEADER_SIZE..],
    })
}

pub fn encode_transport_plaintext(msg_type: MsgType, payload: &[u8]) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(1 + payload.len());
    plaintext.push(msg_type as u8);
    plaintext.extend_from_slice(payload);
    plaintext
}

pub fn decode_transport_plaintext(plaintext: &[u8]) -> Option<(MsgType, &[u8])> {
    let (&first, payload) = plaintext.split_first()?;
    Some((MsgType::from_u8(first)?, payload))
}

/// Bind the public handshake identifier and wire version into Noise's
/// transcript. A modified identifier therefore cannot produce a valid
/// response or transport state.
pub fn handshake_prologue(handshake_id: &[u8; SESSION_ID_SIZE]) -> Vec<u8> {
    let mut prologue = Vec::with_capacity(HANDSHAKE_PROLOGUE_PREFIX.len() + 1 + SESSION_ID_SIZE);
    prologue.extend_from_slice(HANDSHAKE_PROLOGUE_PREFIX);
    prologue.push(WIRE_VERSION);
    prologue.extend_from_slice(handshake_id);
    prologue
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_packet_round_trips() {
        let id = [0x11; SESSION_ID_SIZE];
        let packet = encode_handshake(PacketKind::HandshakeInit, &id, b"noise-message");
        assert_eq!(
            decode_packet(&packet),
            Some(ParsedPacket::Handshake {
                kind: PacketKind::HandshakeInit,
                handshake_id: id,
                message: b"noise-message",
            })
        );
    }

    #[test]
    fn transport_packet_round_trips() {
        let id = [0x22; SESSION_ID_SIZE];
        let ciphertext = vec![0xAA; 17];
        let packet = encode_transport(&id, 42, &ciphertext);
        assert_eq!(
            decode_packet(&packet),
            Some(ParsedPacket::Transport {
                session_id: id,
                counter: 42,
                ciphertext: &ciphertext,
            })
        );
    }

    #[test]
    fn transport_semantic_type_is_inside_plaintext() {
        let plaintext = encode_transport_plaintext(MsgType::Keepalive, KEEPALIVE_PROBE_PAYLOAD);
        let (kind, payload) = decode_transport_plaintext(&plaintext).expect("plaintext");
        assert_eq!(kind, MsgType::Keepalive);
        assert_eq!(payload, KEEPALIVE_PROBE_PAYLOAD);
    }

    #[test]
    fn rejects_old_unknown_and_truncated_packets() {
        assert!(decode_packet(&[]).is_none());
        assert!(decode_packet(&[0x02; HANDSHAKE_HEADER_SIZE]).is_none());

        let mut unknown = vec![0u8; HANDSHAKE_HEADER_SIZE];
        unknown[0] = WIRE_VERSION;
        unknown[1] = 0xff;
        assert!(decode_packet(&unknown).is_none());

        let id = [0x33; SESSION_ID_SIZE];
        let short = encode_transport(&id, 0, &[0u8; 16]);
        assert!(decode_packet(&short).is_none());
    }

    #[test]
    fn handshake_id_is_bound_into_the_prologue() {
        let first = handshake_prologue(&[1u8; SESSION_ID_SIZE]);
        let second = handshake_prologue(&[2u8; SESSION_ID_SIZE]);
        assert_ne!(first, second);
        assert!(first.starts_with(HANDSHAKE_PROLOGUE_PREFIX));
    }
}
