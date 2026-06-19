use std::net::Ipv4Addr;

use thiserror::Error;

#[derive(Clone, Copy, Debug)]
pub struct Ipv4Packet<'a> {
    bytes: &'a [u8],
}

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("packet is too short for an IPv4 header: {0} bytes")]
    TooShort(usize),
    #[error("packet is not IPv4: version={0}")]
    NotIpv4(u8),
    #[error("IPv4 header length exceeds packet length: header={header_len} packet={packet_len}")]
    HeaderTooLong {
        header_len: usize,
        packet_len: usize,
    },
}

impl<'a> Ipv4Packet<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < 20 {
            return Err(PacketError::TooShort(bytes.len()));
        }

        let version = bytes[0] >> 4;
        if version != 4 {
            return Err(PacketError::NotIpv4(version));
        }

        let header_len = usize::from(bytes[0] & 0x0f) * 4;
        if header_len > bytes.len() {
            return Err(PacketError::HeaderTooLong {
                header_len,
                packet_len: bytes.len(),
            });
        }

        Ok(Self { bytes })
    }

    pub fn source(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.bytes[12],
            self.bytes[13],
            self.bytes[14],
            self.bytes[15],
        )
    }

    pub fn destination(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.bytes[16],
            self.bytes[17],
            self.bytes[18],
            self.bytes[19],
        )
    }

    pub fn protocol(&self) -> u8 {
        self.bytes[9]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_addresses_and_protocol() {
        let packet = [
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 64, 6, 0x00, 0x00, 10, 77, 0, 1, 10,
            77, 0, 2,
        ];

        let parsed = Ipv4Packet::parse(&packet).expect("valid IPv4 packet");

        assert_eq!(parsed.source(), Ipv4Addr::new(10, 77, 0, 1));
        assert_eq!(parsed.destination(), Ipv4Addr::new(10, 77, 0, 2));
        assert_eq!(parsed.protocol(), 6);
    }

    #[test]
    fn rejects_non_ipv4_packets() {
        let packet = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 17, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        assert!(matches!(
            Ipv4Packet::parse(&packet),
            Err(PacketError::NotIpv4(6))
        ));
    }
}
