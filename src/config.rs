use std::collections::HashSet;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use ipnet::Ipv4Net;
use serde::Deserialize;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub interface: InterfaceConfig,
    #[serde(default)]
    pub peer: Vec<PeerConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct InterfaceConfig {
    pub name: String,
    pub address: Ipv4Net,
    pub listen: SocketAddr,
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TransportConfig {
    #[default]
    Udp,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PeerConfig {
    pub name: String,
    pub endpoint: SocketAddr,
    pub allowed_ips: Vec<Ipv4Net>,
    /// Base64-encoded 32-byte pre-shared key.
    pub psk: String,
    /// Persistent keepalive interval in seconds (0 = disabled).
    #[serde(default)]
    pub persistent_keepalive: u16,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config: {0}")]
    Read(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("interface name cannot be empty")]
    EmptyInterfaceName,
    #[error("peer name cannot be empty")]
    EmptyPeerName,
    #[error("duplicate peer name: {0}")]
    DuplicatePeerName(String),
    #[error("peer {0} has no allowed_ips")]
    PeerWithoutAllowedIps(String),
    #[error("mtu must be at least 576, got {0}")]
    MtuTooSmall(u16),
    #[error("peer {0} has an invalid psk: must be base64-encoded 32 bytes")]
    InvalidPsk(String),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&text)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.interface.name.trim().is_empty() {
            return Err(ConfigError::EmptyInterfaceName);
        }

        if self.interface.mtu < 576 {
            return Err(ConfigError::MtuTooSmall(self.interface.mtu));
        }

        let mut names = HashSet::new();
        for peer in &self.peer {
            if peer.name.trim().is_empty() {
                return Err(ConfigError::EmptyPeerName);
            }
            if !names.insert(peer.name.clone()) {
                return Err(ConfigError::DuplicatePeerName(peer.name.clone()));
            }
            if peer.allowed_ips.is_empty() {
                return Err(ConfigError::PeerWithoutAllowedIps(peer.name.clone()));
            }
            if decode_psk(&peer.psk).is_none() {
                return Err(ConfigError::InvalidPsk(peer.name.clone()));
            }
        }

        Ok(())
    }
}

fn default_mtu() -> u16 {
    1280
}

/// Decode a base64-encoded 32-byte pre-shared key.
pub fn decode_psk(psk: &str) -> Option<[u8; 32]> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let bytes = STANDARD.decode(psk).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Valid base64-encoded 32-byte PSK used across config tests.
    const VALID_PSK: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=";

    fn interface() -> InterfaceConfig {
        InterfaceConfig {
            name: "utun10".to_string(),
            address: "10.77.0.1/24".parse().unwrap(),
            listen: "127.0.0.1:27777".parse().unwrap(),
            transport: TransportConfig::Udp,
            mtu: 1280,
        }
    }

    fn peer(name: &str) -> PeerConfig {
        PeerConfig {
            name: name.to_string(),
            endpoint: "127.0.0.1:27778".parse().unwrap(),
            allowed_ips: vec!["10.77.0.2/32".parse().unwrap()],
            psk: VALID_PSK.to_string(),
            persistent_keepalive: 0,
        }
    }

    #[test]
    fn accepts_minimal_valid_config() {
        let config = Config {
            interface: interface(),
            peer: vec![peer("node-b")],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn accepts_config_with_no_peers() {
        let config = Config {
            interface: interface(),
            peer: vec![],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_empty_interface_name() {
        let mut config = Config {
            interface: interface(),
            peer: vec![],
        };
        config.interface.name = "   ".to_string();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::EmptyInterfaceName)
        ));
    }

    #[test]
    fn rejects_mtu_below_minimum() {
        let mut config = Config {
            interface: interface(),
            peer: vec![],
        };
        config.interface.mtu = 575;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::MtuTooSmall(575))
        ));
    }

    #[test]
    fn accepts_mtu_at_boundary() {
        let mut config = Config {
            interface: interface(),
            peer: vec![],
        };
        config.interface.mtu = 576;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_empty_peer_name() {
        let mut p = peer("node-b");
        p.name = "".to_string();
        let config = Config {
            interface: interface(),
            peer: vec![p],
        };
        assert!(matches!(config.validate(), Err(ConfigError::EmptyPeerName)));
    }

    #[test]
    fn rejects_duplicate_peer_names() {
        let config = Config {
            interface: interface(),
            peer: vec![peer("dup"), peer("dup")],
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::DuplicatePeerName(n)) if n == "dup"
        ));
    }

    #[test]
    fn rejects_peer_without_allowed_ips() {
        let mut p = peer("node-b");
        p.allowed_ips = vec![];
        let config = Config {
            interface: interface(),
            peer: vec![p],
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::PeerWithoutAllowedIps(_))
        ));
    }

    #[test]
    fn rejects_invalid_psk_wrong_length() {
        let mut p = peer("node-b");
        // 16 bytes instead of 32.
        p.psk = "AAAAAAAAAAAAAAAAAAAAAA==".to_string();
        let config = Config {
            interface: interface(),
            peer: vec![p],
        };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidPsk(_))));
    }

    #[test]
    fn rejects_invalid_psk_not_base64() {
        let mut p = peer("node-b");
        p.psk = "not base64 !!!".to_string();
        let config = Config {
            interface: interface(),
            peer: vec![p],
        };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidPsk(_))));
    }

    #[test]
    fn decode_psk_round_trip() {
        let raw = [0x42u8; 32];
        use base64::{engine::general_purpose::STANDARD, Engine};
        let encoded = STANDARD.encode(raw);
        let decoded = decode_psk(&encoded).expect("valid psk");
        assert_eq!(decoded, raw);
    }

    #[test]
    fn decode_psk_rejects_short() {
        assert!(decode_psk("AAAA").is_none());
    }

    #[test]
    fn decode_psk_rejects_garbage() {
        assert!(decode_psk("@@@@").is_none());
    }
}
