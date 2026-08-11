use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::str::FromStr;

use ipnet::Ipv4Net;
use serde::Deserialize;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub interface: InterfaceConfig,
    /// Optional Linux forwarding-gateway policy. Merely declaring this block
    /// does not modify the host; operators must explicitly run a
    /// `hushwire gateway` command (normally from a dedicated systemd unit).
    #[serde(default)]
    pub gateway: Option<GatewayConfig>,
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
    /// Base64-encoded 32-byte static private key for Noise handshake.
    /// Generate with `hushwire genkey`.
    pub private_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct GatewayConfig {
    /// Host interface that receives packets from downstream LAN clients.
    pub lan_interface: String,
    /// TCP MSS advertised in both directions. When omitted, HushWire derives
    /// the largest safe IPv4 MSS from the configured tunnel MTU.
    #[serde(default)]
    pub tcp_mss: Option<u16>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TransportConfig {
    #[default]
    Udp,
    Tcp,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PeerConfig {
    pub name: String,
    pub endpoint: PeerEndpoint,
    pub allowed_ips: Vec<Ipv4Net>,
    /// Direct-route rules covered by this peer's `allowed_ips`. Rules use
    /// longest-prefix matching, so a more-specific allowed prefix can opt a
    /// host back into the tunnel; an exact-length exclusion wins the tie.
    #[serde(default)]
    pub excluded_ips: Vec<Ipv4Net>,
    /// Base64-encoded 32-byte pre-shared key (authentication factor).
    pub psk: String,
    /// Base64-encoded 32-byte static public key of this peer (for Noise handshake).
    pub public_key: String,
    /// Persistent keepalive interval in seconds (0 = disabled).
    #[serde(default)]
    pub persistent_keepalive: u16,
    /// Rebind the shared UDP socket to a fresh ephemeral port after this many
    /// seconds without authenticated inbound traffic (0 = disabled).
    #[serde(default)]
    pub udp_rebind_after: u16,
    /// Discard a stale cryptographic session and start a fresh handshake after
    /// this many seconds without authenticated inbound traffic.
    ///
    /// `0` explicitly disables the timeout. When omitted, TCP peers with
    /// persistent keepalives use an automatic timeout of three keepalive
    /// intervals (with a 15-second minimum); UDP keeps its existing explicit
    /// `udp_rebind_after` behavior.
    #[serde(default)]
    pub session_timeout: Option<u16>,
}

/// A configured peer endpoint whose host may be an IP literal or DNS name.
///
/// Parsing configuration deliberately performs no network I/O. The router
/// resolves DNS names once while creating a runtime, before any tunnel routes
/// or DNS settings are installed. Creating a new runtime (including a normal
/// macOS reconnect) therefore refreshes a dynamic-DNS endpoint.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PeerEndpoint {
    host: String,
    port: u16,
    literal: Option<SocketAddr>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PeerEndpointParseError {
    #[error("endpoint must be an IP address or DNS name followed by :port")]
    InvalidFormat,
    #[error("endpoint has an invalid port")]
    InvalidPort,
    #[error("endpoint has an invalid DNS name")]
    InvalidDnsName,
}

impl PeerEndpoint {
    pub fn resolve(&self) -> io::Result<SocketAddr> {
        if let Some(literal) = self.literal {
            return Ok(literal);
        }

        let addresses: Vec<_> = (self.host.as_str(), self.port).to_socket_addrs()?.collect();
        addresses
            .iter()
            .find(|address| address.is_ipv4())
            .or_else(|| addresses.first())
            .copied()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("DNS returned no addresses for {}", self.host),
                )
            })
    }

    pub fn is_dns_name(&self) -> bool {
        self.literal.is_none()
    }
}

impl std::fmt::Display for PeerEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(literal) = self.literal {
            write!(formatter, "{literal}")
        } else {
            write!(formatter, "{}:{}", self.host, self.port)
        }
    }
}

impl From<SocketAddr> for PeerEndpoint {
    fn from(value: SocketAddr) -> Self {
        Self {
            host: value.ip().to_string(),
            port: value.port(),
            literal: Some(value),
        }
    }
}

impl FromStr for PeerEndpoint {
    type Err = PeerEndpointParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(literal) = value.parse::<SocketAddr>() {
            return Ok(literal.into());
        }

        let (host, raw_port) = value
            .rsplit_once(':')
            .ok_or(PeerEndpointParseError::InvalidFormat)?;
        if host.is_empty() || host.contains(':') || host.trim() != host {
            return Err(PeerEndpointParseError::InvalidFormat);
        }
        let port = raw_port
            .parse::<u16>()
            .map_err(|_| PeerEndpointParseError::InvalidPort)?;
        if !valid_dns_name(host) {
            return Err(PeerEndpointParseError::InvalidDnsName);
        }

        Ok(Self {
            host: host.to_string(),
            port,
            literal: None,
        })
    }
}

impl<'de> Deserialize<'de> for PeerEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

fn valid_dns_name(value: &str) -> bool {
    let value = value.strip_suffix('.').unwrap_or(value);
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
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
    #[error(
        "peers {first} and {second} use the same psk; every peer must have unique credentials"
    )]
    DuplicatePeerPsk { first: String, second: String },
    #[error(
        "peers {first} and {second} use the same public_key; every peer must have a unique static identity"
    )]
    DuplicatePeerPublicKey { first: String, second: String },
    #[error("peer {0} has no allowed_ips")]
    PeerWithoutAllowedIps(String),
    #[error("peer {peer} contains duplicate excluded_ips entry {prefix}")]
    DuplicateExcludedIp { peer: String, prefix: Ipv4Net },
    #[error("peer {peer} excludes {prefix}, but no allowed_ips entry covers it")]
    ExcludedIpNotCovered { peer: String, prefix: Ipv4Net },
    #[error("peer {0} cannot exclude 0.0.0.0/0")]
    ExcludedDefaultRoute(String),
    #[error("mtu must be at least 576, got {0}")]
    MtuTooSmall(u16),
    #[error("gateway lan_interface cannot be empty")]
    EmptyGatewayLanInterface,
    #[error("gateway interface name is not a valid Linux interface name: {0}")]
    InvalidGatewayInterfaceName(String),
    #[error("gateway lan_interface and tunnel interface must differ: {0}")]
    IdenticalGatewayInterfaces(String),
    #[error(
        "gateway tcp_mss {mss} is outside the safe range {minimum}..={maximum} for tunnel MTU {mtu}"
    )]
    GatewayMssOutOfRange {
        mss: u16,
        minimum: u16,
        maximum: u16,
        mtu: u16,
    },
    #[error("peer {0} has an invalid psk: must be base64-encoded 32 bytes")]
    InvalidPsk(String),
    #[error("peer {0} has an invalid public_key: must be base64-encoded 32 bytes")]
    InvalidPublicKey(String),
    #[error("interface has an invalid private_key: must be base64-encoded 32 bytes")]
    InvalidPrivateKey,
    #[error("peer {0} sets udp_rebind_after, but the interface transport is not UDP")]
    UdpRebindRequiresUdp(String),
    #[error("peer {0} sets udp_rebind_after, but persistent_keepalive is disabled")]
    UdpRebindRequiresKeepalive(String),
    #[error(
        "peer {peer} udp_rebind_after ({rebind_after}s) must be greater than persistent_keepalive ({keepalive}s)"
    )]
    UdpRebindTooSoon {
        peer: String,
        rebind_after: u16,
        keepalive: u16,
    },
    #[error("peer {0} sets session_timeout, but persistent_keepalive is disabled")]
    SessionTimeoutRequiresKeepalive(String),
    #[error(
        "peer {peer} session_timeout ({timeout}s) must be greater than persistent_keepalive ({keepalive}s)"
    )]
    SessionTimeoutTooSoon {
        peer: String,
        timeout: u16,
        keepalive: u16,
    },
}

impl PeerConfig {
    /// Effective transport-independent authenticated-session timeout.
    ///
    /// TCP needs a default because reconnecting its byte stream does not
    /// recreate the Noise session that the remote process lost. An explicit
    /// zero lets operators retain the old no-timeout behavior when desired.
    pub fn effective_session_timeout(&self, transport: TransportConfig) -> u64 {
        match self.session_timeout {
            Some(timeout) => u64::from(timeout),
            None if transport == TransportConfig::Tcp && self.persistent_keepalive > 0 => {
                (u64::from(self.persistent_keepalive) * 3).max(15)
            }
            None => 0,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path)?;
        Self::parse(&text)
    }

    /// Parse and validate a TOML configuration already held in memory.
    ///
    /// Platform integrations such as a Network Extension receive their
    /// configuration from the host application rather than a filesystem
    /// path, so they must not need to create a temporary plaintext file.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text)?;
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

        if let Some(gateway) = &self.gateway {
            let lan_interface = gateway.lan_interface.trim();
            if lan_interface.is_empty() {
                return Err(ConfigError::EmptyGatewayLanInterface);
            }
            for interface in [&self.interface.name, lan_interface] {
                if !is_valid_linux_interface_name(interface) {
                    return Err(ConfigError::InvalidGatewayInterfaceName(
                        interface.to_string(),
                    ));
                }
            }
            if lan_interface == self.interface.name {
                return Err(ConfigError::IdenticalGatewayInterfaces(
                    lan_interface.to_string(),
                ));
            }
            if let Some(mss) = gateway.tcp_mss {
                let maximum = self.interface.mtu - 40;
                let minimum = 536;
                if !(minimum..=maximum).contains(&mss) {
                    return Err(ConfigError::GatewayMssOutOfRange {
                        mss,
                        minimum,
                        maximum,
                        mtu: self.interface.mtu,
                    });
                }
            }
        }

        if decode_key(&self.interface.private_key).is_none() {
            return Err(ConfigError::InvalidPrivateKey);
        }

        let mut names = HashSet::new();
        let mut psks = HashMap::new();
        let mut public_keys = HashMap::new();
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
            let mut exclusions = HashSet::new();
            for prefix in &peer.excluded_ips {
                if prefix.prefix_len() == 0 {
                    return Err(ConfigError::ExcludedDefaultRoute(peer.name.clone()));
                }
                if !exclusions.insert(*prefix) {
                    return Err(ConfigError::DuplicateExcludedIp {
                        peer: peer.name.clone(),
                        prefix: *prefix,
                    });
                }
                let covered = peer.allowed_ips.iter().any(|allowed| {
                    allowed.prefix_len() <= prefix.prefix_len()
                        && allowed.contains(&prefix.network())
                });
                if !covered {
                    return Err(ConfigError::ExcludedIpNotCovered {
                        peer: peer.name.clone(),
                        prefix: *prefix,
                    });
                }
            }
            let psk =
                decode_psk(&peer.psk).ok_or_else(|| ConfigError::InvalidPsk(peer.name.clone()))?;
            if let Some(first) = psks.insert(psk, peer.name.clone()) {
                return Err(ConfigError::DuplicatePeerPsk {
                    first,
                    second: peer.name.clone(),
                });
            }
            let public_key = decode_key(&peer.public_key)
                .ok_or_else(|| ConfigError::InvalidPublicKey(peer.name.clone()))?;
            if let Some(first) = public_keys.insert(public_key, peer.name.clone()) {
                return Err(ConfigError::DuplicatePeerPublicKey {
                    first,
                    second: peer.name.clone(),
                });
            }
            if peer.udp_rebind_after > 0 {
                if self.interface.transport != TransportConfig::Udp {
                    return Err(ConfigError::UdpRebindRequiresUdp(peer.name.clone()));
                }
                if peer.persistent_keepalive == 0 {
                    return Err(ConfigError::UdpRebindRequiresKeepalive(peer.name.clone()));
                }
                if peer.udp_rebind_after <= peer.persistent_keepalive {
                    return Err(ConfigError::UdpRebindTooSoon {
                        peer: peer.name.clone(),
                        rebind_after: peer.udp_rebind_after,
                        keepalive: peer.persistent_keepalive,
                    });
                }
            }
            if let Some(timeout) = peer.session_timeout.filter(|timeout| *timeout > 0) {
                if peer.persistent_keepalive == 0 {
                    return Err(ConfigError::SessionTimeoutRequiresKeepalive(
                        peer.name.clone(),
                    ));
                }
                if timeout <= peer.persistent_keepalive {
                    return Err(ConfigError::SessionTimeoutTooSoon {
                        peer: peer.name.clone(),
                        timeout,
                        keepalive: peer.persistent_keepalive,
                    });
                }
            }
        }

        Ok(())
    }
}

fn default_mtu() -> u16 {
    1280
}

fn is_valid_linux_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// Decode a base64-encoded 32-byte pre-shared key.
pub fn decode_psk(psk: &str) -> Option<[u8; 32]> {
    decode_key(psk)
}

/// Decode a base64-encoded 32-byte key (PSK, private key, or public key).
pub fn decode_key(key: &str) -> Option<[u8; 32]> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let bytes = STANDARD.decode(key).ok()?;
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
    /// Valid base64-encoded 32-byte key (reused for private/public key in tests).
    const VALID_KEY: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=";

    fn interface() -> InterfaceConfig {
        InterfaceConfig {
            name: "utun10".to_string(),
            address: "10.77.0.1/24".parse().unwrap(),
            listen: "127.0.0.1:27777".parse().unwrap(),
            transport: TransportConfig::Udp,
            mtu: 1280,
            private_key: VALID_KEY.to_string(),
        }
    }

    fn peer(name: &str) -> PeerConfig {
        PeerConfig {
            name: name.to_string(),
            endpoint: "127.0.0.1:27778".parse().unwrap(),
            allowed_ips: vec!["10.77.0.2/32".parse().unwrap()],
            excluded_ips: vec![],
            psk: VALID_PSK.to_string(),
            public_key: VALID_KEY.to_string(),
            persistent_keepalive: 0,
            udp_rebind_after: 0,
            session_timeout: None,
        }
    }

    #[test]
    fn parses_ip_and_dns_peer_endpoints_without_resolving() {
        let literal: PeerEndpoint = "192.0.2.10:27777".parse().unwrap();
        assert_eq!(literal.to_string(), "192.0.2.10:27777");
        assert!(!literal.is_dns_name());
        assert_eq!(
            literal.resolve().unwrap(),
            "192.0.2.10:27777".parse().unwrap()
        );

        let hostname: PeerEndpoint = "home.minjie.wang:11063".parse().unwrap();
        assert_eq!(hostname.to_string(), "home.minjie.wang:11063");
        assert!(hostname.is_dns_name());
    }

    #[test]
    fn resolves_hostname_endpoints_with_ipv4_preference() {
        let endpoint: PeerEndpoint = "localhost:27777".parse().unwrap();
        let resolved = endpoint.resolve().unwrap();
        assert_eq!(resolved.port(), 27777);
        assert!(resolved.ip().is_loopback());
        assert!(resolved.is_ipv4());
    }

    #[test]
    fn rejects_malformed_peer_endpoints() {
        for value in [
            "home.minjie.wang",
            "home.minjie.wang:not-a-port",
            "-home.example:11063",
            "home..example:11063",
            "unbracketed::1:11063",
        ] {
            assert!(value.parse::<PeerEndpoint>().is_err(), "accepted {value}");
        }
    }

    #[test]
    fn config_parse_accepts_a_dns_peer_endpoint() {
        let text = format!(
            r#"
[interface]
name = "utun10"
address = "10.77.0.2/30"
listen = "0.0.0.0:0"
private_key = "{VALID_KEY}"

[[peer]]
name = "home"
endpoint = "home.minjie.wang:11063"
allowed_ips = ["10.77.0.1/32"]
psk = "{VALID_PSK}"
public_key = "{VALID_KEY}"
"#
        );
        let config = Config::parse(&text).unwrap();
        assert_eq!(
            config.peer[0].endpoint.to_string(),
            "home.minjie.wang:11063"
        );
    }

    #[test]
    fn accepts_covered_excluded_ips() {
        let mut p = peer("home");
        p.allowed_ips = vec!["0.0.0.0/0".parse().unwrap()];
        p.excluded_ips = vec![
            "10.0.0.0/8".parse().unwrap(),
            "192.168.0.0/16".parse().unwrap(),
        ];
        let config = Config {
            interface: interface(),
            gateway: None,
            peer: vec![p],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_uncovered_duplicate_and_default_exclusions() {
        let mut uncovered = peer("home");
        uncovered.excluded_ips = vec!["192.168.0.0/16".parse().unwrap()];
        let config = Config {
            interface: interface(),
            gateway: None,
            peer: vec![uncovered],
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ExcludedIpNotCovered { .. })
        ));

        let mut duplicate = peer("home");
        duplicate.allowed_ips = vec!["0.0.0.0/0".parse().unwrap()];
        duplicate.excluded_ips = vec!["10.0.0.0/8".parse().unwrap(), "10.0.0.0/8".parse().unwrap()];
        let config = Config {
            interface: interface(),
            gateway: None,
            peer: vec![duplicate],
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::DuplicateExcludedIp { .. })
        ));

        let mut default = peer("home");
        default.allowed_ips = vec!["0.0.0.0/0".parse().unwrap()];
        default.excluded_ips = vec!["0.0.0.0/0".parse().unwrap()];
        let config = Config {
            interface: interface(),
            gateway: None,
            peer: vec![default],
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::ExcludedDefaultRoute(_))
        ));
    }

    fn encoded_key(byte: u8) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD.encode([byte; 32])
    }

    #[test]
    fn accepts_minimal_valid_config() {
        let config = Config {
            interface: interface(),
            gateway: None,
            peer: vec![peer("node-b")],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn accepts_config_with_no_peers() {
        let config = Config {
            interface: interface(),
            gateway: None,
            peer: vec![],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_empty_interface_name() {
        let mut config = Config {
            interface: interface(),
            gateway: None,
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
            gateway: None,
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
            gateway: None,
            peer: vec![],
        };
        config.interface.mtu = 576;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn accepts_explicit_gateway_policy() {
        let config = Config {
            interface: interface(),
            gateway: Some(GatewayConfig {
                lan_interface: "en0".to_string(),
                tcp_mss: Some(1160),
            }),
            peer: vec![],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_gateway_using_the_tunnel_as_its_lan_interface() {
        let config = Config {
            interface: interface(),
            gateway: Some(GatewayConfig {
                lan_interface: "utun10".to_string(),
                tcp_mss: None,
            }),
            peer: vec![],
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::IdenticalGatewayInterfaces(name)) if name == "utun10"
        ));
    }

    #[test]
    fn rejects_gateway_mss_larger_than_tunnel_payload() {
        let config = Config {
            interface: interface(),
            gateway: Some(GatewayConfig {
                lan_interface: "en0".to_string(),
                tcp_mss: Some(1241),
            }),
            peer: vec![],
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::GatewayMssOutOfRange {
                mss: 1241,
                maximum: 1240,
                mtu: 1280,
                ..
            })
        ));
    }

    #[test]
    fn rejects_empty_peer_name() {
        let mut p = peer("node-b");
        p.name = "".to_string();
        let config = Config {
            interface: interface(),
            gateway: None,
            peer: vec![p],
        };
        assert!(matches!(config.validate(), Err(ConfigError::EmptyPeerName)));
    }

    #[test]
    fn rejects_duplicate_peer_names() {
        let config = Config {
            interface: interface(),
            gateway: None,
            peer: vec![peer("dup"), peer("dup")],
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::DuplicatePeerName(n)) if n == "dup"
        ));
    }

    #[test]
    fn rejects_duplicate_peer_psks() {
        let first = peer("first");
        let mut second = peer("second");
        second.public_key = encoded_key(0x43);
        let config = Config {
            interface: interface(),
            gateway: None,
            peer: vec![first, second],
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::DuplicatePeerPsk { first, second })
                if first == "first" && second == "second"
        ));
    }

    #[test]
    fn rejects_duplicate_peer_public_keys() {
        let first = peer("first");
        let mut second = peer("second");
        second.psk = encoded_key(0x43);
        let config = Config {
            interface: interface(),
            gateway: None,
            peer: vec![first, second],
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::DuplicatePeerPublicKey { first, second })
                if first == "first" && second == "second"
        ));
    }

    #[test]
    fn rejects_peer_without_allowed_ips() {
        let mut p = peer("node-b");
        p.allowed_ips = vec![];
        let config = Config {
            interface: interface(),
            gateway: None,
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
            gateway: None,
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
            gateway: None,
            peer: vec![p],
        };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidPsk(_))));
    }

    #[test]
    fn accepts_udp_rebind_with_keepalive() {
        let mut p = peer("node-b");
        p.persistent_keepalive = 25;
        p.udp_rebind_after = 90;
        let config = Config {
            interface: interface(),
            gateway: None,
            peer: vec![p],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_udp_rebind_without_keepalive() {
        let mut p = peer("node-b");
        p.udp_rebind_after = 90;
        let config = Config {
            interface: interface(),
            gateway: None,
            peer: vec![p],
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UdpRebindRequiresKeepalive(name)) if name == "node-b"
        ));
    }

    #[test]
    fn rejects_udp_rebind_for_tcp() {
        let mut p = peer("node-b");
        p.persistent_keepalive = 25;
        p.udp_rebind_after = 90;
        let mut iface = interface();
        iface.transport = TransportConfig::Tcp;
        let config = Config {
            interface: iface,
            gateway: None,
            peer: vec![p],
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UdpRebindRequiresUdp(name)) if name == "node-b"
        ));
    }

    #[test]
    fn rejects_udp_rebind_before_a_probe_can_run() {
        let mut p = peer("node-b");
        p.persistent_keepalive = 25;
        p.udp_rebind_after = 25;
        let config = Config {
            interface: interface(),
            gateway: None,
            peer: vec![p],
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UdpRebindTooSoon {
                rebind_after: 25,
                keepalive: 25,
                ..
            })
        ));
    }

    #[test]
    fn tcp_keepalive_gets_an_automatic_session_timeout() {
        let mut p = peer("node-b");
        p.persistent_keepalive = 5;
        assert_eq!(p.effective_session_timeout(TransportConfig::Tcp), 15);
        assert_eq!(p.effective_session_timeout(TransportConfig::Udp), 0);
    }

    #[test]
    fn explicit_session_timeout_overrides_tcp_default() {
        let mut p = peer("node-b");
        p.persistent_keepalive = 5;
        p.session_timeout = Some(30);
        assert_eq!(p.effective_session_timeout(TransportConfig::Tcp), 30);

        p.session_timeout = Some(0);
        assert_eq!(p.effective_session_timeout(TransportConfig::Tcp), 0);
    }

    #[test]
    fn rejects_session_timeout_without_keepalive() {
        let mut p = peer("node-b");
        p.session_timeout = Some(30);
        let config = Config {
            interface: interface(),
            gateway: None,
            peer: vec![p],
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::SessionTimeoutRequiresKeepalive(name)) if name == "node-b"
        ));
    }

    #[test]
    fn rejects_session_timeout_before_a_probe_can_run() {
        let mut p = peer("node-b");
        p.persistent_keepalive = 10;
        p.session_timeout = Some(10);
        let config = Config {
            interface: interface(),
            gateway: None,
            peer: vec![p],
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::SessionTimeoutTooSoon {
                timeout: 10,
                keepalive: 10,
                ..
            })
        ));
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
