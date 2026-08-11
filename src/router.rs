use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use ipnet::Ipv4Net;
use thiserror::Error;
use x25519_dalek::PublicKey;

use crate::config::{Config, PeerConfig, TransportConfig};

#[derive(Clone, Debug)]
pub struct Peer {
    pub name: String,
    pub endpoint: std::net::SocketAddr,
    pub configured_endpoint: crate::config::PeerEndpoint,
    pub excluded_ips: Vec<Ipv4Net>,
    pub psk: [u8; 32],
    /// Peer's static public key (x25519) for Noise handshake.
    pub public_key: PublicKey,
    pub persistent_keepalive: u16,
    pub udp_rebind_after: u16,
    pub session_timeout: u64,
}

#[derive(Clone, Debug)]
pub struct Route {
    pub prefix: Ipv4Net,
    pub peer: Arc<Peer>,
}

#[derive(Clone, Debug)]
pub struct ExcludedRoute {
    pub prefix: Ipv4Net,
    pub peer: Arc<Peer>,
}

#[derive(Clone, Debug)]
pub struct Router {
    routes: Vec<Route>,
    excluded_routes: Vec<ExcludedRoute>,
}

#[derive(Debug, Error)]
pub enum RouterError {
    #[error("route {prefix} is configured for both {first_peer} and {second_peer}")]
    DuplicatePrefix {
        prefix: Ipv4Net,
        first_peer: String,
        second_peer: String,
    },
    #[error("could not resolve endpoint {endpoint} for peer {peer}: {source}")]
    EndpointResolution {
        peer: String,
        endpoint: crate::config::PeerEndpoint,
        #[source]
        source: std::io::Error,
    },
}

impl Router {
    pub fn new(config: &Config) -> Result<Self, RouterError> {
        let mut routes = Vec::new();
        let mut excluded_routes = Vec::new();

        for peer_config in &config.peer {
            let peer = Arc::new(peer_from_config(peer_config, config.interface.transport)?);
            for prefix in &peer_config.allowed_ips {
                if let Some(existing) = routes.iter().find(|route: &&Route| route.prefix == *prefix)
                {
                    return Err(RouterError::DuplicatePrefix {
                        prefix: *prefix,
                        first_peer: existing.peer.name.clone(),
                        second_peer: peer.name.clone(),
                    });
                }

                routes.push(Route {
                    prefix: *prefix,
                    peer: Arc::clone(&peer),
                });
            }
            for prefix in &peer_config.excluded_ips {
                excluded_routes.push(ExcludedRoute {
                    prefix: *prefix,
                    peer: Arc::clone(&peer),
                });
            }
        }

        routes.sort_by_key(|route| std::cmp::Reverse(route.prefix.prefix_len()));
        excluded_routes.sort_by_key(|route| std::cmp::Reverse(route.prefix.prefix_len()));
        Ok(Self {
            routes,
            excluded_routes,
        })
    }

    pub fn lookup(&self, destination: Ipv4Addr) -> Option<&Route> {
        self.routes.iter().find(|route| {
            if !route.prefix.contains(&destination) {
                return false;
            }
            let most_specific_exclusion = route
                .peer
                .excluded_ips
                .iter()
                .filter(|prefix| prefix.contains(&destination))
                .map(Ipv4Net::prefix_len)
                .max();
            most_specific_exclusion
                .map(|excluded_prefix_length| route.prefix.prefix_len() > excluded_prefix_length)
                .unwrap_or(true)
        })
    }

    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    pub fn excluded_routes(&self) -> &[ExcludedRoute] {
        &self.excluded_routes
    }

    /// Return one representative peer for each transport endpoint whose IPv4
    /// address would itself be captured by the configured tunnel routes.
    pub fn endpoint_exception_peers(&self) -> Vec<&Peer> {
        let mut seen = HashSet::<IpAddr>::new();
        let mut peers = Vec::new();
        for route in &self.routes {
            let peer = route.peer.as_ref();
            let IpAddr::V4(endpoint_ip) = peer.endpoint.ip() else {
                continue;
            };
            if peer.endpoint.port() == 0 || endpoint_ip.is_unspecified() {
                continue;
            }
            if self.lookup(endpoint_ip).is_some() && seen.insert(peer.endpoint.ip()) {
                peers.push(peer);
            }
        }
        peers
    }
}

fn peer_from_config(config: &PeerConfig, transport: TransportConfig) -> Result<Peer, RouterError> {
    let public_key_bytes = crate::config::decode_key(&config.public_key)
        .expect("public_key validated by Config::load");
    let endpoint = config
        .endpoint
        .resolve()
        .map_err(|source| RouterError::EndpointResolution {
            peer: config.name.clone(),
            endpoint: config.endpoint.clone(),
            source,
        })?;
    Ok(Peer {
        name: config.name.clone(),
        endpoint,
        configured_endpoint: config.endpoint.clone(),
        excluded_ips: config.excluded_ips.clone(),
        psk: crate::config::decode_psk(&config.psk).expect("psk validated by Config::load"),
        public_key: PublicKey::from(public_key_bytes),
        persistent_keepalive: config.persistent_keepalive,
        udp_rebind_after: config.udp_rebind_after,
        session_timeout: config.effective_session_timeout(transport),
    })
}

#[cfg(test)]
mod tests {
    use crate::config::InterfaceConfig;

    use super::*;

    #[test]
    fn picks_the_longest_matching_prefix() {
        let config = Config {
            interface: InterfaceConfig {
                name: "utun10".to_string(),
                address: "10.77.0.1/24".parse().unwrap(),
                listen: "127.0.0.1:27777".parse().unwrap(),
                transport: Default::default(),
                mtu: 1280,
                private_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
            },
            gateway: None,
            peer: vec![
                peer("broad", "10.77.0.0/24", "127.0.0.1:27778"),
                peer("specific", "10.77.0.2/32", "127.0.0.1:27779"),
            ],
        };

        let router = Router::new(&config).expect("router");
        let route = router
            .lookup(Ipv4Addr::new(10, 77, 0, 2))
            .expect("matching route");

        assert_eq!(route.peer.name, "specific");
        assert_eq!(route.prefix, "10.77.0.2/32".parse().unwrap());
    }

    #[test]
    fn returns_none_when_no_route_matches() {
        let config = Config {
            interface: InterfaceConfig {
                name: "utun10".to_string(),
                address: "10.77.0.1/24".parse().unwrap(),
                listen: "127.0.0.1:27777".parse().unwrap(),
                transport: Default::default(),
                mtu: 1280,
                private_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
            },
            gateway: None,
            peer: vec![peer("node-b", "10.77.0.2/32", "127.0.0.1:27778")],
        };

        let router = Router::new(&config).expect("router");
        assert!(router.lookup(Ipv4Addr::new(8, 8, 8, 8)).is_none());
    }

    #[test]
    fn handles_peer_with_multiple_allowed_ips() {
        let config = Config {
            interface: InterfaceConfig {
                name: "utun10".to_string(),
                address: "10.77.0.1/24".parse().unwrap(),
                listen: "127.0.0.1:27777".parse().unwrap(),
                transport: Default::default(),
                mtu: 1280,
                private_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
            },
            gateway: None,
            peer: vec![peer_multi(
                "hub",
                &["10.77.0.0/24", "192.168.50.0/24"],
                "127.0.0.1:27778",
            )],
        };

        let router = Router::new(&config).expect("router");
        let routes = router.routes();
        assert_eq!(routes.len(), 2);

        let in_tunnel = router.lookup(Ipv4Addr::new(10, 77, 0, 5)).expect("first");
        assert_eq!(in_tunnel.peer.name, "hub");
        assert_eq!(in_tunnel.prefix, "10.77.0.0/24".parse().unwrap());

        let remote = router
            .lookup(Ipv4Addr::new(192, 168, 50, 99))
            .expect("second");
        assert_eq!(remote.peer.name, "hub");
        assert_eq!(remote.prefix, "192.168.50.0/24".parse().unwrap());
    }

    #[test]
    fn router_with_no_peers_has_no_routes() {
        let config = Config {
            interface: InterfaceConfig {
                name: "utun10".to_string(),
                address: "10.77.0.1/24".parse().unwrap(),
                listen: "127.0.0.1:27777".parse().unwrap(),
                transport: Default::default(),
                mtu: 1280,
                private_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
            },
            gateway: None,
            peer: vec![],
        };

        let router = Router::new(&config).expect("router");
        assert!(router.routes().is_empty());
        assert!(router.lookup(Ipv4Addr::new(10, 77, 0, 2)).is_none());
    }

    #[test]
    fn rejects_duplicate_prefixes() {
        let config = Config {
            interface: InterfaceConfig {
                name: "utun10".to_string(),
                address: "10.77.0.1/24".parse().unwrap(),
                listen: "127.0.0.1:27777".parse().unwrap(),
                transport: Default::default(),
                mtu: 1280,
                private_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
            },
            gateway: None,
            peer: vec![
                peer("first", "10.77.0.2/32", "127.0.0.1:27778"),
                peer("second", "10.77.0.2/32", "127.0.0.1:27779"),
            ],
        };

        assert!(matches!(
            Router::new(&config),
            Err(RouterError::DuplicatePrefix { .. })
        ));
    }

    fn peer(name: &str, prefix: &str, endpoint: &str) -> PeerConfig {
        PeerConfig {
            name: name.to_string(),
            endpoint: endpoint.parse().unwrap(),
            allowed_ips: vec![prefix.parse().unwrap()],
            excluded_ips: vec![],
            psk: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
            public_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
            persistent_keepalive: 0,
            udp_rebind_after: 0,
            session_timeout: None,
        }
    }

    fn peer_multi(name: &str, prefixes: &[&str], endpoint: &str) -> PeerConfig {
        PeerConfig {
            name: name.to_string(),
            endpoint: endpoint.parse().unwrap(),
            allowed_ips: prefixes.iter().map(|p| p.parse().unwrap()).collect(),
            excluded_ips: vec![],
            psk: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
            public_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
            persistent_keepalive: 0,
            udp_rebind_after: 0,
            session_timeout: None,
        }
    }

    #[test]
    fn resolves_dns_endpoint_once_when_building_router() {
        let config = Config {
            interface: InterfaceConfig {
                name: "utun10".to_string(),
                address: "10.77.0.1/24".parse().unwrap(),
                listen: "127.0.0.1:27777".parse().unwrap(),
                transport: Default::default(),
                mtu: 1280,
                private_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
            },
            gateway: None,
            peer: vec![peer("node-b", "10.77.0.2/32", "localhost:27778")],
        };

        let router = Router::new(&config).expect("router");
        let peer = &router.routes()[0].peer;
        assert_eq!(peer.configured_endpoint.to_string(), "localhost:27778");
        assert_eq!(peer.endpoint.port(), 27778);
        assert!(peer.endpoint.ip().is_loopback());
        assert!(peer.endpoint.is_ipv4());
    }

    #[test]
    fn identifies_only_endpoints_captured_by_tunnel_routes() {
        let config = Config {
            interface: InterfaceConfig {
                name: "utun10".to_string(),
                address: "10.77.0.1/24".parse().unwrap(),
                listen: "127.0.0.1:27777".parse().unwrap(),
                transport: Default::default(),
                mtu: 1280,
                private_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
            },
            gateway: None,
            peer: vec![peer_multi(
                "home",
                &["10.0.0.1/32", "192.0.0.0/4"],
                "192.0.2.10:11063",
            )],
        };

        let router = Router::new(&config).expect("router");
        let exceptions = router.endpoint_exception_peers();
        assert_eq!(exceptions.len(), 1);
        assert_eq!(exceptions[0].name, "home");

        let uncaptured = Config {
            peer: vec![peer("home", "10.0.0.1/32", "192.0.2.10:11063")],
            ..config
        };
        assert!(Router::new(&uncaptured)
            .unwrap()
            .endpoint_exception_peers()
            .is_empty());
    }

    #[test]
    fn excluded_ips_override_allowed_routes_without_hiding_other_destinations() {
        let mut home = peer("home", "0.0.0.0/0", "192.0.2.10:11063");
        home.excluded_ips = vec![
            "10.0.0.0/8".parse().unwrap(),
            "192.168.0.0/16".parse().unwrap(),
        ];
        let config = Config {
            interface: InterfaceConfig {
                name: "utun10".to_string(),
                address: "10.77.0.1/24".parse().unwrap(),
                listen: "127.0.0.1:27777".parse().unwrap(),
                transport: Default::default(),
                mtu: 1280,
                private_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
            },
            gateway: None,
            peer: vec![home],
        };

        let router = Router::new(&config).expect("router");
        assert!(router.lookup("8.8.8.8".parse().unwrap()).is_some());
        assert!(router.lookup("10.1.2.3".parse().unwrap()).is_none());
        assert!(router.lookup("192.168.100.1".parse().unwrap()).is_none());
        assert_eq!(router.excluded_routes().len(), 2);
    }

    #[test]
    fn more_specific_allowed_ip_overrides_a_broad_exclusion() {
        let mut home = peer_multi(
            "home",
            &["10.0.0.1/32", "172.16.1.8/32", "0.0.0.0/0"],
            "192.0.2.10:11063",
        );
        home.excluded_ips = vec![
            "10.0.0.0/8".parse().unwrap(),
            "172.16.0.0/12".parse().unwrap(),
        ];
        let config = Config {
            interface: InterfaceConfig {
                name: "utun10".to_string(),
                address: "10.77.0.1/24".parse().unwrap(),
                listen: "127.0.0.1:27777".parse().unwrap(),
                transport: Default::default(),
                mtu: 1280,
                private_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
            },
            gateway: None,
            peer: vec![home],
        };

        let router = Router::new(&config).expect("router");
        assert_eq!(
            router.lookup("10.0.0.1".parse().unwrap()).unwrap().prefix,
            "10.0.0.1/32".parse().unwrap()
        );
        assert_eq!(
            router.lookup("172.16.1.8".parse().unwrap()).unwrap().prefix,
            "172.16.1.8/32".parse().unwrap()
        );
        assert!(router.lookup("10.0.0.2".parse().unwrap()).is_none());
        assert!(router.lookup("172.16.1.9".parse().unwrap()).is_none());
    }

    #[test]
    fn explicit_exclusion_also_prevents_redundant_endpoint_exception() {
        let mut home = peer("home", "0.0.0.0/0", "192.0.2.10:11063");
        home.excluded_ips = vec!["192.0.2.0/24".parse().unwrap()];
        let config = Config {
            interface: InterfaceConfig {
                name: "utun10".to_string(),
                address: "10.77.0.1/24".parse().unwrap(),
                listen: "127.0.0.1:27777".parse().unwrap(),
                transport: Default::default(),
                mtu: 1280,
                private_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
            },
            gateway: None,
            peer: vec![home],
        };

        let router = Router::new(&config).expect("router");
        assert!(router.endpoint_exception_peers().is_empty());
    }
}
