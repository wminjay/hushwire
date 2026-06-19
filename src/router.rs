use std::net::Ipv4Addr;
use std::sync::Arc;

use ipnet::Ipv4Net;
use thiserror::Error;

use crate::config::{Config, PeerConfig};

#[derive(Clone, Debug)]
pub struct Peer {
    pub name: String,
    pub endpoint: std::net::SocketAddr,
    pub psk: [u8; 32],
    pub persistent_keepalive: u16,
}

#[derive(Clone, Debug)]
pub struct Route {
    pub prefix: Ipv4Net,
    pub peer: Arc<Peer>,
}

#[derive(Clone, Debug)]
pub struct Router {
    routes: Vec<Route>,
}

#[derive(Debug, Error)]
pub enum RouterError {
    #[error("route {prefix} is configured for both {first_peer} and {second_peer}")]
    DuplicatePrefix {
        prefix: Ipv4Net,
        first_peer: String,
        second_peer: String,
    },
}

impl Router {
    pub fn new(config: &Config) -> Result<Self, RouterError> {
        let mut routes = Vec::new();

        for peer_config in &config.peer {
            let peer = Arc::new(peer_from_config(peer_config));
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
        }

        routes.sort_by_key(|route| std::cmp::Reverse(route.prefix.prefix_len()));
        Ok(Self { routes })
    }

    pub fn lookup(&self, destination: Ipv4Addr) -> Option<&Route> {
        self.routes
            .iter()
            .find(|route| route.prefix.contains(&destination))
    }

    pub fn routes(&self) -> &[Route] {
        &self.routes
    }
}

fn peer_from_config(config: &PeerConfig) -> Peer {
    Peer {
        name: config.name.clone(),
        endpoint: config.endpoint,
        psk: crate::config::decode_psk(&config.psk).expect("psk validated by Config::load"),
        persistent_keepalive: config.persistent_keepalive,
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

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
            },
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
            },
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
            },
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
            },
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
            },
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
            endpoint: endpoint.parse::<SocketAddr>().unwrap(),
            allowed_ips: vec![prefix.parse().unwrap()],
            psk: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
            persistent_keepalive: 0,
        }
    }

    fn peer_multi(name: &str, prefixes: &[&str], endpoint: &str) -> PeerConfig {
        PeerConfig {
            name: name.to_string(),
            endpoint: endpoint.parse::<SocketAddr>().unwrap(),
            allowed_ips: prefixes.iter().map(|p| p.parse().unwrap()).collect(),
            psk: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
            persistent_keepalive: 0,
        }
    }
}
