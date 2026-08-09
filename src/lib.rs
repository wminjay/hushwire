//! Reusable HushWire protocol and transport library.
//!
//! Platform front ends, including the CLI TUN adapter and the planned macOS
//! Packet Tunnel provider, share these configuration, routing, protocol, peer
//! state, and socket-transport modules. OS route/firewall management and TUN
//! creation remain in the CLI binary.

pub mod auth;
pub mod config;
pub mod engine;
pub mod ffi;
pub mod noise;
pub mod packet;
pub mod replay;
pub mod router;
pub mod scheduler;
pub mod state;
pub mod tcp_transport;
pub mod transport;
