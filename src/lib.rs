//! HushWire library — exposes core modules for integration testing.
//!
//! The binary (`main.rs`) re-exports these for the CLI. Integration tests
//! in `tests/` use this crate to exercise the crypto pipeline without
//! needing TUN devices or UDP sockets.

pub mod auth;
pub mod noise;
pub mod replay;
