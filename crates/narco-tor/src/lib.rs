//! Tor onion-service transport for Narco.
//!
//! Narco needs no server of its own because the room code *is* the meeting
//! point. Both peers stretch the code into two ed25519 keypairs, which are two
//! `.onion` addresses; one peer publishes a service at slot A and dials slot B,
//! the other does the reverse. Tor's existing directory system performs the
//! introduction, and every connection is outbound, so carrier-grade NAT and
//! restrictive networks stop mattering.
//!
//! Nothing here is trusted for confidentiality. The [`narco_proto`] SPAKE2
//! handshake runs on top of whatever connection this module produces, so even a
//! peer who guessed the code and impersonated the service learns nothing.
//!
//! See PROTOCOL.md §11.

#![forbid(unsafe_code)]

pub mod daemon;
pub mod onion;
// iOS runs the same C tor in this process; see the module for why.
#[cfg(target_os = "ios")]
pub mod embedded;
pub mod status;
pub mod transport;
pub mod wire;

pub use daemon::{DaemonError, TorDaemon};
pub use onion::{onion_key, OnionKey};
pub use status::{Status, TorError};
pub use transport::TorTransport;
pub use wire::{run_handshake, ConnectError, Connected};
