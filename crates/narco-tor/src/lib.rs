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

// The daemon engine, and the identity/transport that drive it. iOS cannot
// execute a second binary, so none of this is compiled there.
#[cfg(not(target_os = "ios"))]
pub mod daemon;
pub mod onion;
pub mod status;
#[cfg(not(target_os = "ios"))]
pub mod transport;

// The iOS engine: Arti in this process.
#[cfg(target_os = "ios")]
pub mod arti_transport;
#[cfg(target_os = "ios")]
pub mod identity;
pub mod wire;

#[cfg(not(target_os = "ios"))]
pub use daemon::{DaemonError, TorDaemon};
pub use onion::{onion_key, OnionKey};
pub use status::{Status, TorError};
#[cfg(not(target_os = "ios"))]
pub use transport::TorTransport;
// Same name, same three methods, same statuses — the app never learns which.
#[cfg(target_os = "ios")]
pub use arti_transport::TorTransport;
pub use wire::{run_handshake, ConnectError, Connected};
