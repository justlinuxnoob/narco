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

pub mod identity;
pub mod transport;
pub mod wire;

pub use identity::{identities, identity, OnionIdentity, Slot};
pub use transport::{BridgeSettings, Meeting, Role, Status, TorError, TorTransport};
pub use wire::{connect, ConnectError, Connected};
