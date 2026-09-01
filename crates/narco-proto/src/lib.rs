//! Narco protocol core.
//!
//! This crate is the entire security boundary of Narco. It performs the room
//! code derivation, the SPAKE2 handshake, and the ratcheted transport described
//! in `PROTOCOL.md`, and it holds every byte of key material the app ever sees.
//!
//! It is deliberately transport-agnostic: it takes frames in and hands frames
//! out, and knows nothing about WebSockets, Tauri, or the relay. That is what
//! lets the same code be audited, fuzzed, and unit-tested in isolation.
//!
//! The relay server does **not** depend on this crate — it cannot, because it
//! holds no keys. That absence is itself part of the design.
//!
//! ```no_run
//! use narco_proto::{Session, Event};
//!
//! let mut s = Session::new("PWXK7M2QRT9HFZ")?;
//! let room = s.room_id().to_string(); // safe to hand to the relay
//! let hello = s.pake_frame();         // send when the relay reports a peer
//! # Ok::<(), narco_proto::Error>(())
//! ```

#![forbid(unsafe_code)]

pub mod code;
pub mod error;
pub mod frame;
pub mod kdf;
pub mod session;

pub use code::{generate, normalize, validate, GENERATED_LEN, MIN_CODE_LEN};
pub use error::{Error, Result};
pub use kdf::{derive, derive_multi, derive_with_passphrase, is_valid_room_id, Derived};
pub use session::{Event, Phase, Session};

/// Protocol version. Bumped whenever the wire format or key schedule changes in
/// a way that breaks compatibility.
pub const VERSION: &str = "narco/v1";
