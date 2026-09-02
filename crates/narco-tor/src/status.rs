//! What the app is told while a connection is being made, and how it fails.
//!
//! Shared by both Tor engines. Narco drives the C `tor` daemon as a child
//! process everywhere it can — Windows, Linux, Android — because that binary is
//! about as proven as software gets. iOS forbids executing a second binary at
//! all, so there it links Arti, the Rust Tor implementation, and runs it in
//! process instead. Which engine is in use never reaches the app or the UI:
//! both produce these statuses and these errors.

/// Coarse progress, for a UI that must explain a slow connect.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Status {
    /// Joining the Tor network. `detail` is the engine's own phase description,
    /// e.g. "Loading relay descriptors", so a stall names the stage it stalled
    /// at rather than showing a frozen percentage.
    BootstrappingTor { percent: u8, detail: String },
    /// Connected to Tor; publishing our address.
    PublishingService,
    /// Published (or dialling); waiting for the other person.
    WaitingForPeer,
    /// A peer connection exists. The handshake runs next.
    PeerFound,
}

#[derive(Debug)]
pub enum TorError {
    /// Tor itself could not be started or could not reach the network.
    Engine(String),
    /// Tor is running, but the meeting address could not be published.
    Launch(String),
}

impl std::fmt::Display for TorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TorError::Engine(e) => write!(f, "{e}"),
            TorError::Launch(e) => write!(f, "could not publish onion service: {e}"),
        }
    }
}

impl std::error::Error for TorError {}
