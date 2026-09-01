//! Establishing a peer connection over Tor with no server and no signalling.
//!
//! Both peers derive the *same* onion address from the room secrets (see
//! [`crate::onion`]), but the roles are **explicit**, chosen by the humans like
//! a phone call:
//!
//! * [`TorTransport::host`] publishes an onion service at that address and
//!   accepts the first connection that completes the handshake.
//! * [`TorTransport::join`] dials the address through Tor and never publishes.
//!
//! Because only the host publishes and only the joiner dials, a device never
//! connects to itself, so there is no self-connection to detect and no two
//! services competing to publish one address.
//!
//! The Tor engine is the C `tor` daemon (see [`crate::daemon`]), driven over
//! its control port. It replaced the Arti library, which could not complete
//! circuits on several Windows machines.
//!
//! See PROTOCOL.md §11.

use crate::daemon::{DaemonError, TorDaemon};
use crate::onion::onion_key;
use crate::wire::{run_handshake, ConnectError, Connected};
use narco_proto::kdf::Derived;
use narco_proto::Error as ProtoError;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Virtual port the peer service listens on. Onion services have their own port
/// space, so the value is arbitrary and never appears on the real network.
const VIRTUAL_PORT: u16 = 9001;

/// Give up if the other person never shows. Deliberately long — the two people
/// may press Start and Join minutes apart — and the user can cancel any time.
const MEET_TIMEOUT: Duration = Duration::from_secs(1800);

/// Pause between dial attempts while joining. The host may not have published
/// yet, so early failures are expected rather than fatal.
const DIAL_RETRY: Duration = Duration::from_secs(4);

/// Coarse progress, for a UI that must explain a slow connect.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Status {
    /// Joining the Tor network. `detail` is tor's own phase description, e.g.
    /// "Loading relay descriptors", so a stall names the stage it stalled at.
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
    Daemon(DaemonError),
    Launch(String),
}

impl std::fmt::Display for TorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TorError::Daemon(e) => write!(f, "{e}"),
            TorError::Launch(e) => write!(f, "could not publish onion service: {e}"),
        }
    }
}

impl std::error::Error for TorError {}

impl From<DaemonError> for TorError {
    fn from(e: DaemonError) -> Self {
        TorError::Daemon(e)
    }
}

/// A bootstrapped Tor daemon, reused for every chat in the session.
pub struct TorTransport {
    /// Behind a mutex only because control commands are request/response; the
    /// data path does not touch it.
    daemon: Mutex<TorDaemon>,
    socks_port: u16,
}

impl TorTransport {
    /// Start Tor and wait for it to bootstrap.
    pub async fn bootstrap(on_status: impl Fn(Status)) -> Result<Self, TorError> {
        Self::bootstrap_in(None, on_status).await
    }

    /// As [`Self::bootstrap`], with an explicit data directory. Tests that run
    /// two peers in one process need distinct directories.
    pub async fn bootstrap_in(
        dir: Option<&Path>,
        on_status: impl Fn(Status),
    ) -> Result<Self, TorError> {
        let owned;
        let dir = match dir {
            Some(d) => d,
            None => {
                owned = app_tor_dir();
                owned.as_path()
            }
        };

        let daemon = TorDaemon::launch(dir, |percent, detail| {
            on_status(Status::BootstrappingTor {
                percent,
                detail: detail.to_string(),
            });
        })
        .await?;

        let socks_port = daemon.socks_port();
        Ok(Self {
            daemon: Mutex::new(daemon),
            socks_port,
        })
    }

    /// Host the meeting: publish the onion service, accept the first connection
    /// that completes the handshake, then stop publishing.
    pub async fn host(
        &self,
        derived: &Derived,
        on_status: impl Fn(Status),
    ) -> Result<Connected<TcpStream>, ConnectError> {
        let key = onion_key(derived);
        on_status(Status::PublishingService);

        // Tor forwards the virtual port to this local listener.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(ConnectError::Io)?;
        let local_port = listener.local_addr().map_err(ConnectError::Io)?.port();

        let address = {
            let mut d = self.daemon.lock().await;
            d.add_onion(&key.control_blob, VIRTUAL_PORT, local_port)
                .await
                .map_err(|e| ConnectError::Tor(TorError::Launch(e.to_string())))?
        };

        on_status(Status::WaitingForPeer);
        let deadline = tokio::time::Instant::now() + MEET_TIMEOUT;

        let result = loop {
            let accepted = tokio::time::timeout_at(deadline, listener.accept()).await;
            let Ok(Ok((stream, _))) = accepted else {
                break Err(ConnectError::TimedOut);
            };
            on_status(Status::PeerFound);
            match run_handshake(stream, derived).await {
                Ok(conn) => break Ok(conn),
                // A stray connector, or someone who typed different secrets.
                // Keep the service up and wait for the real peer.
                Err(ConnectError::Protocol(ProtoError::ConfirmMismatch))
                | Err(ConnectError::Protocol(ProtoError::Reflection))
                | Err(ConnectError::Io(_)) => {
                    on_status(Status::WaitingForPeer);
                    continue;
                }
                Err(e) => break Err(e),
            }
        };

        // Close the door: once two people are in, stop publishing so nobody
        // else can connect. Tor has no "unpublish", but removing the service
        // tears down its introduction points, so the descriptor points nowhere.
        let mut d = self.daemon.lock().await;
        let _ = d.del_onion(&address).await;

        result
    }

    /// Join the meeting: dial the onion address through Tor's SOCKS port and
    /// run the handshake. Retries until the host has published.
    pub async fn join(
        &self,
        derived: &Derived,
        on_status: impl Fn(Status),
    ) -> Result<Connected<TcpStream>, ConnectError> {
        let address = onion_key(derived).address;
        on_status(Status::WaitingForPeer);
        let deadline = tokio::time::Instant::now() + MEET_TIMEOUT;

        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(ConnectError::TimedOut);
            }
            match socks5_connect(self.socks_port, &address, VIRTUAL_PORT).await {
                Ok(stream) => {
                    on_status(Status::PeerFound);
                    match run_handshake(stream, derived).await {
                        Ok(conn) => return Ok(conn),
                        // Reached the host but the secrets differ — retrying
                        // cannot help, so surface it.
                        Err(ConnectError::Protocol(ProtoError::ConfirmMismatch)) => {
                            return Err(ConnectError::Protocol(ProtoError::ConfirmMismatch))
                        }
                        Err(_) => {
                            on_status(Status::WaitingForPeer);
                            tokio::time::sleep(DIAL_RETRY).await;
                        }
                    }
                }
                // Expected until the host publishes; keep trying.
                Err(_) => {
                    on_status(Status::WaitingForPeer);
                    tokio::time::sleep(DIAL_RETRY).await;
                }
            }
        }
    }
}

/// Open a connection to `host:port` through Tor's SOCKS5 proxy.
///
/// Hand-rolled rather than pulling in a dependency: this is the whole of SOCKS5
/// for our case — no authentication, one domain-name CONNECT. Sending the
/// address as a *domain name* is what lets Tor resolve the `.onion` itself;
/// resolving locally would both fail and leak the lookup.
async fn socks5_connect(
    socks_port: u16,
    host: &str,
    port: u16,
) -> Result<TcpStream, std::io::Error> {
    use std::io::{Error, ErrorKind};

    let mut s = TcpStream::connect(("127.0.0.1", socks_port)).await?;

    // Greeting: SOCKS5, one method, "no authentication".
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greet = [0u8; 2];
    s.read_exact(&mut greet).await?;
    if greet != [0x05, 0x00] {
        return Err(Error::new(ErrorKind::Other, "SOCKS5 greeting refused"));
    }

    // CONNECT to a domain name.
    let host_bytes = host.as_bytes();
    if host_bytes.len() > u8::MAX as usize {
        return Err(Error::new(ErrorKind::InvalidInput, "address too long"));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    // Reply: VER REP RSV ATYP then a bound address we do not need.
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(Error::new(
            ErrorKind::ConnectionRefused,
            format!("SOCKS5 refused the connection (code {})", head[1]),
        ));
    }
    match head[3] {
        0x01 => {
            let mut skip = [0u8; 4 + 2];
            s.read_exact(&mut skip).await?;
        }
        0x04 => {
            let mut skip = [0u8; 16 + 2];
            s.read_exact(&mut skip).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            s.read_exact(&mut skip).await?;
        }
        other => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("unknown SOCKS5 address type {other}"),
            ))
        }
    }
    Ok(s)
}

/// A data directory owned by this app, so it can be cleared safely and holds
/// only Tor's own state — never a room code, key, or message.
///
/// Named `tor-daemon` rather than `tor` because versions up to 0.4.x ran Arti,
/// which used `tor` for a directory laid out incompatibly: `state` and `cache`
/// are directories there, and the daemon expects `state` to be a file. Pointing
/// the daemon at one killed it on startup — "State file is not a file? Failing"
/// — on every machine that had ever run an older Narco, and on no other.
fn app_tor_dir() -> std::path::PathBuf {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from)
    } else {
        std::env::var_os("XDG_CACHE_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cache"))
            })
    };
    let base = base.unwrap_or_else(std::env::temp_dir).join("narco");

    // That old directory is now dead weight on an upgraded machine, and this
    // app promises to leave nothing behind. Only remove one with Arti's shape,
    // so a directory we did not write is never touched.
    let legacy = base.join("tor");
    if legacy.join("state").is_dir() {
        let _ = std::fs::remove_dir_all(&legacy);
    }

    base.join("tor-daemon")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Host and joiner must derive the same meeting address, or they would
    /// never find each other.
    #[test]
    fn host_and_joiner_target_one_address() {
        let d = narco_proto::kdf::derive("PWXK7M2QRT9HFZ").unwrap();
        assert_eq!(onion_key(&d).address, onion_key(&d).address);
    }

    #[test]
    fn status_is_comparable_for_ui_dedup() {
        assert_eq!(Status::WaitingForPeer, Status::WaitingForPeer);
        assert_ne!(
            Status::BootstrappingTor {
                percent: 1,
                detail: "a".into()
            },
            Status::BootstrappingTor {
                percent: 2,
                detail: "a".into()
            }
        );
    }
}
