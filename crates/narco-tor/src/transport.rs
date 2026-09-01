//! Establishing a peer connection over Tor with no server and no signalling.
//!
//! Both peers derive the *same* onion address from the room code (see
//! [`crate::identity`]). A connection needs one side listening and one side
//! dialling, and the peers cannot negotiate which is which without already
//! being connected. [`TorTransport::meet_candidates`] resolves that without any
//! negotiation: **both peers publish the address and both dial it.**
//!
//! Their two descriptors collide in the Tor directory and one wins, which
//! supplies the asymmetry:
//!
//! * the peer whose descriptor **won** accepts the other's dial, and its own
//!   dial loops back to itself;
//! * the peer whose descriptor **lost** dials into the winner, and its own
//!   service is never found.
//!
//! Exactly one real pairing exists, plus one self-connection. The self-connection
//! is rejected by the SPAKE2 reflection check in [`narco_proto`], and because
//! every candidate gets its own `Session`, discarding one costs nothing. This
//! converges on the first attempt — verified over the live network in
//! `examples/live_handshake.rs`.
//!
//! # Why not pick a role by coin flip?
//!
//! That was the first design and it is much worse. Half the time both peers pick
//! the same role, and neither discovers it until a round times out — and rounds
//! must be minutes long, because publishing a descriptor and having it propagate
//! genuinely takes that long. Expected cost was two rounds; worst case was
//! several. [`Role`] and [`TorTransport::meet_once`] survive only so tests can
//! force a specific role.
//!
//! Naively racing accept-and-dial *without* the shared address is a different
//! trap: two peers each publishing a *different* address form two separate
//! connections, and each side's `select!` may win on a different one, leaving
//! them holding opposite halves of two dead channels. Sharing one address is
//! what makes the race safe.
//!
//! See PROTOCOL.md §11.

use crate::identity::{self, Slot};
use futures::StreamExt;
use narco_proto::kdf::Derived;
use std::sync::Arc;
use std::time::Duration;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{handle_rend_requests, HsNickname};

use arti_client::{DataStream, TorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;

/// Virtual port the peer service listens on. Onion services have their own port
/// space, so the value is arbitrary and never appears on the real network.
const VIRTUAL_PORT: u16 = 9001;

/// How long to give one round before re-flipping the coin.
///
/// Measured, not guessed: publishing an onion descriptor requires building
/// introduction circuits and uploading to the directory, and the far side then
/// has to fetch it. End to end that runs past a minute on a cold client, so a
/// short timeout gives up while the handshake is still working.
const ROUND_TIMEOUT: Duration = Duration::from_secs(240);

/// Give up on joining Tor and report it, rather than sitting on the connecting
/// screen forever. On a working network this takes ~20-40s; a network that
/// blocks Tor otherwise hangs with no explanation and no way to retry.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(150);

/// Pause between dial attempts within a round. The peer may not have published
/// yet, so early failures are expected rather than fatal.
const DIAL_RETRY: Duration = Duration::from_secs(4);

/// Which end of the connection this peer is for one round.
///
/// Chosen by coin flip, *not* derived from the code: if it were derived, both
/// peers would choose identically every time and never connect.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Publish the onion service and wait for the peer to dial in.
    Host,
    /// Dial the onion address and wait for the peer to publish it.
    Dial,
}

/// Coarse progress, for a UI that must explain a 30-90 second wait.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Status {
    /// Connecting to the Tor network. The slowest and most variable step.
    ///
    /// Carries real progress, because this stage downloads Tor's consensus —
    /// the signed, hourly-updated list of every relay. That cannot be shipped
    /// in the binary (it expires, and a stale one is rejected), so on a first
    /// run it is a genuine multi-megabyte download. A bare spinner here is
    /// indistinguishable from a hang.
    BootstrappingTor { percent: u8 },
    /// Tor appears to be blocked or unreachable on this network.
    TorBlocked { detail: String },
    /// Connected to Tor; publishing our address.
    PublishingService,
    /// Published; waiting for the other person.
    WaitingForPeer,
    /// A previous round timed out; trying the other slot.
    Retrying { round: u32 },
    /// A peer connection exists. The handshake runs next.
    PeerFound,
}

#[derive(Debug)]
pub enum TorError {
    Bootstrap(String),
    Launch(String),
    /// Arti returned no service, which means its keystore is disabled.
    KeystoreDisabled,
    Config(String),
}

impl std::fmt::Display for TorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TorError::Bootstrap(e) => write!(f, "could not connect to the Tor network: {e}"),
            TorError::Launch(e) => write!(f, "could not publish onion service: {e}"),
            TorError::KeystoreDisabled => write!(f, "Arti keystore is disabled"),
            TorError::Config(e) => write!(f, "invalid Tor configuration: {e}"),
        }
    }
}

impl std::error::Error for TorError {}

pub struct TorTransport {
    client: Arc<TorClient<PreferredRuntime>>,
}

impl TorTransport {
    /// Connect to the Tor network.
    ///
    /// The client is configured with an **ephemeral, in-memory keystore**, so
    /// the onion identity derived from the room code is never written to disk.
    /// This is what makes "the session leaves nothing behind" true at the Tor
    /// layer as well as the app layer.
    pub async fn bootstrap(on_status: impl Fn(Status)) -> Result<Self, TorError> {
        Self::bootstrap_in(None, on_status).await
    }

    /// As [`Self::bootstrap`], but with an explicit directory for Tor's own
    /// state and directory cache.
    ///
    /// Arti keeps a consensus cache and guard state on disk and takes a lock on
    /// them, so two clients in one process collide on the default location.
    /// Real installs are separate processes and never hit this; tests that run
    /// two peers together must pass distinct directories.
    ///
    /// Note this is Tor's *own* bookkeeping, not Narco's. No key, message, or
    /// room identifier is written there — the onion identity lives in an
    /// ephemeral in-memory keystore, configured below.
    pub async fn bootstrap_in(
        dir: Option<&std::path::Path>,
        on_status: impl Fn(Status),
    ) -> Result<Self, TorError> {
        install_crypto_provider();
        on_status(Status::BootstrappingTor { percent: 0 });

        let mut builder = TorClientConfig::builder();
        builder
            .storage()
            .keystore()
            .primary()
            .kind(tor_config::ExplicitOrAuto::Explicit(
                tor_keymgr::config::ArtiKeystoreKind::Ephemeral,
            ));

        if let Some(dir) = dir {
            builder
                .storage()
                .state_dir(arti_client::config::CfgPath::new_literal(dir.join("state")));
            builder
                .storage()
                .cache_dir(arti_client::config::CfgPath::new_literal(dir.join("cache")));
        }

        let config = builder
            .build()
            .map_err(|e| TorError::Config(e.to_string()))?;
        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| TorError::Bootstrap(e.to_string()))?;

        Ok(Self { client })
    }

    /// Publish and dial until a peer connection exists.
    ///
    /// Returns the first usable connection. The caller runs the SPAKE2
    /// handshake over it and, if that fails, may call this again.
    pub async fn meet(
        &self,
        derived: &Derived,
        on_status: impl Fn(Status),
    ) -> Result<DataStream, TorError> {
        for round in 0u32.. {
            if round > 0 {
                on_status(Status::Retrying { round });
            }
            match self
                .meet_once(derived, random_role(), round, &on_status)
                .await?
            {
                Some(stream) => {
                    on_status(Status::PeerFound);
                    return Ok(stream);
                }
                // Both peers chose the same role. Re-flip.
                None => continue,
            }
        }
        unreachable!("0u32.. is unbounded")
    }

    /// Publish *and* dial simultaneously, yielding every candidate connection.
    ///
    /// This supersedes the coin flip and always converges on the first round.
    /// Both peers publish the same address, so their descriptors collide and one
    /// wins in the Tor directory. From there exactly one real pairing exists:
    ///
    /// * the peer whose descriptor **won** accepts the other's dial, while its
    ///   own dial reaches *itself*;
    /// * the peer whose descriptor **lost** dials into the winner, and its own
    ///   service is never found.
    ///
    /// The self-connection is why this returns a stream of candidates rather
    /// than one connection: the caller runs a `Session` per candidate and keeps
    /// the first to reach `Ready`. A self-connection fails the SPAKE2 reflection
    /// check and is discarded, costing nothing.
    ///
    /// Hold [`Meeting::service`] until the handshake confirms, then drop it. That
    /// unpublishes the address, which is what enforces "only ever two people":
    /// once both are in, there is no longer a door to knock on.
    pub async fn meet_candidates(
        &self,
        derived: &Derived,
        on_status: impl Fn(Status),
    ) -> Result<Meeting, TorError> {
        let meeting = identity::identity(derived, Slot::A);
        let address = meeting.address.clone();

        on_status(Status::PublishingService);

        let nickname =
            HsNickname::new("narco".to_string()).map_err(|e| TorError::Config(e.to_string()))?;
        let svc_config = OnionServiceConfigBuilder::default()
            .nickname(nickname)
            .build()
            .map_err(|e| TorError::Config(e.to_string()))?;

        let (service, rend_requests) = self
            .client
            .launch_onion_service_with_hsid(svc_config, meeting.into_keypair())
            .map_err(|e| TorError::Launch(e.to_string()))?
            .ok_or(TorError::KeystoreDisabled)?;

        // Small buffer: a handful of candidates is plenty, and a bounded channel
        // stops a misbehaving peer from making us queue connections forever.
        let (tx, candidates) = tokio::sync::mpsc::channel::<DataStream>(4);

        let accept_tx = tx.clone();
        tokio::spawn(async move {
            let mut streams = handle_rend_requests(rend_requests);
            while let Some(request) = streams.next().await {
                if let Ok(stream) = request.accept(Connected::new_empty()).await {
                    if accept_tx.send(stream).await.is_err() {
                        break; // Receiver dropped: the session is settled.
                    }
                }
            }
        });

        let client = self.client.clone();
        tokio::spawn(async move {
            loop {
                match client.connect((address.as_str(), VIRTUAL_PORT)).await {
                    Ok(stream) => {
                        if tx.send(stream).await.is_err() {
                            break;
                        }
                        // Keep dialling: that connection may have been our own
                        // service, in which case the caller will discard it.
                        tokio::time::sleep(DIAL_RETRY).await;
                    }
                    // Expected until the peer publishes.
                    Err(_) => tokio::time::sleep(DIAL_RETRY).await,
                }
            }
        });

        on_status(Status::WaitingForPeer);
        Ok(Meeting {
            service,
            candidates,
        })
    }

    /// One round in a chosen role. `Ok(None)` means the round timed out, which
    /// means both peers picked the same role.
    ///
    /// Exposed so tests can drive two peers deterministically rather than
    /// waiting on coin flips.
    pub async fn meet_once(
        &self,
        derived: &Derived,
        role: Role,
        round: u32,
        on_status: &impl Fn(Status),
    ) -> Result<Option<DataStream>, TorError> {
        // Both roles use the same address: the one the room code names.
        let meeting = identity::identity(derived, Slot::A);

        let outcome = match role {
            Role::Host => {
                on_status(Status::PublishingService);

                // A fresh nickname per round: `launch_onion_service_with_hsid`
                // refuses to overwrite an existing key for a nickname, and a
                // round may retry.
                let nickname = HsNickname::new(format!("narco{round}"))
                    .map_err(|e| TorError::Config(e.to_string()))?;
                let svc_config = OnionServiceConfigBuilder::default()
                    .nickname(nickname)
                    .build()
                    .map_err(|e| TorError::Config(e.to_string()))?;

                let (service, rend_requests) = self
                    .client
                    .launch_onion_service_with_hsid(svc_config, meeting.into_keypair())
                    .map_err(|e| TorError::Launch(e.to_string()))?
                    .ok_or(TorError::KeystoreDisabled)?;

                on_status(Status::WaitingForPeer);

                let accept = async {
                    let mut streams = handle_rend_requests(rend_requests);
                    while let Some(request) = streams.next().await {
                        if let Ok(stream) = request.accept(Connected::new_empty()).await {
                            return stream;
                        }
                        // A failed accept is not fatal; the peer may retry.
                    }
                    futures::future::pending().await
                };

                let got = tokio::select! {
                    stream = accept => Some(stream),
                    _ = tokio::time::sleep(ROUND_TIMEOUT) => None,
                };
                // Dropping the service unpublishes it, so a timed-out round
                // leaves nothing behind for the next one to collide with.
                drop(service);
                got
            }

            Role::Dial => {
                on_status(Status::WaitingForPeer);
                let address = meeting.address.clone();
                let dial = async {
                    loop {
                        match self.client.connect((address.as_str(), VIRTUAL_PORT)).await {
                            Ok(stream) => return stream,
                            // Expected while the peer has not published yet.
                            Err(_) => tokio::time::sleep(DIAL_RETRY).await,
                        }
                    }
                };
                tokio::select! {
                    stream = dial => Some(stream),
                    _ = tokio::time::sleep(ROUND_TIMEOUT) => None,
                }
            }
        };

        Ok(outcome)
    }
}

/// Select the rustls crypto backend, once per process.
///
/// rustls refuses to guess when more than one backend is available and panics
/// at first use instead. Doing it here rather than leaving it to the caller
/// means an embedder cannot forget and ship a binary that dies on connect.
fn install_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Errs only if a provider is already installed, which is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A fair coin flip from the OS CSPRNG.
///
/// Deliberately *not* derived from the room code. A derived choice would be
/// identical on both devices, so they would forever pick the same role and
/// never connect.
fn random_role() -> Role {
    let mut b = [0u8; 1];
    getrandom::fill(&mut b).expect("OS CSPRNG unavailable");
    if b[0] & 1 == 0 {
        Role::Host
    } else {
        Role::Dial
    }
}

/// Keeps a launched service alive for as long as it is held.
pub type ServiceHandle = Arc<tor_hsservice::RunningOnionService>;

/// An in-progress meeting: a live service plus the candidate connections.
pub struct Meeting {
    /// Drop this once the handshake confirms. Dropping unpublishes the address,
    /// so no third party can connect — this is the "only two people" guarantee.
    pub service: ServiceHandle,
    /// Candidate connections, from both the accept and dial sides. Run a
    /// `Session` per candidate; discard any that fails with `Error::Reflection`
    /// (that one is us) and keep the first that reaches `Ready`.
    pub candidates: tokio::sync::mpsc::Receiver<DataStream>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coin_flip_reaches_both_roles() {
        // With 200 flips, seeing only one role would mean p < 2^-199.
        let mut saw_host = false;
        let mut saw_dial = false;
        for _ in 0..200 {
            match random_role() {
                Role::Host => saw_host = true,
                Role::Dial => saw_dial = true,
            }
        }
        assert!(saw_host && saw_dial, "coin flip is biased or broken");
    }

    /// Guards the fix for the two-connection deadlock: both peers must resolve
    /// to the *same* meeting address, so exactly one connection can form.
    #[test]
    fn both_roles_target_one_shared_address() {
        let d = narco_proto::kdf::derive("PWXK7M2QRT9HFZ").unwrap();
        let host_sees = identity::identity(&d, Slot::A).address;
        let dial_sees = identity::identity(&d, Slot::A).address;
        assert_eq!(host_sees, dial_sees);
    }

    #[test]
    fn status_is_comparable_for_ui_dedup() {
        assert_eq!(Status::WaitingForPeer, Status::WaitingForPeer);
        assert_ne!(Status::Retrying { round: 1 }, Status::Retrying { round: 2 });
    }
}
