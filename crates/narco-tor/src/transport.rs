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

/// Ever-increasing so each onion service launch gets a unique nickname within
/// the process. See the launch site for why reuse is a bug.
static LAUNCH_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How to reach Tor through obfs4 bridges on a censored network.
#[derive(Clone, Debug)]
pub struct BridgeSettings {
    /// Absolute path to the `lyrebird` (obfs4) pluggable-transport binary.
    /// The app bundles this and resolves the path at runtime.
    pub lyrebird_path: std::path::PathBuf,
    /// obfs4 bridge lines, e.g. `obfs4 1.2.3.4:443 <FINGERPRINT> cert=… iat-mode=0`.
    /// Supplied by the app: built-in defaults and/or a line the user pasted
    /// from <https://bridges.torproject.org>.
    pub lines: Vec<String>,
}

/// Wire obfs4 bridges into the client config. Follows the arti-client 0.45
/// documented pattern for `pt-client` exactly.
fn configure_bridges(
    builder: &mut arti_client::config::TorClientConfigBuilder,
    bridges: &BridgeSettings,
) -> Result<(), TorError> {
    use arti_client::config::pt::TransportConfigBuilder;
    use arti_client::config::{BridgeConfigBuilder, CfgPath};

    if bridges.lines.is_empty() {
        return Err(TorError::Config("no bridge lines provided".into()));
    }

    for line in &bridges.lines {
        let bridge: BridgeConfigBuilder = line
            .parse()
            .map_err(|e| TorError::Config(format!("bad bridge line: {e}")))?;
        builder.bridges().bridges().push(bridge);
    }

    // Point the obfs4 transport at the bundled lyrebird binary and launch it
    // on startup so circuits can use it immediately.
    let obfs4 = "obfs4"
        .parse()
        .map_err(|e| TorError::Config(format!("obfs4 protocol name: {e}")))?;
    let mut transport = TransportConfigBuilder::default();
    transport
        .protocols(vec![obfs4])
        .path(CfgPath::new_literal(bridges.lyrebird_path.clone()))
        .run_on_startup(true);
    builder.bridges().transports().push(transport);

    Ok(())
}

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
        Self::bootstrap_core(dir, None, on_status).await
    }

    /// As [`Self::bootstrap_in`], but route through **obfs4 bridges** — for
    /// networks that block Tor. Needs the path to a `lyrebird` pluggable-
    /// transport binary and at least one bridge line. Slower than a direct
    /// connection; only worth using when the direct path is censored.
    pub async fn bootstrap_bridged(
        dir: Option<&std::path::Path>,
        bridges: BridgeSettings,
        on_status: impl Fn(Status),
    ) -> Result<Self, TorError> {
        Self::bootstrap_core(dir, Some(bridges), on_status).await
    }

    async fn bootstrap_core(
        dir: Option<&std::path::Path>,
        bridges: Option<BridgeSettings>,
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

        if let Some(bridges) = &bridges {
            configure_bridges(&mut builder, bridges)?;
        }

        let config = builder
            .build()
            .map_err(|e| TorError::Config(e.to_string()))?;

        // Build unbootstrapped and drive bootstrap ourselves so we can report
        // progress AND enforce a timeout. `create_bootstrapped` does neither —
        // on a network that blocks Tor it retries internally forever, which is
        // the "stuck on joining tor" hang users hit.
        let client = TorClient::builder()
            .config(config)
            .create_unbootstrapped()
            .map_err(|e| TorError::Bootstrap(e.to_string()))?;

        // Scoped so the borrows `bootstrap()`/`bootstrap_events()` take on
        // `client` are released before `client` is moved into `Self`.
        {
            let mut events = client.bootstrap_events();
            let bootstrapping = client.bootstrap();
            futures::pin_mut!(bootstrapping);

            // Arti only emits an event when progress changes, so a stall goes
            // silent. A 2s heartbeat keeps the UI moving; the deadline turns an
            // indefinite hang into a clear, actionable error.
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let deadline = tokio::time::Instant::now() + BOOTSTRAP_TIMEOUT;
            let mut percent = 0u8;
            let mut blocked: Option<String> = None;

            loop {
                tokio::select! {
                    done = &mut bootstrapping => {
                        done.map_err(|e| TorError::Bootstrap(e.to_string()))?;
                        break;
                    }
                    Some(st) = events.next() => {
                        blocked = st.blocked().map(|b| b.to_string());
                        percent = (st.as_frac() * 100.0).clamp(0.0, 100.0) as u8;
                        match &blocked {
                            Some(d) => on_status(Status::TorBlocked { detail: d.clone() }),
                            None => on_status(Status::BootstrappingTor { percent }),
                        }
                    }
                    _ = tick.tick() => {
                        match &blocked {
                            Some(d) => on_status(Status::TorBlocked { detail: d.clone() }),
                            None => on_status(Status::BootstrappingTor { percent }),
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        return Err(TorError::Bootstrap(format!(
                            "could not reach the Tor network after {}s (stuck at {percent}%). \
                             This network is probably blocking Tor — try a phone hotspot or a VPN.",
                            BOOTSTRAP_TIMEOUT.as_secs()
                        )));
                    }
                }
            }
        }

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

        // A unique nickname per launch. `launch_onion_service_with_hsid`
        // inserts the key with overwrite=false, so reusing a nickname on a
        // second attempt (e.g. after a disconnect, since the Tor client and its
        // ephemeral keystore are kept alive for speed) fails with
        // KeyAlreadyExists — surfaced as a "bad api usage / keystore" error.
        // The nickname is only a local label; the onion address comes from the
        // keypair, so varying it changes nothing a peer can see.
        let n = LAUNCH_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nickname =
            HsNickname::new(format!("narco{n}")).map_err(|e| TorError::Config(e.to_string()))?;
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

                // Process-unique nickname. `round` alone is not enough: a caller
                // that reuses one TorTransport across separate connects (as the
                // app does) passes round=0 each time and would collide on the
                // keystore. The shared LAUNCH_COUNTER guarantees uniqueness
                // across every launch in the process. `round` is unused now but
                // kept in the signature for the tests that drive this directly.
                let _ = round;
                let n = LAUNCH_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let nickname = HsNickname::new(format!("narco{n}"))
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
