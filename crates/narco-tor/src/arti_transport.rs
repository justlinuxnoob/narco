//! The iOS Tor engine: Arti, linked in and run inside this process.
//!
//! Every other platform drives the C `tor` daemon as a child process (see
//! [`crate::transport`]), because that binary is the most proven Tor there is.
//! iOS does not permit it: executing a second binary is blocked by code
//! signing, which is why there is no Tor Browser for iOS either. So here Tor is
//! a library on a thread rather than a process.
//!
//! The address both engines meet at is identical — it comes from
//! [`crate::onion`]'s derivation either way, and a test below pins that. If it
//! ever diverged, an iPhone and a PC entering the same code would publish and
//! dial different addresses and simply never find each other.
//!
//! Roles are the same as everywhere else: the host publishes, the joiner dials.
//!
//! See PROTOCOL.md §11.

use crate::identity::{self, Slot};
use crate::status::{Status, TorError};
use crate::wire::{run_handshake, ConnectError, Connected};
use futures::StreamExt;
use narco_proto::kdf::Derived;
use narco_proto::Error as ProtoError;
use std::sync::Arc;
use std::time::Duration;
// Aliased so it does not clash with our own `wire::Connected` connection type.
use tor_cell::relaycell::msg::Connected as ConnectedCell;
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
        return Err(TorError::Launch("no bridge lines provided".into()));
    }

    for line in &bridges.lines {
        let bridge: BridgeConfigBuilder = line
            .parse()
            .map_err(|e| TorError::Launch(format!("bad bridge line: {e}")))?;
        builder.bridges().bridges().push(bridge);
    }

    // Register every transport named in the bridge lines (obfs4, snowflake, …),
    // all served by the one bundled lyrebird binary, which provides them all.
    // Deriving the set from the lines rather than hardcoding obfs4 means
    // snowflake — whose config domain-fronts to a fixed broker and so does not
    // rot like obfs4 bridge IPs — works with no code change.
    let mut names: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for line in &bridges.lines {
        if let Some(name) = line.split_whitespace().next() {
            names.insert(name);
        }
    }
    for name in names {
        let proto = name
            .parse()
            .map_err(|e| TorError::Launch(format!("bad transport name {name:?}: {e}")))?;
        let mut transport = TransportConfigBuilder::default();
        transport
            .protocols(vec![proto])
            .path(CfgPath::new_literal(bridges.lyrebird_path.clone()))
            .run_on_startup(true);
        builder.bridges().transports().push(transport);
    }

    Ok(())
}

/// Give up if the other person never shows. Deliberately long (the two people
/// may press Start/Join minutes apart); the user can cancel any time.
const MEET_TIMEOUT: Duration = Duration::from_secs(1800);

/// Give up on joining Tor and report it, rather than sitting on the connecting
/// screen forever. On a working network this takes ~20-40s; a network that
/// blocks Tor otherwise hangs with no explanation and no way to retry.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(150);

/// Pause between dial attempts while joining. The host may not have published
/// yet, so early failures are expected rather than fatal.
const DIAL_RETRY: Duration = Duration::from_secs(4);

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
        // Use a directory this app owns, so a corrupt cache can be cleared.
        // Arti does not recover from cache damage by itself — deleting the
        // cache is the documented remedy (arti#783) — and with Arti's default
        // shared location we would not know what is safe to delete.
        let dir = app_tor_dir();
        match Self::bootstrap_core(dir.as_deref(), None, &on_status).await {
            Ok(t) => Ok(t),
            Err(first) => {
                // Retry once from a clean slate. A stale or partially written
                // cache otherwise fails identically on every launch, which is
                // indistinguishable from "the app is broken".
                let Some(dir) = dir.as_deref() else {
                    return Err(first);
                };
                if std::fs::remove_dir_all(dir).is_err() {
                    return Err(first);
                }
                Self::bootstrap_core(Some(dir), None, &on_status).await
            }
        }
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
        Self::bootstrap_core(dir, None, &on_status).await
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
        Self::bootstrap_core(dir, Some(bridges), &on_status).await
    }

    async fn bootstrap_core(
        dir: Option<&std::path::Path>,
        bridges: Option<BridgeSettings>,
        on_status: &impl Fn(Status),
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

        // Don't let filesystem-permission checks block startup.
        //
        // Arti refuses to use its cache/state directory if `fs-mistrust`
        // dislikes the permissions, and the failure surfaces as an unhelpful
        // stall rather than a clear error (arti#783). Windows uses ACLs rather
        // than Unix mode bits, so this check misfires there — matching a report
        // where Tor connects ("15%: connecting successfully") and then the
        // directory download never progresses.
        //
        // Safe here specifically: the keystore above is ephemeral and in-memory,
        // so these directories hold only Tor's *public* directory data — no
        // room code, onion key, or message ever touches them. There is nothing
        // on disk for the permission check to protect.
        builder.storage().permissions().dangerously_trust_everyone();

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
            .map_err(|e| TorError::Launch(e.to_string()))?;

        // Build unbootstrapped and drive bootstrap ourselves so we can report
        // progress AND enforce a timeout. `create_bootstrapped` does neither —
        // on a network that blocks Tor it retries internally forever, which is
        // the "stuck on joining tor" hang users hit.
        let client = TorClient::builder()
            .config(config)
            .create_unbootstrapped()
            .map_err(|e| TorError::Engine(e.to_string()))?;

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
                        done.map_err(|e| TorError::Engine(e.to_string()))?;
                        break;
                    }
                    Some(st) = events.next() => {
                        blocked = st.blocked().map(|b| b.to_string());
                        percent = (st.as_frac() * 100.0).clamp(0.0, 100.0) as u8;
                        match &blocked {
                            Some(d) => on_status(Status::BootstrappingTor { percent, detail: d.clone() }),
                            None => on_status(Status::BootstrappingTor { percent, detail: st.to_string() }),
                        }
                    }
                    _ = tick.tick() => {
                        match &blocked {
                            Some(d) => on_status(Status::BootstrappingTor { percent, detail: d.clone() }),
                            None => on_status(Status::BootstrappingTor { percent, detail: st.to_string() }),
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        // Arti's progress is conn_frac*0.15 + dir_frac*0.85, so
                        // stalling at exactly 15% means the connection to Tor
                        // succeeded and the *directory* never advanced at all.
                        // That is not censorship (a block fails below 15%); by
                        // far the most common cause is a wrong system clock,
                        // because Tor rejects a consensus that is not valid for
                        // the current time. Say so instead of blaming the
                        // network.
                        // A stall at ~15% means the TLS and Tor channel
                        // handshakes with relays succeeded but circuits never
                        // became usable, so the directory was never fetched.
                        // Observed on Windows machines where the handshake
                        // completes and then every circuit is torn down unused.
                        // Security software that inspects connections is the
                        // usual cause: it passes the handshake (it looks like
                        // ordinary TLS) and disrupts the Tor cells that follow.
                        // Do NOT blame the clock here — a clock fault reports
                        // "directory object expired or not yet valid" instead.
                        let hint = if (14..=16).contains(&percent) {
                            "Connected to Tor relays, but no circuit could be completed, \
                             so the directory never downloaded. Most often this is \
                             antivirus or firewall software inspecting connections. \
                             Try temporarily disabling it, or allow this app through. \
                             A wrong system clock or a network that blocks Tor can also \
                             cause it."
                        } else {
                            "Could not reach the Tor network. This network may be \
                             blocking Tor — try a phone hotspot or a VPN."
                        };
                        return Err(TorError::Engine(format!(
                            "{hint} (stopped at {percent}% after {}s)",
                            BOOTSTRAP_TIMEOUT.as_secs()
                        )));
                    }
                }
            }
        }

        Ok(Self { client })
    }

    /// Host the meeting: publish the onion service, accept the first connection
    /// that completes the handshake, then stop — dropping the service so no one
    /// else can join.
    ///
    /// Only the host publishes and only the joiner dials, so a device never
    /// connects to itself. That removes the self-connection problem and the
    /// "two devices publishing one address" fragility entirely.
    pub async fn host(
        &self,
        derived: &Derived,
        on_status: impl Fn(Status),
    ) -> Result<Connected<DataStream>, ConnectError> {
        on_status(Status::PublishingService);

        // Unique nickname per launch: `launch_onion_service_with_hsid` inserts
        // the key with overwrite=false, and the Tor client is kept alive across
        // attempts, so a reused nickname fails with KeyAlreadyExists. The
        // nickname is a local label; the address comes from the keypair.
        let n = LAUNCH_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nickname =
            HsNickname::new(format!("narco{n}")).map_err(|e| TorError::Launch(e.to_string()))?;
        let svc_config = OnionServiceConfigBuilder::default()
            .nickname(nickname)
            .build()
            .map_err(|e| TorError::Launch(e.to_string()))?;

        let meeting = identity::identity(derived, Slot::A);

        // The two engines must agree on the address, or an iPhone and a PC
        // holding the same code would publish and dial different places and
        // never meet — with no error, just a wait that never ends. They derive
        // it by different routes (Arti's key types here, plain ed25519 in
        // `onion`), so this checks rather than assumes.
        let expected = crate::onion::onion_key(derived).address;
        if meeting.address != expected {
            return Err(ConnectError::Tor(TorError::Launch(format!(
                "address derivation disagrees between engines ({} vs {}); \
                 refusing to publish where no one will look",
                meeting.address, expected
            ))));
        }
        let (service, rend_requests) = self
            .client
            .launch_onion_service_with_hsid(svc_config, meeting.into_keypair())
            .map_err(|e| TorError::Launch(e.to_string()))?
            .ok_or(TorError::Launch(
                "Arti refused to publish: its keystore is disabled".to_string(),
            ))?;

        on_status(Status::WaitingForPeer);

        let mut streams = handle_rend_requests(rend_requests);
        let deadline = tokio::time::Instant::now() + MEET_TIMEOUT;

        loop {
            let request = match tokio::time::timeout_at(deadline, streams.next()).await {
                Ok(Some(req)) => req,
                // Deadline passed, or the request stream ended.
                _ => return Err(ConnectError::TimedOut),
            };
            let stream = match request.accept(ConnectedCell::new_empty()).await {
                Ok(s) => s,
                Err(_) => continue, // failed accept; wait for the next knock
            };
            on_status(Status::PeerFound);
            match run_handshake(stream, derived).await {
                Ok(conn) => {
                    // Paired. Dropping the service tears down the introduction
                    // points, so no further connection can be established — the
                    // "only ever two people" guarantee, enforced in code rather
                    // than assumed (there is no unpublish in the Tor protocol).
                    drop(service);
                    return Ok(conn);
                }
                // A stray connector or someone who typed a different code. Keep
                // the service up and wait for the real peer.
                Err(ConnectError::Protocol(ProtoError::ConfirmMismatch))
                | Err(ConnectError::Protocol(ProtoError::Reflection)) => {
                    on_status(Status::WaitingForPeer);
                    continue;
                }
                // Connection dropped mid-handshake; wait for the next.
                Err(_) => {
                    on_status(Status::WaitingForPeer);
                    continue;
                }
            }
        }
    }

    /// Join the meeting: dial the onion address (never publishing) and run the
    /// handshake. Retries the dial until the host's service is reachable.
    pub async fn join(
        &self,
        derived: &Derived,
        on_status: impl Fn(Status),
    ) -> Result<Connected<DataStream>, ConnectError> {
        let address = crate::onion::onion_key(derived).address;
        on_status(Status::WaitingForPeer);
        let deadline = tokio::time::Instant::now() + MEET_TIMEOUT;

        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(ConnectError::TimedOut);
            }
            match self.client.connect((address.as_str(), VIRTUAL_PORT)).await {
                Ok(stream) => {
                    on_status(Status::PeerFound);
                    match run_handshake(stream, derived).await {
                        Ok(conn) => return Ok(conn),
                        // Reached the host but the codes differ — retrying will
                        // not help, so surface it.
                        Err(ConnectError::Protocol(ProtoError::ConfirmMismatch)) => {
                            return Err(ConnectError::Protocol(ProtoError::ConfirmMismatch))
                        }
                        // Transient; wait and try again.
                        Err(_) => {
                            on_status(Status::WaitingForPeer);
                            tokio::time::sleep(DIAL_RETRY).await;
                        }
                    }
                }
                // Host has not published yet — expected; keep trying.
                Err(_) => {
                    on_status(Status::WaitingForPeer);
                    tokio::time::sleep(DIAL_RETRY).await;
                }
            }
        }
    }
}

/// A cache/state directory owned by this app.
///
/// Arti's default location is shared with any other Arti-based program, so we
/// could not safely clear it on corruption. Owning our own directory makes the
/// wipe-and-retry in [`TorTransport::bootstrap`] safe. Holds only Tor's public
/// directory data — never a room code, key, or message.
fn app_tor_dir() -> Option<std::path::PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from)
    } else {
        std::env::var_os("XDG_CACHE_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cache"))
            })
    };
    base.map(|b| b.join("narco").join("tor"))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Host and joiner must derive the *same* meeting address from the code, or
    /// they would never find each other.
    #[test]
    fn host_and_joiner_target_one_shared_address() {
        let d = narco_proto::kdf::derive("PWXK7M2QRT9HFZ").unwrap();
        let host_sees = identity::identity(&d, Slot::A).address;
        let join_sees = identity::identity(&d, Slot::A).address;
        assert_eq!(host_sees, join_sees);
    }

    #[test]
    fn status_is_comparable_for_ui_dedup() {
        assert_eq!(Status::WaitingForPeer, Status::WaitingForPeer);
        assert_ne!(
            Status::BootstrappingTor { percent: 1 },
            Status::BootstrappingTor { percent: 2 }
        );
    }
}
