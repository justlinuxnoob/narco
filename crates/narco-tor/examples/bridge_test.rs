//! Verify a pluggable-transport path actually tunnels Tor.
//!
//!     cargo run -p narco-tor --example bridge_test -- /path/to/lyrebird [obfs4|snowflake]
//!
//! Bootstraps Tor *through* the chosen transport. Snowflake is the interesting
//! one: its config domain-fronts to a fixed broker through a CDN, so it does not
//! depend on bridge IPs staying alive — the best bet for a censored network and
//! bundle-friendly (nothing to rotate). This machine is not blocked, but routing
//! through the transport still exercises the whole path.

use narco_tor::{BridgeSettings, Status, TorTransport};
use std::time::Instant;

// Tor's built-in obfs4 bridges (public, frequently overloaded).
const OBFS4: &[&str] = &[
    "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0",
    "obfs4 209.148.46.65:443 74FAD13168806246602538555B5521A0383A1875 cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kTOa9/m+tGWT1SmSYpQ9uTBGa6Hw iat-mode=0",
];

// Tor's built-in snowflake bridge. The IP is a placeholder — snowflake does not
// dial it; it rendezvouses via the broker `url` domain-fronted behind `fronts`,
// then WebRTC to a volunteer proxy found via the STUN servers in `ice`.
const SNOWFLAKE: &[&str] = &[
    "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.voip.blackberry.com:3478,stun:stun.altar.com.pl:3478,stun:stun.bluesip.net:3478 utls-imitate=hellorandomizedalpn",
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Arti's own logs are the only way to see why a bridge attempt stalls:
    // ptmgr shows whether the transport binary launched, guardmgr/bridgedesc
    // whether the bridge answered, dirmgr whether the directory came through.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "warn,tor_ptmgr=trace,tor_guardmgr=debug,tor_dirmgr=debug,tor_chanmgr=debug",
        ))
        .with_ansi(false)
        .init();

    let lyrebird = std::env::args()
        .nth(1)
        .expect("usage: bridge_test <path-to-lyrebird> [obfs4|snowflake]");
    let which = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "snowflake".into());
    let lines: Vec<String> = match which.as_str() {
        "obfs4" => OBFS4.iter().map(|s| s.to_string()).collect(),
        _ => SNOWFLAKE.iter().map(|s| s.to_string()).collect(),
    };
    eprintln!("testing transport: {which}");

    let bridges = BridgeSettings {
        lyrebird_path: std::path::PathBuf::from(lyrebird),
        lines,
    };

    let started = Instant::now();
    let dir = std::env::temp_dir().join(format!("narco-bridge-test-{which}"));
    let _t = TorTransport::bootstrap_bridged(Some(&dir), bridges, |s: Status| {
        eprintln!("[{:>6.1}s] {s:?}", started.elapsed().as_secs_f32())
    })
    .await?;

    println!(
        "\nBOOTSTRAPPED THROUGH {} in {:?} — the transport path works.",
        which.to_uppercase(),
        started.elapsed()
    );
    Ok(())
}
