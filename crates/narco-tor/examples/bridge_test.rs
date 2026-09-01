//! Verify the obfs4 bridge path actually tunnels Tor.
//!
//!     cargo run -p narco-tor --example bridge_test -- /path/to/lyrebird
//!
//! Bootstraps Tor *through* an obfs4 bridge using the built-in bridge lines. If
//! this succeeds, the bridge plumbing works end to end — a censored network
//! would then connect where a direct one is blocked. (This machine is not
//! blocked, but bootstrapping through the bridge still exercises the whole obfs4
//! path: launching lyrebird, connecting to the bridge, tunnelling Tor.)

use narco_tor::{BridgeSettings, Status, TorTransport};
use std::time::Instant;

// Tor's built-in obfs4 bridges (from the Tor Expert Bundle pt_config.json).
const BRIDGES: &[&str] = &[
    "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0",
    "obfs4 209.148.46.65:443 74FAD13168806246602538555B5521A0383A1875 cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kTOa9/m+tGWT1SmSYpQ9uTBGa6Hw iat-mode=0",
    "obfs4 146.57.248.225:22 10A6CD36A537FCE513A322361547444B393989F0 cert=K1gDtDAIcUfeLqbstggjIw2rtgIKqdIhUlHp82XRqNSq/mtAjp1BIC9vHKJ2FAEpGssTPw iat-mode=0",
    "obfs4 45.145.95.6:27015 C5B7CD6946FF10C5B3E89691A7D3F2C122D2117C cert=TD7PbUO0/0k6xYHMPW3vJxICfkMZNdkRrb63Zhl5j9dW3iRGiCx0A7mPhe5T2EDzQ35+Zw iat-mode=0",
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let lyrebird = std::env::args()
        .nth(1)
        .expect("usage: bridge_test <path-to-lyrebird>");
    let bridges = BridgeSettings {
        lyrebird_path: std::path::PathBuf::from(lyrebird),
        lines: BRIDGES.iter().map(|s| s.to_string()).collect(),
    };

    let started = Instant::now();
    let dir = std::env::temp_dir().join("narco-bridge-test");
    let _t = TorTransport::bootstrap_bridged(Some(&dir), bridges, |s: Status| {
        eprintln!("[{:>6.1}s] {s:?}", started.elapsed().as_secs_f32())
    })
    .await?;

    println!(
        "\nBOOTSTRAPPED THROUGH OBFS4 BRIDGE in {:?} — the bridge path works.",
        started.elapsed()
    );
    Ok(())
}
