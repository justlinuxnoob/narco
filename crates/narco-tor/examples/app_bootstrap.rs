//! Exercise the exact bootstrap path the desktop app uses.
//!
//!     cargo run -p narco-tor --example app_bootstrap
//!
//! `live_handshake` calls `bootstrap_in(Some(dir))` with a temp directory so two
//! peers can share a process. The app calls `bootstrap()`, which uses Arti's
//! default state and cache locations — a different path that nothing covered.
//! If the app hangs on "Joining the Tor network" while the tests pass, the
//! difference is here.

use narco_tor::{Status, TorTransport};
use std::time::Instant;

#[tokio::main]
async fn main() {
    // Arti's own logs, which is what actually explains a stall. Override with
    // RUST_LOG for more or less detail.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(
                    "info,tor_dirmgr=debug,tor_guardmgr=debug,tor_chanmgr=debug,tor_circmgr=debug",
                )
            }),
        )
        .with_ansi(false)
        .init();

    let started = Instant::now();
    println!("narco tor diagnostic — testing the app's exact bootstrap path");
    println!(
        "os: {}  arch: {}\n",
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    let result = TorTransport::bootstrap(|s| match s {
        Status::BootstrappingTor { percent } => {
            println!(
                "  [{:>6.1}s] bootstrap {percent}%",
                started.elapsed().as_secs_f32()
            );
        }
        Status::TorBlocked { detail } => {
            println!(
                "  [{:>6.1}s] BLOCKED: {detail}",
                started.elapsed().as_secs_f32()
            );
        }
        other => println!("  [{:>6.1}s] {other:?}", started.elapsed().as_secs_f32()),
    })
    .await;

    match result {
        Ok(_) => println!("\nOK — bootstrapped in {:?}", started.elapsed()),
        Err(e) => {
            println!("\nFAILED after {:?}: {e}", started.elapsed());
            std::process::exit(1);
        }
    }
}
