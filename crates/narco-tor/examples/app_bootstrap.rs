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
    let started = Instant::now();
    println!("calling TorTransport::bootstrap() — the app's exact path\n");

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
