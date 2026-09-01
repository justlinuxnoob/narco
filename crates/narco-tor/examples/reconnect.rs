//! Reproduce the keystore-reuse bug: two sequential connects on ONE Tor client.
//!
//!     cargo run -p narco-tor --example reconnect
//!
//! Before the unique-nickname fix, the second launch failed with a
//! "bad api usage / keystore" error (KeyAlreadyExists). This drives two peers
//! (A hosts, B dials) twice in a row, reusing the same TorTransport for A —
//! exactly what the GUI does when a user retries after a disconnect.

use narco_tor::transport::{Role, Status};
use narco_tor::TorTransport;
use std::sync::Arc;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let derived = narco_proto::derive_multi(&["RECONNECTTEST9QK"])?;
    let quiet = |_: Status| {};

    let base = std::env::temp_dir().join("narco-reconnect");
    let a = Arc::new(TorTransport::bootstrap_in(Some(&base.join("a")), quiet).await?);
    let b = Arc::new(TorTransport::bootstrap_in(Some(&base.join("b")), quiet).await?);
    println!("both bootstrapped\n");

    for attempt in 1..=2u32 {
        let t0 = Instant::now();
        // A reuses the SAME transport across both attempts — the exact condition
        // that triggered the keystore error on the second launch.
        let (ra, rb) = (a.clone(), b.clone());
        let da = derived.clone();
        let db = derived.clone();
        let host = tokio::spawn(async move { ra.meet_once(&da, Role::Host, 0, &|_| {}).await });
        let dial = tokio::spawn(async move { rb.meet_once(&db, Role::Dial, 0, &|_| {}).await });

        match tokio::try_join!(host, dial) {
            Ok((Ok(Some(_)), Ok(Some(_)))) => {
                println!("attempt {attempt}: CONNECTED in {:?}", t0.elapsed());
            }
            Ok((h, d)) => {
                println!("attempt {attempt}: FAILED host={h:?} dial={d:?}");
                std::process::exit(1);
            }
            Err(e) => {
                println!("attempt {attempt}: JOIN ERROR {e}");
                std::process::exit(1);
            }
        }
    }

    println!("\nRECONNECT OK — reusing one Tor client across two connects works");
    Ok(())
}
