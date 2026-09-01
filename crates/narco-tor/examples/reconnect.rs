//! Reproduce the keystore-reuse bug against the host/join API: reuse one Tor
//! client to host TWICE in a row.
//!
//!     cargo run -p narco-tor --example reconnect
//!
//! Before the unique-nickname fix, the second `host()` failed with a
//! "bad api usage / keystore" error (KeyAlreadyExists), because the onion
//! service was relaunched under the same nickname. This drives two full
//! host/join connections back to back, reusing the same host transport — the
//! exact condition the app hits when a user starts a second chat.

use narco_tor::{Status, TorTransport};
use std::sync::Arc;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let derived = narco_proto::derive_multi(&["RECONNECTTEST9QK"])?;
    let quiet = |_: Status| {};

    let base = std::env::temp_dir().join("narco-reconnect");
    let host = Arc::new(TorTransport::bootstrap_in(Some(&base.join("host")), quiet).await?);
    let join = Arc::new(TorTransport::bootstrap_in(Some(&base.join("join")), quiet).await?);
    println!("both bootstrapped\n");

    for attempt in 1..=2u32 {
        let t0 = Instant::now();
        // The host reuses the SAME transport (and its ephemeral keystore) on
        // both attempts — the condition that triggered KeyAlreadyExists.
        let (h, j) = (host.clone(), join.clone());
        let (dh, dj) = (derived.clone(), derived.clone());
        let hs = tokio::spawn(async move { h.host(&dh, |_| {}).await });
        let js = tokio::spawn(async move { j.join(&dj, |_| {}).await });

        // Connected has no Debug (it holds a live stream), so report only the
        // errors, which do implement Display.
        let (hr, jr) = tokio::try_join!(hs, js)?;
        match (hr, jr) {
            (Ok(_), Ok(_)) => println!("attempt {attempt}: CONNECTED in {:?}", t0.elapsed()),
            (h, j) => {
                let he = h.err().map(|e| e.to_string()).unwrap_or_default();
                let je = j.err().map(|e| e.to_string()).unwrap_or_default();
                println!("attempt {attempt}: FAILED host_err=[{he}] join_err=[{je}]");
                std::process::exit(1);
            }
        }
    }

    println!("\nRECONNECT OK — reusing one Tor client to host twice works");
    Ok(())
}
