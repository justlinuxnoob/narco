//! Prove the C Tor daemon path works end to end.
//!
//!     PATH=/path/containing/tor:$PATH \
//!     cargo run -p narco-tor --example daemon_test
//!
//! Launches tor, waits for bootstrap, then publishes the onion service derived
//! from a room code and checks the address tor reports matches the one we
//! computed offline. If those agree, the engine swap preserves the whole
//! "the secret is the address" design.

use narco_tor::daemon::TorDaemon;
use narco_tor::onion::onion_key;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let started = Instant::now();
    let derived = narco_proto::derive_multi(&["PWXK7M2QRT9HFZ"])?;
    let key = onion_key(&derived);
    println!("expected address (computed offline): {}", key.address);

    let dir = std::env::temp_dir().join("narco-daemon-test");
    let _ = std::fs::remove_dir_all(&dir);

    println!("\nlaunching tor…");
    let mut tor = TorDaemon::launch(&dir, |pct, summary| {
        println!(
            "  [{:>6.1}s] {pct}% {summary}",
            started.elapsed().as_secs_f32()
        );
    })
    .await?;
    println!(
        "bootstrapped in {:?}, socks port {}",
        started.elapsed(),
        tor.socks_port()
    );

    // Somewhere for the service to point; we only need the address back.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let local_port = listener.local_addr()?.port();

    let published = tor.add_onion(&key.control_blob, 9001, local_port).await?;
    println!("\ntor published:  {published}");
    println!("we computed:    {}", key.address);
    assert_eq!(
        published, key.address,
        "address mismatch — the key blob is wrong"
    );

    tor.del_onion(&published).await?;
    println!("\nDAEMON PATH WORKS — addresses match, service published and removed.");
    println!("total {:?}", started.elapsed());
    Ok(())
}
