//! Live end-to-end proof of the host/join architecture over real Tor.
//!
//!     cargo run -p narco-tor --example live_handshake
//!
//! One peer hosts the onion service, the other joins (dials only). They complete
//! the SPAKE2 handshake and exchange an encrypted message. Two independent Tor
//! clients with separate state directories, matching two real installs. No
//! device connects to itself, because only the host publishes.

use narco_proto::Event;
use narco_tor::wire::{recv_frame, send_frame, Connected};
use narco_tor::{Status, TorTransport};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CODE: &str = "PWXK7M2QRT9HFZ";
const PASSPHRASE: &str = "said out loud";

/// Exchange one message in each direction over a confirmed session.
async fn chat<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    name: &'static str,
    mut c: Connected<S>,
    greeting: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    println!("[{name}] connected — encrypted");
    send_frame(&mut c.stream, &c.session.encrypt(greeting.as_bytes())?).await?;
    let frame = recv_frame(&mut c.stream).await?;
    match c.session.handle(&frame)? {
        Event::Message(m) => Ok(String::from_utf8(m)?),
        other => panic!("[{name}] expected a message, got {other:?}"),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let started = Instant::now();
    let derived = narco_proto::derive_multi(&[CODE, PASSPHRASE])?;
    let addr = narco_tor::onion_key(&derived);
    println!("meeting at {}\n", addr.address);

    // Distinct state dirs so two clients can share one machine without fighting
    // over Tor's on-disk cache lock. Separate installs never hit this.
    let tmp = std::env::temp_dir().join("narco-live-test");
    let (host_dir, join_dir) = (tmp.join("host"), tmp.join("join"));
    let (host_tor, join_tor) = tokio::try_join!(
        TorTransport::bootstrap_in(Some(&host_dir), |s| println!("  [host-tor] {s:?}")),
        TorTransport::bootstrap_in(Some(&join_dir), |s| println!("  [join-tor] {s:?}")),
    )?;
    println!("bootstrapped in {:?}\n", started.elapsed());

    let (dh, dj) = (derived.clone(), derived.clone());
    let (hc, jc) = tokio::try_join!(
        host_tor.host(&dh, |s: Status| println!("  [host] {s:?}")),
        join_tor.join(&dj, |s: Status| println!("  [join] {s:?}")),
    )?;
    println!("\nconnected over Tor in {:?}\n", started.elapsed());

    let (a, b) = tokio::join!(
        chat("host", hc, "hello from the host"),
        chat("join", jc, "hello from the joiner"),
    );
    let (a, b) = (a?, b?);

    println!("\nhost received: {a:?}");
    println!("join received: {b:?}");
    assert_eq!(a, "hello from the joiner");
    assert_eq!(b, "hello from the host");

    println!(
        "\nLIVE host/join END-TO-END PASSED in {:?}",
        started.elapsed()
    );
    println!("Host published, joiner dialled — no self-connection possible, no server.");
    Ok(())
}
