//! Live end-to-end proof over the real Tor network.
//!
//!     cargo run -p narco-tor --example live_handshake
//!
//! Two peers, one shared code, no server anywhere. Each derives the same onion
//! address from the code, both publish *and* dial it, discard the connection to
//! their own service, and settle on the one real pairing. Then they run the
//! SPAKE2 handshake and exchange encrypted messages.
//!
//! Two independent Tor clients are used, matching two real installs. Expect a
//! few minutes: bootstrap, descriptor publish, and directory propagation are
//! all genuinely slow.

use futures::io::{AsyncReadExt, AsyncWriteExt};
use narco_proto::Event;
use narco_tor::{Status, TorTransport};
use narco_tor::wire::{recv_frame, send_frame, Connected};
use std::time::Instant;

const CODE: &str = "PWXK7M2QRT9HFZ";
const PASSPHRASE: &str = "said out loud";

/// Exchange one message in each direction over a confirmed session.
async fn chat<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    name: &'static str,
    mut c: Connected<S>,
    greeting: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    println!("[{name}] handshake confirmed — encryption is live");
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

    // Two secrets, as two people would use them: one messaged, one spoken.
    let derived = narco_proto::derive_multi(&[CODE, PASSPHRASE])?;
    let (addr, _) = narco_tor::identities(&derived);
    println!("code          {CODE}");
    println!("passphrase    {PASSPHRASE:?}");
    println!("meeting at    {}", addr.address);
    println!("\nbootstrapping two independent Tor clients...");

    // Distinct state dirs: two clients in one process would otherwise fight
    // over Tor's on-disk cache lock. Separate installs never hit this.
    let tmp = std::env::temp_dir().join("narco-live-test");
    let (p1, p2) = (tmp.join("peer1"), tmp.join("peer2"));
    let (t1, t2) = tokio::try_join!(
        TorTransport::bootstrap_in(Some(&p1), |s| println!("  [peer1] {s:?}")),
        TorTransport::bootstrap_in(Some(&p2), |s| println!("  [peer2] {s:?}")),
    )?;
    println!("bootstrapped in {:?}\n", started.elapsed());

    let (d1, d2) = (derived.clone(), derived.clone());
    let (c1, c2) = tokio::try_join!(
        narco_tor::connect(&t1, &d1, |s: Status| println!("  [peer1] {s:?}")),
        narco_tor::connect(&t2, &d2, |s: Status| println!("  [peer2] {s:?}")),
    )?;
    println!("\nconnected over Tor in {:?}\n", started.elapsed());

    let (a, b) = tokio::join!(
        chat("peer1", c1, "hello from peer one"),
        chat("peer2", c2, "hello from peer two"),
    );
    let (a, b) = (a?, b?);

    println!("\npeer1 received: {a:?}");
    println!("peer2 received: {b:?}");
    assert_eq!(a, "hello from peer two");
    assert_eq!(b, "hello from peer one");

    println!("\nLIVE TOR END-TO-END PASSED in {:?}", started.elapsed());
    println!("No server was involved at any point.");
    println!("The address is now unpublished — nobody else can join.");
    Ok(())
}
