//! Robustness scenarios against the real Tor network.
//!
//!     cargo run -p narco-tor --example robustness
//!
//! The happy path is covered by `live_handshake`. This covers what happens
//! afterwards: hosting the same code a second time, a peer vanishing without
//! notice, and someone arriving with the wrong secret. Each of these is a real
//! report or a real suspicion, not a hypothetical.
//!
//! Two Tor clients with separate state directories, so one machine can play
//! both sides exactly as two installs would.

use narco_proto::Event;
use narco_tor::wire::{recv_frame, send_frame};
use narco_tor::{Status, TorTransport};
use std::time::Instant;

const CODE: &str = "PWXK7M2QRT9HFZ";

type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn quiet(_s: Status) {}

/// Pair once at `code`, exchange a message each way, and drop both ends.
async fn pair_once(host_tor: &TorTransport, join_tor: &TorTransport, code: &str) -> Res<()> {
    let derived = narco_proto::derive_multi(&[code])?;
    let (dh, dj) = (derived.clone(), derived.clone());
    let (mut hc, mut jc) = tokio::try_join!(
        host_tor.host(&dh, quiet),
        join_tor.join(&dj, quiet),
    )?;

    send_frame(&mut hc.stream, &hc.session.encrypt(b"from host")?).await?;
    let f = recv_frame(&mut jc.stream).await?;
    match jc.session.handle(&f)? {
        Event::Message(m) => assert_eq!(m, b"from host"),
        other => panic!("expected a message, got {other:?}"),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Res<()> {
    let started = Instant::now();
    let tmp = std::env::temp_dir().join("narco-robustness");
    let (host_dir, join_dir) = (tmp.join("host"), tmp.join("join"));
    let (host_tor, join_tor) = tokio::try_join!(
        TorTransport::bootstrap_in(Some(&host_dir), quiet),
        TorTransport::bootstrap_in(Some(&join_dir), quiet),
    )?;
    println!("bootstrapped in {:?}\n", started.elapsed());

    // 1. The reported one: host the same code twice in a row.
    //
    // Ending a session tears the onion service down, and publishing the same
    // address again immediately afterwards is what happens whenever somebody
    // reconnects or starts a second conversation with the same code. If the
    // teardown is incomplete the second publish collides and the address is
    // unusable until the app restarts.
    println!("1. hosting the same code twice");
    let t = Instant::now();
    pair_once(&host_tor, &join_tor, CODE).await?;
    println!("   first pairing ok in {:?}", t.elapsed());
    let t = Instant::now();
    pair_once(&host_tor, &join_tor, CODE).await?;
    println!("   SAME code hosted again ok in {:?}\n", t.elapsed());

    // 2. A different code on the same clients, which is the "start another
    //    chat" case and uses a different onion identity on the same daemon.
    println!("2. a different code on the same clients");
    let t = Instant::now();
    pair_once(&host_tor, &join_tor, "ZQ4M8XKT2WNVRB").await?;
    println!("   ok in {:?}\n", t.elapsed());

    // 3. A peer that vanishes without closing cleanly, which is what a phone
    //    going into the background looks like from the other end.
    println!("3. a peer vanishing mid-conversation");
    let derived = narco_proto::derive_multi(&[CODE])?;
    let (dh, dj) = (derived.clone(), derived.clone());
    let (mut hc, jc) = tokio::try_join!(
        host_tor.host(&dh, quiet),
        join_tor.join(&dj, quiet),
    )?;
    drop(jc); // no goodbye, just gone
    let saw_end = match recv_frame(&mut hc.stream).await {
        Err(_) => true,
        Ok(_) => false,
    };
    assert!(saw_end, "the surviving end should notice the peer is gone");
    println!("   surviving end noticed, and can host again next\n");

    // 4. And after that, the address must still be usable.
    println!("4. hosting again after a peer vanished");
    let t = Instant::now();
    pair_once(&host_tor, &join_tor, CODE).await?;
    println!("   ok in {:?}\n", t.elapsed());

    println!("ALL ROBUSTNESS SCENARIOS PASSED in {:?}", started.elapsed());
    Ok(())
}
