//! A one-off command-line peer, so a single human with the GUI can test a real
//! chat without a second device.
//!
//!     cargo run -p narco-tor --example chat_peer -- "THE-SHARED-CODE"
//!
//! Uses its own temporary Tor state directory so it can run on the same machine
//! as the GUI app (which uses the default directory) without fighting over the
//! cache lock. Connects with the given code, greets, and echoes whatever the
//! GUI sends — proving bidirectional encrypted delivery end to end.

use futures::io::AsyncReadExt;
use narco_proto::Event;
use narco_tor::wire::{recv_frame, send_frame};
use narco_tor::{Status, TorTransport};
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let code = std::env::args().nth(1).expect("usage: chat_peer <code>");
    let started = Instant::now();

    let derived = narco_proto::derive_multi(&[code.as_str()])?;
    let (addr, _) = narco_tor::identities(&derived);
    eprintln!("[peer] meeting at {}", addr.address);

    // Separate Tor dir so this can coexist with the GUI app's Tor instance.
    let dir = std::env::temp_dir().join("narco-cli-peer");
    let transport =
        TorTransport::bootstrap_in(Some(&dir), |s: Status| eprintln!("[peer] {s:?}")).await?;
    eprintln!("[peer] tor ready in {:?}, connecting…", started.elapsed());

    let conn =
        narco_tor::connect(&transport, &derived, |s: Status| eprintln!("[peer] {s:?}")).await?;
    let mut session = conn.session;
    let (mut reader, mut writer) = conn.stream.split();

    eprintln!(
        "[peer] CONNECTED to the GUI in {:?} — encrypted",
        started.elapsed()
    );
    send_frame(
        &mut writer,
        &session.encrypt(b"hello from Claude's test peer")?,
    )
    .await?;

    // Echo loop: decrypt, print, reply. Runs until the GUI ends the session.
    loop {
        let frame = match recv_frame(&mut reader).await {
            Ok(f) => f,
            Err(_) => {
                eprintln!("[peer] GUI disconnected");
                return Ok(());
            }
        };
        match session.handle(&frame)? {
            Event::Message(m) => {
                let text = String::from_utf8_lossy(&m);
                eprintln!("[peer] <<< GUI said: {text}");
                let reply = format!("echo: {text}");
                send_frame(&mut writer, &session.encrypt(reply.as_bytes())?).await?;
                eprintln!("[peer] >>> replied");
            }
            other => {
                eprintln!("[peer] unexpected: {other:?}");
                return Ok(());
            }
        }
    }
}
