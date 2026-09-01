//! A command-line peer, so a single human with the GUI can test a real chat
//! without a second device.
//!
//!     cargo run -p narco-tor --example chat_peer -- host "THE-CODE"
//!     cargo run -p narco-tor --example chat_peer -- join "THE-CODE"
//!
//! Pick the opposite role to the GUI: if the GUI hosts, run `join` here, and
//! vice versa. Uses its own temporary Tor state directory so it can run on the
//! same machine as the GUI. Greets, then echoes whatever the GUI sends.

use narco_proto::Event;
use narco_tor::wire::{recv_frame, send_frame};
use narco_tor::{Status, TorTransport};
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut args = std::env::args().skip(1);
    let role = args.next().expect("usage: chat_peer <host|join> <code>");
    let code = args.next().expect("usage: chat_peer <host|join> <code>");
    let started = Instant::now();

    let derived = narco_proto::derive_multi(&[code.as_str()])?;
    let addr = narco_tor::onion_key(&derived);
    eprintln!("[peer] role={role}, meeting at {}", addr.address);

    let dir = std::env::temp_dir().join("narco-cli-peer");
    let transport =
        TorTransport::bootstrap_in(Some(&dir), |s: Status| eprintln!("[peer] {s:?}")).await?;
    eprintln!("[peer] tor ready in {:?}, connecting…", started.elapsed());

    let cb = |s: Status| eprintln!("[peer] {s:?}");
    let conn = match role.as_str() {
        "host" => transport.host(&derived, cb).await?,
        "join" => transport.join(&derived, cb).await?,
        other => panic!("unknown role {other:?}; use `host` or `join`"),
    };
    let mut session = conn.session;
    let (mut reader, mut writer) = tokio::io::split(conn.stream);

    eprintln!("[peer] CONNECTED in {:?} — encrypted", started.elapsed());
    send_frame(
        &mut writer,
        &session.encrypt(b"hello from Claude's test peer")?,
    )
    .await?;

    loop {
        let frame = match recv_frame(&mut reader).await {
            Ok(f) => f,
            Err(_) => {
                eprintln!("[peer] the other side disconnected");
                return Ok(());
            }
        };
        match session.handle(&frame)? {
            Event::Message(m) => {
                let text = String::from_utf8_lossy(&m).to_string();
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
