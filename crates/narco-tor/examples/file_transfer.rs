//! A real file crossing a real Tor connection.
//!
//!     cargo run -p narco-tor --example file_transfer
//!
//! Photos have been the least-verified part of this app. They were shipped on
//! the strength of a browser harness — which has no content policy, so it
//! could not see that the page's own CSP was blocking every image — and the
//! sender's copy was missing for a release because nothing exercised both
//! sides at once. This drives the actual chunking, the actual encryption and
//! the actual reassembly over an actual onion circuit.

use narco_proto::{message, Event};
use narco_tor::wire::{recv_frame, send_frame};
use narco_tor::{Status, TorTransport};
use std::time::Instant;

const CODE: &str = "QM4XT8WNVRB2ZK";

type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn quiet(_s: Status) {}

/// A file big enough to span many pieces, and compressible in no useful way,
/// so a bug that drops or reorders a piece shows up as a mismatch rather than
/// as bytes that happen to look the same.
fn sample(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut x: u32 = 0x1234_5678;
    while v.len() < len {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.truncate(len);
    v
}

#[tokio::main]
async fn main() -> Res<()> {
    let started = Instant::now();
    let tmp = std::env::temp_dir().join("narco-filetest");
    let (host_dir, join_dir) = (tmp.join("host"), tmp.join("join"));
    let (host_tor, join_tor) = tokio::try_join!(
        TorTransport::bootstrap_in(Some(&host_dir), quiet),
        TorTransport::bootstrap_in(Some(&join_dir), quiet),
    )?;
    println!("bootstrapped in {:?}", started.elapsed());

    let derived = narco_proto::derive_multi(&[CODE])?;
    let (dh, dj) = (derived.clone(), derived.clone());
    let (mut hc, mut jc) = tokio::try_join!(host_tor.host(&dh, quiet), join_tor.join(&dj, quiet))?;
    println!("paired in {:?}\n", started.elapsed());

    // Names that have broken things before: one long enough in a non-Latin
    // script to have been cut mid-character by the encoder, and one that reads
    // backwards on screen.
    for (label, name, size) in [
        ("a small photo", "holiday.png", 40_000usize),
        ("a large photo", "raw-scan.png", 900_000),
        (
            "a long non-Latin name",
            &"日本語の写真".repeat(40) as &str,
            50_000,
        ),
        (
            "a name that reads backwards",
            "holiday\u{202E}gnp.exe",
            1_000,
        ),
    ] {
        let data = sample(size);
        let total = data.len().div_ceil(message::CHUNK).max(1) as u32;
        let t = Instant::now();

        for (i, part) in data.chunks(message::CHUNK).enumerate() {
            let msg = message::encode_file_chunk("", 7, i as u32, total, name, part);
            send_frame(&mut hc.stream, &hc.session.encrypt(&msg)?).await?;
        }

        // Reassemble exactly as the app does.
        let mut parts: Vec<Option<Vec<u8>>> = vec![None; total as usize];
        let mut have = 0u32;
        let mut got_name = String::new();
        while have < total {
            let f = recv_frame(&mut jc.stream).await?;
            match jc.session.handle(&f)? {
                Event::Message(m) => match message::decode(&m) {
                    Some(message::Incoming::File {
                        index, name, data, ..
                    }) => {
                        if parts[index as usize].is_none() {
                            have += 1;
                        }
                        parts[index as usize] = Some(data);
                        got_name = name;
                    }
                    other => panic!("expected a file piece, got {other:?}"),
                },
                other => panic!("expected a message, got {other:?}"),
            }
        }

        let rebuilt: Vec<u8> = parts.into_iter().flatten().collect::<Vec<_>>().concat();
        assert_eq!(rebuilt.len(), data.len(), "{label}: wrong length");
        assert_eq!(rebuilt, data, "{label}: bytes differ");
        assert!(!got_name.is_empty(), "{label}: lost the name");
        assert!(
            !got_name.contains('\u{202E}'),
            "{label}: a display override survived the wire"
        );
        println!(
            "{label}: {} bytes in {total} pieces, {:?}, arrived as {got_name:?}",
            data.len(),
            t.elapsed()
        );
    }

    // And the chat still works afterwards, with the ratchet in step.
    send_frame(
        &mut hc.stream,
        &hc.session
            .encrypt(&message::encode_text("", "still here"))?,
    )
    .await?;
    let f = recv_frame(&mut jc.stream).await?;
    match jc.session.handle(&f)? {
        Event::Message(m) => match message::decode(&m) {
            Some(message::Incoming::Text { text, .. }) => assert_eq!(text, "still here"),
            other => panic!("expected text, got {other:?}"),
        },
        other => panic!("expected a message, got {other:?}"),
    }

    println!("\nFILE TRANSFER OVER TOR PASSED in {:?}", started.elapsed());
    Ok(())
}
