//! Narco relay — a blind, in-memory WebSocket pipe for exactly two peers.
//!
//! Read this file before trusting any Narco server. It is deliberately short so
//! that it can be read end to end in a few minutes, and its most important
//! properties are absences:
//!
//! * There is **no database, no disk write, and no persistence** of any kind.
//!   Rooms live in one `HashMap` and vanish when the process ends.
//! * There is **no dependency on `narco-proto`**. This binary holds no keys and
//!   contains no cryptography. It could not decrypt a message if it wanted to.
//! * There is **no parsing on the relay path**. Exactly one frame per
//!   connection is inspected — the join frame — and every byte after that is
//!   copied from one socket to the other without being looked at.
//! * **Nothing identifying is ever logged**: no room ids, no IP addresses, no
//!   payloads, no sizes.
//!
//! See `PROTOCOL.md` §6–§8 for the specification this implements.

use axum::extract::ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Idle time after which a room is destroyed. PROTOCOL.md §8.
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);
/// How often the reaper scans for idle rooms.
const REAP_INTERVAL: Duration = Duration::from_secs(15);
/// A client that never identifies itself is dropped.
const JOIN_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest relayed frame. The biggest legitimate payload is a 64 KiB padding
/// bucket plus AEAD and framing overhead.
const MAX_FRAME: usize = 128 * 1024;
/// Token-bucket rate limit per connection.
const RATE_PER_SEC: f64 = 30.0;
const RATE_BURST: f64 = 60.0;
/// Backstop against memory exhaustion by room creation.
const MAX_ROOMS: usize = 20_000;

/// Kind byte of the join frame. Distinct from every peer-to-peer kind.
const KIND_JOIN: u8 = 0x00;
const ROOM_ID_LEN: usize = 32;

// Control messages are fixed strings, so this binary needs no JSON serializer.
const SYS_WAITING: &str = r#"{"t":"sys","e":"waiting"}"#;
const SYS_PEER_JOINED: &str = r#"{"t":"sys","e":"peer_joined"}"#;
const SYS_PEER_LEFT: &str = r#"{"t":"sys","e":"peer_left"}"#;
const SYS_ROOM_FULL: &str = r#"{"t":"sys","e":"room_full"}"#;
const SYS_EXPIRED: &str = r#"{"t":"sys","e":"expired"}"#;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Something to write to a peer's socket.
enum Out {
    Sys(&'static str),
    Bin(Vec<u8>),
    /// Flush what is queued, then close.
    Close,
}

type PeerTx = mpsc::UnboundedSender<Out>;

struct Room {
    /// Exactly two slots. This array is the entire reason a third peer cannot
    /// join — there is nowhere to put one.
    peers: [Option<PeerTx>; 2],
    last_activity: Instant,
}

struct AppState {
    /// The only place room state exists. Never serialized, never written out.
    rooms: Mutex<HashMap<String, Room>>,
}

impl AppState {
    fn new() -> Self {
        Self { rooms: Mutex::new(HashMap::new()) }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // Railway supplies PORT.
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let state = Arc::new(AppState::new());
    tokio::spawn(reaper(state.clone()));

    let app = Router::new()
        .route("/", get(root))
        .route("/healthz", get(|| async { "ok" }))
        .route("/ws", get(ws_upgrade))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");

    // The only startup line. Note what is absent: no request logging middleware
    // is installed anywhere in this file, by design.
    println!("narco-relay v{} listening on {addr}", env!("CARGO_PKG_VERSION"));

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("server error");
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    // Rooms are process memory. Exiting destroys every one of them.
}

async fn root() -> impl IntoResponse {
    concat!(
        "narco-relay\n\n",
        "A blind relay for end-to-end encrypted two-person chats.\n",
        "This server cannot read your messages and stores nothing.\n\n",
        "Source: https://github.com/justlinuxnoob/narco\n"
    )
}

// ---------------------------------------------------------------------------
// Idle reaper
// ---------------------------------------------------------------------------

/// Destroys rooms that have been silent for [`IDLE_TIMEOUT`].
async fn reaper(state: Arc<AppState>) {
    let mut ticker = tokio::time::interval(REAP_INTERVAL);
    loop {
        ticker.tick().await;
        let now = Instant::now();
        let mut rooms = state.rooms.lock().expect("rooms mutex poisoned");
        rooms.retain(|_room_id, room| {
            if now.duration_since(room.last_activity) < IDLE_TIMEOUT {
                return true;
            }
            for peer in room.peers.iter().flatten() {
                let _ = peer.send(Out::Sys(SYS_EXPIRED));
                let _ = peer.send(Out::Close);
            }
            false
        });
    }
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

async fn ws_upgrade(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> Response {
    ws.max_message_size(MAX_FRAME)
        .on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Out>();

    // Writer task: the only thing that touches the socket's send half, so
    // ordering is well defined even when the peer and the reaper both write.
    let writer = tokio::spawn(async move {
        while let Some(out) = rx.recv().await {
            let msg = match out {
                Out::Sys(s) => Message::Text(Utf8Bytes::from_static(s)),
                Out::Bin(b) => Message::Binary(b.into()),
                Out::Close => break,
            };
            if sink.send(msg).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    // --- Join -------------------------------------------------------------
    let room_id = match tokio::time::timeout(JOIN_TIMEOUT, read_join(&mut stream)).await {
        Ok(Some(id)) => id,
        // Timed out, disconnected, or sent something that was not a valid join.
        _ => {
            let _ = tx.send(Out::Close);
            let _ = writer.await;
            return;
        }
    };

    let slot = match join_room(&state, &room_id, tx.clone()) {
        Some(slot) => slot,
        None => {
            // Room already has two peers, or the server is at capacity. The
            // existing conversation is left completely undisturbed.
            let _ = tx.send(Out::Sys(SYS_ROOM_FULL));
            let _ = tx.send(Out::Close);
            let _ = writer.await;
            return;
        }
    };

    // --- Relay ------------------------------------------------------------
    relay_loop(&mut stream, &state, &room_id, slot).await;

    // --- Teardown ---------------------------------------------------------
    // Reached on disconnect, protocol violation, or rate-limit trip. Either way
    // the room and both peers go away. PROTOCOL.md §8.8.
    destroy_room(&state, &room_id);
    let _ = tx.send(Out::Close);
    let _ = writer.await;
}

/// Read frames until a well-formed join frame arrives, or give up.
///
/// This is the only frame this server ever parses.
async fn read_join(
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
) -> Option<String> {
    let msg = stream.next().await?.ok()?;
    let Message::Binary(b) = msg else {
        // Text, or anything else, as a first frame is a protocol violation.
        return None;
    };
    if b.len() != 1 + ROOM_ID_LEN || b[0] != KIND_JOIN {
        return None;
    }
    let id = std::str::from_utf8(&b[1..]).ok()?;
    if !is_valid_room_id(id) {
        return None;
    }
    Some(id.to_owned())
}

/// Exactly 32 lowercase hex characters.
///
/// Duplicated from `narco_proto::is_valid_room_id` on purpose: taking a
/// dependency on the protocol crate just for this would undercut the claim that
/// the relay contains no protocol logic.
fn is_valid_room_id(s: &str) -> bool {
    s.len() == ROOM_ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Place a peer into a free slot, creating the room if needed.
///
/// Returns the slot index, or `None` if the room is full or the server is at
/// capacity.
fn join_room(state: &AppState, room_id: &str, tx: PeerTx) -> Option<usize> {
    let mut rooms = state.rooms.lock().expect("rooms mutex poisoned");

    if !rooms.contains_key(room_id) && rooms.len() >= MAX_ROOMS {
        return None;
    }

    let room = rooms.entry(room_id.to_owned()).or_insert_with(|| Room {
        peers: [None, None],
        last_activity: Instant::now(),
    });

    let slot = room.peers.iter().position(Option::is_none)?;
    room.peers[slot] = Some(tx);
    room.last_activity = Instant::now();

    let occupied = room.peers.iter().flatten().count();
    if occupied == 2 {
        for peer in room.peers.iter().flatten() {
            let _ = peer.send(Out::Sys(SYS_PEER_JOINED));
        }
    } else if let Some(me) = &room.peers[slot] {
        let _ = me.send(Out::Sys(SYS_WAITING));
    }

    Some(slot)
}

/// Remove a room and tell whoever is left that it is over.
fn destroy_room(state: &AppState, room_id: &str) {
    let mut rooms = state.rooms.lock().expect("rooms mutex poisoned");
    let Some(room) = rooms.remove(room_id) else {
        return;
    };
    for peer in room.peers.iter().flatten() {
        let _ = peer.send(Out::Sys(SYS_PEER_LEFT));
        let _ = peer.send(Out::Close);
    }
    // `room` drops here. Its buffers are freed; nothing was ever written down.
}

/// Copy binary frames to the other slot until the connection ends.
async fn relay_loop(
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
    state: &AppState,
    room_id: &str,
    slot: usize,
) {
    let mut bucket = RATE_BURST;
    let mut last_refill = Instant::now();

    while let Some(Ok(msg)) = stream.next().await {
        let payload = match msg {
            Message::Binary(b) => b,
            // A client must never send text. PROTOCOL.md §6.
            Message::Text(_) => return,
            // Keepalives are answered by axum; they count as activity only.
            Message::Ping(_) | Message::Pong(_) => {
                touch(state, room_id);
                continue;
            }
            Message::Close(_) => return,
        };

        if payload.len() > MAX_FRAME {
            return;
        }

        // Token bucket. Tripping it drops the connection, which ends the room.
        let now = Instant::now();
        bucket = (bucket + now.duration_since(last_refill).as_secs_f64() * RATE_PER_SEC)
            .min(RATE_BURST);
        last_refill = now;
        if bucket < 1.0 {
            return;
        }
        bucket -= 1.0;

        // The forwarding path. `payload` is moved to the other peer without
        // being inspected: no parsing, no inspection, no copy kept.
        let mut rooms = state.rooms.lock().expect("rooms mutex poisoned");
        let Some(room) = rooms.get_mut(room_id) else {
            return; // Reaped or torn down while we were reading.
        };
        room.last_activity = now;
        if let Some(peer) = room.peers[1 - slot].as_ref() {
            if peer.send(Out::Bin(payload.to_vec())).is_err() {
                return;
            }
        }
        // No peer yet: the frame is dropped. Nothing is buffered for later.
    }
}

/// Reset a room's idle timer.
fn touch(state: &AppState, room_id: &str) {
    if let Some(room) = state
        .rooms
        .lock()
        .expect("rooms mutex poisoned")
        .get_mut(room_id)
    {
        room.last_activity = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy() -> (PeerTx, mpsc::UnboundedReceiver<Out>) {
        mpsc::unbounded_channel()
    }

    /// Pull the next control message as a plain string.
    ///
    /// Comparing with `assert_eq!` rather than `matches!(.., Out::Sys(CONST))`
    /// is deliberate: a const in pattern position is easy to misread as a
    /// binding, which would make an ordering assertion pass unconditionally.
    fn next_sys(rx: &mut mpsc::UnboundedReceiver<Out>) -> String {
        match rx.try_recv() {
            Ok(Out::Sys(s)) => s.to_owned(),
            Ok(Out::Bin(_)) => panic!("expected a control message, got binary"),
            Ok(Out::Close) => "<close>".to_owned(),
            Err(e) => panic!("expected a control message, got {e:?}"),
        }
    }

    #[test]
    fn control_messages_are_distinguishable() {
        // Guards the helper above: these must not be equal to each other.
        assert_ne!(SYS_WAITING, SYS_PEER_JOINED);
        assert_ne!(SYS_PEER_LEFT, SYS_EXPIRED);
        assert_ne!(SYS_ROOM_FULL, SYS_PEER_JOINED);
    }

    #[test]
    fn room_id_validation_is_strict() {
        assert!(is_valid_room_id("0123456789abcdef0123456789abcdef"));
        assert!(!is_valid_room_id("0123456789ABCDEF0123456789ABCDEF"));
        assert!(!is_valid_room_id("0123456789abcdef0123456789abcde"));
        assert!(!is_valid_room_id("0123456789abcdef0123456789abcdeg"));
        assert!(!is_valid_room_id(""));
        assert!(!is_valid_room_id("../../../etc/passwd0123456789abc"));
    }

    #[test]
    fn third_peer_is_refused_and_does_not_disturb_the_room() {
        let state = AppState::new();
        let id = "0123456789abcdef0123456789abcdef";

        let (tx0, mut rx0) = dummy();
        let (tx1, mut rx1) = dummy();
        let (tx2, _rx2) = dummy();

        assert_eq!(join_room(&state, id, tx0), Some(0));
        assert_eq!(join_room(&state, id, tx1), Some(1));
        assert_eq!(join_room(&state, id, tx2), None, "third peer must be refused");

        // First peer: waiting, then peer_joined, in that order.
        assert_eq!(next_sys(&mut rx0), SYS_WAITING);
        assert_eq!(next_sys(&mut rx0), SYS_PEER_JOINED);
        // Second peer: peer_joined only, never `waiting`.
        assert_eq!(next_sys(&mut rx1), SYS_PEER_JOINED);
        // Neither incumbent was disturbed by the refusal.
        assert!(rx0.try_recv().is_err());
        assert!(rx1.try_recv().is_err());

        let rooms = state.rooms.lock().unwrap();
        assert_eq!(rooms[id].peers.iter().flatten().count(), 2);
    }

    #[test]
    fn leaving_frees_a_slot_only_via_room_destruction() {
        let state = AppState::new();
        let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let (tx0, _rx0) = dummy();
        let (tx1, mut rx1) = dummy();
        join_room(&state, id, tx0);
        join_room(&state, id, tx1);

        destroy_room(&state, id);

        // The survivor is told, and the room is gone entirely.
        assert_eq!(next_sys(&mut rx1), SYS_PEER_JOINED);
        assert_eq!(next_sys(&mut rx1), SYS_PEER_LEFT);
        assert_eq!(next_sys(&mut rx1), "<close>");
        assert!(state.rooms.lock().unwrap().is_empty());
    }

    #[test]
    fn destroying_an_unknown_room_is_harmless() {
        let state = AppState::new();
        destroy_room(&state, "ffffffffffffffffffffffffffffffff");
        assert!(state.rooms.lock().unwrap().is_empty());
    }

    #[test]
    fn room_capacity_is_enforced() {
        let state = AppState::new();
        {
            let mut rooms = state.rooms.lock().unwrap();
            for i in 0..MAX_ROOMS {
                rooms.insert(
                    format!("{i:032x}"),
                    Room { peers: [None, None], last_activity: Instant::now() },
                );
            }
        }
        let (tx, _rx) = dummy();
        // A brand-new room is refused at capacity...
        assert_eq!(join_room(&state, "ffffffffffffffffffffffffffffffff", tx), None);
        // ...but an existing room still accepts its second peer.
        let (tx2, _rx2) = dummy();
        assert_eq!(join_room(&state, &format!("{:032x}", 0), tx2), Some(0));
    }

    #[test]
    fn idle_rooms_expire_and_active_ones_survive() {
        let state = AppState::new();
        let (tx_old, mut rx_old) = dummy();
        let (tx_new, _rx_new) = dummy();
        {
            let mut rooms = state.rooms.lock().unwrap();
            rooms.insert(
                "0".repeat(32),
                Room {
                    peers: [Some(tx_old), None],
                    last_activity: Instant::now() - IDLE_TIMEOUT - Duration::from_secs(1),
                },
            );
            rooms.insert(
                "1".repeat(32),
                Room { peers: [Some(tx_new), None], last_activity: Instant::now() },
            );
        }

        // Inline the reaper's body; the loop itself is just a timer.
        let now = Instant::now();
        state.rooms.lock().unwrap().retain(|_, room| {
            if now.duration_since(room.last_activity) < IDLE_TIMEOUT {
                return true;
            }
            for peer in room.peers.iter().flatten() {
                let _ = peer.send(Out::Sys(SYS_EXPIRED));
                let _ = peer.send(Out::Close);
            }
            false
        });

        let rooms = state.rooms.lock().unwrap();
        assert!(!rooms.contains_key(&"0".repeat(32)), "idle room must be reaped");
        assert!(rooms.contains_key(&"1".repeat(32)), "active room must survive");
        assert!(matches!(rx_old.try_recv(), Ok(Out::Sys(SYS_EXPIRED))));
        assert!(matches!(rx_old.try_recv(), Ok(Out::Close)));
    }

    #[test]
    fn touch_resets_the_idle_timer() {
        let state = AppState::new();
        let id = "b".repeat(32);
        let stale = Instant::now() - Duration::from_secs(300);
        state
            .rooms
            .lock()
            .unwrap()
            .insert(id.clone(), Room { peers: [None, None], last_activity: stale });
        touch(&state, &id);
        assert!(state.rooms.lock().unwrap()[&id].last_activity > stale);
    }
}
