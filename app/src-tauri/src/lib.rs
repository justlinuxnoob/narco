//! Narco desktop app.
//!
//! Everything security-relevant lives in `narco-proto` and `narco-tor`. This
//! layer only owns the session task and shuttles plaintext between it and the
//! webview. Plaintext exists in exactly two places — the running session task
//! and the on-screen message list — and both are destroyed together.

use base64::Engine as _;
use narco_proto::{message, Error as ProtoError, Event};

/// Files cross to the webview as text; an event payload cannot carry bytes.
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;
use narco_tor::wire::{recv_frame, send_frame, Connected};
use narco_tor::{Status, TorTransport};
use serde::Serialize;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::mpsc;

/// Commands from the UI to the running session task.
enum Cmd {
    Send(String),
    /// A file to cut up and send. Held in memory only: it came from the user's
    /// own disk and never goes back to ours.
    SendFile {
        name: String,
        data: Vec<u8>,
    },
    End,
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum UiEvent {
    /// Progress during the slow connect. `stage` drives the checklist in the
    /// UI; a four-minute wait with no visible movement is indistinguishable
    /// from a hang.
    Status { text: String, stage: String },
    /// Handshake confirmed; the chat is live.
    Ready,
    /// A decrypted message from the peer. `from` is the name they chose, and
    /// is empty when they did not choose one.
    Message { from: String, text: String },
    /// A file arrived whole. `data` is base64 because an event payload cannot
    /// carry raw bytes; it is held in memory and written nowhere.
    File {
        from: String,
        name: String,
        data: String,
    },
    /// How far along a transfer is, in either direction.
    FileProgress {
        name: String,
        sent: u32,
        total: u32,
        outgoing: bool,
    },
    /// Session over. `reason` is shown to the user.
    Ended { reason: String },
    /// The connection dropped and is being re-established. The conversation is
    /// not over and the message history stays on screen.
    Reconnecting,
    /// Back. A fresh handshake completed at the same address.
    Reconnected,
    /// The idle timeout is about to fire, or has been called off because
    /// something happened. Ending a chat with no warning is an ambush; this
    /// gives the user a chance to stay.
    IdleWarning { seconds_left: u32, active: bool },
    /// Progress joining Tor, reported while the user is still typing.
    TorProgress {
        text: String,
        ready: bool,
        failed: bool,
    },
}

#[derive(Default)]
struct AppState {
    /// `Some` while a session is running.
    tx: Mutex<Option<mpsc::Sender<Cmd>>>,
    /// The Tor client, bootstrapped once at launch and reused for every chat.
    ///
    /// Bootstrapping needs no secrets, so it runs while the user is still
    /// typing and sharing a code — hiding the slowest stage behind time they
    /// were spending anyway. Keeping it alive afterwards means a second
    /// conversation skips the stage entirely.
    tor: Arc<tokio::sync::OnceCell<Arc<TorTransport>>>,
}

/// Recent log lines, shown in the app's Diagnostics panel.
///
/// The release build has no console (a GUI app on Windows gets no stdout), so
/// without this the user can see a failure but never the reason. Capped so it
/// cannot grow without bound.
const MAX_LOG_LINES: usize = 500;
static LOG_BUF: std::sync::OnceLock<Mutex<std::collections::VecDeque<String>>> =
    std::sync::OnceLock::new();

fn log_buf() -> &'static Mutex<std::collections::VecDeque<String>> {
    LOG_BUF.get_or_init(|| Mutex::new(std::collections::VecDeque::new()))
}

fn push_log(line: &str) {
    let line = line.trim_end();
    if line.is_empty() {
        return;
    }
    let mut b = log_buf().lock().expect("log buffer poisoned");
    if b.len() >= MAX_LOG_LINES {
        b.pop_front();
    }
    b.push_back(line.to_string());
}

/// Sink that routes `tracing` output (including Arti's internals) into the
/// in-app buffer, so the Diagnostics panel shows the real cause of a failure.
struct LogWriter;

impl std::io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for line in String::from_utf8_lossy(buf).lines() {
            push_log(line);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct LogWriterMaker;

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogWriterMaker {
    type Writer = LogWriter;
    fn make_writer(&'a self) -> Self::Writer {
        LogWriter
    }
}

/// Everything the Diagnostics panel shows. Safe to share: it carries no room
/// code, onion address, key, or message content.
#[tauri::command]
fn get_logs() -> String {
    let b = log_buf().lock().expect("log buffer poisoned");
    if b.is_empty() {
        return "(no logs yet)".into();
    }
    b.iter().cloned().collect::<Vec<_>>().join("\n")
}

fn emit(app: &AppHandle, e: UiEvent) {
    // Record connection status for troubleshooting. Deliberately safe to log:
    // it carries no room code, onion address, key, or message content — only
    // coarse connection state.
    let line = match &e {
        UiEvent::Status { text, stage } => Some(format!("[narco] status[{stage}] {text}")),
        UiEvent::IdleWarning { active, .. } => Some(format!(
            "[narco] idle warning {}",
            if *active { "shown" } else { "cleared" }
        )),
        UiEvent::Ready => Some("[narco] handshake confirmed — chat live".to_string()),
        UiEvent::Reconnecting => Some("[narco] connection lost — reconnecting".to_string()),
        UiEvent::Reconnected => Some("[narco] reconnected".to_string()),
        UiEvent::Ended { reason } => Some(format!("[narco] ended: {reason}")),
        UiEvent::TorProgress {
            text,
            ready,
            failed,
        } => Some(format!(
            "[narco] tor: {text} (ready={ready} failed={failed})"
        )),
        UiEvent::Message { .. } => None, // never log message events
        UiEvent::File { .. } => None,    // nor file contents
        // Only that a transfer is happening, never the name or the bytes.
        UiEvent::FileProgress {
            sent,
            total,
            outgoing,
            ..
        } => Some(format!(
            "[narco] file {} {sent}/{total}",
            if *outgoing { "sending" } else { "receiving" }
        )),
    };
    if let Some(line) = line {
        eprintln!("{line}");
        push_log(&line);
    }
    let _ = app.emit("narco", e);
}

/// Human text plus the stage id the UI checklist keys off.
fn status_parts(s: Status) -> (String, &'static str) {
    match s {
        // Bootstrap downloads Tor's relay directory, so show real progress
        // rather than a spinner that cannot be told apart from a hang.
        // tor reports its own phase text ("Loading relay descriptors", …), so a
        // stall names the stage it stalled at instead of showing a bare number.
        Status::BootstrappingTor { percent, detail } => (
            format!("Joining the Tor network… {percent}% — {detail}"),
            "tor",
        ),
        Status::PublishingService => ("Publishing your address…".into(), "publish"),
        Status::WaitingForPeer => ("Waiting for the other person…".into(), "peer"),
        Status::PeerFound => ("Found them. Verifying it's really them…".into(), "verify"),
    }
}

fn emit_status(app: &AppHandle, s: Status) {
    let (text, stage) = status_parts(s);
    emit(
        app,
        UiEvent::Status {
            text,
            stage: stage.into(),
        },
    );
}

/// Bootstrap Tor once, or return the already-bootstrapped client.
///
/// Safe to call concurrently: `OnceCell` guarantees one bootstrap, and later
/// callers await that same one.
async fn ensure_tor(
    app: &AppHandle,
    cell: &tokio::sync::OnceCell<Arc<TorTransport>>,
) -> Result<Arc<TorTransport>, String> {
    let out = cell
        .get_or_try_init(|| async {
            let a = app.clone();
            TorTransport::bootstrap(move |s| {
                let (text, _) = status_parts(s);
                emit(
                    &a,
                    UiEvent::TorProgress {
                        text,
                        ready: false,
                        failed: false,
                    },
                );
            })
            .await
            .map(Arc::new)
            .map_err(|e| e.to_string())
        })
        .await
        .cloned();

    match out {
        Ok(t) => {
            emit(
                app,
                UiEvent::TorProgress {
                    text: "Tor ready".into(),
                    ready: true,
                    failed: false,
                },
            );
            Ok(t)
        }
        Err(e) => {
            // Surface the failure instead of swallowing it — this is what left
            // the entry screen stuck on "joining tor…" with no way out.
            // `get_or_try_init` does not cache errors, so retry works without
            // restarting the app.
            emit(
                app,
                UiEvent::TorProgress {
                    text: e.clone(),
                    ready: false,
                    failed: true,
                },
            );
            Err(e)
        }
    }
}

/// Start joining Tor without waiting for it. Called at launch.
#[tauri::command]
fn warm_tor(app: AppHandle, state: State<'_, AppState>) {
    let cell = state.tor.clone();
    tauri::async_runtime::spawn(async move {
        let _ = ensure_tor(&app, &cell).await;
    });
}

/// Generate a fresh 130-bit code.
#[tauri::command]
fn generate_code() -> String {
    narco_proto::generate()
}

/// Validate a code without connecting, so the UI can complain immediately.
#[tauri::command]
fn check_code(code: String) -> Result<(), String> {
    narco_proto::validate(&narco_proto::normalize(&code)).map_err(|e| e.to_string())
}

/// Start a session. Returns as soon as the work is queued; progress arrives as
/// `narco` events.
#[tauri::command]
async fn connect(
    app: AppHandle,
    state: State<'_, AppState>,
    secrets: Vec<String>,
    idle_secs: u64,
    host: bool,
    nickname: String,
) -> Result<(), String> {
    // Validate before doing anything slow.
    let derived = narco_proto::derive_multi(&secrets).map_err(|e| e.to_string())?;

    let (tx, rx) = mpsc::channel::<Cmd>(16);
    // Kept so the cleanup below can tell whether the slot still holds *this*
    // session's sender.
    let mine = tx.clone();
    {
        let mut slot = state.tx.lock().expect("state poisoned");
        if slot.is_some() {
            return Err("a session is already running".into());
        }
        *slot = Some(tx);
    }

    let tor = state.tor.clone();
    tauri::async_runtime::spawn(async move {
        // Catch panics so a bug can never leave the UI waiting forever with no
        // explanation. Every path out of here emits an Ended event.
        let reason = match futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(
            run_session(&app, derived, rx, idle_secs, tor, host, nickname),
        ))
        .await
        {
            Ok(reason) => reason,
            Err(_) => "Something went wrong inside the app. The session was ended \
                       and all keys destroyed."
                .to_string(),
        };
        // Whatever happened, the session is over and holds nothing.
        //
        // Only clear the slot if it still belongs to us. `end_session` takes
        // the sender out on its way, so a later `connect` can be admitted and
        // install its own before this task finishes — and clearing
        // unconditionally then cut the *new* session's channel, leaving it
        // running with a live peer and a published onion service that nothing
        // could stop.
        if let Some(state) = app.try_state::<AppState>() {
            let mut slot = state.tx.lock().expect("state poisoned");
            if slot.as_ref().is_some_and(|s| s.same_channel(&mine)) {
                *slot = None;
            }
        }
        emit(&app, UiEvent::Ended { reason });
    });

    Ok(())
}

/// How many times a dropped connection is chased before giving up. Generous:
/// a phone that spent a while in the background may need several.
const MAX_RECONNECTS: u32 = 20;

/// How long before the idle timeout the user is warned.
const IDLE_WARNING: Duration = Duration::from_secs(60);

/// Owns the session and its stream for the whole conversation.
///
/// Returns the reason the session ended. Every exit path drops the `Session`,
/// whose `Drop` zeroizes all key material.
async fn run_session(
    app: &AppHandle,
    derived: narco_proto::Derived,
    mut rx: mpsc::Receiver<Cmd>,
    idle_secs: u64,
    tor: Arc<tokio::sync::OnceCell<Arc<TorTransport>>>,
    host: bool,
    nickname: String,
) -> String {
    // 0 means the user chose "never". Represent it as an effectively unreachable
    // deadline rather than branching the select! arm.
    let idle = if idle_secs == 0 {
        Duration::from_secs(u32::MAX as u64)
    } else {
        Duration::from_secs(idle_secs)
    };
    // Usually already done: the client was bootstrapped at launch.
    let transport = match ensure_tor(app, &tor).await {
        Ok(t) => t,
        Err(e) => return e,
    };

    // Reconnect instead of ending when the connection drops on its own.
    //
    // A phone suspends a backgrounded app and closes its sockets, so switching
    // apps for a moment would otherwise end the conversation — and the secrets
    // are still here, so there is nothing to ask the user for. The address is
    // derived from them, so reconnecting means publishing and dialling the same
    // place again.
    //
    // A fresh handshake runs each time, with new ephemerals and new session
    // keys, so nothing is weakened by doing this: it is a new session at the
    // same address, not a resumed one.
    let mut reconnects = 0u32;

    let reason = 'connection: loop {
        let app_status = app.clone();
        let cb = move |s| emit_status(&app_status, s);
        // The starter hosts the onion service; the joiner only dials it. One side
        // publishing and the other dialling is what makes a device never connect to
        // itself.
        // Cancel has to work *here*, not just once the chat is up. Finding the
        // other person is where a user actually gives up, and the End command used
        // to sit unread in the channel until the 30-minute meet timeout: the onion
        // service stayed published, the session stayed alive, and if a peer turned
        // up in the meantime the UI jumped into a chat the user thought they had
        // killed. Meanwhile the front end had already claimed "You cancelled."
        let connected = tokio::select! {
            result = async {
                if host {
                    transport.host(&derived, cb).await
                } else {
                    transport.join(&derived, cb).await
                }
            } => result,

            // `Receiver::recv` is cancellation-safe, so losing this race costs
            // nothing; anything that is not End would have been ignored anyway.
            _ = async {
                while let Some(cmd) = rx.recv().await {
                    if matches!(cmd, Cmd::End) {
                        break;
                    }
                }
            } => return "You cancelled.".into(),
        };

        let Connected {
            mut session,
            stream,
        } = match connected {
            Ok(c) => c,
            Err(e) => {
                // Failing to connect at all is the user's problem to see. Failing
                // to get back is worth another try, since they were talking a
                // moment ago.
                if reconnects == 0 {
                    break 'connection e.to_string();
                }
                reconnects += 1;
                if reconnects > MAX_RECONNECTS {
                    break 'connection "Lost the connection and could not get it back.".into();
                }
                continue 'connection;
            }
        };

        if reconnects == 0 {
            emit(app, UiEvent::Ready);
        } else {
            emit(app, UiEvent::Reconnected);
        }

        let (mut reader, mut writer) = tokio::io::split(stream);

        // Frames are read in a task of their own, not in a `select!` arm.
        //
        // `recv_frame` is two sequential `read_exact` calls, so it is not
        // cancellation-safe. `select!` drops the losing branch's future, so every
        // time the user sent a message or the idle timer ticked while a frame was
        // half-read, the bytes already taken off the socket were lost. The stream
        // desynchronised, the next length prefix was read out of the middle of a
        // message, and the session died telling the user their peer had tampered
        // with it — for a message they had just sent themselves. Padding buckets
        // start at 256 bytes and the next is 1024, so any message past roughly 230
        // characters spans several reads and hits this routinely.
        //
        // `Receiver::recv` is cancellation-safe, so the race now happens somewhere
        // losing it costs nothing.
        let (frame_tx, mut frame_rx) = mpsc::channel::<Vec<u8>>(8);
        let reader_task = tauri::async_runtime::spawn(async move {
            while let Ok(frame) = recv_frame(&mut reader).await {
                if frame_tx.send(frame).await.is_err() {
                    break;
                }
            }
        });

        // Cleared on any traffic, so a warning shown once does not stay on screen
        // after the conversation resumes.
        let mut idle_warned = false;

        // Pieces of files still arriving, keyed by transfer. Memory only, and gone
        // with the session like everything else.
        let mut incoming_files: std::collections::HashMap<u64, (String, Vec<Vec<u8>>)> =
            std::collections::HashMap::new();
        let mut next_transfer_id: u64 = 0;

        let reason = 'session: loop {
            tokio::select! {
                // Peer traffic.
                frame = frame_rx.recv() => {
                    let Some(frame) = frame else {
                        break 'session ("The other person disconnected.".to_string(), true);
                    };
                    if idle_warned {
                        idle_warned = false;
                        emit(app, UiEvent::IdleWarning { seconds_left: 0, active: false });
                    }
                    match session.handle(&frame) {
                        Ok(Event::Message(m)) => match message::decode(&m) {
                            Some(message::Incoming::Text { from, text }) => {
                                emit(app, UiEvent::Message { from, text })
                            }
                            Some(message::Incoming::File {
                                from, id, index, total, name, data,
                            }) => {
                                // Pieces are held until the set is complete. A
                                // transfer that is abandoned halfway is dropped
                                // when the session ends, along with everything
                                // else.
                                let entry = incoming_files
                                    .entry(id)
                                    .or_insert_with(|| (name.clone(), vec![Vec::new(); total as usize]));
                                if entry.1.len() == total as usize {
                                    entry.1[index as usize] = data;
                                    let have = entry.1.iter().filter(|c| !c.is_empty()).count() as u32;
                                    emit(app, UiEvent::FileProgress {
                                        name: name.clone(),
                                        sent: have,
                                        total,
                                        outgoing: false,
                                    });
                                    if have == total {
                                        let (name, parts) = incoming_files.remove(&id).expect("just seen");
                                        let bytes: Vec<u8> = parts.concat();
                                        emit(app, UiEvent::File {
                                            from,
                                            name,
                                            data: B64.encode(&bytes),
                                        });
                                    }
                                }
                            }
                            None => break 'session (
                                "Received a malformed message.".to_string(),
                                false,
                            ),
                        },
                        Ok(_) => break 'session ("Unexpected handshake frame.".to_string(), false),
                        // Any protocol error is terminal by design.
                        Err(ProtoError::Decrypt) | Err(ProtoError::OutOfOrder { .. }) => {
                            break 'session (
                                "Message failed verification — session ended for safety."
                                    .to_string(),
                                false,
                            )
                        }
                        Err(e) => break 'session (e.to_string(), false),
                    }
                }

                // UI commands.
                cmd = rx.recv() => {
                    match cmd {
                        Some(Cmd::Send(text)) => {
                            if idle_warned {
                                idle_warned = false;
                                emit(app, UiEvent::IdleWarning { seconds_left: 0, active: false });
                            }
                            match session.encrypt(&message::encode_text(&nickname, &text)) {
                                Ok(frame) => {
                                    if send_frame(&mut writer, &frame).await.is_err() {
                                        break 'session ("The other person disconnected.".to_string(), true);
                                    }
                                }
                                Err(ProtoError::TooLong) => {
                                    emit(
                                        app,
                                        UiEvent::Status {
                                            text: "Message too long.".into(),
                                            stage: "verify".into(),
                                        },
                                    );
                                }
                                Err(e) => break 'session (e.to_string(), false),
                            }
                        }
                        Some(Cmd::SendFile { name, data }) => {
                            // Each piece is an ordinary encrypted message, so a
                            // file gets exactly the protection everything else in
                            // the room gets, and the transport never learns it is
                            // carrying a file.
                            let total = data.len().div_ceil(message::CHUNK).max(1) as u32;
                            let id = next_transfer_id;
                            next_transfer_id = next_transfer_id.wrapping_add(1);
                            let mut failed = false;
                            for (i, part) in data.chunks(message::CHUNK).enumerate() {
                                let msg = message::encode_file_chunk(
                                    &nickname, id, i as u32, total, &name, part,
                                );
                                match session.encrypt(&msg) {
                                    Ok(frame) => {
                                        if send_frame(&mut writer, &frame).await.is_err() {
                                            failed = true;
                                            break;
                                        }
                                    }
                                    Err(_) => {
                                        failed = true;
                                        break;
                                    }
                                }
                                emit(app, UiEvent::FileProgress {
                                    name: name.clone(),
                                    sent: i as u32 + 1,
                                    total,
                                    outgoing: true,
                                });
                            }
                            if failed {
                                break 'session ("The other person disconnected.".to_string(), true);
                            }
                        }
                        Some(Cmd::End) => break 'session ("You ended the session.".to_string(), false),
                        None => break 'session ("Session closed.".to_string(), false),
                    }
                }

                // Idle reaper, in two stages. The first pass warns and the second
                // ends it, so silence never closes a chat without notice. Any
                // traffic resets both, because the whole select! restarts.
                _ = tokio::time::sleep(idle.saturating_sub(IDLE_WARNING)) , if !idle_warned => {
                    idle_warned = true;
                    emit(app, UiEvent::IdleWarning {
                        seconds_left: IDLE_WARNING.as_secs() as u32,
                        active: true,
                    });
                }
                _ = tokio::time::sleep(idle) => {
                    break 'session (
                        format!(
                            "Session ended after {} minutes of silence.",
                            idle.as_secs() / 60
                        ),
                        false,
                    );
                }
            }
        };

        // The reader is parked in `read_exact` and would outlive the session,
        // holding the read half of the connection open, until the peer happened to
        // disconnect.
        reader_task.abort();

        let (why, worth_retrying) = reason;
        if !worth_retrying {
            break 'connection why;
        }
        reconnects += 1;
        if reconnects > MAX_RECONNECTS {
            break 'connection why;
        }
        emit(app, UiEvent::Reconnecting);
        // `session` drops here; Drop zeroizes every key. The next pass derives
        // fresh ones from the secrets we still hold.
    };

    reason
}

#[tauri::command]
fn send(state: State<'_, AppState>, text: String) -> Result<(), String> {
    let guard = state.tx.lock().expect("state poisoned");
    let tx = guard.as_ref().ok_or("no session")?;
    tx.try_send(Cmd::Send(text))
        .map_err(|_| "session busy".to_string())
}

/// Send a file the user picked. `data` is base64, because that is what the
/// webview can hand across the IPC boundary.
#[tauri::command]
fn send_file(state: State<'_, AppState>, name: String, data: String) -> Result<(), String> {
    let bytes = B64.decode(&data).map_err(|_| "could not read that file")?;
    if bytes.is_empty() {
        return Err("that file is empty".into());
    }
    let guard = state.tx.lock().expect("state poisoned");
    let tx = guard.as_ref().ok_or("no session")?;
    tx.try_send(Cmd::SendFile { name, data: bytes })
        .map_err(|_| "session busy".to_string())
}

#[tauri::command]
fn end_session(state: State<'_, AppState>) {
    if let Some(tx) = state.tx.lock().expect("state poisoned").take() {
        let _ = tx.try_send(Cmd::End);
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // WebKitGTK's default DMABUF/compositing rendering path draws a blank white
    // window on a lot of Linux setups (common with Nvidia and under Wayland,
    // e.g. Fedora). Forcing it off costs a little GPU acceleration and fixes the
    // blank screen. Must be set before the webview initialises. `set_var` is
    // safe on edition 2021.
    // WebKitGTK's default DMABUF/compositing path renders a blank white window
    // on many Linux setups (Nvidia, some Wayland/Fedora configurations).
    //
    // Setting these from inside `main` is too late: WebKitGTK reads them when
    // its shared library is loaded, which happens before `main` runs. So the
    // process re-executes itself once with the variables present. The guard
    // variable makes this strictly one extra exec, never a loop.
    #[cfg(target_os = "linux")]
    {
        const GUARD: &str = "NARCO_WEBKIT_ENV_SET";
        if std::env::var_os(GUARD).is_none() {
            use std::os::unix::process::CommandExt;
            let exe = std::env::current_exe();
            if let Ok(exe) = exe {
                let err = std::process::Command::new(exe)
                    .args(std::env::args_os().skip(1))
                    .env(GUARD, "1")
                    .env("WEBKIT_DISABLE_DMABUF_RENDERER", "1")
                    .env("WEBKIT_DISABLE_COMPOSITING_MODE", "1")
                    .exec();
                // `exec` only returns on failure; carry on unreplaced rather
                // than refusing to start.
                eprintln!("[narco] could not re-exec with WebKit env: {err}");
            }
        }
    }

    // Capture our logs AND Arti's into the in-app Diagnostics panel. Without
    // this a failure is invisible in a release build, which has no console.
    // Tor's directory and guard managers are raised to debug because that is
    // where bootstrap actually stalls.
    // Includes the layers that actually move bytes — chanmgr (TCP/TLS to
    // relays), dirclient (the directory fetch itself), proto and netdir. A
    // narrower filter left the real failure invisible: a Windows report showed
    // "connecting successfully; directory is fetching a consensus" and then
    // silence, because the fetching layers were not being logged.
    let filter = tracing_subscriber::EnvFilter::new(
        "info,tor_dirmgr=debug,tor_guardmgr=debug,tor_circmgr=debug,arti_client=debug,\
         tor_chanmgr=debug,tor_dirclient=debug,tor_proto=debug,tor_netdir=debug,\
         tor_rtcompat=debug",
    );
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(LogWriterMaker)
        .with_ansi(false)
        .try_init();
    push_log(&format!(
        "[narco] narco {} starting on {}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS
    ));

    tauri::Builder::default()
        .manage(AppState::default())
        .setup(|app| {
            // Point the transport at the tor binary we bundle. Tauri's resource
            // directory differs by platform and packaging format, so the crate
            // cannot locate it on its own.
            if let Ok(dir) = app.path().resource_dir() {
                let tor_dir = dir.join("tor");
                push_log(&format!("[narco] bundled tor dir: {}", tor_dir.display()));
                std::env::set_var("NARCO_TOR_DIR", tor_dir);
            }

            // Where Tor may keep its own cache and state. Guessing this from
            // HOME works on desktop and fails on iOS, where the app bundle is
            // read-only and Tor's own default lands inside it — the 0.6.1 iOS
            // build could start Arti and then not write a byte. Tauri already
            // knows the right per-platform directory, so it says so rather than
            // leaving the transport to infer it.
            if let Ok(dir) = app.path().app_cache_dir() {
                let state = dir.join("tor");
                let _ = std::fs::create_dir_all(&state);
                push_log(&format!("[narco] tor state dir: {}", state.display()));
                std::env::set_var("NARCO_STATE_DIR", state);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            generate_code,
            check_code,
            get_logs,
            warm_tor,
            connect,
            send,
            send_file,
            end_session
        ])
        .run(tauri::generate_context!())
        .expect("error while running Narco");
}
