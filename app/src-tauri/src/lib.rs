//! Narco desktop app.
//!
//! Everything security-relevant lives in `narco-proto` and `narco-tor`. This
//! layer only owns the session task and shuttles plaintext between it and the
//! webview. Plaintext exists in exactly two places — the running session task
//! and the on-screen message list — and both are destroyed together.

use narco_proto::{Error as ProtoError, Event};
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
    /// A decrypted message from the peer.
    Message { text: String },
    /// Session over. `reason` is shown to the user.
    Ended { reason: String },
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
        UiEvent::Ready => Some("[narco] handshake confirmed — chat live".to_string()),
        UiEvent::Ended { reason } => Some(format!("[narco] ended: {reason}")),
        UiEvent::TorProgress {
            text,
            ready,
            failed,
        } => Some(format!(
            "[narco] tor: {text} (ready={ready} failed={failed})"
        )),
        UiEvent::Message { .. } => None, // never log message events
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
        Status::BootstrappingTor { percent } => {
            (format!("Joining the Tor network… {percent}%"), "tor")
        }
        Status::TorBlocked { detail } => (
            format!("Tor seems blocked on this network ({detail}). Still trying…"),
            "tor",
        ),
        Status::PublishingService => ("Publishing your address…".into(), "publish"),
        Status::WaitingForPeer => ("Waiting for the other person…".into(), "peer"),
        Status::Retrying { .. } => ("Still waiting…".into(), "peer"),
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
) -> Result<(), String> {
    // Validate before doing anything slow.
    let derived = narco_proto::derive_multi(&secrets).map_err(|e| e.to_string())?;

    let (tx, rx) = mpsc::channel::<Cmd>(16);
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
            run_session(&app, derived, rx, idle_secs, tor, host),
        ))
        .await
        {
            Ok(reason) => reason,
            Err(_) => "Something went wrong inside the app. The session was ended \
                       and all keys destroyed."
                .to_string(),
        };
        // Whatever happened, the session is over and holds nothing.
        if let Some(state) = app.try_state::<AppState>() {
            *state.tx.lock().expect("state poisoned") = None;
        }
        emit(&app, UiEvent::Ended { reason });
    });

    Ok(())
}

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

    let app_status = app.clone();
    let cb = move |s| emit_status(&app_status, s);
    // The starter hosts the onion service; the joiner only dials it. One side
    // publishing and the other dialling is what makes a device never connect to
    // itself.
    let connected = if host {
        transport.host(&derived, cb).await
    } else {
        transport.join(&derived, cb).await
    };

    let Connected {
        mut session,
        stream,
    } = match connected {
        Ok(c) => c,
        Err(e) => return e.to_string(),
    };

    emit(app, UiEvent::Ready);

    let (mut reader, mut writer) = futures::AsyncReadExt::split(stream);

    loop {
        tokio::select! {
            // Peer traffic.
            frame = recv_frame(&mut reader) => {
                let Ok(frame) = frame else {
                    return "The other person disconnected.".into();
                };
                match session.handle(&frame) {
                    Ok(Event::Message(m)) => match String::from_utf8(m) {
                        Ok(text) => emit(app, UiEvent::Message { text }),
                        Err(_) => return "Received a malformed message.".into(),
                    },
                    Ok(_) => return "Unexpected handshake frame.".into(),
                    // Any protocol error is terminal by design.
                    Err(ProtoError::Decrypt) | Err(ProtoError::OutOfOrder { .. }) => {
                        return "Message failed verification — session ended for safety.".into()
                    }
                    Err(e) => return e.to_string(),
                }
            }

            // UI commands.
            cmd = rx.recv() => {
                match cmd {
                    Some(Cmd::Send(text)) => {
                        match session.encrypt(text.as_bytes()) {
                            Ok(frame) => {
                                if send_frame(&mut writer, &frame).await.is_err() {
                                    return "The other person disconnected.".into();
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
                            Err(e) => return e.to_string(),
                        }
                    }
                    Some(Cmd::End) => return "You ended the session.".into(),
                    None => return "Session closed.".into(),
                }
            }

            // Idle reaper.
            _ = tokio::time::sleep(idle) => {
                return format!(
                    "Session ended after {} minutes of silence.",
                    idle.as_secs() / 60
                );
            }
        }
    }
    // `session` drops here; Drop zeroizes every key.
}

#[tauri::command]
fn send(state: State<'_, AppState>, text: String) -> Result<(), String> {
    let guard = state.tx.lock().expect("state poisoned");
    let tx = guard.as_ref().ok_or("no session")?;
    tx.try_send(Cmd::Send(text))
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
        .invoke_handler(tauri::generate_handler![
            generate_code,
            check_code,
            get_logs,
            warm_tor,
            connect,
            send,
            end_session
        ])
        .run(tauri::generate_context!())
        .expect("error while running Narco");
}
