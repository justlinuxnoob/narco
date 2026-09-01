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

fn emit(app: &AppHandle, e: UiEvent) {
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
            run_session(&app, derived, rx, idle_secs, tor),
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
    let connected = narco_tor::connect(transport.as_ref(), &derived, move |s| {
        emit_status(&app_status, s);
    })
    .await;

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
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            generate_code,
            check_code,
            warm_tor,
            connect,
            send,
            end_session
        ])
        .run(tauri::generate_context!())
        .expect("error while running Narco");
}
