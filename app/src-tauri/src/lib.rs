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
use std::sync::Mutex;
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
}

#[derive(Default)]
struct AppState {
    /// `Some` while a session is running.
    tx: Mutex<Option<mpsc::Sender<Cmd>>>,
}

fn emit(app: &AppHandle, e: UiEvent) {
    let _ = app.emit("narco", e);
}

/// Human text plus the stage id the UI checklist keys off.
fn status_parts(s: Status) -> (&'static str, &'static str) {
    match s {
        Status::BootstrappingTor => ("Joining the Tor network…", "tor"),
        Status::PublishingService => ("Publishing your address…", "publish"),
        Status::WaitingForPeer => ("Waiting for the other person…", "peer"),
        Status::Retrying { .. } => ("Still waiting…", "peer"),
        Status::PeerFound => ("Found them. Verifying it's really them…", "verify"),
    }
}

fn emit_status(app: &AppHandle, s: Status) {
    let (text, stage) = status_parts(s);
    emit(
        app,
        UiEvent::Status {
            text: text.into(),
            stage: stage.into(),
        },
    );
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

    tauri::async_runtime::spawn(async move {
        // Catch panics so a bug can never leave the UI waiting forever with no
        // explanation. Every path out of here emits an Ended event.
        let reason = match futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(
            run_session(&app, derived, rx, idle_secs),
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
) -> String {
    // 0 means the user chose "never". Represent it as an effectively unreachable
    // deadline rather than branching the select! arm.
    let idle = if idle_secs == 0 {
        Duration::from_secs(u32::MAX as u64)
    } else {
        Duration::from_secs(idle_secs)
    };
    let app_status = app.clone();
    let transport = match TorTransport::bootstrap(move |s| {
        emit_status(&app_status, s);
    })
    .await
    {
        Ok(t) => t,
        Err(e) => return e.to_string(),
    };

    let app_status = app.clone();
    let connected = narco_tor::connect(&transport, &derived, move |s| {
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
            connect,
            send,
            end_session
        ])
        .run(tauri::generate_context!())
        .expect("error while running Narco");
}
