//! Length-prefixed framing and the candidate-racing handshake.
//!
//! [`TorTransport::meet_candidates`](crate::TorTransport::meet_candidates) can
//! hand back a connection to our *own* service. This module is what turns that
//! stream of maybes into one confirmed peer.

use crate::transport::{Meeting, Status, TorTransport};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use narco_proto::kdf::Derived;
use narco_proto::{Error as ProtoError, Event, Session};
use std::time::Duration;

/// Upper bound on a single frame. The largest legitimate frame is a 64 KiB
/// padding bucket plus AEAD and framing overhead.
pub const MAX_FRAME: usize = 128 * 1024;

/// Give up on a peer that never appears.
///
/// Deliberately far longer than a connection takes. A measured cold connect is
/// around 258 s, so the previous 300 s left a 42-second margin — meaning the
/// two people had to press start within about forty seconds of each other or
/// the first one gave up before the second was ready. Waiting costs nothing;
/// the user can cancel whenever they like.
const MEET_TIMEOUT: Duration = Duration::from_secs(1800);

/// Give up on a candidate that stalls mid-handshake.
///
/// The handshake is two round trips over an already-established circuit, so a
/// live peer answers in seconds. A candidate still silent after this is our own
/// service, and no longer blocks anything now that candidates run concurrently.
const CANDIDATE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum ConnectError {
    Tor(crate::TorError),
    Protocol(ProtoError),
    Io(std::io::Error),
    /// No peer completed a handshake before the timeout.
    TimedOut,
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Tor(e) => write!(f, "{e}"),
            ConnectError::Protocol(e) => write!(f, "{e}"),
            ConnectError::Io(e) => write!(f, "connection lost: {e}"),
            ConnectError::TimedOut => write!(f, "the other person never arrived"),
        }
    }
}

impl std::error::Error for ConnectError {}

impl From<crate::TorError> for ConnectError {
    fn from(e: crate::TorError) -> Self {
        ConnectError::Tor(e)
    }
}
impl From<ProtoError> for ConnectError {
    fn from(e: ProtoError) -> Self {
        ConnectError::Protocol(e)
    }
}
impl From<std::io::Error> for ConnectError {
    fn from(e: std::io::Error) -> Self {
        ConnectError::Io(e)
    }
}

pub async fn send_frame<S: AsyncWriteExt + Unpin>(s: &mut S, f: &[u8]) -> std::io::Result<()> {
    s.write_all(&(f.len() as u32).to_be_bytes()).await?;
    s.write_all(f).await?;
    s.flush().await
}

pub async fn recv_frame<S: AsyncReadExt + Unpin>(s: &mut S) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame exceeds maximum size",
        ));
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Run the SPAKE2 handshake over one candidate connection.
///
/// Returns `Ok(None)` when the candidate is not a real peer — our own service,
/// or someone who does not know the secrets. Neither is fatal; the caller simply
/// moves to the next candidate.
async fn try_candidate<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    derived: &Derived,
) -> Result<Option<Session>, ConnectError> {
    let mut session = Session::from_derived(derived);
    send_frame(stream, &session.pake_frame()).await?;

    loop {
        let frame = match recv_frame(stream).await {
            Ok(f) => f,
            // A dead or hung-up candidate is not a failure of the whole attempt.
            Err(_) => return Ok(None),
        };
        match session.handle(&frame) {
            Ok(Event::Send(out)) => send_frame(stream, &out).await?,
            Ok(Event::Ready) => return Ok(Some(session)),
            Ok(Event::Message(_)) => return Ok(None), // Impossible before Ready.
            // `Reflection` means we connected to ourselves; `ConfirmMismatch`
            // means the far side does not know the secrets. Both are expected
            // and are simply skipped.
            Err(ProtoError::Reflection) | Err(ProtoError::ConfirmMismatch) => return Ok(None),
            Err(e) => return Err(e.into()),
        }
    }
}

/// A confirmed, encrypted connection to exactly one other person.
pub struct Connected<S> {
    pub session: Session,
    pub stream: S,
}

/// Meet the peer over Tor and return a confirmed encrypted session.
///
/// Races every candidate connection until one completes the handshake, then
/// **unpublishes the onion address** so nobody else can join.
pub async fn connect(
    transport: &TorTransport,
    derived: &Derived,
    on_status: impl Fn(Status),
) -> Result<Connected<arti_client::DataStream>, ConnectError> {
    let Meeting {
        service,
        mut candidates,
    } = transport.meet_candidates(derived, &on_status).await?;

    let deadline = tokio::time::Instant::now() + MEET_TIMEOUT;

    // Candidates are handshaken *concurrently*, not one after another.
    //
    // Connecting to our own service is normal here — it is how the shared
    // address works — and such a candidate never completes a handshake, so it
    // simply hangs until its timeout. Trying candidates sequentially let a few
    // of those queue ahead of the peer's real connection and consume the whole
    // budget before it was ever attempted, which looked exactly like "the other
    // person never arrived".
    let mut running = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            // A new candidate arrived: start its handshake alongside the others.
            next = tokio::time::timeout_at(deadline, candidates.recv()) => {
                match next {
                    Ok(Some(mut stream)) => {
                        let derived = derived.clone();
                        running.spawn(async move {
                            let out = tokio::time::timeout(
                                CANDIDATE_TIMEOUT,
                                try_candidate(&mut stream, &derived),
                            )
                            .await;
                            match out {
                                Ok(Ok(Some(session))) => Some((session, stream)),
                                _ => None,
                            }
                        });
                    }
                    // Channel closed, or the overall deadline passed.
                    _ => return Err(ConnectError::TimedOut),
                }
            }

            // One of the in-flight handshakes finished.
            Some(done) = running.join_next(), if !running.is_empty() => {
                if let Ok(Some((session, stream))) = done {
                    on_status(Status::PeerFound);
                    // Both people are in. Take the door away: dropping the
                    // service unpublishes the address, so nobody else can join.
                    drop(service);
                    drop(candidates);
                    running.abort_all();
                    return Ok(Connected { session, stream });
                }
                // Not a real peer. The others keep going.
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two ends of an in-memory duplex, so the handshake can be exercised
    /// without touching Tor.
    fn duplex() -> (futures::io::Cursor<Vec<u8>>, futures::io::Cursor<Vec<u8>>) {
        (
            futures::io::Cursor::new(Vec::new()),
            futures::io::Cursor::new(Vec::new()),
        )
    }

    #[test]
    fn frame_roundtrip_and_oversize_rejection() {
        futures::executor::block_on(async {
            let (mut a, _) = duplex();
            send_frame(&mut a, b"hello").await.unwrap();
            a.set_position(0);
            assert_eq!(recv_frame(&mut a).await.unwrap(), b"hello");

            // A length header larger than MAX_FRAME must be refused outright,
            // not used to allocate.
            let mut evil = futures::io::Cursor::new((u32::MAX).to_be_bytes().to_vec());
            assert!(recv_frame(&mut evil).await.is_err());
        });
    }

    #[test]
    fn empty_frame_roundtrips() {
        futures::executor::block_on(async {
            let (mut a, _) = duplex();
            send_frame(&mut a, b"").await.unwrap();
            a.set_position(0);
            assert_eq!(recv_frame(&mut a).await.unwrap(), b"");
        });
    }
}
