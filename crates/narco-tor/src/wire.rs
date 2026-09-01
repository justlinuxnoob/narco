//! Length-prefixed framing and the peer handshake.
//!
//! [`run_handshake`] takes one established connection and runs the SPAKE2
//! handshake over it. It is used identically by the host (over an accepted
//! connection) and the joiner (over a dialled one).

use futures::io::{AsyncReadExt, AsyncWriteExt};
use narco_proto::kdf::Derived;
use narco_proto::{Error as ProtoError, Event, Session};

/// Upper bound on a single frame. The largest legitimate frame is a 64 KiB
/// padding bucket plus AEAD and framing overhead.
pub const MAX_FRAME: usize = 128 * 1024;

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

/// A confirmed, encrypted connection to exactly one other person.
pub struct Connected<S> {
    pub session: Session,
    pub stream: S,
}

/// Run the SPAKE2 handshake over a single connection and return the confirmed
/// session, or an error saying why it failed.
///
/// This is the whole security handshake, shared by both the host and the
/// joiner. It is symmetric — it does not care which side published the onion
/// service — so both ends run exactly this.
///
/// Errors the caller should treat as "this particular connection is not our
/// peer" (a stray connector, or someone who typed a different code):
/// [`ConnectError::Protocol`] wrapping [`ProtoError::ConfirmMismatch`] or
/// [`ProtoError::Reflection`]. An [`ConnectError::Io`] means the connection
/// dropped mid-handshake.
pub async fn run_handshake<S>(
    mut stream: S,
    derived: &Derived,
) -> Result<Connected<S>, ConnectError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut session = Session::from_derived(derived);
    send_frame(&mut stream, &session.pake_frame()).await?;

    loop {
        let frame = recv_frame(&mut stream).await?;
        match session.handle(&frame) {
            Ok(Event::Send(out)) => send_frame(&mut stream, &out).await?,
            Ok(Event::Ready) => return Ok(Connected { session, stream }),
            // A message before Ready is impossible in a well-behaved peer.
            Ok(Event::Message(_)) => return Err(ConnectError::Protocol(ProtoError::WrongPhase)),
            Err(e) => return Err(ConnectError::Protocol(e)),
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
