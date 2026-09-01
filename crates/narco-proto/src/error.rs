use core::fmt;

/// Every way a Narco session can fail.
///
/// Variants deliberately carry no plaintext, key material, or room code, so an
/// `Error` is always safe to surface to the UI or to a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Code is shorter than [`crate::code::MIN_CODE_LEN`] after trimming.
    CodeTooShort,
    /// Code has fewer than [`crate::code::MIN_DISTINCT`] distinct characters.
    CodeTooRepetitive,
    /// Code is a monotonic run such as `0123456789`.
    CodeSequential,
    /// Code matched the built-in weak list.
    CodeWeak,

    /// Argon2id failed. Only reachable on allocation failure.
    Kdf,

    /// Frame was truncated, empty, or the wrong length for its kind.
    BadFrame,
    /// Frame kind byte is not one of the three defined kinds.
    UnknownKind(u8),

    /// The peer's handshake message was byte-identical to ours: the relay
    /// reflected our own message back at us.
    Reflection,
    /// Key confirmation did not match. In practice: the two sides typed
    /// different codes, or the relay tampered with the handshake.
    ConfirmMismatch,

    /// Message counter was not the expected next value. Over an ordered
    /// transport this means replay or reordering, never packet loss.
    OutOfOrder { expected: u64, got: u64 },
    /// AEAD authentication failed.
    Decrypt,
    /// Padding was malformed or its trailing bytes were not zero.
    Padding,
    /// Plaintext exceeded [`crate::frame::MAX_PLAINTEXT`].
    TooLong,

    /// Operation is not valid in the session's current phase.
    WrongPhase,
    /// Session was aborted or wiped and cannot be reused.
    Dead,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            CodeTooShort => write!(
                f,
                "code must be at least {} characters",
                crate::code::MIN_CODE_LEN
            ),
            CodeTooRepetitive => write!(
                f,
                "code must use at least {} different characters",
                crate::code::MIN_DISTINCT
            ),
            CodeSequential => write!(f, "code must not be a simple sequence"),
            CodeWeak => write!(f, "code is too common to be secret"),
            Kdf => write!(f, "key derivation failed"),
            BadFrame => write!(f, "malformed frame"),
            UnknownKind(k) => write!(f, "unknown frame kind {k}"),
            Reflection => write!(f, "handshake reflected: the relay is misbehaving"),
            ConfirmMismatch => write!(f, "handshake failed: codes do not match"),
            OutOfOrder { expected, got } => {
                write!(f, "out-of-order message (expected {expected}, got {got})")
            }
            Decrypt => write!(f, "message failed authentication"),
            Padding => write!(f, "malformed padding"),
            TooLong => write!(f, "message too long"),
            WrongPhase => write!(f, "operation not valid in this phase"),
            Dead => write!(f, "session has ended"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
