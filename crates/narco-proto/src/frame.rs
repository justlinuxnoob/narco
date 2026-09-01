//! Peer-to-peer framing and length padding.
//!
//! These bytes are opaque to the relay. See PROTOCOL.md §5.4 and §6.1.

use crate::error::{Error, Result};

pub const KIND_PAKE: u8 = 0x01;
pub const KIND_CONFIRM: u8 = 0x02;
pub const KIND_MSG: u8 = 0x03;

/// Length of a SPAKE2 (Ed25519 group) handshake message.
pub const PAKE_LEN: usize = 33;
/// Length of a key-confirmation tag.
pub const CONFIRM_LEN: usize = 32;

/// Largest plaintext a single message may carry.
pub const MAX_PLAINTEXT: usize = 32 * 1024;

/// Padded sizes. Ciphertext length therefore reveals only which bucket a
/// message fell into, not its true length.
pub const BUCKETS: [usize; 5] = [256, 1024, 4096, 16384, 65536];

/// A parsed peer-to-peer frame, borrowing from the input buffer.
#[derive(Debug)]
pub enum Frame<'a> {
    Pake(&'a [u8]),
    Confirm(&'a [u8]),
    Msg { ctr: u64, ct: &'a [u8] },
}

pub fn pake_frame(msg: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + msg.len());
    v.push(KIND_PAKE);
    v.extend_from_slice(msg);
    v
}

pub fn confirm_frame(tag: &[u8; CONFIRM_LEN]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + CONFIRM_LEN);
    v.push(KIND_CONFIRM);
    v.extend_from_slice(tag);
    v
}

pub fn msg_frame(ctr: u64, ct: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(9 + ct.len());
    v.push(KIND_MSG);
    v.extend_from_slice(&ctr.to_be_bytes());
    v.extend_from_slice(ct);
    v
}

/// Parse a frame, enforcing exact lengths for the fixed-size kinds.
pub fn parse(b: &[u8]) -> Result<Frame<'_>> {
    let (&kind, rest) = b.split_first().ok_or(Error::BadFrame)?;
    match kind {
        KIND_PAKE if rest.len() == PAKE_LEN => Ok(Frame::Pake(rest)),
        KIND_CONFIRM if rest.len() == CONFIRM_LEN => Ok(Frame::Confirm(rest)),
        KIND_MSG if rest.len() > 8 => {
            let (ctr_bytes, ct) = rest.split_at(8);
            let ctr = u64::from_be_bytes(ctr_bytes.try_into().expect("split_at(8)"));
            Ok(Frame::Msg { ctr, ct })
        }
        KIND_PAKE | KIND_CONFIRM | KIND_MSG => Err(Error::BadFrame),
        other => Err(Error::UnknownKind(other)),
    }
}

/// Prefix with a big-endian length, then zero-fill to the next bucket.
pub fn pad(pt: &[u8]) -> Result<Vec<u8>> {
    if pt.len() > MAX_PLAINTEXT {
        return Err(Error::TooLong);
    }
    let inner = 4 + pt.len();
    let target = BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= inner)
        .ok_or(Error::TooLong)?;

    let mut out = vec![0u8; target];
    out[..4].copy_from_slice(&(pt.len() as u32).to_be_bytes());
    out[4..inner].copy_from_slice(pt);
    Ok(out)
}

/// Reverse [`pad`], rejecting anything that a faithful `pad` could not produce.
///
/// Verifying the bucket size and the zero tail removes a malleability channel:
/// without those checks an attacker could vary the padding of a message they
/// cannot decrypt and still have it accepted.
pub fn unpad(p: &[u8]) -> Result<Vec<u8>> {
    if !BUCKETS.contains(&p.len()) {
        return Err(Error::Padding);
    }
    let len = u32::from_be_bytes(p[..4].try_into().expect("bucket >= 256")) as usize;
    if len > MAX_PLAINTEXT {
        return Err(Error::Padding);
    }
    let end = 4 + len;
    if end > p.len() {
        return Err(Error::Padding);
    }
    if p[end..].iter().any(|&b| b != 0) {
        return Err(Error::Padding);
    }
    Ok(p[4..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_round_trips_across_buckets() {
        for len in [0usize, 1, 251, 252, 253, 1019, 1020, 4000, 16000, 32768] {
            let pt = vec![0xABu8; len];
            let padded = pad(&pt).unwrap();
            assert!(BUCKETS.contains(&padded.len()), "len {len} → {}", padded.len());
            assert_eq!(unpad(&padded).unwrap(), pt, "round trip failed at {len}");
        }
    }

    #[test]
    fn pad_hides_length_within_a_bucket() {
        assert_eq!(pad(b"hi").unwrap().len(), pad(&[0u8; 200]).unwrap().len());
    }

    #[test]
    fn pad_rejects_oversize() {
        assert_eq!(pad(&vec![0u8; MAX_PLAINTEXT + 1]).unwrap_err(), Error::TooLong);
    }

    #[test]
    fn unpad_rejects_nonzero_tail() {
        let mut padded = pad(b"hello").unwrap();
        let last = padded.len() - 1;
        padded[last] = 1;
        assert_eq!(unpad(&padded).unwrap_err(), Error::Padding);
    }

    #[test]
    fn unpad_rejects_non_bucket_length() {
        assert_eq!(unpad(&[0u8; 100]).unwrap_err(), Error::Padding);
        assert_eq!(unpad(&[]).unwrap_err(), Error::Padding);
    }

    #[test]
    fn unpad_rejects_length_overrunning_the_buffer() {
        let mut padded = pad(b"hello").unwrap();
        padded[..4].copy_from_slice(&9999u32.to_be_bytes());
        assert_eq!(unpad(&padded).unwrap_err(), Error::Padding);
    }

    #[test]
    fn frames_round_trip() {
        match parse(&pake_frame(&[7u8; PAKE_LEN])).unwrap() {
            Frame::Pake(m) => assert_eq!(m, &[7u8; PAKE_LEN]),
            other => panic!("expected Pake, got {other:?}"),
        }
        match parse(&confirm_frame(&[9u8; CONFIRM_LEN])).unwrap() {
            Frame::Confirm(t) => assert_eq!(t, &[9u8; CONFIRM_LEN]),
            other => panic!("expected Confirm, got {other:?}"),
        }
        match parse(&msg_frame(42, b"ct")).unwrap() {
            Frame::Msg { ctr, ct } => {
                assert_eq!(ctr, 42);
                assert_eq!(ct, b"ct");
            }
            other => panic!("expected Msg, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_malformed_input() {
        assert_eq!(parse(&[]).unwrap_err(), Error::BadFrame);
        assert_eq!(parse(&[KIND_PAKE, 1, 2]).unwrap_err(), Error::BadFrame);
        assert_eq!(parse(&[KIND_CONFIRM]).unwrap_err(), Error::BadFrame);
        // KIND_MSG with a counter but no ciphertext.
        assert_eq!(parse(&[KIND_MSG, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap_err(), Error::BadFrame);
        assert_eq!(parse(&[0xFF, 1]).unwrap_err(), Error::UnknownKind(0xFF));
    }
}
