//! What a message looks like once it is decrypted.
//!
//! The encrypted frame carries bytes; this decides what those bytes mean. A
//! message is a kind, the sender's chosen name, and a payload — text, or one
//! piece of a file.
//!
//! Files have to be cut up: a single message holds at most 32 KiB of plaintext
//! (`narco_proto::frame::MAX_PLAINTEXT`), and a photo is comfortably larger
//! than that. Each piece travels as an ordinary encrypted message, so a file
//! gets exactly the same protection as anything else said in the room, and the
//! transport never learns it is carrying a file at all.

use narco_proto::frame::MAX_PLAINTEXT;

/// A text message.
pub const KIND_TEXT: u8 = 1;
/// One piece of a file.
pub const KIND_FILE: u8 = 2;

/// How much file data rides in one message.
///
/// Under the plaintext limit with room for the header, and a round number so a
/// transfer's piece count is easy to reason about when something goes wrong.
pub const CHUNK: usize = 30_000;

/// Names are bounded so a hostile peer cannot spend the whole message on one.
const MAX_NAME: usize = 64;
const MAX_FILENAME: usize = 255;

#[derive(Debug, PartialEq, Eq)]
pub enum Incoming {
    Text {
        from: String,
        text: String,
    },
    /// One piece of a file. `id` groups the pieces of a single transfer;
    /// pieces of different transfers can arrive interleaved.
    File {
        from: String,
        id: u64,
        index: u32,
        total: u32,
        name: String,
        data: Vec<u8>,
    },
}

fn put_str(out: &mut Vec<u8>, s: &str, max: usize) {
    // A name cannot be longer than its length prefix can describe, and is cut
    // on a character boundary so what arrives is still valid text.
    let mut s = s;
    while s.len() > max {
        s = &s[..s.char_indices().last().map(|(i, _)| i).unwrap_or(0)];
    }
    out.push(s.len() as u8);
    out.extend_from_slice(s.as_bytes());
}

pub fn encode_text(from: &str, text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + MAX_NAME + 2);
    out.push(KIND_TEXT);
    put_str(&mut out, from, MAX_NAME);
    out.extend_from_slice(text.as_bytes());
    out
}

pub fn encode_file_chunk(
    from: &str,
    id: u64,
    index: u32,
    total: u32,
    name: &str,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 320);
    out.push(KIND_FILE);
    put_str(&mut out, from, MAX_NAME);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(MAX_FILENAME);
    out.extend_from_slice(&(name_len as u16).to_be_bytes());
    out.extend_from_slice(&name_bytes[..name_len]);
    out.extend_from_slice(data);
    debug_assert!(
        out.len() <= MAX_PLAINTEXT,
        "a chunk must fit in one message"
    );
    out
}

/// Read a message, or `None` if it is malformed.
///
/// Every field is length-checked before it is read. The peer is authenticated,
/// but a bug on their side should still not be able to walk this off the end of
/// the buffer.
pub fn decode(raw: &[u8]) -> Option<Incoming> {
    let (&kind, rest) = raw.split_first()?;
    let (&name_len, rest) = rest.split_first()?;
    let name_len = name_len as usize;
    if rest.len() < name_len {
        return None;
    }
    let (from, rest) = rest.split_at(name_len);
    let from = String::from_utf8(from.to_vec()).ok()?;

    match kind {
        KIND_TEXT => Some(Incoming::Text {
            from,
            text: String::from_utf8(rest.to_vec()).ok()?,
        }),
        KIND_FILE => {
            if rest.len() < 18 {
                return None;
            }
            let id = u64::from_be_bytes(rest[0..8].try_into().ok()?);
            let index = u32::from_be_bytes(rest[8..12].try_into().ok()?);
            let total = u32::from_be_bytes(rest[12..16].try_into().ok()?);
            let fname_len = u16::from_be_bytes(rest[16..18].try_into().ok()?) as usize;
            let rest = &rest[18..];
            if rest.len() < fname_len {
                return None;
            }
            let (name, data) = rest.split_at(fname_len);
            // A transfer claiming more pieces than could ever be sent is a bug
            // or an attempt to make the receiver hold memory for nothing.
            if total == 0 || index >= total || total > 100_000 {
                return None;
            }
            Some(Incoming::File {
                from,
                id,
                index,
                total,
                name: String::from_utf8(name.to_vec()).ok()?,
                data: data.to_vec(),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trips() {
        let raw = encode_text("alice", "hello");
        assert_eq!(
            decode(&raw),
            Some(Incoming::Text {
                from: "alice".into(),
                text: "hello".into()
            })
        );
    }

    #[test]
    fn an_unnamed_sender_is_fine() {
        let raw = encode_text("", "anon");
        match decode(&raw).unwrap() {
            Incoming::Text { from, text } => {
                assert_eq!(from, "");
                assert_eq!(text, "anon");
            }
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[test]
    fn a_file_chunk_round_trips() {
        let data = vec![7u8; 1000];
        let raw = encode_file_chunk("bob", 42, 3, 10, "cat.jpg", &data);
        assert_eq!(
            decode(&raw),
            Some(Incoming::File {
                from: "bob".into(),
                id: 42,
                index: 3,
                total: 10,
                name: "cat.jpg".into(),
                data,
            })
        );
    }

    /// A full-size chunk plus its header must still fit in one message, or a
    /// transfer would fail only on large files.
    #[test]
    fn a_full_chunk_fits_in_one_message() {
        let raw = encode_file_chunk(
            &"n".repeat(64),
            1,
            0,
            1,
            &"f".repeat(255),
            &vec![0u8; CHUNK],
        );
        assert!(raw.len() <= MAX_PLAINTEXT, "{} bytes", raw.len());
    }

    #[test]
    fn truncated_input_is_refused_rather_than_panicking() {
        let raw = encode_file_chunk("bob", 1, 0, 2, "x.bin", &[1, 2, 3]);
        for cut in 0..raw.len() {
            // Must not panic at any truncation point.
            let _ = decode(&raw[..cut]);
        }
        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[KIND_FILE]), None);
    }

    #[test]
    fn a_nonsense_piece_count_is_refused() {
        let bad = encode_file_chunk("b", 1, 5, 5, "x", &[1]); // index == total
        assert_eq!(decode(&bad), None);
        let none = encode_file_chunk("b", 1, 0, 0, "x", &[1]);
        assert_eq!(decode(&none), None);
    }

    #[test]
    fn an_unknown_kind_is_refused() {
        assert_eq!(decode(&[99, 0]), None);
    }
}
