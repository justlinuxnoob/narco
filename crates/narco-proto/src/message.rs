//! What a message looks like once it is decrypted.
//!
//! Lives here rather than in the app because it is protocol, not interface:
//! pure byte handling with a decoder that has to survive whatever a peer
//! sends. In the app crate its tests could only run on a machine with the
//! whole desktop toolchain installed, which is a lot of apparatus for parsing
//! a header.
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

use crate::frame::MAX_PLAINTEXT;

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

/// The most pieces one transfer may be cut into, and so the largest file that
/// can cross: `MAX_CHUNKS * CHUNK`, a little over 61 MB.
///
/// This is a memory bound, not a preference. The receiver allocates room for
/// every piece the sender claims is coming, and the previous ceiling of 100,000
/// let a 285-byte message on the wire reserve 2.4 MB — an amplification of
/// roughly 8,000× that a peer could repeat with a fresh transfer id until the
/// process was killed. A killed process does not run the destructors that wipe
/// the session keys, so this was also the one way to end a session with the keys
/// left in memory.
pub const MAX_CHUNKS: u32 = 2048;

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

/// Cut a string to at most `max` bytes without splitting a character.
fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn put_str(out: &mut Vec<u8>, s: &str, max: usize) {
    let s = truncate(s, max);
    out.push(s.len() as u8);
    out.extend_from_slice(s.as_bytes());
}

/// Characters that let a name lie about what it is.
///
/// A right-to-left override reverses everything after it when displayed, so
/// `holiday\u{202E}gnp.exe` reads as `holidayexe.png` on screen while the file
/// it saves is still an executable. Control characters can blank or overwrite
/// parts of a line the same way.
fn is_deceptive(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{200E}' | '\u{200F}' | '\u{061C}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}')
}

/// Make a peer's filename safe to show and to hand to a save dialog.
///
/// The name is chosen entirely by the other side. It reaches a download
/// attribute and an on-screen label, so it must not contain path separators,
/// must not be able to misrepresent its own extension, and must not be able to
/// name a parent directory.
pub fn sanitize_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' => '_',
            c if is_deceptive(c) => '_',
            c => c,
        })
        .collect();

    // A leading dot hides the file on Unix; a name that is only dots is `..`.
    let cleaned = cleaned.trim();
    let cleaned = cleaned.trim_start_matches('.').trim();
    let cleaned = truncate(cleaned, MAX_FILENAME);

    if cleaned.is_empty() {
        "file".to_string()
    } else {
        cleaned.to_string()
    }
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
    // Cut on a character boundary. Slicing at a raw byte count split multi-byte
    // characters, and the receiver rejects invalid UTF-8 by treating the whole
    // message as malformed — which ends the conversation. Attaching a photo
    // whose name ran past 255 bytes in any non-Latin script therefore killed
    // your own session on the first chunk, and told the other person you had
    // sent them something broken.
    let name = truncate(name, MAX_FILENAME);
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(name.as_bytes());
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
    // The limits were enforced only where we build a message, which bounds
    // nothing: the peer builds theirs. A `from` of 255 bytes was accepted and
    // rendered verbatim in a pre-wrap list, so a "name" could be several lines
    // long and carry the same display-reversing characters a filename can.
    if name_len > MAX_NAME || rest.len() < name_len {
        return None;
    }
    let (from, rest) = rest.split_at(name_len);
    let from: String = String::from_utf8(from.to_vec())
        .ok()?
        .chars()
        .filter(|c| !is_deceptive(*c))
        .collect();

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
            if fname_len > MAX_FILENAME {
                return None;
            }
            let (name, data) = rest.split_at(fname_len);
            // A transfer claiming more pieces than could ever be sent is a bug
            // or an attempt to make the receiver hold memory for nothing.
            if total == 0 || index >= total || total > MAX_CHUNKS {
                return None;
            }
            // We never send more than `CHUNK` in a piece, so nobody honest ever
            // sends more. Without this the ceiling was the whole plaintext
            // limit, and a transfer could claim a size no real file has.
            if data.len() > CHUNK {
                return None;
            }
            Some(Incoming::File {
                from,
                id,
                index,
                total,
                name: sanitize_filename(&String::from_utf8(name.to_vec()).ok()?),
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

    /// Build a file chunk field by field, so a test can claim things the
    /// encoder would never claim.
    fn raw_chunk(
        from: &[u8],
        id: u64,
        index: u32,
        total: u32,
        name: &[u8],
        data: &[u8],
    ) -> Vec<u8> {
        let mut v = vec![KIND_FILE, from.len() as u8];
        v.extend_from_slice(from);
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&index.to_be_bytes());
        v.extend_from_slice(&total.to_be_bytes());
        v.extend_from_slice(&(name.len() as u16).to_be_bytes());
        v.extend_from_slice(name);
        v.extend_from_slice(data);
        v
    }

    /// The receiver reserves room for every piece a sender says is coming, so
    /// `total` is an allocation the peer gets to choose. At the old ceiling of
    /// 100,000 a 20-byte message reserved 2.4 MB, and repeating it with a fresh
    /// transfer id walked the process into the out-of-memory killer — which
    /// does not run the destructors that wipe the session keys.
    #[test]
    fn an_absurd_piece_count_is_refused() {
        assert!(decode(&raw_chunk(b"", 1, 0, MAX_CHUNKS, b"a", b"x")).is_some());
        assert_eq!(
            decode(&raw_chunk(b"", 1, 0, MAX_CHUNKS + 1, b"a", b"x")),
            None
        );
        assert_eq!(decode(&raw_chunk(b"", 1, 0, 100_000, b"a", b"x")), None);
    }

    #[test]
    fn a_piece_larger_than_chunk_is_refused() {
        let ok = vec![7u8; CHUNK];
        assert!(decode(&raw_chunk(b"", 1, 0, 2, b"a", &ok)).is_some());
        let too_big = vec![7u8; CHUNK + 1];
        assert_eq!(decode(&raw_chunk(b"", 1, 0, 2, b"a", &too_big)), None);
    }

    #[test]
    fn oversized_names_are_refused_on_the_way_in() {
        // Both limits were enforced only by the encoder, which bounds nothing:
        // the peer runs their own.
        let long_from = vec![b'a'; MAX_NAME + 1];
        assert_eq!(decode(&raw_chunk(&long_from, 1, 0, 2, b"a", b"x")), None);
        let long_name = vec![b'a'; MAX_FILENAME + 1];
        assert_eq!(decode(&raw_chunk(b"", 1, 0, 2, &long_name, b"x")), None);
    }

    #[test]
    fn a_filename_cannot_lie_about_its_extension() {
        // Reads as `holidayexe.png` on screen; saves as a `.exe`.
        let got = sanitize_filename("holiday\u{202E}gnp.exe");
        assert!(!got.contains('\u{202E}'), "bidi override survived: {got:?}");
        assert!(
            got.ends_with(".exe"),
            "the real extension should stay visible"
        );
    }

    #[test]
    fn a_filename_cannot_escape_its_directory() {
        assert_eq!(
            sanitize_filename("../../.ssh/authorized_keys"),
            "_.._.ssh_authorized_keys"
        );
        assert_eq!(
            sanitize_filename("..\\..\\Startup\\a.exe"),
            "_.._Startup_a.exe"
        );
        assert_eq!(sanitize_filename("..."), "file");
        assert_eq!(sanitize_filename(""), "file");
        assert_eq!(sanitize_filename("  .hidden  "), "hidden");
        assert_eq!(sanitize_filename("a\0b\nc.png"), "a_b_c.png");
    }

    /// The encoder cut the filename at a byte count. Splitting a character
    /// there produces invalid UTF-8, the receiver treats a message it cannot
    /// decode as fatal, and the sender's own conversation ends — with the peer
    /// told they sent something malformed. It depended on the script the name
    /// was written in, so it never showed up in testing.
    #[test]
    fn a_long_name_in_any_script_still_round_trips() {
        for name in [
            "e".repeat(300),
            "😀".repeat(80),     // 4 bytes each
            "日本語".repeat(90), // 3 bytes each
            "ñ".repeat(200),     // 2 bytes each
        ] {
            let raw = encode_file_chunk("", 1, 0, 2, &name, b"x");
            let got = decode(&raw);
            assert!(got.is_some(), "a {} byte name did not survive", name.len());
            match got.unwrap() {
                Incoming::File { name, .. } => assert!(!name.is_empty()),
                other => panic!("expected a file, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_sender_name_cannot_rewrite_the_line_it_is_on() {
        let raw = raw_chunk("a\u{202E}b".as_bytes(), 1, 0, 2, b"x.png", b"x");
        match decode(&raw).expect("should decode") {
            Incoming::File { from, .. } => assert_eq!(from, "ab"),
            other => panic!("expected a file, got {other:?}"),
        }
    }
}
