//! Room code generation, normalization, and validation.
//!
//! See PROTOCOL.md §1.

use crate::error::{Error, Result};
use unicode_normalization::UnicodeNormalization;

/// Minimum length for a hand-typed code, per PROTOCOL.md §1.2.
pub const MIN_CODE_LEN: usize = 10;

/// Minimum number of distinct characters. Rejects `aaaaaaaaaa`.
pub const MIN_DISTINCT: usize = 6;

/// Ambiguity-free alphabet: A–Z without `I`/`O`, plus `2`–`9`.
///
/// Exactly 32 characters, which matters: 256 is a multiple of 32, so mapping a
/// uniform random byte with `& 31` is itself uniform. No rejection sampling and
/// no modulo bias.
pub const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Length of a generated code: 26 × 5 bits = 130 bits of entropy.
pub const GENERATED_LEN: usize = 26;

/// Codes so common they are worthless as secrets, despite passing the
/// structural checks. Compared after normalization, case-insensitively.
const WEAK_LIST: &[&str] = &[
    "password12",
    "password123",
    "1234567890",
    "0123456789",
    "qwertyuiop",
    "abcdefghij",
    "letmeinnow",
    "narcotest1",
    "testtest12",
    "aaaaaaaaaa",
    "1111111111",
    "changeme12",
    "secretcode",
];

/// Generate a fresh 130-bit code from the OS CSPRNG.
pub fn generate() -> String {
    let mut buf = [0u8; GENERATED_LEN];
    getrandom::fill(&mut buf).expect("OS CSPRNG unavailable");
    let s: String = buf
        .iter()
        .map(|b| ALPHABET[(b & 31) as usize] as char)
        .collect();
    // The raw entropy is no longer needed; the string is the only live copy.
    zeroize::Zeroize::zeroize(&mut buf);
    s
}

/// Trim surrounding whitespace and apply NFC so both devices agree on bytes.
///
/// Case is deliberately preserved: folding it would throw away entropy from
/// hand-typed codes.
pub fn normalize(code: &str) -> String {
    code.trim().nfc().collect()
}

/// Validate a normalized code against PROTOCOL.md §1.2.
pub fn validate(code: &str) -> Result<()> {
    let chars: Vec<char> = code.chars().collect();

    if chars.len() < MIN_CODE_LEN {
        return Err(Error::CodeTooShort);
    }

    let mut distinct: Vec<char> = chars.clone();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() < MIN_DISTINCT {
        return Err(Error::CodeTooRepetitive);
    }

    if is_monotonic_run(&chars) {
        return Err(Error::CodeSequential);
    }

    let lower = code.to_lowercase();
    if WEAK_LIST.contains(&lower.as_str()) {
        return Err(Error::CodeWeak);
    }

    Ok(())
}

/// True if every adjacent pair steps by a constant ±1, e.g. `abcdefghij`.
fn is_monotonic_run(chars: &[char]) -> bool {
    if chars.len() < 2 {
        return false;
    }
    let step = chars[1] as i64 - chars[0] as i64;
    if step != 1 && step != -1 {
        return false;
    }
    chars.windows(2).all(|w| w[1] as i64 - w[0] as i64 == step)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_are_valid_and_unique() {
        let a = generate();
        let b = generate();
        assert_eq!(a.chars().count(), GENERATED_LEN);
        assert_ne!(a, b, "two generated codes must not collide");
        validate(&a).expect("generated code must pass validation");
        assert!(a.bytes().all(|c| ALPHABET.contains(&c)));
    }

    #[test]
    fn rejects_short_codes() {
        assert_eq!(validate("abc123def").unwrap_err(), Error::CodeTooShort);
        // Exactly at the boundary is allowed.
        validate("abc123defg").unwrap();
    }

    #[test]
    fn rejects_repetitive_codes() {
        assert_eq!(
            validate("aaaaaaaaaaaa").unwrap_err(),
            Error::CodeTooRepetitive
        );
        assert_eq!(
            validate("ababababababab").unwrap_err(),
            Error::CodeTooRepetitive
        );
    }

    #[test]
    fn rejects_sequences() {
        assert_eq!(validate("abcdefghijkl").unwrap_err(), Error::CodeSequential);
        assert_eq!(validate("zyxwvutsrqpo").unwrap_err(), Error::CodeSequential);
    }

    #[test]
    fn rejects_weak_list_case_insensitively() {
        assert_eq!(validate("QwErTyUiOp").unwrap_err(), Error::CodeWeak);
    }

    #[test]
    fn accepts_realistic_user_codes() {
        // The example from the original brief.
        validate("13749832sfdbdjdv78394324").unwrap();
        validate("correct-horse-battery").unwrap();
    }

    #[test]
    fn normalize_trims_but_preserves_case() {
        assert_eq!(normalize("  AbC123xyz9  "), "AbC123xyz9");
    }

    #[test]
    fn normalize_makes_equivalent_unicode_agree() {
        // "é" precomposed vs. "e" + combining acute must derive the same key.
        let precomposed = normalize("caf\u{00e9}rocks12");
        let decomposed = normalize("cafe\u{0301}rocks12");
        assert_eq!(precomposed, decomposed);
    }
}
