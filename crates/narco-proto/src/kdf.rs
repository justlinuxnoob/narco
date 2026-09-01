//! Deriving the room identifier and PAKE password from the room code.
//!
//! See PROTOCOL.md §2.

use crate::code;
use crate::error::{Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Argon2id memory cost in KiB. Chosen to stay comfortable on mobile while
/// making offline guessing of a weak code expensive.
pub const ARGON_MEM_KIB: u32 = 32 * 1024;
pub const ARGON_TIME: u32 = 3;
pub const ARGON_LANES: u32 = 1;

/// Fixed salt. It must be a constant: both peers derive from the code alone,
/// with nothing else to agree on. PROTOCOL.md §2 explains the consequence.
const SALT: &[u8] = b"narco-v1-room-salt";

const INFO_ROOM_ID: &[u8] = b"narco/v1/room-id";
const INFO_PAKE_PW: &[u8] = b"narco/v1/pake-pw";
const INFO_ONION_A: &[u8] = b"narco/v1/onion-a";
const INFO_ONION_B: &[u8] = b"narco/v1/onion-b";

/// Everything derivable from a room code.
///
/// Cheap to clone, and deliberately so: the Tor transport opens several
/// candidate connections at once and each needs its own
/// [`Session`](crate::Session). Cloning this avoids re-running Argon2id per
/// candidate, which would cost a hundred milliseconds each time.
#[derive(Clone)]
pub struct Derived {
    /// Public: names the room on a relay. 32 lowercase hex chars.
    pub room_id: String,
    /// Secret: the SPAKE2 password. Never leaves the device.
    pub pake_pw: Zeroizing<[u8; 32]>,
    /// Secret: ed25519 seed for onion identity A. See PROTOCOL.md §11.
    pub onion_seed_a: Zeroizing<[u8; 32]>,
    /// Secret: ed25519 seed for onion identity B.
    pub onion_seed_b: Zeroizing<[u8; 32]>,
}

/// Hand-written rather than derived, so that formatting a `Derived` can never
/// spill the PAKE password into a log line or a panic message.
impl core::fmt::Debug for Derived {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Derived")
            .field("room_id", &self.room_id)
            .field("pake_pw", &"<redacted>")
            .field("onion_seed_a", &"<redacted>")
            .field("onion_seed_b", &"<redacted>")
            .finish()
    }
}

/// Stretch a room code into a room id and a PAKE password.
///
/// Equivalent to [`derive_with_passphrase`] with an empty passphrase.
pub fn derive(raw_code: &str) -> Result<Derived> {
    derive_with_passphrase(raw_code, "")
}

/// Stretch a room code plus one extra secret.
///
/// Convenience wrapper over [`derive_multi`].
pub fn derive_with_passphrase(raw_code: &str, raw_passphrase: &str) -> Result<Derived> {
    derive_multi(&[raw_code, raw_passphrase])
}

/// Stretch any number of shared secrets into a room id and a PAKE password.
///
/// Both peers must supply the same secrets **in the same order**. Empty entries
/// are ignored, so a UI can offer several fields and let people fill in as many
/// as they want. The first non-empty secret is the room code and must satisfy
/// [`code::validate`]; the rest are free-form.
///
/// # What extra secrets actually buy
///
/// Cryptographically, `n` secrets are *identical* to one longer secret — their
/// entropy simply adds. Five secrets are not five times stronger than one, and
/// against a generated 130-bit code, guessing is already hopeless with just one.
///
/// The real gain is **channel separation**, and that does scale. Send each
/// secret a different way — one messaged, one spoken on a call, one said in
/// person — and an attacker must compromise *every* channel to learn anything.
/// Compromising all but one yields nothing at all: every derived value depends
/// on every secret, so a party missing one cannot even locate the room, let
/// alone impersonate a peer.
pub fn derive_multi<S: AsRef<str>>(raw_secrets: &[S]) -> Result<Derived> {
    let secrets: Vec<String> = raw_secrets
        .iter()
        .map(|s| code::normalize(s.as_ref()))
        .filter(|s| !s.is_empty())
        .collect();

    let first = secrets.first().ok_or(Error::CodeTooShort)?;
    code::validate(first)?;

    let params = Params::new(ARGON_MEM_KIB, ARGON_TIME, ARGON_LANES, Some(64))
        .map_err(|_| Error::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Each secret is length-prefixed so the sequence cannot be re-split
    // ambiguously. Plain concatenation would make ("ab", "c") and ("a", "bc")
    // the same room. The count is prefixed too, so adding a trailing empty
    // secret can never coincide with a shorter list.
    let mut secret = Zeroizing::new(Vec::with_capacity(64));
    secret.extend_from_slice(&(secrets.len() as u32).to_be_bytes());
    for s in &secrets {
        secret.extend_from_slice(&(s.len() as u32).to_be_bytes());
        secret.extend_from_slice(s.as_bytes());
    }

    let mut ikm = Zeroizing::new([0u8; 64]);
    argon
        .hash_password_into(secret.as_ref(), SALT, ikm.as_mut())
        .map_err(|_| Error::Kdf)?;

    let hk = Hkdf::<Sha256>::new(None, ikm.as_ref());

    let mut room_raw = Zeroizing::new([0u8; 16]);
    hk.expand(INFO_ROOM_ID, room_raw.as_mut()).map_err(|_| Error::Kdf)?;

    let mut pake_pw = Zeroizing::new([0u8; 32]);
    hk.expand(INFO_PAKE_PW, pake_pw.as_mut()).map_err(|_| Error::Kdf)?;

    let mut onion_seed_a = Zeroizing::new([0u8; 32]);
    hk.expand(INFO_ONION_A, onion_seed_a.as_mut()).map_err(|_| Error::Kdf)?;

    let mut onion_seed_b = Zeroizing::new([0u8; 32]);
    hk.expand(INFO_ONION_B, onion_seed_b.as_mut()).map_err(|_| Error::Kdf)?;

    let room_id = room_raw.iter().map(|b| format!("{b:02x}")).collect();

    Ok(Derived { room_id, pake_pw, onion_seed_a, onion_seed_b })
}

/// True if `s` is exactly 32 lowercase hex characters. Used by both the client
/// and the relay to reject malformed room identifiers.
pub fn is_valid_room_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let a = derive("hunter2-is-not-great").unwrap();
        let b = derive("hunter2-is-not-great").unwrap();
        assert_eq!(a.room_id, b.room_id);
        assert_eq!(a.pake_pw.as_ref(), b.pake_pw.as_ref());
    }

    #[test]
    fn different_codes_give_different_rooms_and_passwords() {
        let a = derive("hunter2-is-not-great").unwrap();
        let b = derive("hunter3-is-not-great").unwrap();
        assert_ne!(a.room_id, b.room_id);
        assert_ne!(a.pake_pw.as_ref(), b.pake_pw.as_ref());
    }

    #[test]
    fn room_id_is_well_formed_and_distinct_from_password() {
        let d = derive("some-decent-code-42").unwrap();
        assert!(is_valid_room_id(&d.room_id), "got {}", d.room_id);
        // The public value must not be a prefix of the secret one.
        let pw_hex: String = d.pake_pw.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!pw_hex.starts_with(&d.room_id));
    }

    #[test]
    fn whitespace_and_unicode_form_do_not_change_the_room() {
        let a = derive("  caf\u{00e9}-code-here  ").unwrap();
        let b = derive("cafe\u{0301}-code-here").unwrap();
        assert_eq!(a.room_id, b.room_id);
    }

    #[test]
    fn invalid_codes_are_rejected_before_any_derivation() {
        assert_eq!(derive("short").unwrap_err(), Error::CodeTooShort);
        assert_eq!(derive("aaaaaaaaaaaa").unwrap_err(), Error::CodeTooRepetitive);
    }

    #[test]
    fn a_passphrase_changes_everything_derived() {
        let plain = derive("some-decent-code-42").unwrap();
        let with_pass = derive_with_passphrase("some-decent-code-42", "spoken aloud").unwrap();
        // Someone holding only the code cannot even find the room.
        assert_ne!(plain.room_id, with_pass.room_id);
        assert_ne!(plain.pake_pw.as_ref(), with_pass.pake_pw.as_ref());
        assert_ne!(plain.onion_seed_a.as_ref(), with_pass.onion_seed_a.as_ref());
    }

    #[test]
    fn a_wrong_passphrase_lands_somewhere_else_entirely() {
        let a = derive_with_passphrase("some-decent-code-42", "correct").unwrap();
        let b = derive_with_passphrase("some-decent-code-42", "corrupt").unwrap();
        assert_ne!(a.room_id, b.room_id);
    }

    #[test]
    fn empty_passphrase_matches_the_plain_derivation() {
        let a = derive("some-decent-code-42").unwrap();
        let b = derive_with_passphrase("some-decent-code-42", "").unwrap();
        assert_eq!(a.room_id, b.room_id);
        assert_eq!(a.pake_pw.as_ref(), b.pake_pw.as_ref());
    }

    /// Length-prefixing must stop the two secrets being re-split. Without it,
    /// ("xk7m2qrt9h", "fz") and ("xk7m2qrt9hf", "z") would be the same room.
    #[test]
    fn the_split_between_code_and_passphrase_is_unambiguous() {
        let a = derive_with_passphrase("xk7m2qrt9h", "fz").unwrap();
        let b = derive_with_passphrase("xk7m2qrt9hf", "z").unwrap();
        assert_ne!(a.room_id, b.room_id);
    }

    #[test]
    fn any_number_of_secrets_works_and_is_deterministic() {
        let s = ["some-decent-code-42", "spoken aloud", "written down", "4", "5"];
        assert_eq!(derive_multi(&s).unwrap().room_id, derive_multi(&s).unwrap().room_id);
        // Each additional secret lands the pair somewhere else entirely.
        let mut seen = std::collections::HashSet::new();
        for n in 1..=s.len() {
            assert!(
                seen.insert(derive_multi(&s[..n]).unwrap().room_id),
                "{n} secrets collided with a shorter list"
            );
        }
    }

    #[test]
    fn secret_order_matters() {
        let a = derive_multi(&["some-decent-code-42", "alpha", "beta"]).unwrap();
        let b = derive_multi(&["some-decent-code-42", "beta", "alpha"]).unwrap();
        assert_ne!(a.room_id, b.room_id);
    }

    #[test]
    fn empty_secrets_are_ignored_so_blank_fields_are_harmless() {
        let a = derive_multi(&["some-decent-code-42", "extra"]).unwrap();
        let b = derive_multi(&["", "some-decent-code-42", "", "extra", "  "]).unwrap();
        assert_eq!(a.room_id, b.room_id);
    }

    #[test]
    fn the_first_secret_must_still_be_a_valid_code() {
        assert_eq!(derive_multi(&["short", "padding"]).unwrap_err(), Error::CodeTooShort);
        let empty: [&str; 0] = [];
        assert_eq!(derive_multi(&empty).unwrap_err(), Error::CodeTooShort);
        // Extra secrets are free-form; only the first is constrained.
        derive_multi(&["some-decent-code-42", "a"]).unwrap();
    }

    #[test]
    fn passphrase_is_unicode_normalized_like_the_code() {
        let a = derive_with_passphrase("some-decent-code-42", "caf\u{00e9}").unwrap();
        let b = derive_with_passphrase("some-decent-code-42", "cafe\u{0301}").unwrap();
        assert_eq!(a.room_id, b.room_id);
    }

    #[test]
    fn every_derived_secret_is_independent() {
        let d = derive("some-decent-code-42").unwrap();
        let secrets: [&[u8]; 4] = [
            d.pake_pw.as_ref(),
            d.onion_seed_a.as_ref(),
            d.onion_seed_b.as_ref(),
            // The public value must not coincide with any secret.
            d.room_id.as_bytes(),
        ];
        for i in 0..secrets.len() {
            for j in (i + 1)..secrets.len() {
                assert_ne!(secrets[i], secrets[j], "labels {i} and {j} collided");
            }
        }
    }

    #[test]
    fn onion_seeds_are_deterministic_across_derivations() {
        let a = derive("some-decent-code-42").unwrap();
        let b = derive("some-decent-code-42").unwrap();
        // Both peers must land on the same two onion identities.
        assert_eq!(a.onion_seed_a.as_ref(), b.onion_seed_a.as_ref());
        assert_eq!(a.onion_seed_b.as_ref(), b.onion_seed_b.as_ref());
    }

    #[test]
    fn room_id_validator_rejects_junk() {
        assert!(is_valid_room_id("0123456789abcdef0123456789abcdef"));
        assert!(!is_valid_room_id("0123456789ABCDEF0123456789ABCDEF")); // uppercase
        assert!(!is_valid_room_id("short"));
        assert!(!is_valid_room_id("0123456789abcdef0123456789abcdeg")); // 'g'
        assert!(!is_valid_room_id("../../etc/passwd0123456789abcdef"));
    }
}
