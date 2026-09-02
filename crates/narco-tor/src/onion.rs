//! Deriving a v3 onion identity from a room secret, with no Tor library.
//!
//! Everything here is plain ed25519 plus two hashes, so it does not depend on
//! Arti. The resulting address is identical to the one Arti computed — proven
//! by a test that checks both against the same seeds — which means switching
//! the Tor engine does not change where two peers meet.
//!
//! See PROTOCOL.md §11.1.

use base64::Engine as _;
use narco_proto::kdf::Derived;
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

/// `.onion` version byte for v3 addresses (rend-spec-v3 §6).
const ONION_VERSION: u8 = 0x03;

/// A code-derived onion service identity.
///
/// Held in memory only and never written to disk. `Debug` is redacted because
/// the address is as sensitive as the room secret it comes from.
pub struct OnionKey {
    /// `<56 base32 chars>.onion`
    pub address: String,
    /// Expanded ed25519 secret key (scalar ‖ hash prefix), base64.
    ///
    /// This is exactly the blob Tor's `ADD_ONION ED25519-V3:` expects.
    ///
    /// Wrapped so it is wiped when the key goes out of scope. It was the last
    /// secret in the codebase left in a plain `String`, which meant the private
    /// key the whole room is built on stayed in freed heap — and in swap — for
    /// the life of the process, while everything around it was zeroized.
    pub control_blob: Zeroizing<String>,
}

impl core::fmt::Debug for OnionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OnionKey")
            .field("address", &"<redacted>.onion")
            .field("control_blob", &"<redacted>")
            .finish()
    }
}

/// Expand a 32-byte seed into ed25519's `(scalar ‖ hash_prefix)` form.
///
/// This is the standard expansion: SHA-512 of the seed with the usual clamping
/// of the low half. Tor stores onion service keys in this expanded form, which
/// is why `ADD_ONION` wants 64 bytes rather than the 32-byte seed.
fn expand_secret(seed: &[u8; 32]) -> Zeroizing<[u8; 64]> {
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&Sha512::digest(seed));
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    out
}

/// `base32(pubkey ‖ checksum ‖ version)` per rend-spec-v3 §6.
fn onion_address(pubkey: &[u8; 32]) -> String {
    // checksum = SHA3-256(".onion checksum" ‖ pubkey ‖ version)[..2]
    let mut h = <sha3::Sha3_256 as Digest>::new();
    h.update(b".onion checksum");
    h.update(pubkey);
    h.update([ONION_VERSION]);
    let checksum = h.finalize();

    let mut buf = [0u8; 35];
    buf[..32].copy_from_slice(pubkey);
    buf[32..34].copy_from_slice(&checksum[..2]);
    buf[34] = ONION_VERSION;

    let mut s = data_encoding::BASE32_NOPAD.encode(&buf);
    s.make_ascii_lowercase();
    s.push_str(".onion");
    s
}

/// Derive the onion identity both peers meet at, from the room secrets.
pub fn onion_key(derived: &Derived) -> OnionKey {
    let seed: &[u8; 32] = &derived.onion_seed_a;
    let signing = ed25519_dalek::SigningKey::from_bytes(seed);
    let pubkey = signing.verifying_key().to_bytes();

    OnionKey {
        address: onion_address(&pubkey),
        control_blob: Zeroizing::new(
            base64::engine::general_purpose::STANDARD.encode(expand_secret(seed).as_ref()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use narco_proto::kdf;

    /// Addresses must never drift: a change here would move where peers meet
    /// and silently break every code already in use. These vectors were
    /// captured from the previous Arti-based implementation, and the first was
    /// re-confirmed by the live daemon, which published exactly this address.
    #[test]
    fn addresses_match_known_vectors() {
        for (code, want) in [
            (
                "PWXK7M2QRT9HFZ",
                "nhcp7vstfbdtyxjz3cz2752qvcife4vnliikpux3c3kijquxd2ksxjqd.onion",
            ),
            (
                "13749832sfdbdjdv78394324",
                "47v7es3j2epeuqz3cmkrxhu2mzhaeud2jvsw5goedca2hublscb74kid.onion",
            ),
        ] {
            let got = onion_key(&kdf::derive(code).unwrap()).address;
            assert_eq!(got, want, "address drifted for {code:?}");
        }
    }

    #[test]
    fn address_is_well_formed() {
        let d = kdf::derive("PWXK7M2QRT9HFZ").unwrap();
        let k = onion_key(&d);
        assert!(k.address.ends_with(".onion"));
        assert_eq!(k.address.len(), 62, "v3 = 56 base32 chars + .onion");
        // 64-byte expanded key base64-encodes to 88 chars.
        assert_eq!(k.control_blob.len(), 88);
    }

    #[test]
    fn derivation_is_deterministic_and_code_specific() {
        let a = onion_key(&kdf::derive("PWXK7M2QRT9HFZ").unwrap());
        let b = onion_key(&kdf::derive("PWXK7M2QRT9HFZ").unwrap());
        let c = onion_key(&kdf::derive("LDN4VB8SGJ3YQC").unwrap());
        assert_eq!(a.address, b.address);
        assert_eq!(a.control_blob, b.control_blob);
        assert_ne!(a.address, c.address);
    }

    #[test]
    fn debug_does_not_leak() {
        let k = onion_key(&kdf::derive("PWXK7M2QRT9HFZ").unwrap());
        let s = format!("{k:?}");
        assert!(!s.contains(k.address.trim_end_matches(".onion")));
        assert!(!s.contains(k.control_blob.as_str()));
    }
}
