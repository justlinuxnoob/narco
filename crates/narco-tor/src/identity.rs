//! Turning a room code into onion-service identities.
//!
//! This is the piece that removes the need for a server. Both peers derive the
//! same two ed25519 keypairs from the same code, so they arrive at the same two
//! `.onion` addresses without ever being introduced. The Tor directory system
//! does the introducing, and it already exists.
//!
//! See PROTOCOL.md §11.

use narco_proto::kdf::Derived;
use safelog::DisplayRedacted;
use tor_hscrypto::pk::{HsIdKey, HsIdKeypair};
use tor_llcrypto::pk::ed25519;

/// Which of the two code-derived onion identities this is.
///
/// Two identities exist so the peers can take opposite roles: one listens on
/// `A` while dialling `B`, and the other does the reverse. With a single
/// identity both peers would try to publish the same service and neither could
/// dial the other.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    pub fn other(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Slot::A => "A",
            Slot::B => "B",
        }
    }
}

/// A code-derived onion service identity.
///
/// The keypair is held in memory only. It is never written to a keystore on
/// disk — see [`crate::transport`], which configures Arti with an ephemeral
/// keystore precisely so that this stays true.
pub struct OnionIdentity {
    /// `<56 base32 chars>.onion`
    pub address: String,
    pub slot: Slot,
    keypair: HsIdKeypair,
}

impl OnionIdentity {
    /// Consume this identity, yielding the keypair for launching a service.
    pub fn into_keypair(self) -> HsIdKeypair {
        self.keypair
    }
}

/// Redacted so an identity can be logged or `{:?}`-printed without publishing
/// the address, which is equivalent to publishing the room code's fingerprint.
impl core::fmt::Debug for OnionIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OnionIdentity")
            .field("slot", &self.slot)
            .field("address", &"<redacted>.onion")
            .field("keypair", &"<redacted>")
            .finish()
    }
}

/// Build an onion identity from a 32-byte seed.
///
/// The seed is treated as an ed25519 secret key and expanded in the standard
/// way, so the resulting address is an ordinary v3 onion address that any Tor
/// client can reach.
fn from_seed(seed: &[u8; 32], slot: Slot) -> OnionIdentity {
    let keypair = HsIdKeypair::from(ed25519::ExpandedKeypair::from(
        &ed25519::Keypair::from_bytes(seed),
    ));
    let address = HsIdKey::from(&keypair)
        .id()
        .display_unredacted()
        .to_string();
    OnionIdentity {
        address,
        slot,
        keypair,
    }
}

/// Derive both onion identities for a room.
///
/// Both peers call this with the same code and get identical results, which is
/// the entire trick: no signalling server is needed because the code already
/// encodes where to meet.
pub fn identities(derived: &Derived) -> (OnionIdentity, OnionIdentity) {
    (
        from_seed(&derived.onion_seed_a, Slot::A),
        from_seed(&derived.onion_seed_b, Slot::B),
    )
}

/// Derive just one slot's identity.
pub fn identity(derived: &Derived, slot: Slot) -> OnionIdentity {
    match slot {
        Slot::A => from_seed(&derived.onion_seed_a, Slot::A),
        Slot::B => from_seed(&derived.onion_seed_b, Slot::B),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use narco_proto::kdf;

    const CODE: &str = "PWXK7M2QRT9HFZ";

    #[test]
    fn a_code_maps_to_two_valid_onion_addresses() {
        let d = kdf::derive(CODE).unwrap();
        let (a, b) = identities(&d);

        for id in [&a, &b] {
            assert!(id.address.ends_with(".onion"));
            // v3: 56 base32 characters plus the suffix.
            assert_eq!(id.address.len(), 62, "bad address: {}", id.address);
            // Parsing with Tor's own parser validates version and checksum,
            // proving the address is real and not merely the right shape.
            let parsed: tor_hscrypto::pk::HsId =
                id.address.parse().expect("must be a valid onion address");
            assert_eq!(parsed.display_unredacted().to_string(), id.address);
        }
        assert_ne!(a.address, b.address, "the two slots must differ");
    }

    /// The property the whole design rests on: two devices, same code, same
    /// meeting point, with nothing exchanged between them.
    #[test]
    fn both_peers_independently_derive_the_same_addresses() {
        let peer1 = kdf::derive(CODE).unwrap();
        let peer2 = kdf::derive(CODE).unwrap();
        let (a1, b1) = identities(&peer1);
        let (a2, b2) = identities(&peer2);
        assert_eq!(a1.address, a2.address);
        assert_eq!(b1.address, b2.address);
    }

    #[test]
    fn a_different_code_meets_somewhere_else() {
        let (a1, b1) = identities(&kdf::derive(CODE).unwrap());
        let (a2, b2) = identities(&kdf::derive("LDN4VB8SGJ3YQC").unwrap());
        for x in [&a1.address, &b1.address] {
            for y in [&a2.address, &b2.address] {
                assert_ne!(x, y, "codes must not collide");
            }
        }
    }

    #[test]
    fn slot_helper_is_consistent_with_the_pair() {
        let d = kdf::derive(CODE).unwrap();
        let (a, b) = identities(&d);
        assert_eq!(identity(&d, Slot::A).address, a.address);
        assert_eq!(identity(&d, Slot::B).address, b.address);
        assert_eq!(Slot::A.other(), Slot::B);
        assert_eq!(Slot::B.other(), Slot::A);
    }

    #[test]
    fn debug_output_never_leaks_the_address_or_key() {
        let d = kdf::derive(CODE).unwrap();
        let (a, _) = identities(&d);
        let rendered = format!("{a:?}");
        assert!(!rendered.contains(a.address.trim_end_matches(".onion")));
        assert!(rendered.contains("redacted"));
    }
}
