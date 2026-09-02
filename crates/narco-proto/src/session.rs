//! The Narco session state machine: handshake, then ratcheted transport.
//!
//! See PROTOCOL.md §3–§5.
//!
//! Every protocol error is terminal. `handle` wipes all key material and moves
//! to [`Phase::Dead`] on any failure, so a session that has seen a bad frame can
//! never be coaxed back into carrying plaintext.

use crate::error::{Error, Result};
use crate::frame::{self, Frame};
use crate::kdf;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const INFO_CONFIRM_A: &[u8] = b"narco/v1/confirm-A";
const INFO_CONFIRM_B: &[u8] = b"narco/v1/confirm-B";
const INFO_KEY_A: &[u8] = b"narco/v1/key-A";
const INFO_KEY_B: &[u8] = b"narco/v1/key-B";
const INFO_RATCHET: &[u8] = b"narco/v1/ratchet";
const AAD_PREFIX: &[u8] = b"narco/v1/msg";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    /// Waiting for the peer's SPAKE2 message.
    AwaitPake,
    /// Keys derived; waiting for the peer's confirmation tag.
    AwaitConfirm,
    /// Confirmed. Messaging is unlocked.
    Ready,
    /// Ended or aborted. Holds no key material.
    Dead,
}

/// Which side of the transcript this peer is. Decided by byte order of the two
/// handshake messages so both peers agree without an extra round trip.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    A,
    B,
}

/// What the caller should do as a result of feeding in a peer frame.
#[derive(Debug)]
pub enum Event {
    /// Transmit these bytes to the peer.
    Send(Vec<u8>),
    /// Handshake succeeded in both directions.
    Ready,
    /// A decrypted, authenticated message from the peer.
    Message(Vec<u8>),
}

/// One direction of the transport: a single-use key plus its counter.
struct Dir {
    key: Zeroizing<[u8; 32]>,
    ctr: u64,
}

impl Dir {
    /// Replace the key with its HKDF successor, overwriting the old bytes in
    /// place. One-way, so past messages stay unreadable after compromise.
    fn ratchet(&mut self) {
        let hk = Hkdf::<Sha256>::new(None, self.key.as_ref());
        let mut next = Zeroizing::new([0u8; 32]);
        hk.expand(INFO_RATCHET, next.as_mut())
            .expect("32 bytes is a valid HKDF length");
        self.key.copy_from_slice(next.as_ref());
        self.ctr += 1;
    }
}

pub struct Session {
    phase: Phase,
    room_id: String,
    spake: Option<Spake2<Ed25519Group>>,
    my_pake: Vec<u8>,
    my_confirm: Zeroizing<[u8; 32]>,
    peer_confirm_expected: Zeroizing<[u8; 32]>,
    tx: Option<Dir>,
    rx: Option<Dir>,
}

impl Session {
    /// Stretch the code and begin a handshake.
    ///
    /// This runs Argon2id and takes on the order of 100 ms on desktop and
    /// several hundred on mobile. Call it off the UI thread.
    ///
    /// To open several candidate connections from one code — as the Tor
    /// transport does — derive once with [`kdf::derive`] and call
    /// [`Session::from_derived`] per candidate instead of paying for Argon2id
    /// each time.
    pub fn new(code: &str) -> Result<Self> {
        Ok(Self::from_derived(&kdf::derive(code)?))
    }

    /// Begin a handshake from already-stretched key material.
    ///
    /// Each call produces an independent session with a fresh SPAKE2 ephemeral,
    /// so several may run concurrently without interfering.
    pub fn from_derived(derived: &kdf::Derived) -> Self {
        let (spake, my_pake) = Spake2::<Ed25519Group>::start_symmetric(
            &Password::new(derived.pake_pw.as_ref()),
            &Identity::new(derived.room_id.as_bytes()),
        );
        Self {
            phase: Phase::AwaitPake,
            room_id: derived.room_id.clone(),
            spake: Some(spake),
            my_pake,
            my_confirm: Zeroizing::new([0u8; 32]),
            peer_confirm_expected: Zeroizing::new([0u8; 32]),
            tx: None,
            rx: None,
        }
    }

    pub fn room_id(&self) -> &str {
        &self.room_id
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn is_ready(&self) -> bool {
        self.phase == Phase::Ready
    }

    /// The handshake frame to send once the relay reports a peer is present.
    pub fn pake_frame(&self) -> Vec<u8> {
        frame::pake_frame(&self.my_pake)
    }

    /// Feed in one frame received from the peer.
    ///
    /// On any error the session is wiped and permanently dead.
    pub fn handle(&mut self, raw: &[u8]) -> Result<Event> {
        let out = self.handle_inner(raw);
        if out.is_err() {
            self.wipe();
        }
        out
    }

    fn handle_inner(&mut self, raw: &[u8]) -> Result<Event> {
        if self.phase == Phase::Dead {
            return Err(Error::Dead);
        }
        match (self.phase, frame::parse(raw)?) {
            (Phase::AwaitPake, Frame::Pake(peer_msg)) => self.on_pake(peer_msg),
            (Phase::AwaitConfirm, Frame::Confirm(tag)) => self.on_confirm(tag),
            (Phase::Ready, Frame::Msg { ctr, ct }) => self.on_message(ctr, ct),
            _ => Err(Error::WrongPhase),
        }
    }

    fn on_pake(&mut self, peer_msg: &[u8]) -> Result<Event> {
        // A relay that echoes our own handshake back would otherwise have us
        // agree a key with ourselves. See PROTOCOL.md §3.1.
        if peer_msg == self.my_pake.as_slice() {
            return Err(Error::Reflection);
        }

        let spake = self.spake.take().ok_or(Error::WrongPhase)?;
        // SPAKE2 does not fail on a wrong password; it yields a different key.
        // Confirmation in `on_confirm` is what actually rejects a bad code.
        // A failure here means the bytes were not a usable SPAKE2 message —
        // wrong length, wrong side, off the curve. It does not mean the wrong
        // password: SPAKE2 does not fail on a wrong password, it yields a
        // different key, and `on_confirm` is what rejects that.
        let k = Zeroizing::new(spake.finish(peer_msg).map_err(|_| Error::BadHandshake)?);

        let role = if self.my_pake.as_slice() < peer_msg {
            Role::A
        } else {
            Role::B
        };

        // Bind the key schedule to both handshake messages, ordered so that
        // each peer computes an identical transcript.
        let mut transcript = Vec::with_capacity(frame::PAKE_LEN * 2);
        let (lo, hi) = if role == Role::A {
            (self.my_pake.as_slice(), peer_msg)
        } else {
            (peer_msg, self.my_pake.as_slice())
        };
        transcript.extend_from_slice(lo);
        transcript.extend_from_slice(hi);

        let hk = Hkdf::<Sha256>::new(Some(&transcript), k.as_ref());
        let expand = |info: &[u8]| -> Zeroizing<[u8; 32]> {
            let mut out = Zeroizing::new([0u8; 32]);
            hk.expand(info, out.as_mut())
                .expect("32 bytes is a valid HKDF length");
            out
        };

        let confirm_a = expand(INFO_CONFIRM_A);
        let confirm_b = expand(INFO_CONFIRM_B);
        let key_a = expand(INFO_KEY_A);
        let key_b = expand(INFO_KEY_B);

        let (mine, theirs, tx_key, rx_key) = match role {
            Role::A => (confirm_a, confirm_b, key_a, key_b),
            Role::B => (confirm_b, confirm_a, key_b, key_a),
        };

        self.my_confirm = mine;
        self.peer_confirm_expected = theirs;
        self.tx = Some(Dir {
            key: tx_key,
            ctr: 0,
        });
        self.rx = Some(Dir {
            key: rx_key,
            ctr: 0,
        });
        self.phase = Phase::AwaitConfirm;

        Ok(Event::Send(frame::confirm_frame(&self.my_confirm)))
    }

    fn on_confirm(&mut self, tag: &[u8]) -> Result<Event> {
        let ok: bool = tag.ct_eq(self.peer_confirm_expected.as_ref()).into();
        if !ok {
            return Err(Error::ConfirmMismatch);
        }
        // No longer needed once verified.
        self.my_confirm.zeroize();
        self.peer_confirm_expected.zeroize();
        self.phase = Phase::Ready;
        Ok(Event::Ready)
    }

    fn on_message(&mut self, ctr: u64, ct: &[u8]) -> Result<Event> {
        let rx = self.rx.as_mut().ok_or(Error::WrongPhase)?;
        // The transport is ordered, so any deviation is tampering, not loss.
        if ctr != rx.ctr {
            return Err(Error::OutOfOrder {
                expected: rx.ctr,
                got: ctr,
            });
        }
        let cipher =
            ChaCha20Poly1305::new_from_slice(rx.key.as_ref()).map_err(|_| Error::Decrypt)?;
        let padded = cipher
            .decrypt(
                &nonce_for(ctr).into(),
                Payload {
                    msg: ct,
                    aad: &aad_for(ctr),
                },
            )
            .map_err(|_| Error::Decrypt)?;
        let padded = Zeroizing::new(padded);
        let plaintext = frame::unpad(padded.as_ref())?;
        rx.ratchet();
        Ok(Event::Message(plaintext))
    }

    /// Encrypt a message for the peer, returning the frame to transmit.
    ///
    /// An oversize plaintext is rejected without harming the session; any other
    /// failure is terminal.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.phase != Phase::Ready {
            return Err(Error::WrongPhase);
        }
        // Checked before touching key state so a too-long message is a
        // recoverable user error rather than a dead session.
        if plaintext.len() > frame::MAX_PLAINTEXT {
            return Err(Error::TooLong);
        }
        let result = (|| -> Result<Vec<u8>> {
            let tx = self.tx.as_mut().ok_or(Error::WrongPhase)?;
            let ctr = tx.ctr;
            let padded = Zeroizing::new(frame::pad(plaintext)?);
            let cipher =
                ChaCha20Poly1305::new_from_slice(tx.key.as_ref()).map_err(|_| Error::Decrypt)?;
            let ct = cipher
                .encrypt(
                    &nonce_for(ctr).into(),
                    Payload {
                        msg: padded.as_ref(),
                        aad: &aad_for(ctr),
                    },
                )
                .map_err(|_| Error::Decrypt)?;
            tx.ratchet();
            Ok(frame::msg_frame(ctr, &ct))
        })();
        if result.is_err() {
            self.wipe();
        }
        result
    }

    /// Destroy all key material and mark the session dead. Idempotent.
    pub fn wipe(&mut self) {
        self.spake = None;
        self.my_confirm.zeroize();
        self.peer_confirm_expected.zeroize();
        self.my_pake.zeroize();
        // Dir owns Zeroizing keys, so dropping erases them.
        self.tx = None;
        self.rx = None;
        self.phase = Phase::Dead;
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.wipe();
    }
}

fn nonce_for(ctr: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&ctr.to_be_bytes());
    n
}

fn aad_for(ctr: u64) -> [u8; 20] {
    let mut a = [0u8; 20];
    a[..AAD_PREFIX.len()].copy_from_slice(AAD_PREFIX);
    a[AAD_PREFIX.len()..].copy_from_slice(&ctr.to_be_bytes());
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive two sessions through a full handshake over an in-memory "relay".
    fn handshake(code_a: &str, code_b: &str) -> Result<(Session, Session)> {
        let mut a = Session::new(code_a)?;
        let mut b = Session::new(code_b)?;

        let a_pake = a.pake_frame();
        let b_pake = b.pake_frame();

        let a_confirm = match a.handle(&b_pake)? {
            Event::Send(f) => f,
            other => panic!("expected Send, got {other:?}"),
        };
        let b_confirm = match b.handle(&a_pake)? {
            Event::Send(f) => f,
            other => panic!("expected Send, got {other:?}"),
        };

        matches!(a.handle(&b_confirm)?, Event::Ready)
            .then_some(())
            .expect("a should be ready");
        matches!(b.handle(&a_confirm)?, Event::Ready)
            .then_some(())
            .expect("b should be ready");

        Ok((a, b))
    }

    fn exchange(from: &mut Session, to: &mut Session, msg: &[u8]) -> Vec<u8> {
        let frame = from.encrypt(msg).expect("encrypt");
        match to.handle(&frame).expect("decrypt") {
            Event::Message(m) => m,
            other => panic!("expected Message, got {other:?}"),
        }
    }

    const CODE: &str = "PWXK7M2QRT9HFZ";
    const OTHER: &str = "LDN4VB8SGJ3YQC";

    #[test]
    fn matching_codes_reach_ready_and_agree_on_room() {
        let (a, b) = handshake(CODE, CODE).unwrap();
        assert!(a.is_ready() && b.is_ready());
        assert_eq!(a.room_id(), b.room_id());
    }

    #[test]
    fn messages_round_trip_in_both_directions() {
        let (mut a, mut b) = handshake(CODE, CODE).unwrap();
        assert_eq!(exchange(&mut a, &mut b, b"hello from a"), b"hello from a");
        assert_eq!(exchange(&mut b, &mut a, b"hello from b"), b"hello from b");
        for i in 0..50u32 {
            let msg = format!("message {i}");
            assert_eq!(exchange(&mut a, &mut b, msg.as_bytes()), msg.as_bytes());
        }
    }

    #[test]
    fn empty_and_maximum_messages_work() {
        let (mut a, mut b) = handshake(CODE, CODE).unwrap();
        assert_eq!(exchange(&mut a, &mut b, b""), b"");
        let big = vec![0x5Au8; frame::MAX_PLAINTEXT];
        assert_eq!(exchange(&mut a, &mut b, &big), big);
    }

    #[test]
    fn oversize_message_is_rejected_without_killing_the_session() {
        let (mut a, mut b) = handshake(CODE, CODE).unwrap();
        let too_big = vec![0u8; frame::MAX_PLAINTEXT + 1];
        assert_eq!(a.encrypt(&too_big).unwrap_err(), Error::TooLong);
        assert!(a.is_ready(), "session must survive a too-long message");
        assert_eq!(exchange(&mut a, &mut b, b"still fine"), b"still fine");
    }

    /// The headline property: a wrong code must fail closed, not silently
    /// produce a working-looking session.
    #[test]
    /// Rubbish is not a guess.
    ///
    /// A host counts wrong secrets against a limit and abandons the room once it
    /// has seen enough of them. Every `spake.finish` failure used to arrive as
    /// `ConfirmMismatch`, so thirty-three bytes of nonsense counted as somebody
    /// typing the wrong secret — five junk connections and the host gave up on
    /// the meeting, telling its owner the codes did not match. Anyone who could
    /// reach the address could shut the room without ever guessing anything.
    #[test]
    fn unreadable_handshake_input_is_not_a_wrong_secret() {
        let a_pake = Session::new(CODE).unwrap().pake_frame();
        for junk in [
            // Right length, all zeroes: not a point on the curve.
            vec![0u8; a_pake.len()],
            // Right length, wrong side marker.
            {
                let mut v = a_pake.clone();
                v[1] ^= 0xff;
                v
            },
            // Truncated.
            a_pake[..a_pake.len() - 1].to_vec(),
        ] {
            let mut s = Session::new(CODE).unwrap();
            match s.handle(&junk) {
                Err(Error::ConfirmMismatch) => {
                    panic!("junk was counted as a wrong secret, which lets it close the room")
                }
                Err(_) => {}
                Ok(e) => panic!("junk was accepted: {e:?}"),
            }
        }
    }

    #[test]
    fn mismatched_codes_fail_at_confirmation() {
        let mut a = Session::new(CODE).unwrap();
        let mut b = Session::new(OTHER).unwrap();
        // Different codes mean different rooms, so they would never meet; force
        // them together to prove confirmation is what rejects them.
        assert_ne!(a.room_id(), b.room_id());

        let a_pake = a.pake_frame();
        let b_pake = b.pake_frame();
        let a_confirm = match a.handle(&b_pake).unwrap() {
            Event::Send(f) => f,
            other => panic!("got {other:?}"),
        };
        let b_confirm = match b.handle(&a_pake).unwrap() {
            Event::Send(f) => f,
            other => panic!("got {other:?}"),
        };

        assert_eq!(a.handle(&b_confirm).unwrap_err(), Error::ConfirmMismatch);
        assert_eq!(b.handle(&a_confirm).unwrap_err(), Error::ConfirmMismatch);
        assert_eq!(a.phase(), Phase::Dead);
        assert_eq!(b.phase(), Phase::Dead);
        assert_eq!(a.encrypt(b"leak?").unwrap_err(), Error::WrongPhase);
    }

    #[test]
    fn reflected_handshake_is_rejected() {
        let mut a = Session::new(CODE).unwrap();
        let own = a.pake_frame();
        assert_eq!(a.handle(&own).unwrap_err(), Error::Reflection);
        assert_eq!(a.phase(), Phase::Dead);
    }

    #[test]
    fn replayed_message_is_rejected() {
        let (mut a, mut b) = handshake(CODE, CODE).unwrap();
        let frame = a.encrypt(b"once").unwrap();
        assert!(matches!(b.handle(&frame).unwrap(), Event::Message(_)));
        assert_eq!(
            b.handle(&frame).unwrap_err(),
            Error::OutOfOrder {
                expected: 1,
                got: 0
            }
        );
        assert_eq!(b.phase(), Phase::Dead);
    }

    #[test]
    fn reordered_message_is_rejected() {
        let (mut a, mut b) = handshake(CODE, CODE).unwrap();
        let first = a.encrypt(b"one").unwrap();
        let second = a.encrypt(b"two").unwrap();
        assert_eq!(
            b.handle(&second).unwrap_err(),
            Error::OutOfOrder {
                expected: 0,
                got: 1
            }
        );
        drop(first);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut a, mut b) = handshake(CODE, CODE).unwrap();
        let mut frame = a.encrypt(b"authentic").unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 0x01;
        assert_eq!(b.handle(&frame).unwrap_err(), Error::Decrypt);
        assert_eq!(b.phase(), Phase::Dead);
    }

    #[test]
    fn forward_secrecy_old_key_cannot_decrypt_later_message() {
        let (mut a, mut b) = handshake(CODE, CODE).unwrap();
        // Capture the key that encrypts message 0, then advance past it.
        let key0 = a.tx.as_ref().unwrap().key.clone();
        let _ = exchange(&mut a, &mut b, b"first");
        let frame1 = a.encrypt(b"second").unwrap();

        // A recorded key from before the ratchet must not open a later message.
        let ct = &frame1[9..];
        let cipher = ChaCha20Poly1305::new_from_slice(key0.as_ref()).unwrap();
        assert!(cipher
            .decrypt(
                &nonce_for(1).into(),
                Payload {
                    msg: ct,
                    aad: &aad_for(1)
                }
            )
            .is_err());
        // And the key genuinely changed.
        assert_ne!(a.tx.as_ref().unwrap().key.as_ref(), key0.as_ref());
    }

    #[test]
    fn out_of_phase_frames_are_rejected() {
        let mut a = Session::new(CODE).unwrap();
        // A message frame before the handshake completes.
        assert_eq!(
            a.handle(&frame::msg_frame(0, b"x")).unwrap_err(),
            Error::WrongPhase
        );
        assert_eq!(a.phase(), Phase::Dead);

        let mut c = Session::new(CODE).unwrap();
        assert_eq!(
            c.handle(&frame::confirm_frame(&[0u8; 32])).unwrap_err(),
            Error::WrongPhase
        );
    }

    #[test]
    fn wipe_is_idempotent_and_terminal() {
        let (mut a, _b) = handshake(CODE, CODE).unwrap();
        a.wipe();
        a.wipe();
        assert_eq!(a.phase(), Phase::Dead);
        assert_eq!(a.encrypt(b"x").unwrap_err(), Error::WrongPhase);
        assert_eq!(
            a.handle(&frame::msg_frame(0, b"x")).unwrap_err(),
            Error::Dead
        );
    }

    #[test]
    fn counters_advance_independently_per_direction() {
        let (mut a, mut b) = handshake(CODE, CODE).unwrap();
        exchange(&mut a, &mut b, b"a1");
        exchange(&mut a, &mut b, b"a2");
        exchange(&mut b, &mut a, b"b1");
        assert_eq!(a.tx.as_ref().unwrap().ctr, 2);
        assert_eq!(a.rx.as_ref().unwrap().ctr, 1);
        assert_eq!(b.tx.as_ref().unwrap().ctr, 1);
        assert_eq!(b.rx.as_ref().unwrap().ctr, 2);
    }

    #[test]
    fn peers_take_opposite_roles_so_directions_do_not_collide() {
        let (a, b) = handshake(CODE, CODE).unwrap();
        // A's send key must be B's receive key, and vice versa.
        assert_eq!(
            a.tx.as_ref().unwrap().key.as_ref(),
            b.rx.as_ref().unwrap().key.as_ref()
        );
        assert_eq!(
            a.rx.as_ref().unwrap().key.as_ref(),
            b.tx.as_ref().unwrap().key.as_ref()
        );
        // The two directions must not share a key.
        assert_ne!(
            a.tx.as_ref().unwrap().key.as_ref(),
            a.rx.as_ref().unwrap().key.as_ref()
        );
    }
}
