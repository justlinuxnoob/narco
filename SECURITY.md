# Security

## Reporting

Open a [private security advisory](https://github.com/justlinuxnoob/narco/security/advisories/new).
Please don't file a public issue for anything exploitable.

**Narco has not been audited.** It is early software. If you are in real danger,
use something that has been reviewed by professionals — [Signal](https://signal.org)
is the honest recommendation.

## Threat model

### What an attacker cannot do

| | Why |
| --- | --- |
| Read your messages | End-to-end encrypted with a key neither the network nor any server ever sees |
| Decrypt a recording after stealing your device | Per-message ratchet; each key is destroyed after one use |
| Decrypt an old session after learning your secret | Fresh ephemerals each session are discarded; the secret alone cannot rebuild the key |
| Guess the secret offline from a transcript | SPAKE2 permits only one *online* guess per attempt |
| Join a conversation in progress | The address is unpublished the moment two peers confirm |
| Learn your IP from your chat partner | The circuit terminates at a Tor rendezvous point |
| Recover anything after the session | Nothing is ever written to disk |

### What an attacker can do

- **Compromise an endpoint.** Plaintext is on both screens. Nothing in a
  messenger survives a device someone else controls.
- **Observe that you use Tor.** Narco is not an anonymity system on its own. A
  network observer sees a Tor connection, not who you talked to or what you said.
- **Guess a weak secret.** The room address is derived from the secret. A
  guessable secret means a guessable address. Argon2id at 32 MiB makes each guess
  expensive, but it cannot rescue `password12345`. Use the generate button.
- **Reuse a leaked secret.** Old messages stay unrecoverable, but someone with
  your secret can open a *new* room at the same address and impersonate your
  contact. Generate a fresh secret per conversation.
- **Deny service.** Anyone who knows the secret can occupy the room, and Tor
  itself can be blocked. Narco fails closed — it will not connect rather than
  connect insecurely.

### If you use the optional relay instead of Tor

`server/` is not used by default. If you self-host it, the operator additionally
sees the room id (an Argon2id-hardened hash of your secrets), both IP addresses,
timing, message counts, and padded sizes. Never message content — the relay holds
no keys and does not parse the bytes it forwards.

## Design decisions worth reviewing

Places where a reviewer should look hardest:

1. **Key confirmation is mandatory.** SPAKE2 does not error on a wrong password;
   it silently derives a different key. `session.rs` confirms explicitly and
   fails closed. Removing that check would silently break everything.
2. **Every protocol error is terminal.** A session that sees a bad frame is
   wiped and cannot be reused. This is deliberate: no error path may leave a
   session able to carry plaintext.
3. **The fixed Argon2id salt** is unavoidable — both peers derive from the
   secrets alone. It makes the derivation a global precomputation target, which
   is exactly why the work factor and the code-strength rules matter.
4. **Self-connections are expected.** Both peers publish and dial the same
   address, so one reaches itself. The SPAKE2 reflection check rejects it. If
   that check were removed, a peer could complete a handshake with itself.
5. **Padding is verified on receive.** Trailing bytes must be zero and the length
   must be a valid bucket, closing a malleability channel.

## Cryptography

Nothing is hand-rolled. Argon2id (`argon2`), HKDF-SHA256 (`hkdf`), SPAKE2 over
Ed25519 (`spake2`), ChaCha20-Poly1305 (`chacha20poly1305`), constant-time
comparison (`subtle`), key erasure (`zeroize`). Tor via `arti-client`.

`#![forbid(unsafe_code)]` in every crate.
