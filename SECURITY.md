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
- **Hunt for weak secrets without touching you.** This is the sharpest edge in
  the design, so it is worth stating plainly. The onion address is derived from
  the secret, so an attacker can guess a secret, derive its address, and ask the
  Tor directory whether that service exists — offline, in bulk, with no
  connection to either of you and nothing you could observe. Argon2id at 32 MiB
  prices each guess in memory rather than cycles, which rules out cheap GPU
  farming, but it only buys a constant factor. What actually decides this is the
  secret: a generated one is 130 bits and unreachable; one a person invents is
  usually nearer 30 bits, and 30 bits is a weekend on rented hardware. **Use the
  generated code.** Narco fills one in for you and warns when you replace it.
- **Reuse a leaked secret.** Old messages stay unrecoverable, but someone with
  your secret can open a *new* room at the same address and impersonate your
  contact. Generate a fresh secret per conversation.
- **Deny service.** Anyone who knows the secret can occupy the room, and Tor
  itself can be blocked. Narco fails closed — it will not connect rather than
  connect insecurely.

## Known weaknesses

Found in internal reviews and listed here because a security tool that keeps its
open problems to itself is not worth trusting. Ordered by how much they should
worry you. Last revised for 0.10.0, after a three-way audit of the crypto, the
app, and the Tor transport.

1. **The SPAKE2 library never erases its own state.** `spake2` 0.4.0 has no
   zeroization — not even as an optional feature. Its ephemeral scalar and a
   plain copy of the PAKE password are freed un-wiped when the handshake
   finishes, and they stay in the heap for the whole conversation. Anyone who
   can read this process's memory (a core dump, a hibernation image, a seized
   and unlocked device) can recompute the session key from that scalar plus the
   handshake messages, which are public. The password copy does not reveal your
   code — HKDF is one way — but it is enough to impersonate either side in any
   future session using the same secrets. Fixing this needs a patched or
   replaced PAKE crate; nothing in Narco's own code can reach that memory.

2. **The guessing limit cannot stop an offline dictionary attack, and never
   could.** A host answers at most five wrong secrets and slows down in
   between, which bounds guessing *against the host*. It does not bound
   guessing at all, because the onion address and the SPAKE2 password come from
   the same derivation: an attacker derives a candidate address offline and
   asks the Tor directory whether it exists. No connection to you, nothing to
   rate-limit, nothing you could observe. Argon2id at 32 MiB × 3 passes is what
   actually stands between a weak secret and this attack, which is why the
   generated code is 14 characters from a 32-symbol alphabet — about 70 bits —
   and why typing your own is warned about. The limit is worth having against
   someone who already has the address; it is not what keeps you safe.

3. **Tor's cache stays on disk.** No message, key, or code is ever written —
   but tor keeps its consensus cache and its chosen entry guards in a folder
   Narco owns, which is what makes the second connection quick instead of
   another 40 seconds. It holds nothing of yours, but its timestamps show this
   machine ran Tor and roughly when, and the guard list shows which relays it
   used. Until 0.10.0 this section claimed the folder was deleted on a clean
   shutdown; it was not. The code that deletes it lives in a destructor, and
   Tauri exits the process without running destructors, so it had never run in
   a released build. Delete `~/.cache/narco` (or `%LOCALAPPDATA%\narco`)
   yourself if it matters to you.

4. **The room code is held in ordinary strings.** `code::generate` and
   `code::normalize` use `String`, which is not wiped when dropped. The secret
   list the app receives from the webview is now wiped, and so is every
   derived value, but the copy serde makes while decoding the message from the
   webview is out of reach. Recovering the code from memory is worse than
   recovering a key, because it reproduces every past and future session for
   that code.

5. **A file in flight exists in several unwiped copies.** Text is handled
   tightly: one buffer in the session task, one on screen, destroyed together.
   A file is not. It exists as its pieces, as the joined bytes, as base64
   across the IPC boundary, and again as bytes and a blob inside the webview.
   All of it is freed when the session ends and none of it reaches disk unless
   you save it, but the individual copies are not zeroized, and the ones inside
   the webview are past the reach of Narco's own code.

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
4. **Roles are asymmetric, so a self-connection cannot happen.** One person
   hosts and publishes; the other only dials. An earlier design had both do
   both, which meant each peer also reached itself and relied on the SPAKE2
   reflection check to reject it. The reflection check is still there, but it is
   now a backstop rather than load-bearing.
5. **Padding is verified on receive.** Trailing bytes must be zero and the length
   must be a valid bucket, closing a malleability channel.

## Cryptography

Nothing is hand-rolled. Argon2id (`argon2`), HKDF-SHA256 (`hkdf`), SPAKE2 over
Ed25519 (`spake2`), ChaCha20-Poly1305 (`chacha20poly1305`), constant-time
comparison (`subtle`), key erasure (`zeroize`).

Tor is the C `tor` daemon from the Tor Expert Bundle — the same binary Tor
Browser ships — driven over its control port as a child process. Narco used the
Arti library until 0.5.0, and switched because Arti could not complete circuits
on several Windows machines: channels handshook, then every circuit sat unused
until the relay tore it down. No cryptography moved with that change; the
transport crate does no crypto and the protocol crate has no Tor dependency.

`#![forbid(unsafe_code)]` in every crate.
