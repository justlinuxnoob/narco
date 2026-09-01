# Narco Protocol v1

This document is the normative specification. The implementation in
`crates/narco-proto` follows it exactly; if the two ever disagree, that is a bug.

The design goal: **no server is needed, and any server that is used cannot read,
cannot authenticate, and cannot retain.**

The default transport (§11) uses **no server at all** — the shared secrets derive
an onion address, so the two peers meet through Tor's existing directory with
nothing hosted by anyone. Sections 6–9 additionally describe an optional
self-hosted relay for people who want instant connections instead; every security
property below holds even if that relay's operator is actively malicious.

---

## 0. Notation

- `||` — byte concatenation
- `be64(n)` — 8-byte big-endian encoding of `n`
- `HKDF(ikm, salt, info, L)` — HKDF-SHA256, Extract-then-Expand, `L` output bytes
- All string literals are ASCII, no trailing NUL

---

## 1. The room code

The shared secrets are the **only** secrets. There are no accounts, keys-on-disk,
or identities of any kind. The first secret is the *room code* and is described
here; §2.1 covers using several.

### 1.1 Generated codes

The app generates codes from a 32-character ambiguity-free alphabet:

```
ABCDEFGHJKLMNPQRSTUVWXYZ23456789
```

(A–Z with `I` and `O` removed, plus `2`–`9`.) The default length is **26
characters = 130 bits** of entropy, drawn from the OS CSPRNG.

### 1.2 User-supplied codes

A code typed by hand MUST pass all of:

| Rule | Reason |
| --- | --- |
| ≥ 10 characters after trimming | Floor on brute-force cost |
| ≥ 6 distinct characters | Rejects `aaaaaaaaaa` |
| Not a monotonic run | Rejects `0123456789`, `abcdefghij` |
| Not in the built-in weak list | Rejects `password12`, `1234567890`, … |

Codes are **case-sensitive**, trimmed of leading/trailing whitespace, and
NFC-normalized before use. Case sensitivity preserves entropy; the cost is that
a case mismatch fails closed (no connection) rather than silently degrading.

> A 10-character code is the floor, not a recommendation. Use the generate
> button. See [§9](#9-what-the-server-learns) for what a weak code actually costs you.

---

## 2. Key derivation

Both peers derive everything from the shared secrets alone. No key material is
ever transmitted in a recoverable form.

### 2.1 Multiple secrets

Peers may share **any number** of secrets, entered in the same order on both
devices. Empty entries are ignored. The first non-empty secret is the room code
and must satisfy §1.2; the rest are free-form.

They are combined with a count prefix and per-secret length prefixes, so a list
cannot be re-split ambiguously — without this, `("ab", "c")` and `("a", "bc")`
would be the same room:

```
secret_bytes = be32(n) || ( be32(len(sᵢ)) || UTF8(NFC(trim(sᵢ))) )  for i in 1..n
```

Cryptographically, `n` secrets are identical to one longer secret — entropy
simply adds, and against a generated 130-bit code guessing is already hopeless
with one. The gain is **channel separation**: send each secret a different way
(messaged, spoken on a call, said in person) and an attacker must compromise
*every* channel. Holding all but one yields nothing, since every derived value
below depends on every secret.

### 2.2 Stretching

```
ikm[64] = Argon2id(
    password = secret_bytes,
    salt     = "narco-v1-room-salt",     // fixed domain constant
    m        = 32768 KiB (32 MiB),
    t        = 3,
    p        = 1,
    outlen   = 64
)

hk       = HKDF-Extract(salt = <none>, ikm = ikm)
room_id  = hk.expand("narco/v1/room-id", 16)      // → 32 lowercase hex chars
pake_pw  = hk.expand("narco/v1/pake-pw", 32)
```

`room_id` is the **only** derived value the server ever sees. `pake_pw` never
leaves the device.

The salt is a fixed constant because both peers must arrive at the same value
knowing only the code. This makes the derivation a global precomputation target;
Argon2id at 32 MiB / t=3 is what makes that precomputation uneconomical for
anything but a weak code. This is stated plainly rather than hidden — it is the
single most important reason to use a generated code.

---

## 3. Handshake — SPAKE2

A plain "hash the code into an AES key" scheme would let a malicious relay run
an **offline dictionary attack**: capture one transcript, then guess codes at
GPU speed forever. Narco uses SPAKE2, a password-authenticated key exchange, so
that a malicious relay gets **one online guess per connection attempt** and
learns nothing offline.

Both peers run the *symmetric* variant (neither is client nor server):

```
(state, pake_msg) = SPAKE2-Symmetric-Start(
    password = pake_pw,
    identity = room_id
)
→ send pake_msg (33 bytes)
← receive peer_msg
K[32] = state.finish(peer_msg)
```

### 3.1 Reflection defence

If `peer_msg == pake_msg`, the session is **aborted**. A malicious relay could
otherwise echo a peer's own handshake message back at it, causing that peer to
complete a key agreement with itself.

### 3.2 Role assignment

Roles are assigned deterministically by byte-comparing the two handshake
messages, so both sides independently agree without extra round trips:

```
A = the peer whose pake_msg sorts lexicographically lower
B = the other peer
```

---

## 4. Key schedule

**SPAKE2 does not fail on a wrong password — it silently produces a different
key.** Key confirmation is therefore mandatory, not optional hardening.

```
transcript = min(pake_msg, peer_msg) || max(pake_msg, peer_msg)
hk2        = HKDF-Extract(salt = transcript, ikm = K)

confirm_A = hk2.expand("narco/v1/confirm-A", 32)
confirm_B = hk2.expand("narco/v1/confirm-B", 32)
key_A     = hk2.expand("narco/v1/key-A", 32)     // A encrypts with this
key_B     = hk2.expand("narco/v1/key-B", 32)     // B encrypts with this
```

### 4.1 Confirmation exchange

Each peer sends its **own** role's confirmation tag and verifies the tag it
expects from the **other** role, in constant time:

- A sends `confirm_A`, and requires the peer to send exactly `confirm_B`
- B sends `confirm_B`, and requires the peer to send exactly `confirm_A`

Because the tags are role-tagged, a reflected confirmation fails even if §3.1
were bypassed.

On any mismatch the session aborts immediately, all key material is zeroized,
and the UI reports a failed handshake. There is no retry on the same socket —
a wrong code means reconnecting from scratch.

The message UI does not unlock until confirmation succeeds in both directions.

---

## 5. Transport

Each peer holds:

| | |
| --- | --- |
| `tx_key` | its own role's key, `tx_ctr` starting at 0 |
| `rx_key` | the peer role's key, `rx_ctr` starting at 0 |

### 5.1 Sending

```
nonce  = 0x00000000 || be64(tx_ctr)
aad    = "narco/v1/msg" || be64(tx_ctr)
ct     = ChaCha20-Poly1305(tx_key).encrypt(nonce, pad(plaintext), aad)
→ send  0x03 || be64(tx_ctr) || ct

tx_key ← HKDF(ikm = tx_key).expand("narco/v1/ratchet", 32)   // old key zeroized
tx_ctr ← tx_ctr + 1
```

### 5.2 Receiving

The counter MUST equal `rx_ctr` exactly. WebSocket over TCP guarantees ordering,
so a gap, repeat, or reordering is evidence of tampering, not of a lossy
network — the session aborts. This gives replay and reorder protection for free.

Decryption failure likewise aborts the session.

### 5.3 Forward secrecy

Each message key is used exactly once and then replaced by its HKDF successor,
with the predecessor zeroized. The ratchet is one-way, so an attacker who
compromises a device at message *n* cannot decrypt messages *0…n−1* — including
from a full recording of the ciphertext.

Note the counter is carried in both the nonce and the AAD even though every key
is single-use. That redundancy is deliberate: it makes nonce reuse structurally
impossible even if a future change breaks the once-per-key invariant.

### 5.4 Padding

Ciphertext length leaks plaintext length, so plaintext is padded into buckets:

```
pad(pt):
    inner  = be32(len(pt)) || pt
    target = smallest of {256, 1024, 4096, 16384, 65536} that is ≥ len(inner)
    return inner || 0x00 * (target − len(inner))
```

Unpadding reads the length prefix and **verifies every remaining byte is zero**,
aborting otherwise. Maximum plaintext is 32 KiB.

---

## 6. Wire format

The framing is chosen so that the relay's forwarding path contains **zero
parsing**.

| Direction | Frame type | Meaning |
| --- | --- | --- |
| client → server | Binary, **first frame only** | Join request (§6.2). The one frame the server parses. |
| client → server | Binary, all later frames | Opaque payload, relayed verbatim. Never inspected beyond its length. |
| client → server | Text | **Rejected.** Connection closed. |
| server → client | Binary | A peer's bytes, forwarded verbatim |
| server → client | Text | Server control message (JSON, see §7) |

The server distinguishes control from payload by WebSocket frame type alone, so
there is no parser on the data path and no possibility of payload/control
confusion.

### 6.1 Inner payload (peer ↔ peer, opaque to the server)

```
0x01 || pake_msg[33]                    handshake
0x02 || confirm[32]                     key confirmation
0x03 || be64(counter) || ciphertext     encrypted message
```

### 6.2 Join frame

The connection URL is exactly `/ws`, with **no query string**. The room
identifier travels in the first binary frame instead:

```
0x00 || room_id[32]     // 32 ASCII lowercase hex characters
```

This matters. A room id in `?r=<id>` would be written to the access logs of
every reverse proxy and hosting platform on the path — logs the operator may not
control and cannot promise to erase. Request bodies and WebSocket frames are not
logged that way. The URL carries nothing.

The kind byte `0x00` is distinct from the three peer-to-peer kinds, so a join
frame can never be confused with relayed payload. A client that sends no join
frame within 10 seconds is disconnected.

---

## 7. Server control messages

```json
{"t":"sys","e":"waiting"}      // room created, you are alone
{"t":"sys","e":"peer_joined"}  // second peer present, begin handshake
{"t":"sys","e":"peer_left"}    // peer gone; room is being destroyed
{"t":"sys","e":"room_full"}    // two peers already present; you are refused
{"t":"sys","e":"expired"}      // 10-minute idle timeout fired
```

A malicious server can **lie** about these — for example forging `peer_left` to
end a session. That is a denial of service, and it is the limit of what it can
do: control messages carry no key material and are never trusted for anything
beyond UI state. Confidentiality and authenticity of messages do not depend on
them.

---

## 8. Room lifecycle

1. Client opens `GET /ws` and sends a join frame (§6.2) carrying a `room_id` of
   exactly 32 lowercase hex characters. Anything else is closed immediately.
2. Room absent → created in RAM, peer takes slot 0, receives `waiting`.
3. Room has one peer → joiner takes slot 1, **both** receive `peer_joined`.
4. Room has two peers → joiner receives `room_full` and is closed. The existing
   room and its occupants are untouched. **A room never holds more than two.**
5. Binary frame from a peer → forwarded to the other slot; dropped if empty.
6. Any frame resets the room's idle timer.
7. Idle > **10 minutes** → both peers receive `expired`, sockets close, room
   removed.
8. **Any** disconnect → the other peer receives `peer_left`, its socket closes,
   and the room is removed.

There is no reconnect and no grace period. A dropped connection ends the
session. This is deliberate: resuming would require either persisting ratchet
state or re-running the handshake with a code the user believed was single-use.
Ending is the behaviour that matches the promise.

Rooms exist only as entries in an in-memory map. Nothing is written to disk,
and there is no database.

---

## 9. What the server learns

Stated exhaustively, because a privacy claim that hides its limits is worthless.

**The server can see:**

- `room_id` — an Argon2id-hardened hash of the code. Recoverable by brute force
  only if the code is weak; infeasible for a generated 130-bit code.
- Source IP addresses, and therefore that two particular addresses spoke.
- Connection and message **timing**.
- Message **sizes**, quantized to the §5.4 buckets.
- Message **counts**.

**The server cannot see:**

- Message contents — it holds no key and the handshake is a PAKE.
- Any identity: no accounts, usernames, emails, phone numbers, or device IDs.
- Anything at all after the room is dropped from the map.

**Narco does not protect against network-level metadata.** It is not an anonymity
system. Route it over Tor or a VPN if an observer knowing *that you connected*
is part of your threat model.

**Reusing a code across sessions lets the server correlate the two sessions**, since
the same code always yields the same `room_id`. Generate a fresh code each time.

**Endpoint compromise defeats everything.** Plaintext exists on both devices while
the conversation is on screen. Narco protects data in transit, not a device
someone else controls.

---

## 10. Cryptographic inventory

| Purpose | Primitive | Crate |
| --- | --- | --- |
| Code stretching | Argon2id, 32 MiB / t=3 / p=1 | `argon2` |
| Key derivation | HKDF-SHA256 | `hkdf`, `sha2` |
| Key agreement | SPAKE2 (Ed25519 group) | `spake2` |
| Message encryption | ChaCha20-Poly1305 | `chacha20poly1305` |
| Constant-time compare | — | `subtle` |
| Key erasure | — | `zeroize` |

No cryptographic primitive is implemented in this project. Every one comes from
an established, widely-reviewed crate.

---

## 11. Tor transport (default)

Narco's shipping transport uses no server at all. The room secrets derive an
onion service identity, so the code itself is the meeting place.

### 11.1 Address derivation

```
onion_seed = hk.expand("narco/v1/onion-a", 32)      // from §2
keypair    = ed25519_expand(onion_seed)             // standard SHA-512 expansion
address    = base32(pubkey || checksum || 0x03) || ".onion"
```

Both peers compute this offline from the secrets alone, so no signalling server
is needed. Verify it yourself:

```
cargo run -p narco-tor --example derive -- "YOUR-CODE"
```

### 11.2 Meeting without negotiation

A connection needs a listener and a dialler, and the peers cannot agree on which
is which before they are connected. **Both do both.** Their descriptors collide
in the Tor directory and one wins, supplying the asymmetry:

| | accepts | its own dial reaches |
| --- | --- | --- |
| descriptor **won** | the other peer | itself |
| descriptor **lost** | nobody | the winner |

Exactly one real pairing forms, plus one self-connection. Each candidate gets its
own [`Session`](#3-handshake--spake2); the self-connection is rejected by the
§3.1 reflection check and discarded. This converges on the first attempt.

A coin-flipped host/dial role was tried first and rejected: it fails half the
time, and a failure is only detectable by timeout — which must be minutes long,
because descriptor propagation is.

### 11.3 Enforcing "only ever two"

The moment the handshake confirms, the onion service is **dropped, which
unpublishes the address**. There is no longer anything to connect to, so a third
party cannot join. This is structural, not a check that could be bypassed.

### 11.4 Keys and disk

Arti is configured with `ArtiKeystoreKind::Ephemeral`, an in-memory keystore, so
the code-derived onion identity is **never written to disk**. Tor's own consensus
cache and guard state are still stored normally; they contain no Narco key,
message, or room identifier.

### 11.5 Measured cost

From `examples/live_handshake.rs` against the live network, two cold clients:

| | |
| --- | --- |
| Tor bootstrap | ~40 s |
| Publish, propagate, connect, handshake | ~215 s |
| **Total, cold** | **~258 s** |

Slow, and honestly so. A warm client skips most of the bootstrap. This is the
price of needing no server and revealing no IP address to anyone — including to
the person you are talking to.

### 11.6 What Tor changes about §9

Compared to the relay, the Tor transport removes the operator entirely: there is
no server that sees `room_id`, IP addresses, timing, or sizes, because there is
no server. Peers do not learn each other's IPs either — the circuit terminates at
a rendezvous point.

What remains: an onion descriptor exists in Tor's distributed directory for a few
hours. It is encrypted and blinded, and it cannot be browsed or enumerated —
finding it requires already knowing the exact address, which requires the
secrets. But "nothing exists anywhere" is not literally true at the Tor layer,
and it would be dishonest to claim otherwise.
