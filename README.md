# narco

Private chat for two people. No accounts, no server, no history.

Both people enter the same secret. The app turns that secret into a Tor address,
they meet there, and everything they say is end-to-end encrypted. When the
session ends, the keys are destroyed and the conversation is gone — because it
was never written down anywhere.

```
type a secret  →  it becomes an address  →  you meet there  →  encrypted chat
                                                             →  end  →  gone
```

## There is no server

That's the point, and it's the part worth understanding.

A server's only real job is introducing two people who can't find each other.
Narco doesn't need one, because **the secret is the address**:

```
PWXK7M2QRT9HFZ  →  Argon2id  →  ed25519 key  →  ew3r52hw…qu3hhxyd.onion
```

Both devices compute that offline, from the secret alone, and arrive at the same
place. Tor's existing public directory does the introduction. Nothing is hosted,
nothing is rented, and there is no bill that can ever arrive.

See for yourself, without connecting to anything:

```sh
cargo run -p narco-tor --example derive -- "YOUR-SECRET-HERE"
```

## What it does

- **Two people, ever.** The moment the handshake confirms, the address is
  unpublished. There is no longer a door for a third person to knock on.
- **Any number of secrets.** Use one, or five. Send each a different way — one
  messaged, one spoken aloud — so intercepting one channel yields nothing.
- **Nothing on disk.** No database, no history, no logs. Messages live in memory
  and die with the session.
- **Forward secrecy.** Each message's key is destroyed right after use. Someone
  who takes your device tomorrow cannot read what you said today, even with a
  full recording of the traffic.
- **Ends three ways.** You hit end, ten minutes of silence pass, or the app
  closes. All three wipe everything.

## What it does not do

Stated plainly, because a privacy claim that hides its limits is worthless.

- **It is not instant.** A cold start takes about **90 seconds** — roughly 35 s
  to join the Tor network, then under a minute for the two apps to find each
  other. That is the price of needing no server. Measured, not estimated.
- **It does not protect a compromised device.** Plaintext is on both screens.
- **The onion descriptor exists in Tor's directory for a few hours.** It is
  encrypted and cannot be enumerated, but "nothing exists anywhere" is not
  literally true at the Tor layer.
- **Reused secrets meet at the same address.** Old messages are unrecoverable
  either way, but someone who learns your secret could show up in a *new* empty
  room pretending to be your friend. Generate a fresh one each time.

## Security design

[`PROTOCOL.md`](PROTOCOL.md) is the normative spec — key derivation, the SPAKE2
handshake, the ratchet, padding, and an exhaustive list of what leaks.

The short version: secrets are stretched with Argon2id, then a **SPAKE2**
password-authenticated key exchange establishes a session key. SPAKE2 matters
because it makes offline dictionary attacks impossible — an attacker gets one
online guess per attempt and learns nothing from a recorded transcript. Messages
use ChaCha20-Poly1305 with a per-message ratchet and length padding.

**SPAKE2 does not fail on a wrong secret — it silently yields a different key.**
So the protocol confirms the key explicitly before unlocking the UI. A wrong
secret connects to nothing and says nothing.

No cryptographic primitive is implemented here. Every one comes from an
established, reviewed crate.

## Layout

| | |
| --- | --- |
| `crates/narco-proto` | All cryptography. Transport-agnostic, no Tor dependency. |
| `crates/narco-tor` | Secret → onion address, and meeting without a server. |
| `app/` | Tauri desktop app. Holds no keys; the UI is 4 kB of JavaScript. |
| `server/` | **Optional.** A blind relay you can self-host for instant connects instead of Tor. Not used by default. |

`server/` has no dependency on `narco-proto`, and must never gain one — the relay
holds no keys and contains no cryptography. That absence is checkable from its
`Cargo.toml`.

## Build

Needs [Rust](https://rustup.rs) and [Node](https://nodejs.org), plus the
[Tauri prerequisites](https://tauri.app/start/prerequisites/) for your platform.

```sh
cd app
npm install
npm run tauri build     # or: npm run tauri dev
```

Run the tests, including a live end-to-end check over the real Tor network:

```sh
cargo test --manifest-path crates/narco-proto/Cargo.toml
cargo test --manifest-path crates/narco-tor/Cargo.toml
cargo run -p narco-tor --example live_handshake   # takes a few minutes
```

## Status

Early. The protocol and transport are implemented and tested, including live
over Tor. It has **not** been audited. Don't stake your safety on it yet.

## Licence

[AGPL-3.0-or-later](LICENSE). If you run a modified version as a service, you
have to publish your changes — which is the point, for software whose whole
claim is that you can check what it does.
